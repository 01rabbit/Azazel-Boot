from __future__ import annotations

import json
import hashlib
import base64
import tempfile
import unittest
from pathlib import Path

from tools.payload.run_nexus_guest_e2e import format_report_frame
from tools.payload.run_nexus_guest_e2e import REPORT_CHUNK_BYTES
from tools.payload.run_qemu_nexus_e2e import (
    guest_report_passes,
    guest_evidence_is_terminal,
    measurement_passes,
    parse_guest_boot_state,
    parse_guest_report,
    parse_guest_report_frame,
    persist_partial_report,
    report_output_complete,
    verify_build_binding,
)


REPORT_OBJECT = {
    "schema": "azazel-nexus/disposable-guest-e2e@1",
    "verdict": "pass",
    "lifecycle_scope": "package-install-and-status-plus-disposable-import-fixture",
    "hardware_verified": False,
    "secure_boot_verified": False,
    "network_fetch_performed": False,
    "provider_admission_performed": False,
    "edge_activation_performed": False,
    "package": {
        "name": "azazel-nexus-prototype",
        "version": "0.0.1~prototype1",
        "architecture": "all",
        "package_sha256": "a" * 64,
    },
    "installer": {
        "exit_code": 0,
        "activation_controller_enabled_not_started": True,
        "operational_units_masked": {"azazel-model-fetchd.service": "masked"},
    },
    "status": {"exit_code": 0},
    "generation": {
        "evidence_scope": "disposable_fixture_direct_ModelImport_API",
        "current_before_rollback": 2,
        "reading_one_after_rollback": "present",
        "reading_two_after_rollback": "declared",
    },
    "rollback": {"restored_generation": 1, "current_generation": 1},
}
REPORT = json.dumps(REPORT_OBJECT, separators=(",", ":"), sort_keys=True)
EXPECTED_PACKAGE_SHA256 = "a" * 64


def framed(payload: str = REPORT, *, length: int | None = None, digest: str | None = None) -> str:
    payload_bytes = payload.encode("utf-8")
    frame_length = len(payload_bytes) if length is None else length
    frame_digest = hashlib.sha256(payload_bytes).hexdigest() if digest is None else digest
    chunks = [payload_bytes[offset:offset + REPORT_CHUNK_BYTES]
              for offset in range(0, len(payload_bytes), REPORT_CHUNK_BYTES)]
    metadata = f"length={frame_length} sha256={frame_digest} chunks={len(chunks)}"
    lines = [f"AZAZEL_NEXUS_E2E_REPORT_BEGIN {metadata}"]
    lines.extend(
        f"AZAZEL_NEXUS_E2E_REPORT_CHUNK seq={seq} data={base64.b64encode(chunk).decode('ascii')}"
        for seq, chunk in enumerate(chunks)
    )
    lines.append(f"AZAZEL_NEXUS_E2E_REPORT_END {metadata}")
    return "\n".join(lines) + "\n"


class QemuNexusE2ETests(unittest.TestCase):
    def test_guest_emits_compact_length_and_digest_bound_frame(self) -> None:
        frame = "\n".join(format_report_frame(REPORT_OBJECT)) + "\n"
        report, raw, error, partial = parse_guest_report(frame)
        details = parse_guest_report_frame(frame)
        self.assertEqual(report, REPORT_OBJECT)
        self.assertEqual(raw, REPORT)
        self.assertIsNone(error)
        self.assertIsNone(partial)
        self.assertEqual(details["status"], "complete")
        self.assertEqual(details["expected_length"], len(REPORT.encode("utf-8")))
        self.assertEqual(details["received_sha256"], hashlib.sha256(REPORT.encode()).hexdigest())

    def test_parses_single_structured_report_and_boot_marker(self) -> None:
        text = (
            f"AZAZEL_NEXUS_E2E_PASS\n{framed()}"
            "Reached target multi-user.target - Multi-User System.\n"
        )
        report, raw, error, partial = parse_guest_report(text)
        state = parse_guest_boot_state(text)
        self.assertEqual(raw, REPORT)
        self.assertIsNone(error)
        self.assertIsNone(partial)
        self.assertTrue(state["reached_multi_user_target"])
        self.assertTrue(guest_report_passes(report, error, EXPECTED_PACKAGE_SHA256))
        self.assertTrue(measurement_passes(report, error, True))

    def test_parses_systemd_prefixed_complete_frame(self) -> None:
        frame_lines = framed().splitlines()
        text = (
            "AZAZEL_NEXUS_E2E_PASS\n"
            + "".join(f"[ 50.630401] azazel-nexus-prototype-e2e[897]: {line}\n" for line in frame_lines)
            + "[ 50.7] systemd[1]: Reached target multi-user.target - Multi-User System.\n"
        )
        report, raw, error, partial = parse_guest_report(text)
        self.assertEqual(raw, REPORT)
        self.assertIsNone(partial)
        self.assertIsNone(error)
        self.assertTrue(guest_report_passes(report, error, EXPECTED_PACKAGE_SHA256))
        self.assertTrue(measurement_passes(report, error, True))

    def test_missing_duplicate_and_malformed_report_fail_closed(self) -> None:
        self.assertEqual(parse_guest_report("console output\n")[2], "guest_report_missing")
        duplicate = framed() + framed()
        self.assertEqual(parse_guest_report(duplicate)[2], "guest_report_duplicate")
        malformed = framed("{bad}")
        self.assertEqual(parse_guest_report(malformed)[2], "guest_report_malformed_json")
        for text in ("console output\n", duplicate, malformed):
            parsed, _, error, _ = parse_guest_report(text)
            self.assertFalse(guest_report_passes(parsed, error))

    def test_incomplete_frame_is_not_complete_and_keeps_partial_payload(self) -> None:
        incomplete = (
            "AZAZEL_NEXUS_E2E_REPORT_BEGIN length=100 sha256=" + "a" * 64 + " chunks=2\n"
            "AZAZEL_NEXUS_E2E_REPORT_CHUNK seq=0 data="
            + base64.b64encode(b'{"verdict":').decode("ascii")
        )
        report, raw, error, partial = parse_guest_report(incomplete)
        self.assertIsNone(report)
        self.assertIsNone(raw)
        self.assertEqual(error, "guest_report_incomplete")
        self.assertEqual(partial, incomplete)
        self.assertFalse(report_output_complete(incomplete))

    def test_bad_length_and_digest_fail_closed(self) -> None:
        bad_length = framed(length=len(REPORT.encode("utf-8")) + 1)
        bad_digest = framed(digest="f" * 64)
        self.assertEqual(parse_guest_report(bad_length)[2], "guest_report_bad_length")
        self.assertEqual(parse_guest_report(bad_digest)[2], "guest_report_bad_digest")

    def test_rejects_missing_duplicate_reordered_and_truncated_chunks(self) -> None:
        lines = framed().splitlines()
        begin, end, chunks = lines[0], lines[-1], lines[1:-1]
        self.assertGreaterEqual(len(chunks), 2)
        missing = "\n".join([begin, *chunks[:-1], end]) + "\n"
        self.assertEqual(parse_guest_report(missing)[2], "guest_report_missing_chunks")
        duplicate = "\n".join([begin, *chunks, chunks[0], end]) + "\n"
        self.assertEqual(parse_guest_report(duplicate)[2], "guest_report_duplicate")
        reordered = "\n".join([begin, *reversed(chunks), end]) + "\n"
        self.assertEqual(parse_guest_report(reordered)[2], "guest_report_chunk_sequence_invalid")
        truncated = "\n".join([begin, chunks[0]])
        details = parse_guest_report_frame(truncated)
        self.assertEqual(details["status"], "incomplete")
        self.assertEqual(details["error"], "guest_report_incomplete")
        self.assertEqual(details["raw_frame"], truncated)

        # A chunk being written when the host polls is incomplete, not a
        # conclusive encoding error that should stop QEMU early.
        in_flight = "\n".join([begin, chunks[0][:-3]])
        self.assertEqual(parse_guest_report(in_flight)[2], "guest_report_incomplete")

    def test_rejects_reordered_markers_bad_chunk_digest_and_duplicate_frame(self) -> None:
        lines = framed().splitlines()
        reordered = "\n".join([lines[-1], *lines[:-1]]) + "\n"
        self.assertEqual(parse_guest_report(reordered)[2], "guest_report_frame_reordered")
        changed = lines[1][:-1] + ("A" if lines[1][-1] != "A" else "B")
        bad_digest = "\n".join([lines[0], changed, *lines[2:]]) + "\n"
        self.assertEqual(parse_guest_report(bad_digest)[2], "guest_report_bad_digest")
        self.assertEqual(parse_guest_report(framed() + framed())[2], "guest_report_duplicate")

    def test_strips_console_osc_around_frame(self) -> None:
        report, _, error, _ = parse_guest_report("\x1b]104\x07" + framed())
        self.assertEqual(report, REPORT_OBJECT)
        self.assertIsNone(error)

    def test_partial_timeout_evidence_is_persisted_separately(self) -> None:
        incomplete = "AZAZEL_NEXUS_E2E_REPORT_BEGIN length=80 sha256=" + "a" * 64 + " chunks=1\n"
        incomplete += "AZAZEL_NEXUS_E2E_REPORT_CHUNK seq=0 data=" + base64.b64encode(b'{"schema":').decode() + "\n"
        _, _, error, partial = parse_guest_report(incomplete)
        self.assertEqual(error, "guest_report_incomplete")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            path = persist_partial_report(output, partial)
            self.assertEqual(path, output / "guest-report-partial.txt")
            self.assertEqual(path.read_bytes(), partial.encode("latin-1"))
            self.assertFalse((output / "guest-report.json").exists())

    def test_incomplete_report_keeps_polling_even_if_json_parses(self) -> None:
        incomplete_frame = "\n".join(framed().splitlines()[:2])
        text = f"AZAZEL_NEXUS_E2E_PASS\n{incomplete_frame}"
        report, _, error, _ = parse_guest_report(text)
        self.assertEqual(error, "guest_report_incomplete")
        self.assertFalse(
            guest_evidence_is_terminal(text, report, error, EXPECTED_PACKAGE_SHA256)
        )

    def test_terminal_conditions_require_complete_pass_and_multi_user(self) -> None:
        passing = (
            f"AZAZEL_NEXUS_E2E_PASS\n{framed()}"
            "Reached target multi-user.target - Multi-User System.\n"
        )
        report, _, error, _ = parse_guest_report(passing)
        self.assertTrue(
            guest_evidence_is_terminal(passing, report, error, EXPECTED_PACKAGE_SHA256)
        )

        before_multi_user = f"AZAZEL_NEXUS_E2E_PASS\n{framed()}"
        report, _, error, _ = parse_guest_report(before_multi_user)
        self.assertFalse(
            guest_evidence_is_terminal(
                before_multi_user, report, error, EXPECTED_PACKAGE_SHA256
            )
        )

        malformed = f"AZAZEL_NEXUS_E2E_PASS\n{framed('{bad}')}console tail"
        report, _, error, _ = parse_guest_report(malformed)
        self.assertEqual(error, "guest_report_malformed_json")
        self.assertTrue(guest_evidence_is_terminal(malformed, report, error, EXPECTED_PACKAGE_SHA256))

        failed_json = json.dumps({**REPORT_OBJECT, "verdict": "fail"}, separators=(",", ":"), sort_keys=True)
        failed = f"AZAZEL_NEXUS_E2E_FAIL\n{framed(failed_json)}"
        report, _, error, _ = parse_guest_report(failed)
        self.assertTrue(guest_evidence_is_terminal(failed, report, error, EXPECTED_PACKAGE_SHA256))

    def test_requires_pass_verdict_exact_false_authority_flags_and_boot(self) -> None:
        report, _, error, _ = parse_guest_report(f"AZAZEL_NEXUS_E2E_PASS\n{framed()}")
        self.assertTrue(guest_report_passes(report, error))
        self.assertFalse(measurement_passes(report, error, False))
        self.assertFalse(guest_report_passes({**report, "verdict": "fail"}, None))
        self.assertFalse(
            guest_report_passes(
                {**report, "edge_activation_performed": True},
                None,
            )
        )

    def test_requires_package_digest_and_full_lifecycle_evidence(self) -> None:
        self.assertFalse(guest_report_passes(REPORT_OBJECT, None, "b" * 64))
        for field, value in (
            ("installer", {"exit_code": 1}),
            ("status", {"exit_code": 1}),
            ("package", {**REPORT_OBJECT["package"], "name": "other"}),
            ("rollback", {"restored_generation": 2, "current_generation": 2}),
        ):
            with self.subTest(field=field):
                self.assertFalse(guest_report_passes({**REPORT_OBJECT, field: value}, None))

    def test_qemu_inputs_must_match_pinned_build_result_and_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload.iso"
            kernel = root / "vmlinuz"
            initramfs = root / "initrd.img"
            package = root / "azazel-nexus-prototype.deb"
            runner = root / "run_qemu_nexus_e2e.py"
            manifest = root / "build-input-manifest.json"
            build_result = root / "build-result.json"
            for path, content in (
                (payload, b"iso"),
                (kernel, b"kernel"),
                (initramfs, b"initramfs"),
                (package, b"deb"),
                (runner, b"pinned runner"),
            ):
                path.write_bytes(content)
            def digest(path: Path) -> str:
                return hashlib.sha256(path.read_bytes()).hexdigest()

            package_hash = digest(package)
            (root / "azazel-nexus-prototype.deb.sha256").write_text(
                f"{package_hash}  azazel-nexus-prototype.deb\n"
            )
            manifest.write_text(json.dumps({
                "inputs": {"nexus_qemu_runner": {"sha256": digest(runner)}},
            }))
            build_result.write_text(json.dumps({
                "schema": "azazel-payload/build-result@4",
                "payload_digest": f"sha256:{digest(payload)}",
                "kernel_digest": f"sha256:{digest(kernel)}",
                "initramfs_digest": f"sha256:{digest(initramfs)}",
                "build_input_manifest_digest": f"sha256:{digest(manifest)}",
                "nexus_package_digest": f"sha256:{digest(package)}",
                "nexus_package_in_iso_rootfs_digest": f"sha256:{digest(package)}",
                "squashfs_digest": "sha256:" + "b" * 64,
                "iso_embedded_squashfs_digest": "sha256:" + "b" * 64,
                "nexus_qemu_runner_sha256": digest(runner),
            }))
            binding = verify_build_binding(
                build_result, payload, kernel, initramfs, manifest, runner
            )
            self.assertEqual(binding["nexus_package_sha256"], digest(package))

            kernel.write_bytes(b"wrong kernel")
            with self.assertRaisesRegex(ValueError, "kernel_digest"):
                verify_build_binding(
                    build_result, payload, kernel, initramfs, manifest, runner
                )
            kernel.write_bytes(b"kernel")
            result = json.loads(build_result.read_text())
            result["nexus_package_in_iso_rootfs_digest"] = "sha256:" + "c" * 64
            build_result.write_text(json.dumps(result))
            with self.assertRaisesRegex(ValueError, "ISO root filesystem"):
                verify_build_binding(
                    build_result, payload, root / "vmlinuz", initramfs, manifest, runner
                )


if __name__ == "__main__":
    unittest.main()
