#!/usr/bin/env python3
"""Run the test-only Nexus lifecycle service in an isolated QEMU guest.

The guest payload, kernel and initramfs are regular input files. No host block
device or USB device is passed through, and the guest NIC is disabled.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path


FRAME_BEGIN = "AZAZEL_NEXUS_E2E_REPORT_BEGIN"
FRAME_END = "AZAZEL_NEXUS_E2E_REPORT_END"
FRAME_PREFIX = "AZAZEL_NEXUS_E2E_REPORT_"
FRAME_CHUNK = "AZAZEL_NEXUS_E2E_REPORT_CHUNK"
FRAME_RE = re.compile(
    r"^(AZAZEL_NEXUS_E2E_REPORT_(?:BEGIN|END)) length=(0|[1-9][0-9]*) "
    r"sha256=([0-9a-f]{64}) chunks=([1-9][0-9]*)$"
)
CHUNK_RE = re.compile(r"^AZAZEL_NEXUS_E2E_REPORT_CHUNK seq=(0|[1-9][0-9]*) data=([A-Za-z0-9+/]*={0,2})$")
MULTI_USER_RE = re.compile(r"Reached target\s+multi-user\.target(?:\s|$)")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_OSC_ESCAPE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.DOTALL)
MAX_REPORT_BYTES = 1024 * 1024
MAX_REPORT_CHUNK_BYTES = 768
AUTHORITY_FLAGS = ("network_fetch", "provider_admission", "edge_activation")


def _frame_line_content(line: str) -> str:
    """Remove the common systemd/journald console prefix from one line."""
    candidate = line.strip("\r\n")
    if candidate.startswith("[") and "]: " in candidate:
        candidate = candidate.split("]: ", 1)[1]
    if not candidate.startswith((FRAME_BEGIN, FRAME_END, "{")) and "]:" in candidate:
        candidate = candidate.split(":", 1)[1].lstrip()
    return candidate


def parse_guest_report(
    serial_text: str,
) -> tuple[dict | None, str | None, str | None, str | None]:
    """Return the decoded report, raw JSON, error, and captured partial frame."""
    details = parse_guest_report_frame(serial_text)
    return (
        details["report"],
        details["raw"],
        details["error"],
        details["raw_frame"] if details["status"] != "complete" else None,
    )


def parse_guest_report_frame(serial_text: str) -> dict[str, object]:
    """Validate exactly one framed report before decoding its JSON payload."""
    raw_lines = serial_text.splitlines(keepends=True)
    clean_text = ANSI_ESCAPE.sub("", ANSI_OSC_ESCAPE.sub("", serial_text))
    lines = clean_text.splitlines(keepends=True)
    content = [_frame_line_content(line) for line in lines]
    markers = [
        (index, line)
        for index, line in enumerate(content)
        if FRAME_PREFIX in line
    ]
    begin_indexes = [index for index, line in markers if FRAME_BEGIN in line]
    if not markers:
        return _frame_result("missing", "guest_report_missing")

    raw_frame = "".join(raw_lines[index] for index, _ in markers if index < len(raw_lines))
    unknown_markers = [
        line for _, line in markers
        if not line.startswith((FRAME_BEGIN, FRAME_END, FRAME_CHUNK))
    ]
    if unknown_markers:
        return _frame_result("invalid", "guest_report_malformed_frame", raw_frame=raw_frame)
    if len(begin_indexes) != 1:
        return _frame_result("invalid", "guest_report_duplicate", raw_frame=raw_frame)
    begin_index = begin_indexes[0]
    begin_line = content[begin_index]
    begin_match = FRAME_RE.fullmatch(begin_line)
    if begin_match is None or begin_match.group(1) != FRAME_BEGIN:
        if not lines[begin_index].endswith(("\n", "\r")):
            return _frame_result("incomplete", "guest_report_incomplete", raw_frame=raw_frame)
        return _frame_result("invalid", "guest_report_malformed_frame", raw_frame=raw_frame)
    expected_length = int(begin_match.group(2))
    expected_digest = begin_match.group(3)
    expected_chunks = int(begin_match.group(4))
    if expected_length > MAX_REPORT_BYTES:
        return _frame_result(
            "invalid", "guest_report_length_limit_exceeded", raw_frame=raw_frame,
            expected_length=expected_length, expected_sha256=expected_digest,
            expected_chunks=expected_chunks,
        )

    end_indexes = [index for index, line in markers if FRAME_END in line]
    chunk_records = [(index, line) for index, line in markers if FRAME_CHUNK in line]
    common = {
        "expected_length": expected_length,
        "expected_sha256": expected_digest,
        "expected_chunks": expected_chunks,
        "raw_frame": raw_frame,
    }
    decoded_chunks: list[bytes] = []
    if any(index < begin_index for index, _ in chunk_records):
        return _frame_result("invalid", "guest_report_frame_reordered", **common)
    seen_sequences: set[int] = set()
    for index, line in chunk_records:
        if not lines[index].endswith(("\n", "\r")):
            return _frame_result("incomplete", "guest_report_incomplete", **common)
        match = CHUNK_RE.fullmatch(content[index])
        if match is None:
            return _frame_result("invalid", "guest_report_malformed_chunk", **common)
        sequence = int(match.group(1))
        if sequence in seen_sequences:
            return _frame_result("invalid", "guest_report_duplicate", **common)
        if sequence != len(decoded_chunks):
            return _frame_result("invalid", "guest_report_chunk_sequence_invalid", **common)
        if sequence >= expected_chunks:
            return _frame_result("invalid", "guest_report_extra_chunks", **common)
        seen_sequences.add(sequence)
        try:
            chunk = base64.b64decode(match.group(2), validate=True)
        except (binascii.Error, ValueError):
            return _frame_result("invalid", "guest_report_chunk_encoding_invalid", **common)
        if not chunk or len(chunk) > MAX_REPORT_CHUNK_BYTES:
            return _frame_result("invalid", "guest_report_chunk_size_invalid", **common)
        decoded_chunks.append(chunk)
    common["chunks_received"] = len(chunk_records)
    if decoded_chunks:
        partial_bytes = b"".join(decoded_chunks)
        common["received_length"] = len(partial_bytes)
        common["received_sha256"] = hashlib.sha256(partial_bytes).hexdigest()
    if len(end_indexes) > 1:
        return _frame_result("invalid", "guest_report_duplicate", **common)
    if not end_indexes:
        return _frame_result("incomplete", "guest_report_incomplete", **common)
    end_index = end_indexes[0]
    end_match = FRAME_RE.fullmatch(content[end_index])
    if end_match is None or end_match.group(1) != FRAME_END:
        if not lines[end_index].endswith(("\n", "\r")):
            return _frame_result("incomplete", "guest_report_incomplete", **common)
        return _frame_result("invalid", "guest_report_malformed_frame", **common)
    if not lines[end_index].endswith(("\n", "\r")):
        return _frame_result("incomplete", "guest_report_incomplete", **common)
    if end_index < begin_index:
        return _frame_result("invalid", "guest_report_frame_reordered", **common)
    if end_match.group(2) != begin_match.group(2) or end_match.group(3) != expected_digest or end_match.group(4) != begin_match.group(4):
        return _frame_result("invalid", "guest_report_frame_metadata_mismatch", **common)
    if any(index < begin_index or index > end_index for index, _ in chunk_records):
        return _frame_result("invalid", "guest_report_frame_reordered", **common)
    if len(chunk_records) < expected_chunks:
        return _frame_result("invalid", "guest_report_missing_chunks", **common)
    if len(chunk_records) != expected_chunks:
        return _frame_result("invalid", "guest_report_duplicate", **common)

    payload_parts: list[bytes] = []
    for expected_sequence, (index, line) in enumerate(chunk_records):
        match = CHUNK_RE.fullmatch(content[index])
        if int(match.group(1)) != expected_sequence:
            return _frame_result("invalid", "guest_report_chunk_sequence_invalid", **common)
        if not lines[index].endswith(("\n", "\r")):
            return _frame_result("incomplete", "guest_report_incomplete", **common)
        if expected_sequence < expected_chunks - 1 and len(decoded_chunks[expected_sequence]) != MAX_REPORT_CHUNK_BYTES:
            return _frame_result("invalid", "guest_report_chunk_size_invalid", **common)
        payload_parts.append(decoded_chunks[expected_sequence])
    payload_bytes = b"".join(payload_parts)
    common["received_length"] = len(payload_bytes)
    common["received_sha256"] = hashlib.sha256(payload_bytes).hexdigest()
    common["chunks_received"] = len(payload_parts)
    if len(payload_bytes) != expected_length:
        return _frame_result("invalid", "guest_report_bad_length", **common)
    actual_digest = hashlib.sha256(payload_bytes).hexdigest()
    if actual_digest != expected_digest:
        return _frame_result("invalid", "guest_report_bad_digest", **common)
    try:
        payload = payload_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return _frame_result("invalid", "guest_report_invalid_utf8", **common)
    try:
        report = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return _frame_result("invalid", "guest_report_malformed_json", **common)
    if not isinstance(report, dict):
        return _frame_result("invalid", "guest_report_not_object", **common)
    if json.dumps(report, sort_keys=True, separators=(",", ":")) != payload:
        return _frame_result("invalid", "guest_report_not_compact_json", **common)
    return _frame_result("complete", None, report=report, raw=payload, **common)


def _frame_result(
    status: str,
    error: str | None,
    *,
    report: dict | None = None,
    raw: str | None = None,
    raw_frame: str = "",
    expected_length: int | None = None,
    received_length: int | None = None,
    expected_sha256: str | None = None,
    received_sha256: str | None = None,
    expected_chunks: int | None = None,
    chunks_received: int = 0,
) -> dict[str, object]:
    return {
        "status": status,
        "error": error,
        "report": report,
        "raw": raw,
        "raw_frame": raw_frame,
        "expected_length": expected_length,
        "received_length": received_length,
        "expected_sha256": expected_sha256,
        "received_sha256": received_sha256,
        "expected_chunks": expected_chunks,
        "chunks_received": chunks_received,
    }


def report_output_complete(serial_text: str) -> bool:
    """Whether the strict report frame is complete or conclusively invalid."""
    _, _, error, _ = parse_guest_report(serial_text)
    return error not in {"guest_report_missing", "guest_report_incomplete"}


def guest_evidence_is_terminal(
    serial_text: str,
    report: dict | None,
    report_error: str | None,
    expected_package_sha256: str,
) -> bool:
    """Stop only for terminal failure or a complete valid pass plus boot."""
    if report_error not in {
        None,
        "guest_report_missing",
        "guest_report_incomplete",
    }:
        return True
    if report is None or report_error is not None:
        return False
    if report.get("verdict") != "pass":
        return True
    if not guest_report_passes(report, report_error, expected_package_sha256):
        return True
    return parse_guest_boot_state(serial_text)["reached_multi_user_target"]


def parse_guest_boot_state(serial_text: str) -> dict[str, bool | str]:
    clean_text = ANSI_ESCAPE.sub("", serial_text)
    reached = MULTI_USER_RE.search(clean_text) is not None
    return {
        "reached_multi_user_target": reached,
        "state": "reached_multi_user_target" if reached else "not_observed",
    }


def guest_report_passes(
    report: dict | None,
    error: str | None,
    expected_package_sha256: str | None = None,
) -> bool:
    if error is not None or report is None:
        return False
    if report.get("verdict") != "pass":
        return False
    if report.get("schema") != "azazel-nexus/disposable-guest-e2e@1":
        return False
    if report.get("lifecycle_scope") != "package-install-and-status-plus-disposable-import-fixture":
        return False
    package = report.get("package")
    if not isinstance(package, dict) or package.get("name") != "azazel-nexus-prototype":
        return False
    if package.get("version") != "0.0.1~prototype1" or package.get("architecture") != "all":
        return False
    package_digest = package.get("package_sha256")
    if not isinstance(package_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", package_digest):
        return False
    if expected_package_sha256 is not None and package_digest != expected_package_sha256:
        return False
    installer = report.get("installer")
    if not isinstance(installer, dict) or installer.get("exit_code") != 0:
        return False
    if installer.get("activation_controller_enabled_not_started") is not True:
        return False
    masked = installer.get("operational_units_masked")
    if not isinstance(masked, dict) or not masked or any(value != "masked" for value in masked.values()):
        return False
    status = report.get("status")
    if not isinstance(status, dict) or status.get("exit_code") != 0:
        return False
    generation = report.get("generation")
    rollback = report.get("rollback")
    if (
        not isinstance(generation, dict)
        or generation.get("evidence_scope") != "disposable_fixture_direct_ModelImport_API"
        or generation.get("current_before_rollback") != 2
        or generation.get("reading_one_after_rollback") != "present"
        or generation.get("reading_two_after_rollback") != "declared"
        or not isinstance(rollback, dict)
        or rollback.get("restored_generation") != 1
        or rollback.get("current_generation") != 1
    ):
        return False
    flags = report.get("authority_flags")
    if not isinstance(flags, dict):
        flags = {
            "network_fetch": report.get("network_fetch_performed"),
            "provider_admission": report.get("provider_admission_performed"),
            "edge_activation": report.get("edge_activation_performed"),
        }
    if not all(flags.get(name) is False for name in AUTHORITY_FLAGS):
        return False
    return report.get("hardware_verified") is False and report.get("secure_boot_verified") is False


def measurement_passes(
    report: dict | None,
    report_error: str | None,
    guest_reached_multi_user: bool,
) -> bool:
    return guest_report_passes(report, report_error) and guest_reached_multi_user


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_build_binding(
    build_result_path: Path,
    payload: Path,
    kernel: Path,
    initramfs: Path,
    manifest: Path,
    runner: Path,
) -> dict[str, str]:
    build_result_path = build_result_path.resolve(strict=True)
    result = json.loads(build_result_path.read_text(encoding="utf-8"))
    if result.get("schema") != "azazel-payload/build-result@4":
        raise ValueError("unsupported payload build result")
    expected_fields = {
        "payload_digest": payload,
        "kernel_digest": kernel,
        "initramfs_digest": initramfs,
        "build_input_manifest_digest": manifest,
    }
    for field, path in expected_fields.items():
        expected = result.get(field)
        actual = f"sha256:{sha256(path)}"
        if expected != actual:
            raise ValueError(f"QEMU input {field} does not match build result")
    manifest_document = json.loads(manifest.read_text(encoding="utf-8"))
    runner_digest = sha256(runner.resolve(strict=True))
    pinned_runner = manifest_document.get("inputs", {}).get("nexus_qemu_runner", {}).get("sha256")
    if (
        not isinstance(pinned_runner, str)
        or pinned_runner != runner_digest
        or result.get("nexus_qemu_runner_sha256") != pinned_runner
    ):
        raise ValueError("QEMU Nexus runner differs from the frozen input manifest")
    package = build_result_path.parent / "azazel-nexus-prototype.deb"
    package_digest = f"sha256:{sha256(package)}"
    if result.get("nexus_package_digest") != package_digest:
        raise ValueError("Nexus package does not match the build result")
    if result.get("nexus_package_in_iso_rootfs_digest") != package_digest:
        raise ValueError("Nexus package digest is not bound to the ISO root filesystem")
    if result.get("iso_embedded_squashfs_digest") != result.get("squashfs_digest"):
        raise ValueError("ISO-embedded SquashFS digest differs from the build result")
    sidecar = build_result_path.parent / "azazel-nexus-prototype.deb.sha256"
    if sidecar.read_text(encoding="ascii").split() != [
        package_digest.removeprefix("sha256:"),
        "azazel-nexus-prototype.deb",
    ]:
        raise ValueError("Nexus package checksum sidecar does not match the build result")
    manifest_digest = sha256(manifest)
    if result.get("build_input_manifest_digest") != f"sha256:{manifest_digest}":
        raise ValueError("build result is not bound to the supplied input manifest")
    return {
        "build_result_sha256": sha256(build_result_path),
        "nexus_package_sha256": package_digest.removeprefix("sha256:"),
        "runner_sha256": runner_digest,
    }


def verify_manifest_sidecar(manifest: Path) -> str:
    digest = sha256(manifest)
    sidecar = manifest.with_suffix(".sha256")
    fields = sidecar.read_text(encoding="ascii").split()
    if fields != [digest, "build-input-manifest.json"]:
        raise ValueError("input manifest digest sidecar is invalid")
    return digest


def _stop_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def persist_partial_report(output: Path, partial_report: str | None) -> Path | None:
    """Persist the exact captured incomplete/invalid frame bytes separately."""
    if partial_report is None:
        return None
    path = output / "guest-report-partial.txt"
    path.write_bytes(partial_report.encode("latin-1"))
    return path


def run(args: argparse.Namespace) -> dict:
    output = args.output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError(f"evidence output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    if args.timeout_seconds <= 0:
        raise ValueError("timeout-seconds must be positive")

    payload = args.payload.resolve(strict=True)
    kernel = args.kernel.resolve(strict=True)
    initramfs = args.initramfs.resolve(strict=True)
    manifest = args.input_manifest.resolve(strict=True)
    if not all(path.is_file() for path in (payload, kernel, initramfs, manifest)):
        raise ValueError("payload, kernel, initramfs and input manifest must be regular files")
    manifest_digest = verify_manifest_sidecar(manifest)
    binding = verify_build_binding(
        args.build_result,
        payload,
        kernel,
        initramfs,
        manifest,
        Path(__file__),
    )

    serial_log = output / "serial.log"
    stderr_log = output / "qemu-stderr.log"
    report_path = output / "guest-report.json"
    result_path = output / "result.json"
    command = [
        args.qemu_binary,
        "-name", "azazel-nexus-test-only-e2e",
        "-machine", "q35,accel=tcg",
        "-cpu", "max",
        "-smp", "2",
        "-m", "8192",
        "-cdrom", str(payload),
        "-nic", "none",
        "-kernel", str(kernel),
        "-initrd", str(initramfs),
        "-append", "boot=live components live-media=/dev/sr0 console=ttyS0 systemd.show_status=yes azazel.nexus_e2e=1",
        "-display", "none",
        "-monitor", "none",
        "-serial", f"file:{serial_log}",
        "-no-reboot",
        "-no-shutdown",
    ]

    timed_out = False
    process = None
    with stderr_log.open("wb") as stderr_stream:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr_stream)
        deadline = time.monotonic() + args.timeout_seconds
        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                text = serial_log.read_bytes().decode("latin-1") if serial_log.exists() else ""
                report, _, report_error, _ = parse_guest_report(text)
                if guest_evidence_is_terminal(
                    text, report, report_error, binding["nexus_package_sha256"]
                ):
                    break
                time.sleep(0.25)
            else:
                timed_out = True
        finally:
            _stop_process(process)

    serial_text = serial_log.read_bytes().decode("latin-1") if serial_log.exists() else ""
    frame = parse_guest_report_frame(serial_text)
    report, report_raw, report_error = frame["report"], frame["raw"], frame["error"]
    boot_state = parse_guest_boot_state(serial_text)
    if timed_out:
        report_error = "qemu_timeout" if report_error is None else report_error
    if report_raw is not None and report_error is None:
        report_path.write_text(report_raw + "\n", encoding="utf-8")
    partial_path = persist_partial_report(
        output,
        frame["raw_frame"] if frame["status"] != "complete" else None,
    )
    serial_hash = sha256(serial_log) if serial_log.exists() else None
    stderr_hash = sha256(stderr_log)
    report_hash = sha256(report_path) if report_path.exists() else None
    passed = measurement_passes(
        report, report_error, bool(boot_state["reached_multi_user_target"])
    ) and guest_report_passes(report, report_error, binding["nexus_package_sha256"]) and not timed_out
    failure_reason = "qemu_timeout" if timed_out else report_error
    if failure_reason is None and not passed:
        if not boot_state["reached_multi_user_target"]:
            failure_reason = "guest_multi_user_target_not_observed"
        elif report is not None and report.get("verdict") != "pass":
            failure_reason = "guest_e2e_report_verdict_fail"
        elif report is not None:
            failure_reason = "guest_report_boundary_or_hardware_flags_invalid"
    qemu_version_result = subprocess.run(
        [args.qemu_binary, "--version"], check=False, capture_output=True, text=True
    )
    qemu_version = (qemu_version_result.stdout or qemu_version_result.stderr).splitlines()
    authority_flags = None
    if report is not None:
        authority_flags = report.get("authority_flags") or {
            "network_fetch": report.get("network_fetch_performed"),
            "provider_admission": report.get("provider_admission_performed"),
            "edge_activation": report.get("edge_activation_performed"),
        }
    document = {
        "schema": "azazel-payload/qemu-nexus-e2e@1",
        "verdict": "pass" if passed else "fail",
        "failure_reason": failure_reason,
        "evidence_type": "qemu_test_only_guest_e2e",
        "build_input_manifest_sha256": f"sha256:{manifest_digest}",
        "artifacts": {
            "payload_iso_sha256": f"sha256:{sha256(payload)}",
            "kernel_sha256": f"sha256:{sha256(kernel)}",
            "initramfs_sha256": f"sha256:{sha256(initramfs)}",
            "input_manifest_sha256": f"sha256:{manifest_digest}",
            "expected_nexus_package_sha256": f"sha256:{binding['nexus_package_sha256']}",
            "build_result_sha256": f"sha256:{binding['build_result_sha256']}",
            "runner_sha256": f"sha256:{binding['runner_sha256']}",
            "serial_log_sha256": f"sha256:{serial_hash}" if serial_hash else None,
            "qemu_stderr_log_sha256": f"sha256:{stderr_hash}",
            "guest_report_sha256": f"sha256:{report_hash}" if report_hash else None,
        },
        "guest_state": {
            **boot_state,
            "report_error": report_error,
            "report": report,
            "report_frame": {
                "status": frame["status"],
                "error": frame["error"],
                "expected_length": frame["expected_length"],
                "received_length": frame["received_length"],
                "expected_sha256": frame["expected_sha256"],
                "received_sha256": frame["received_sha256"],
                "expected_chunks": frame["expected_chunks"],
                "chunks_received": frame["chunks_received"],
                "capture_timed_out": timed_out,
                "partial_frame_path": partial_path.name if partial_path else None,
                "partial_frame_sha256": sha256(partial_path) if partial_path else None,
            },
            "partial_report_path": partial_path.name if partial_path is not None else None,
            "partial_report_sha256": sha256(partial_path) if partial_path is not None else None,
            "authority_flags": authority_flags,
        },
        "qemu_process": {
            "returncode": process.returncode if process else None,
            "timed_out": timed_out,
            "version": qemu_version[0] if qemu_version else None,
            "machine": "q35,accel=tcg; amd64 emulation",
            "command": command,
        },
        "isolation": {
            "nic_disabled": True,
            "host_block_device_passthrough": False,
            "usb_passthrough": False,
            "direct_kernel_initramfs_boot": True,
            "test_cmdline_flag": "azazel.nexus_e2e=1",
        },
        "evidence_limits": [
            "QEMU guest evidence only; not hardware verification.",
            "Direct kernel/initramfs invocation does not verify firmware or bootloader paths.",
            "Secure Boot was not verified.",
            "The enabled test-only service and its report do not prove production deployment behavior.",
        ],
        "hardware_verified": False,
        "secure_boot_verified": False,
        "production_builder_selected": False,
    }
    result_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--initramfs", required=True, type=Path)
    parser.add_argument("--input-manifest", required=True, type=Path)
    parser.add_argument("--build-result", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--qemu-binary", default="qemu-system-x86_64")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    measurement = run(args)
    print(json.dumps({"verdict": measurement["verdict"], "output": str(args.output)}))
    return 0 if measurement["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
