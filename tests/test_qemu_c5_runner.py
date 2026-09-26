from __future__ import annotations

import json
import hashlib
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tools.payload.run_qemu_c5_fixture import (
    FIXTURE_EVENT,
    HOTPLUG_EVENT,
    PERSISTENCE_EVENT,
    HOTPLUG_BUS,
    QMPClient,
    _require_regular_input,
    _kernel_vdb_discovery,
    c5_event_ordering,
    has_complete_hotplug_quarantine_record,
    parse_c5_events,
    parse_guest_boot_state,
    parse_qemu_block_write_trace,
    parse_runtime_c5_evidence,
    cold_boot_fixture_attached,
    parse_structured_c5_records,
    validate_build_binding,
    validate_c5_manifest_digest,
    hotplug_device_arguments,
    _stage_enforcement_evidence,
    _phase_observation,
    _ro_evidence_observation,
    _write_probe_observation,
    _validate_persistence_phase,
    _validate_udev_provenance,
)


INITRAMFS_EVENT = "AZAZEL_C5_INITRAMFS_QUARANTINE state=active devices=1 udev_rule=present"
MULTI_USER = "Reached target multi-user.target - Multi-User System."


def enforcement(stage: str, target: str) -> list[str]:
    return [
        f"AZAZEL_C5_ENFORCE_SYSCALL stage={stage} target={target} ioctl(3<{target}>, BLKROSET, [RO]) = 0",
        f"AZAZEL_C5_PHASE phase=enforce_ioctl stage={stage} target={target} status=PASS syscall=ioctl result=0 errno=0",
        f"AZAZEL_C5_PHASE phase=post_ro stage={stage} target={target} status=PASS sysfs_ro_after=1 blockdev_ro_after=1",
    ]


def post_probe(stage: str, target: str) -> str:
    return f"AZAZEL_C5_PHASE phase=target_write stage={stage} target={target} status=PASS sysfs_ro_after=1 blockdev_ro_after=1"


def minimal_initramfs_chain(*, include_ioctl: bool = True, post_state: str = "1") -> str:
    lines = [
        "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
    ]
    if include_ioctl:
        lines.extend(enforcement("initramfs", "/dev/vda"))
    lines.extend((
        "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
        'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda write(1</dev/vda>, "x", 1) = -1 EROFS (Read-only file system)',
        f"AZAZEL_C5_PHASE phase=target_write stage=initramfs target=/dev/vda status=PASS sysfs_ro_after={post_state} blockdev_ro_after={post_state}",
    ))
    return "\n".join(lines) + "\n"


def evidence(*, hotplug: bool = True) -> str:
    lines = [INITRAMFS_EVENT, FIXTURE_EVENT, PERSISTENCE_EVENT, MULTI_USER]
    if hotplug:
        lines.append(HOTPLUG_EVENT)
    return "\n".join(lines) + "\n"


class QemuC5RunnerTests(unittest.TestCase):
    def test_vda_fixture_must_be_attached_before_guest_kernel_at_cold_boot(self) -> None:
        fixture = Path("/tmp/c5-vda.raw")
        valid = [
            "qemu", "-drive", f"if=none,id=c5fixture,file={fixture},format=raw",
            "-device", "virtio-blk-pci,drive=c5fixture,serial=azc5-vda",
            "-kernel", "/boot/vmlinuz",
        ]
        self.assertTrue(cold_boot_fixture_attached(valid, fixture))
        self.assertFalse(cold_boot_fixture_attached([
            "qemu", "-kernel", "/boot/vmlinuz", "-drive",
            f"file={fixture},format=raw", "-device", "serial=azc5-vda",
        ], fixture))

    def test_kernel_log_records_keep_their_timestamped_raw_line(self) -> None:
        before = (
            "AZAZEL_C5_KERNEL_LOG stage=initramfs target=/dev/vda "
            "phase=before_probe guest_uptime_seconds=3.25 "
            "raw=[    3.200000] vda: write-protect enabled"
        )
        after = (
            "AZAZEL_C5_KERNEL_LOG stage=initramfs target=/dev/vda "
            "phase=after_probe guest_uptime_seconds=3.30 "
            "raw=[    3.200000] vda: write-protect enabled"
        )
        record = parse_structured_c5_records(before + "\n")["kernel_log"][0]
        self.assertTrue(record["valid"])
        self.assertEqual(record["fields"]["phase"], "before_probe")
        self.assertEqual(record["fields"]["guest_uptime_seconds"], "3.25")
        self.assertEqual(record["fields"]["raw"], "[    3.200000] vda: write-protect enabled")

        evidence = parse_runtime_c5_evidence(
            before + "\n" + after + "\n", qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )
        self.assertEqual(evidence["phases"]["initramfs_kernel_log"]["status"], "FAIL")
        self.assertEqual(evidence["phases"]["initramfs_kernel_log"]["observed_phases"], ["after_probe", "before_probe"])

        truncated = parse_runtime_c5_evidence(
            before + "\n" + after, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )
        self.assertEqual(truncated["phases"]["initramfs_kernel_log"]["status"], "FAIL")

    def test_hotplug_probe_emits_raw_target_syscalls(self) -> None:
        root = Path(__file__).parents[1]
        helper = (root / "tools/payload/quarantine-block-device").read_text()
        service = (root / "tools/payload/c5-hotplug-write-probe@.service").read_text()
        self.assertIn("/usr/bin/strace -qq -yy -e trace=openat,open,write", helper)
        self.assertIn('AZAZEL_C5_WRITE_SYSCALL stage=hotplug target=/dev/vdb %s\\n', helper)
        self.assertIn(
            'if [ "$raw_probe_count" -eq 0 ] || [ "$probe_exit" -ne 0 ]; then',
            helper,
        )
        self.assertIn('ExecStart=/usr/libexec/azazel-quarantine-block %i probe probe', service)

    def test_generic_eio_is_recorded_but_not_quarantine_causality(self) -> None:
        serial = "\n".join((
            "AZAZEL_C5_PHASE phase=ro_state stage=hotplug target=/dev/vdb status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_WRITE_PROBE stage=hotplug target=/dev/vdb syscall=write result=-1 errno=5 errno_name=EIO",
        )) + "\n"
        records = parse_structured_c5_records(serial)
        ro = _ro_evidence_observation(records["phase"], "hotplug", "/dev/vdb", ("ro_state",))
        probe = _write_probe_observation(records["write_probe"], ro)
        self.assertEqual(probe["status"], "FAIL")
        self.assertEqual(probe["syscall_outcome"], "write_failed_causality_unproven")
        self.assertEqual(probe["quarantine_causality"], "UNPROVEN")
        self.assertEqual(probe["syscalls"][0]["errno"], 5)
        self.assertEqual(probe["syscalls"][0]["errno_name"], "EIO")

    def test_open_time_read_only_denial_preserves_exact_syscall_and_errno(self) -> None:
        serial = "\n".join((
            "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda openat(AT_FDCWD, "/dev/vda", O_WRONLY) = -1 EROFS (Read-only file system)',
        )) + "\n"
        parsed = parse_structured_c5_records(serial)
        ro = _ro_evidence_observation(parsed["phase"], "initramfs", "/dev/vda", ("discovered", "quarantine"))
        probe = _write_probe_observation(parsed["write_syscall"], ro)
        self.assertEqual(probe["status"], "PASS")
        self.assertEqual(probe["syscall_outcome"], "open_denied_by_read_only_policy")
        self.assertEqual(probe["syscalls"][0]["syscall"], "openat")
        self.assertEqual((probe["syscalls"][0]["result"], probe["syscalls"][0]["errno"], probe["syscalls"][0]["errno_name"]), (-1, 30, "EROFS"))

    def test_udev_provenance_and_mount_guard_pass_labels_are_validated(self) -> None:
        record = {"fields": {
            "origin": "udev", "udev_provenance": "PASS", "action": "add",
            "subsystem": "block", "target": "/dev/vdb", "kernel_name": "vdb",
            "device_serial": "AZC5-VDB-FILE-01", "devpath": "/devices/pci0000/virtio1/block/vdb",
            "sysfs_devno": "254:16",
        }}
        valid_udev = {"status": "PASS", "observation": record}
        self.assertEqual(_validate_udev_provenance(valid_udev)["status"], "PASS")
        for key, value in (
            ("action", "remove"),
            ("subsystem", "disk"),
            ("devpath", "NOT_OBSERVED"),
            ("device_serial", ""),
            ("udev_provenance", "NOT_OBSERVED"),
            ("sysfs_devno", "25416"),
            ("sysfs_devno", ":16"),
            ("sysfs_devno", "254:"),
            ("sysfs_devno", "254:16:1"),
            ("sysfs_devno", "+254:16"),
            ("sysfs_devno", "254:-16"),
            ("sysfs_devno", "254: 16"),
            ("sysfs_devno", "254:１６"),
            ("sysfs_devno", None),
        ):
            malformed = {"status": "PASS", "observation": {"fields": {**record["fields"], key: value}}}
            with self.subTest(field=key):
                self.assertEqual(_validate_udev_provenance(malformed)["status"], "FAIL")

        base_fields = {"target": "/dev/vda", "path": "/dev/vda", "mount_state": "not_mounted", "required_state": "not_mounted"}
        guard = {"status": "PASS", "observation": {"fields": base_fields}}
        self.assertEqual(_validate_persistence_phase("mount_guard", guard, {})["status"], "PASS")
        contradictory = {"status": "PASS", "observation": {"fields": {**base_fields, "mount_state": "mounted"}}}
        self.assertEqual(_validate_persistence_phase("mount_guard", contradictory, {})["status"], "FAIL")
        wrong_target = {"status": "PASS", "observation": {"fields": {**base_fields, "target": "/dev/vdb"}}}
        self.assertEqual(_validate_persistence_phase("mount_guard", wrong_target, {})["status"], "FAIL")

    def test_hotplug_write_probe_accepts_explicit_read_only_post_state_fields(self) -> None:
        serial = "\n".join((
            "AZAZEL_C5_PHASE phase=ro_state stage=hotplug target=/dev/vdb "
            "status=PASS sysfs_ro_before=0 blockdev_ro_before=0 "
            "sysfs_ro_after=1 blockdev_ro_after=1",
            "AZAZEL_C5_WRITE_PROBE stage=hotplug target=/dev/vdb "
            "syscall=write result=-1 errno=30 errno_name=EROFS",
        )) + "\n"
        records = parse_structured_c5_records(serial)
        ro_evidence = _ro_evidence_observation(
            records["phase"], "hotplug", "/dev/vdb", ("ro_state",),
        )
        write_probe = _write_probe_observation(records["write_probe"], ro_evidence)

        self.assertEqual(ro_evidence["status"], "PASS")
        self.assertEqual(ro_evidence["phases"]["ro_state"]["sysfs_ro"], "1")
        self.assertEqual(ro_evidence["phases"]["ro_state"]["blockdev_ro"], "1")
        self.assertEqual(write_probe["status"], "PASS")

    def test_qemu_inputs_must_be_non_symlink_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "payload.iso"
            regular.write_bytes(b"fixture")
            self.assertEqual(_require_regular_input(regular, "payload"), regular.resolve())

            symlink = root / "payload-link.iso"
            symlink.symlink_to(regular)
            with self.assertRaisesRegex(ValueError, "non-symlink regular file"):
                _require_regular_input(symlink, "payload")

            with self.assertRaisesRegex(ValueError, "non-symlink regular file"):
                _require_regular_input(Path("/dev/null"), "payload")

    def test_missing_hotplug_serial_is_machine_readable_and_fail_closed(self) -> None:
        record = (
            "AZAZEL_C5_PHASE phase=target_write status=NOT_OBSERVED stage=hotplug "
            "target=/dev/vdb fixture_disk_serial_read_status=NOT_OBSERVED "
            "fixture_disk_serial_status=FAIL fixture_disk_serial_bytes=0 "
            "fixture_disk_serial_hex=NOT_OBSERVED"
        )
        parsed = parse_structured_c5_records(record + "\n")["phase"]
        self.assertEqual(len(parsed), 1)
        self.assertTrue(parsed[0]["valid"])
        self.assertEqual(parsed[0]["fields"]["fixture_disk_serial_hex"], "NOT_OBSERVED")
        self.assertEqual(parsed[0]["fields"]["fixture_disk_serial_status"], "FAIL")

    def test_serial_parser_removes_bel_and_st_terminated_osc_controls(self) -> None:
        post_ro = (
            "AZAZEL_C5_PHASE phase=post_ro status=PASS stage=hotplug "
            "target=/dev/vdb sysfs_ro_before=0 sysfs_ro_after=1 "
            "blockdev_ro_before=0 blockdev_ro_after=1\n"
        )
        kernel_vdb = (
            "[   34.871000] virtio_blk virtio1: [vdb] 65536 512-byte logical blocks\n"
        )
        controls = (
            "\x1b[!p\x1b]104\x07\x1b[?7h\x1b[6n",
            "\x1b[!p\x1b]104\x1b\\\x1b[?7h\x1b[6n",
        )
        for control in controls:
            with self.subTest(terminator="BEL" if "\x07" in control else "ST"):
                parsed = parse_structured_c5_records(control + post_ro)["phase"]
                self.assertEqual(len(parsed), 1)
                self.assertTrue(parsed[0]["valid"])
                self.assertEqual(parsed[0]["fields"]["phase"], "post_ro")

                discovery = _kernel_vdb_discovery(control + kernel_vdb)
                self.assertEqual(discovery["status"], "PASS")
                self.assertIn("[vdb]", discovery["observation"]["line"])

    def _structured_hotplug_enforcement(self, *, target="/dev/vdb", method="blockdev-setro",
                                        command_return="0", sysfs_before="0",
                                        blockdev_before="0", sysfs_after="1",
                                        blockdev_after="1", probe_target="/dev/vdb",
                                        probe_stage="hotplug", probe_syscall="write",
                                        probe_result="-1", probe_errno="30",
                                        probe_errno_name="EROFS", mount_state="not_mounted",
                                        probe_before_gate=False,
                                        fixture_disk_serial="AZC5-VDB-FILE-01",
                                        dmi_manufacturer="QEMU",
                                        dmi_product_hex="417a617a656c2043352046696c652046697874757265",
                                        return_serial=False):
        enforce_line = (
            "AZAZEL_C5_PHASE phase=enforce_ioctl stage=hotplug "
            f"target={target} status=PASS method={method} "
            f"command_return={command_return} sysfs_ro_before={sysfs_before} "
            f"blockdev_ro_before={blockdev_before} sysfs_ro_after={sysfs_after} "
            f"blockdev_ro_after={blockdev_after}"
        )
        post_ro_line = (
            "AZAZEL_C5_PHASE phase=post_ro stage=hotplug target=/dev/vdb "
            "status=PASS sysfs_ro_before=0 blockdev_ro_before=0 "
            "sysfs_ro_after=1 blockdev_ro_after=1"
        )
        gate_line = (
            "AZAZEL_C5_PHASE phase=target_write_started stage=hotplug target=/dev/vdb "
            "status=PASS sysfs_ro_before=1 blockdev_ro_before=1 "
            f"mount_state={mount_state} mechanism_supported=PASS "
            f"fixture_disk_serial={fixture_disk_serial} dmi_manufacturer={dmi_manufacturer} "
            f"dmi_product_hex={dmi_product_hex}"
        )
        probe_line = (
            f"AZAZEL_C5_WRITE_PROBE stage={probe_stage} target={probe_target} "
            f"syscall={probe_syscall} result={probe_result} errno={probe_errno} "
            f"errno_name={probe_errno_name}"
        )
        serial = "\n".join((
            "AZAZEL_C5_PHASE phase=udev_rule stage=hotplug target=/dev/vdb status=PASS",
            "AZAZEL_C5_PHASE phase=helper_started stage=hotplug target=/dev/vdb status=PASS",
            "AZAZEL_C5_PHASE phase=enforce_ioctl_started stage=hotplug target=/dev/vdb status=PASS",
            enforce_line,
            post_ro_line,
            "AZAZEL_C5_PHASE phase=helper stage=hotplug target=/dev/vdb status=PASS",
            "AZAZEL_C5_PHASE phase=ro_state stage=hotplug target=/dev/vdb "
            "status=PASS sysfs_ro=1 blockdev_ro=1",
            *((probe_line, gate_line) if probe_before_gate else (gate_line, probe_line)),
            "AZAZEL_C5_PHASE phase=target_write stage=hotplug target=/dev/vdb "
            "status=PASS sysfs_ro_after=1 blockdev_ro_after=1 mount_state=not_mounted",
        )) + "\n"
        records = parse_structured_c5_records(serial)
        return _stage_enforcement_evidence(
            records["phase"], records["enforce_syscall"],
            records["write_syscall"], "hotplug", "/dev/vdb",
            structured_probe_records=records["write_probe"],
        ) if not return_serial else (
            _stage_enforcement_evidence(
                records["phase"], records["enforce_syscall"],
                records["write_syscall"], "hotplug", "/dev/vdb",
                structured_probe_records=records["write_probe"],
            ),
            serial,
        )

    def test_hotplug_accepts_exact_structured_blockdev_setro_transition(self) -> None:
        result, serial = self._structured_hotplug_enforcement(return_serial=True)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["enforce_ioctl"]["status"], "PASS")
        self.assertIsNone(result["enforce_syscall"])
        self.assertIsNone(result["raw_ioctl_trace"])
        records = parse_structured_c5_records(serial)
        ordered_phases = [
            (record["fields"].get("phase"), record["offset"])
            for record in records["phase"]
        ]
        expected_order = [
            "udev_rule", "helper_started", "enforce_ioctl_started", "enforce_ioctl",
            "post_ro", "helper", "ro_state", "target_write_started", "target_write",
        ]
        probe_offset = records["write_probe"][0]["offset"]
        self.assertEqual([phase for phase, _ in ordered_phases], expected_order)
        self.assertTrue(all(
            left[1] < right[1] for left, right in zip(ordered_phases, ordered_phases[1:])
        ))
        self.assertLess(ordered_phases[7][1], probe_offset)
        self.assertLess(probe_offset, ordered_phases[8][1])

    def test_hotplug_structured_blockdev_setro_rejects_incomplete_or_wrong_evidence(self) -> None:
        invalid_evidence = (
            {"target": "/dev/vdc"},
            {"command_return": "1"},
            {"sysfs_before": "1"},
            {"blockdev_before": "1"},
            {"sysfs_after": "0"},
            {"blockdev_after": "0"},
            {"method": "blkroset"},
            {"probe_target": "/dev/vdc"},
            {"probe_stage": "userspace"},
            {"probe_syscall": "pwrite64"},
            {"probe_result": "0", "probe_errno": "0", "probe_errno_name": "NONE"},
            {"probe_result": "-1", "probe_errno": "5", "probe_errno_name": "EIO"},
            {"mount_state": "mounted"},
            {"fixture_disk_serial": "wrong-fixture"},
            {"fixture_disk_serial": ""},
            {"dmi_manufacturer": "not-QEMU"},
            {"dmi_manufacturer": ""},
            {"dmi_product_hex": "00"},
            {"dmi_product_hex": ""},
            {"probe_before_gate": True},
        )
        for overrides in invalid_evidence:
            with self.subTest(overrides=overrides):
                result = self._structured_hotplug_enforcement(**overrides)
                self.assertEqual(result["status"], "FAIL")
                enforcement_overrides = {
                    "target", "command_return", "sysfs_before", "blockdev_before",
                    "sysfs_after", "blockdev_after", "method",
                }
                if set(overrides) & enforcement_overrides:
                    self.assertIn(
                        result["enforce_ioctl"]["status"], {"FAIL", "NOT_OBSERVED"}
                    )

    def test_next14_serial_structured_phases_preserve_order_and_hotplug_failure(self) -> None:
        # Verbatim C5 records from next14 serial.log (ANSI retained as observed).
        serial = r"""AZAZEL_C5_PHASE phase=initial_quarantine status=PASS stage=initramfs marker=/run/azazel/host-storage-quarantined devices=0 fixture_device=not-yet-registered
[    3.306205] virtio_blk virtio0: [vda] 65536 512-byte logical blocks (33.6 MB/32.0 MiB)
AZAZEL_C5_ENFORCE_SYSCALL stage=initramfs target=/dev/vda command_return=0 status=PASS trace_path=/run/azazel/c5-hotplug-enforce.strace raw_hex=696f63746c28333c2f6465762f7664613c626c6f636b203235343a303e3e2c20424c4b524f5345542c205b315d29203d2030 raw=ioctl(3</dev/vda<block 254:0>>, BLKROSET, [1]) = 0
AZAZEL_C5_PHASE phase=enforce_ioctl status=PASS stage=initramfs target=/dev/vda path=/dev/vda origin=initramfs devpath=NOT_OBSERVED action=NOT_OBSERVED subsystem=NOT_OBSERVED guest_uptime_seconds=3.43 syscall=ioctl result=0 errno=NOT_OBSERVED command_return=0 trace_path=/run/azazel/c5-hotplug-enforce.strace raw_hex=696f63746c28333c2f6465762f7664613c626c6f636b203235343a303e3e2c20424c4b524f5345542c205b315d29203d2030 sysfs_ro_before=0 blockdev_ro_before=0 sysfs_ro_after=1 blockdev_ro_after=1 mount_state=not_mounted mount_type=N/A mount_flags=N/A
AZAZEL_C5_PHASE phase=post_ro status=PASS stage=initramfs target=/dev/vda path=/dev/vda origin=initramfs devpath=NOT_OBSERVED action=NOT_OBSERVED subsystem=NOT_OBSERVED guest_uptime_seconds=3.44 sysfs_ro_before=0 blockdev_ro_before=0 sysfs_ro_after=1 blockdev_ro_after=1 mount_state=not_mounted
AZAZEL_C5_PHASE phase=fixture_device_quarantined status=PASS stage=initramfs target=/dev/vda helper_invoked=PASS sysfs_ro=1 blockdev_ro=1
AZAZEL_C5_PHASE phase=discovered status=PASS stage=initramfs target=/dev/vda sysfs_ro=1 blockdev_ro=1 guest_uptime_seconds=3.48
AZAZEL_C5_PHASE phase=quarantine status=PASS stage=initramfs target=/dev/vda sysfs_ro=1 blockdev_ro=1 guest_uptime_seconds=3.48
AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda write(1</dev/vda<block 254:0>>, "\0", 1) = -1 EPERM (Operation not permitted)
AZAZEL_C5_PHASE phase=target_write status=PASS stage=initramfs target=/dev/vda syscall_scope=explicit-fixture syscall_count=1 probe_exit=1 sysfs_ro_before=1 blockdev_ro_before=1 sysfs_ro_after=1 blockdev_ro_after=1 mount_state=not_mounted mount_state_after=not_mounted observation=target_write_denied guest_uptime_seconds=3.59
AZAZEL_C5_PHASE phase=discovered status=PASS stage=userspace target=/dev/vda path=/dev/vda udev_devpath=NOT_OBSERVED udev_action=NOT_OBSERVED guest_uptime_seconds=34.67 boot_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092
AZAZEL_C5_PHASE phase=mounted status=PASS stage=userspace target=/dev/vda path=/dev/vda mount_state=not_mounted mount_point=N/A mount_type=N/A mount_flags=N/A mount_source=N/A guest_uptime_seconds=34.71 boot_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092
AZAZEL_C5_PHASE phase=marker_present status=PASS stage=userspace target=/dev/vda path=/dev/vda marker_path=/run/azazel/host-storage-quarantined marker_contents=schema=azazel-c5-handoff-v1|session_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092|phase=device_quarantined|device=/dev/vda| guest_uptime_seconds=35.18 boot_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092
AZAZEL_C5_PHASE phase=marker_valid status=PASS stage=userspace target=/dev/vda path=/dev/vda schema=azazel-c5-handoff-v1 marker_session_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092 guest_uptime_seconds=35.20 boot_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092
AZAZEL_C5_PHASE phase=session_binding_valid status=PASS stage=userspace target=/dev/vda path=/dev/vda boot_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092 marker_session_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092 guest_uptime_seconds=35.21 boot_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092
AZAZEL_C5_WRITE_SYSCALL stage=userspace target=/dev/vda write(1</dev/vda<block 254:0>>, "\0", 1) = -1 EPERM (Operation not permitted)
AZAZEL_C5_PHASE phase=write_probe status=PASS stage=userspace target=/dev/vda path=/dev/vda observation=target_write_denied syscall_count=1 probe_exit=1 probe_uptime_seconds=35.27 sysfs_ro_before=1 blockdev_ro_before=1 sysfs_ro_after=1 blockdev_ro_after=1 mount_state_after=not_mounted udev_devpath=NOT_OBSERVED udev_action=NOT_OBSERVED guest_uptime_seconds=35.67 boot_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092
AZAZEL_C5_PHASE phase=handoff_valid status=PASS stage=userspace target=/dev/vda path=/dev/vda sysfs_ro_after=1 blockdev_ro_after=1 probe=PASS mounted_after=PASS guest_uptime_seconds=35.91 boot_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092
[\x1b[0;32m  OK  \x1b[0m] Reached target \x1b[0;1;39mmulti-user.target\x1b[0m - Multi-User System.
[   36.099604] virtio_blk virtio1: [vdb] 65536 512-byte logical blocks (33.6 MB/32.0 MiB)
AZAZEL_C5_PHASE phase=helper_started status=PASS stage=hotplug target=/dev/vdb path=/dev/vdb origin=udev devpath=/devices/pci0000:00/0000:00:02.0/0000:01:00.0/virtio1/block/vdb action=add subsystem=block guest_uptime_seconds=36.14 fixture_cmdline=PASS sysfs_ro_before=0 blockdev_ro_before=0 sysfs_ro_after=0 blockdev_ro_after=0 mount_state=not_mounted
AZAZEL_C5_PHASE phase=enforce_ioctl status=NOT_OBSERVED stage=hotplug target=/dev/vdb path=/dev/vdb origin=udev devpath=/devices/pci0000:00/0000:00:02.0/0000:01:00.0/virtio1/block/vdb action=add subsystem=block guest_uptime_seconds=36.23 command_return=1 trace_path=/run/azazel/c5-hotplug-enforce.strace raw_hex=NOT_OBSERVED sysfs_ro_before=0 blockdev_ro_before=0 sysfs_ro_after=0 blockdev_ro_after=0 mount_state=not_mounted
AZAZEL_C5_PHASE phase=post_ro status=FAIL stage=hotplug target=/dev/vdb path=/dev/vdb origin=udev devpath=/devices/pci0000:00/0000:00:02.0/0000:01:00.0/virtio1/block/vdb action=add subsystem=block guest_uptime_seconds=36.24 sysfs_ro_before=0 blockdev_ro_before=0 sysfs_ro_after=0 blockdev_ro_after=0 mount_state=not_mounted
AZAZEL_C5_PHASE phase=udev_rule status=FAIL stage=hotplug target=/dev/vdb path=/dev/vdb origin=udev devpath=/devices/pci0000:00/0000:00:02.0/0000:01:00.0/virtio1/block/vdb action=add subsystem=block guest_uptime_seconds=36.26 helper=/usr/libexec/azazel-quarantine-block
AZAZEL_C5_PHASE phase=helper status=FAIL stage=hotplug target=/dev/vdb path=/dev/vdb origin=udev devpath=/devices/pci0000:00/0000:00:02.0/0000:01:00.0/virtio1/block/vdb action=add subsystem=block guest_uptime_seconds=36.27 sysfs_ro_before=0 blockdev_ro_before=0 sysfs_ro_after=0 blockdev_ro_after=0 mechanism_supported=FAIL
AZAZEL_C5_PHASE phase=ro_state status=FAIL stage=hotplug target=/dev/vdb path=/dev/vdb origin=udev devpath=/devices/pci0000:00/0000:00:02.0/0000:01:00.0/virtio1/block/vdb action=add subsystem=block guest_uptime_seconds=36.29 sysfs_ro_before=0 blockdev_ro_before=0 sysfs_ro_after=0 blockdev_ro_after=0
AZAZEL_C5_PHASE phase=quarantine status=FAIL stage=hotplug target=/dev/vdb path=/dev/vdb origin=udev devpath=/devices/pci0000:00/0000:00:02.0/0000:01:00.0/virtio1/block/vdb action=add subsystem=block guest_uptime_seconds=36.31 mechanism_supported=FAIL sysfs_ro=0 blockdev_ro=0
"""
        qmp_start = serial.index("multi-user.target") + len("multi-user.target")
        qmp_response = len(serial)

        records = parse_structured_c5_records(serial)
        enforcement = records["enforce_syscall"][0]
        self.assertTrue(enforcement["valid"])
        self.assertEqual(enforcement["fields"]["command_return"], "0")
        self.assertEqual(enforcement["fields"]["raw_hex"], "696f63746c28333c2f6465762f7664613c626c6f636b203235343a303e3e2c20424c4b524f5345542c205b315d29203d2030")
        self.assertEqual(enforcement["fields"]["raw_syscall"], "ioctl(3</dev/vda<block 254:0>>, BLKROSET, [1]) = 0")

        events = parse_c5_events(serial)
        self.assertEqual(len(events["initramfs_quarantine"]), 1)
        self.assertEqual(len(events["fixture_initramfs"]), 1)
        self.assertTrue(any(
            record["fields"].get("stage") == "initramfs"
            and "EPERM" in record["fields"].get("raw_syscall", "")
            for record in records["write_syscall"]
        ))
        self.assertEqual(len(events["userspace_persistence"]), 0)
        self.assertEqual(len(events["hotplug_quarantine"]), 0)

        evidence = parse_runtime_c5_evidence(
            serial,
            qmp_hotplug_attached=True,
            qmp_add_start_serial_offset=qmp_start,
            qmp_add_response_serial_offset=qmp_response,
        )
        self.assertEqual(evidence["phases"]["initramfs_enforcement"]["status"], "PASS")
        self.assertEqual(evidence["phases"]["initramfs_write_probe"]["status"], "PASS")
        self.assertEqual(evidence["phases"]["persistence"]["mount_observation"]["status"], "NOT_OBSERVED")
        self.assertEqual(evidence["phases"]["persistence"]["mount_guard"]["status"], "NOT_OBSERVED")
        self.assertNotIn("mounted", evidence["phases"]["persistence"])
        first_action = evidence["phases"]["first_action_ordering"]
        self.assertTrue(first_action["ordered"])
        self.assertTrue(first_action["offsets_ordered"])
        self.assertTrue(first_action["evidence_valid"])
        self.assertEqual(first_action["pre_registration_quarantine"]["status"], "NOT_OBSERVED")
        self.assertEqual(first_action["fixture_device_quarantine_timing"], "after_kernel_registration")
        self.assertIn("device count=0", first_action["claim"])
        self.assertIn("pre-registration device quarantine was not observed", first_action["claim"])
        self.assertEqual(first_action["events"], [
            "initial_quarantine_marker", "kernel_vda_registration",
            "fixture_device_quarantined_after_registration", "target_write"
        ])
        self.assertEqual(evidence["phases"]["kernel_vda_registration"]["status"], "PASS")
        self.assertIn("[vda]", evidence["phases"]["kernel_vda_registration"]["observation"]["line"])
        self.assertEqual(evidence["phases"]["hotplug"]["enforcement"]["status"], "FAIL")
        self.assertEqual(evidence["phases"]["hotplug"]["read_only_state"]["status"], "FAIL")
        self.assertEqual(evidence["phases"]["hotplug"]["quarantine_event"]["status"], "NOT_OBSERVED")
        self.assertEqual(evidence["verdict"], "fail")

    def test_raw_strace_event_is_normalized_and_preserved(self) -> None:
        line = (
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda '
            'openat(AT_FDCWD, "/dev/vda", O_WRONLY) = -1 EACCES '
            '(Permission denied)'
        )
        records = parse_structured_c5_records(line + "\n")["write_syscall"]

        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["valid"])
        self.assertEqual(records[0]["fields"]["syscall"], "openat")
        self.assertEqual(records[0]["fields"]["result"], "-1")
        self.assertEqual(records[0]["fields"]["errno"], 13)
        self.assertEqual(records[0]["fields"]["errno_name"], "EACCES")
        self.assertEqual(records[0]["raw_syscall"], line.split("target=/dev/vda ", 1)[1])

    def test_write_syscall_protocol_rejects_suffix_but_preserves_raw_bytes(self) -> None:
        raw = 'write(4</dev/vda>, "x", 1) = -1 EACCES (Permission denied)'
        valid = parse_structured_c5_records(
            f"AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda {raw}\n"
        )["write_syscall"][0]
        suffixed = parse_structured_c5_records(
            f"AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda {raw} guest_uptime_seconds=1\n"
        )["write_syscall"][0]
        self.assertTrue(valid["valid"])
        self.assertEqual(valid["raw_syscall"], raw)
        self.assertFalse(suffixed["valid"])

    def test_successful_openat_accepts_strace_yy_returned_fd_annotation(self) -> None:
        raw = 'openat(AT_FDCWD, "/dev/vda", O_WRONLY) = 3</dev/vda<block 254:0>>'
        record = parse_structured_c5_records(
            f"AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda {raw}\n"
        )["write_syscall"][0]

        self.assertTrue(record["valid"])
        self.assertEqual(record["fields"]["syscall"], "openat")
        self.assertEqual(record["fields"]["result"], "3")
        self.assertEqual(record["fields"]["result_annotation"], "</dev/vda<block 254:0>>")
        self.assertEqual(record["fields"]["result_fd_path"], "/dev/vda")

    def test_failed_target_write_or_handoff_is_not_a_success_event(self) -> None:
        serial = "\n".join((
            "AZAZEL_C5_PHASE phase=initial_quarantine stage=initramfs status=PASS devices=0",
            "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda write(1</dev/vda>, "x", 1) = -1 EROFS (Read-only file system)',
            "AZAZEL_C5_PHASE phase=target_write stage=initramfs target=/dev/vda status=FAIL sysfs_ro_after=1 blockdev_ro_after=1",
            'AZAZEL_C5_WRITE_SYSCALL stage=userspace target=/dev/vda write(1</dev/vda>, "x", 1) = -1 EROFS (Read-only file system)',
            "AZAZEL_C5_PHASE phase=write_probe stage=userspace target=/dev/vda path=/dev/vda status=FAIL sysfs_ro_after=1 blockdev_ro_after=1",
            "AZAZEL_C5_PHASE phase=handoff_valid stage=userspace target=/dev/vda path=/dev/vda status=FAIL sysfs_ro_after=1 blockdev_ro_after=1 mount_state_after=not_mounted",
        )) + "\n"

        events = parse_c5_events(serial)

        self.assertEqual(events["fixture_initramfs"], [])
        self.assertEqual(events["userspace_persistence"], [])

    def test_zero_device_marker_and_later_quarantine_do_not_claim_preregistration(self) -> None:
        serial = "\n".join((
            "AZAZEL_C5_PHASE phase=initial_quarantine stage=initramfs status=PASS devices=0 fixture_device=not-yet-registered",
            "[    3.30] virtio_blk virtio0: [vda] 65536 512-byte logical blocks",
            "AZAZEL_C5_PHASE phase=fixture_device_quarantined stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda write(1</dev/vda>, "x", 1) = -1 EROFS (Read-only file system)',
            "AZAZEL_C5_PHASE phase=target_write stage=initramfs target=/dev/vda status=PASS sysfs_ro_before=1 blockdev_ro_before=1 sysfs_ro_after=1 blockdev_ro_after=1",
        )) + "\n"

        evidence_result = parse_runtime_c5_evidence(
            serial, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )
        ordering = evidence_result["phases"]["first_action_ordering"]

        self.assertTrue(ordering["offsets_ordered"])
        self.assertTrue(ordering["evidence_valid"])
        self.assertTrue(ordering["ordered"])
        self.assertEqual(ordering["pre_registration_quarantine"]["status"], "NOT_OBSERVED")
        self.assertEqual(ordering["fixture_device_quarantine_timing"], "after_kernel_registration")
        self.assertIn("device count=0", ordering["claim"])
        self.assertIn("was quarantined only after kernel registration", ordering["claim"])
        self.assertIn("pre-registration device quarantine was not observed", ordering["claim"])

    def test_target_label_does_not_override_non_target_fd_annotation(self) -> None:
        record = parse_structured_c5_records(
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda write(4</dev/vdb>, "x", 1) = -1 EACCES (Permission denied)\n'
        )["write_syscall"][0]
        self.assertTrue(record["valid"])
        self.assertEqual(record["fields"]["errno_name"], "EACCES")
        self.assertEqual(record["raw_syscall"], 'write(4</dev/vdb>, "x", 1) = -1 EACCES (Permission denied)')

    def test_runtime_requires_successful_ioctl_order_and_post_probe_ro_state(self) -> None:
        valid = parse_runtime_c5_evidence(
            minimal_initramfs_chain(), qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_enforcement"]
        self.assertEqual(valid["status"], "PASS")

        missing_ioctl = parse_runtime_c5_evidence(
            minimal_initramfs_chain(include_ioctl=False), qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_enforcement"]
        self.assertEqual(missing_ioctl["status"], "FAIL")

        unordered_text = minimal_initramfs_chain().splitlines()
        enforce_lines = [line for line in unordered_text if "phase=enforce_ioctl" in line]
        unordered_text = [line for line in unordered_text if "phase=enforce_ioctl" not in line]
        unordered_text.insert(2, unordered_text[-1])
        unordered_text.extend(enforce_lines)
        unordered = parse_runtime_c5_evidence(
            "\n".join(unordered_text) + "\n", qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_enforcement"]
        self.assertEqual(unordered["status"], "FAIL")

        mismatch = minimal_initramfs_chain().replace(
            "ioctl(3</dev/vda>, BLKROSET, [RO]) = 0",
            "ioctl(3</dev/vdb>, BLKROSET, [RO]) = 0",
        )
        self.assertEqual(parse_runtime_c5_evidence(
            mismatch, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_enforcement"]["status"], "FAIL")

        phase_mismatch = minimal_initramfs_chain().replace(
            "phase=enforce_ioctl stage=initramfs target=/dev/vda status=PASS syscall=ioctl result=0 errno=0",
            "phase=enforce_ioctl stage=initramfs target=/dev/vda status=PASS syscall=ioctl result=-1 errno=1",
        )
        self.assertEqual(parse_runtime_c5_evidence(
            phase_mismatch, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_enforcement"]["status"], "FAIL")

        bad_post_state = parse_runtime_c5_evidence(
            minimal_initramfs_chain(post_state="0"), qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_enforcement"]
        self.assertEqual(bad_post_state["status"], "FAIL")

    def test_unterminated_nonfinal_phase_record_fails_closed(self) -> None:
        line = (
            "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda "
            "status=PASS sysfs_ro=1 blockdev_ro=1"
        )
        terminated = parse_structured_c5_records(line + "\n")["phase"]
        unterminated = parse_structured_c5_records(line)["phase"]

        self.assertEqual(
            _phase_observation(terminated, "discovered", "initramfs", target="/dev/vda")["status"],
            "PASS",
        )
        observation = _phase_observation(
            unterminated, "discovered", "initramfs", target="/dev/vda",
        )
        self.assertEqual(observation["status"], "FAIL")
        self.assertEqual(observation["reason"], "unterminated_record")

    def test_absent_or_unparsed_raw_syscall_is_not_observed(self) -> None:
        common = [
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs status=PASS",
            "AZAZEL_C5_PHASE phase=discovered stage=userspace target=/dev/vda path=/dev/vda status=PASS",
            "AZAZEL_C5_PHASE phase=mount_observation stage=userspace target=/dev/vda path=/dev/vda status=PASS mount_state=not_mounted",
            "AZAZEL_C5_PHASE phase=mount_guard stage=userspace target=/dev/vda path=/dev/vda status=PASS mount_state=not_mounted required_state=not_mounted",
            "AZAZEL_C5_PHASE phase=marker_present stage=userspace target=/dev/vda path=/dev/vda status=PASS marker_path=/run/azazel/host-storage-quarantined marker_contents=schema=azazel-c5-handoff-v1|session_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092|phase=device_quarantined|device=/dev/vda|",
            "AZAZEL_C5_PHASE phase=marker_valid stage=userspace target=/dev/vda path=/dev/vda status=PASS schema=azazel-c5-handoff-v1 marker_session_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092",
            "AZAZEL_C5_PHASE phase=session_binding_valid stage=userspace target=/dev/vda path=/dev/vda status=PASS boot_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092 marker_session_id=0fea8fe1-2e8e-4fff-bd14-e37befb83092",
            'AZAZEL_C5_WRITE_SYSCALL stage=userspace target=/dev/vda openat(AT_FDCWD, "/dev/vda", O_WRONLY) = 3',
            'AZAZEL_C5_WRITE_SYSCALL stage=userspace target=/dev/vda '
            'write(1</dev/vda>, "x", 1) = -1 EROFS (Read-only file system)',
            "AZAZEL_C5_PHASE phase=write_probe stage=userspace target=/dev/vda path=/dev/vda "
            "status=PASS observation=target_write_denied_by_read_only_policy syscall_count=1 target_syscall_count=2 probe_exit=1 "
            "sysfs_ro_before=1 blockdev_ro_before=1 sysfs_ro_after=1 "
            "blockdev_ro_after=1 mount_state_after=not_mounted",
            "AZAZEL_C5_PHASE phase=handoff_valid stage=userspace target=/dev/vda path=/dev/vda status=PASS sysfs_ro_after=1 blockdev_ro_after=1 mount_state_after=not_mounted",
        ]
        absent = parse_runtime_c5_evidence(
            "\n".join(common), qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )
        self.assertEqual(absent["phases"]["initramfs_write_probe"]["status"], "NOT_OBSERVED")

        malformed = "AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda not-strace\n"
        records = parse_structured_c5_records(malformed)["write_syscall"]
        evidence = parse_runtime_c5_evidence(
            "\n".join(common + [malformed.strip()]),
            qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )
        self.assertFalse(records[0]["valid"])
        self.assertEqual(evidence["phases"]["initramfs_write_probe"]["status"], "NOT_OBSERVED")

    def test_runtime_evidence_requires_persistence_hotplug_and_syscall_chain(self) -> None:
        lines = [
            "AZAZEL_C5_PHASE phase=initial_quarantine stage=initramfs status=PASS "
            "devices=0 fixture_device=not-yet-registered",
            "[    3.306205] virtio_blk virtio0: [vda] 65536 512-byte logical blocks",
            "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda "
            "status=PASS sysfs_ro=1 blockdev_ro=1",
            *enforcement("initramfs", "/dev/vda"),
            "AZAZEL_C5_PHASE phase=fixture_device_quarantined stage=initramfs "
            "target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda "
            "status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_KERNEL_LOG stage=initramfs target=/dev/vda "
            "phase=before_probe guest_uptime_seconds=3.50 raw=[ 3.45] vda: write-protect enabled",
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda '
            'openat(AT_FDCWD, "/dev/vda", O_WRONLY) = 3',
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda '
            'write(3</dev/vda>, "x", 1) = -1 EROFS (Read-only file system)',
            "AZAZEL_C5_KERNEL_LOG stage=initramfs target=/dev/vda "
            "phase=after_probe guest_uptime_seconds=3.60 raw=[ 3.55] vda: write-protect enabled",
            "AZAZEL_C5_PHASE phase=target_write stage=initramfs target=/dev/vda path=/dev/vda "
            "status=PASS observation=target_write_denied_by_read_only_policy syscall_count=1 target_syscall_count=2 "
            "sysfs_ro_before=1 blockdev_ro_before=1 sysfs_ro_after=1 blockdev_ro_after=1 mount_state=not_mounted",
            "AZAZEL_C5_PHASE phase=discovered stage=userspace target=/dev/vda path=/dev/vda status=PASS",
            "AZAZEL_C5_PHASE phase=mount_observation stage=userspace target=/dev/vda path=/dev/vda "
            "status=PASS mount_state=not_mounted mount_point=N/A filesystem_type=N/A mount_flags=N/A",
            "AZAZEL_C5_PHASE phase=mount_guard stage=userspace target=/dev/vda path=/dev/vda "
            "status=PASS mount_state=not_mounted required_state=not_mounted",
            "AZAZEL_C5_PHASE phase=marker_present stage=userspace target=/dev/vda path=/dev/vda "
            "status=PASS marker_path=/run/azazel/host-storage-quarantined "
            "marker_contents=schema=azazel-c5-handoff-v1|session_id=11111111-1111-4111-8111-111111111111|phase=device_quarantined|device=/dev/vda|",
            "AZAZEL_C5_PHASE phase=marker_valid stage=userspace target=/dev/vda path=/dev/vda "
            "status=PASS schema=azazel-c5-handoff-v1 marker_session_id=11111111-1111-4111-8111-111111111111",
            "AZAZEL_C5_PHASE phase=session_binding_valid stage=userspace target=/dev/vda path=/dev/vda "
            "status=PASS boot_id=11111111-1111-4111-8111-111111111111 marker_session_id=11111111-1111-4111-8111-111111111111",
            'AZAZEL_C5_WRITE_SYSCALL stage=userspace target=/dev/vda '
            'openat(AT_FDCWD, "/dev/vda", O_WRONLY) = 3',
            'AZAZEL_C5_WRITE_SYSCALL stage=userspace target=/dev/vda '
            'write(3</dev/vda>, "x", 1) = -1 EROFS (Read-only file system)',
            "AZAZEL_C5_PHASE phase=write_probe stage=userspace target=/dev/vda path=/dev/vda "
            "status=PASS observation=target_write_denied_by_read_only_policy syscall_count=1 target_syscall_count=2 probe_exit=1 "
            "sysfs_ro_before=1 blockdev_ro_before=1 sysfs_ro_after=1 "
            "blockdev_ro_after=1 mount_state_after=not_mounted",
            "AZAZEL_C5_PHASE phase=handoff_valid stage=userspace target=/dev/vda path=/dev/vda "
            "status=PASS sysfs_ro_after=1 blockdev_ro_after=1 mount_state_after=not_mounted",
            MULTI_USER,
            "[    8.345678] virtio_blk virtio2: [vdb] 65536 512-byte logical blocks",
            "AZAZEL_C5_PHASE phase=udev_rule stage=hotplug target=/dev/vdb status=PASS path=/dev/vdb origin=udev udev_provenance=PASS action=add subsystem=block kernel_name=vdb devpath=/devices/pci0000/virtio1/block/vdb sysfs_devno=254:16 device_serial=AZC5-VDB-FILE-01",
            "AZAZEL_C5_PHASE phase=helper_started stage=hotplug target=/dev/vdb status=PASS",
            "AZAZEL_C5_PHASE phase=enforce_ioctl stage=hotplug target=/dev/vdb "
            "status=PASS method=blockdev-setro command_return=0 "
            "sysfs_ro_before=0 blockdev_ro_before=0 sysfs_ro_after=1 blockdev_ro_after=1",
            "AZAZEL_C5_PHASE phase=post_ro stage=hotplug target=/dev/vdb "
            "status=PASS sysfs_ro_before=0 blockdev_ro_before=0 "
            "sysfs_ro_after=1 blockdev_ro_after=1",
            "AZAZEL_C5_PHASE phase=helper stage=hotplug target=/dev/vdb status=PASS",
            "AZAZEL_C5_PHASE phase=ro_state stage=hotplug target=/dev/vdb "
            "status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=target_write_started stage=hotplug target=/dev/vdb "
            "status=PASS fixture_cmdline=PASS mount_state=not_mounted "
            "sysfs_ro_before=1 blockdev_ro_before=1 mechanism_supported=PASS "
            "fixture_disk_serial=AZC5-VDB-FILE-01 dmi_manufacturer=QEMU "
            "dmi_product_hex=417a617a656c2043352046696c652046697874757265",
            "AZAZEL_C5_WRITE_PROBE stage=hotplug target=/dev/vdb syscall=write "
            "result=-1 errno=30 errno_name=EROFS",
            'AZAZEL_C5_WRITE_SYSCALL stage=hotplug target=/dev/vdb '
            'write(4</dev/vdb>, "x", 1) = -1 EROFS (Read-only file system)',
            "AZAZEL_C5_PHASE phase=target_write stage=hotplug target=/dev/vdb "
            "status=PASS syscall=write result=-1 errno=30 errno_name=EROFS classification=read_only_policy_denial_observed causality=SUPPORTED_BY_MEASURED_READ_ONLY_TRANSITION "
            "sysfs_ro_before=1 blockdev_ro_before=1 sysfs_ro_after=1 "
            "blockdev_ro_after=1 mount_state=not_mounted",
            "AZAZEL_C5_HOTPLUG_QUARANTINED target=/dev/vdb device_added=1 "
            "udev_rule=1 helper=1 sysfs_ro=1 blockdev_ro=1",
        ]
        serial = "\n".join(lines) + "\n"
        add_start_offset = serial.index(MULTI_USER) + len(MULTI_USER)
        # Model guest output arriving before the host receives QMP's response.
        response_offset = len(serial)
        evidence = parse_runtime_c5_evidence(
            serial, qmp_hotplug_attached=True,
            qmp_add_start_serial_offset=add_start_offset,
            qmp_add_response_serial_offset=response_offset,
            qmp_add_response_elapsed_seconds=5.25,
            qmp_add_response_host_monotonic_seconds=1234.5,
            qmp_add_start_host_monotonic_seconds=1234.0,
        )

        self.assertEqual(evidence["verdict"], "pass", json.dumps({
            "persistence": {name: value["status"] for name, value in evidence["phases"]["persistence"].items()},
            "hotplug": {name: value["status"] for name, value in evidence["phases"]["hotplug"].items() if isinstance(value, dict) and "status" in value},
            "initramfs_enforcement": {
                "status": evidence["phases"]["initramfs_enforcement"]["status"],
                "reason": evidence["phases"]["initramfs_enforcement"].get("reason"),
                "ioctl": evidence["phases"]["initramfs_enforcement"]["enforce_ioctl"].get("status"),
                "post_ro": evidence["phases"]["initramfs_enforcement"]["post_ro"].get("status"),
                "post_probe": evidence["phases"]["initramfs_enforcement"]["post_probe"].get("status"),
                "probe": evidence["phases"]["initramfs_enforcement"].get("write_probe", {}).get("status"),
            },
            "initramfs_probe": evidence["phases"]["initramfs_write_probe"]["status"],
            "first_action_ordered": evidence["phases"]["first_action_ordering"]["ordered"],
            "lifecycle_ordered": evidence["phases"]["lifecycle_ordering"]["ordered"],
        }, sort_keys=True))
        self.assertEqual(evidence["phases"]["hotplug"]["write_probe"]["status"], "PASS")
        self.assertEqual(evidence["phases"]["initramfs_kernel_log"]["status"], "PASS")
        self.assertEqual(
            evidence["phases"]["hotplug"]["write_probe"]["syscalls"][0]["errno"],
            30,
        )
        self.assertEqual(
            evidence["phases"]["initramfs_write_probe"]["syscalls"][1]["errno_name"], "EROFS"
        )
        self.assertEqual(
            evidence["phases"]["hotplug"]["kernel_discovery"]["observation"]["guest_uptime_seconds"],
            8.345678,
        )
        self.assertTrue(evidence["phases"]["hotplug"]["chain_ordered"])
        chain_offsets = evidence["phases"]["hotplug"]["chain_event_offsets"]
        self.assertTrue(
            all(left < right for left, right in zip(chain_offsets, chain_offsets[1:])),
            chain_offsets,
        )
        qmp_add = evidence["phases"]["hotplug"]["qmp_attach"]
        self.assertGreater(
            qmp_add["response_serial_offset"],
            evidence["phases"]["hotplug"]["kernel_discovery"]["observation"]["offset"],
        )
        self.assertEqual(qmp_add["response_elapsed_seconds"], 5.25)
        self.assertEqual(qmp_add["response_host_monotonic_seconds"], 1234.5)
        self.assertEqual(qmp_add["command_start_host_monotonic_seconds"], 1234.0)

        missing_kernel_log = "\n".join(
            line for line in lines if not line.startswith("AZAZEL_C5_KERNEL_LOG ")
        ) + "\n"
        missing_log_evidence = parse_runtime_c5_evidence(
            missing_kernel_log, qmp_hotplug_attached=True,
            qmp_add_start_serial_offset=add_start_offset,
            qmp_add_response_serial_offset=response_offset,
        )
        self.assertEqual(
            missing_log_evidence["phases"]["initramfs_kernel_log"]["status"],
            "NOT_OBSERVED",
        )
        self.assertEqual(missing_log_evidence["verdict"], "fail")
        self.assertEqual(
            evidence["phases"]["hotplug"]["helper_started"]["status"], "PASS"
        )
        self.assertEqual(
            evidence["phases"]["hotplug"]["helper_completed"]["status"], "PASS"
        )
        missing_persistence = "\n".join(
            line for line in lines if "phase=marker_valid stage=userspace" not in line
        ) + "\n"
        missing_result = parse_runtime_c5_evidence(
            missing_persistence, qmp_hotplug_attached=True,
            qmp_add_start_serial_offset=add_start_offset,
            qmp_add_response_serial_offset=response_offset,
        )
        self.assertEqual(
            missing_result["phases"]["persistence"]["marker_valid"]["status"],
            "NOT_OBSERVED",
        )
        duplicate_result = parse_runtime_c5_evidence(
            serial + "AZAZEL_C5_PHASE phase=marker_valid stage=userspace target=/dev/vda path=/dev/vda "
            "status=PASS schema=azazel-c5-handoff-v1 "
            "marker_session_id=11111111-1111-4111-8111-111111111111\n",
            qmp_hotplug_attached=True,
            qmp_add_start_serial_offset=add_start_offset,
            qmp_add_response_serial_offset=response_offset,
        )
        self.assertEqual(
            duplicate_result["phases"]["persistence"]["marker_valid"]["status"],
            "FAIL",
        )

    def test_probe_distinguishes_write_success_from_missing_ro_evidence(self) -> None:
        serial = "\n".join((
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda status=PASS",
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda '
            'openat(AT_FDCWD, "/dev/vda", O_WRONLY) = 3',
        ))
        evidence = parse_runtime_c5_evidence(
            serial, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )
        probe = evidence["phases"]["initramfs_write_probe"]
        self.assertEqual(probe["syscall_outcome"], "open_succeeded_without_write_observed")
        self.assertEqual(probe["classification"], "ro_evidence_missing")
        self.assertEqual(probe["status"], "FAIL")

    def test_hotplug_wait_accepts_extended_structured_record_only_when_complete(self) -> None:
        partial = (
            "AZAZEL_C5_HOTPLUG_QUARANTINED target=/dev/vdb device_added=1 "
            "udev_rule=present helper=completed write_result=denied"
        )
        self.assertFalse(has_complete_hotplug_quarantine_record(partial))
        self.assertTrue(has_complete_hotplug_quarantine_record(partial + "\n"))

    def test_open_success_followed_by_write_errno_is_one_denied_probe(self) -> None:
        serial = "\n".join((
            "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda '
            'openat(AT_FDCWD, "/dev/vda", O_WRONLY) = 3',
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda '
            'write(3</dev/vda>, "\\0", 1) = -1 EROFS (Read-only file system)',
        ))
        evidence = parse_runtime_c5_evidence(
            serial, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )
        probe = evidence["phases"]["initramfs_write_probe"]
        self.assertEqual(probe["status"], "PASS")
        self.assertEqual(probe["syscall_outcome"], "write_denied_by_read_only_policy")
        self.assertEqual([item["syscall"] for item in probe["syscalls"]], ["openat", "write"])
        self.assertEqual(probe["syscalls"][1]["errno_name"], "EROFS")

    def test_distinct_discovered_and_quarantine_ro_observations_are_both_required(self) -> None:
        prefix = [
            "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda write(3</dev/vda>, "x", 1) = -1 EROFS (Read-only file system)',
        ]
        valid = parse_runtime_c5_evidence(
            "\n".join(prefix) + "\n", qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_write_probe"]
        self.assertEqual(valid["status"], "PASS")
        self.assertEqual(valid["ro_evidence"]["required_phases"], ["discovered", "quarantine"])
        self.assertEqual(valid["ro_evidence"]["phase_offsets"], sorted(valid["ro_evidence"]["phase_offsets"]))

        duplicate = parse_runtime_c5_evidence(
            "\n".join(prefix[:1] + prefix) + "\n", qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_write_probe"]
        self.assertEqual(duplicate["status"], "FAIL")
        self.assertEqual(duplicate["ro_evidence"]["phases"]["discovered"]["reason"], "duplicate")

    def test_fd_alias_without_yy_path_annotation_is_not_attributed_to_fixture(self) -> None:
        serial = "\n".join((
            "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda openat(AT_FDCWD, "/dev/vda", O_WRONLY) = 3',
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda write(1, "x", 1) = -1 EPERM (Operation not permitted)',
        )) + "\n"
        probe = parse_runtime_c5_evidence(
            serial, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_write_probe"]
        self.assertEqual(probe["status"], "FAIL")
        self.assertEqual(probe["syscall_outcome"], "target_write_identity_unverified")
        write_call = probe["syscalls"][1]
        self.assertFalse(write_call["target_attributed"])
        self.assertEqual(write_call["target_attribution"], "fd_path_annotation_missing")
        self.assertEqual((write_call["result"], write_call["errno"], write_call["errno_name"]), (-1, 1, "EPERM"))

    def test_nested_block_fd_annotation_attributes_exact_target_and_keeps_ioctl_evidence(self) -> None:
        serial = minimal_initramfs_chain().replace(
            "ioctl(3</dev/vda>, BLKROSET, [RO]) = 0",
            "ioctl(3</dev/vda<block 254:0>>, BLKROSET, [RO]) = 0",
        ).replace(
            'write(1</dev/vda>, "x", 1)',
            'write(1</dev/vda<block 254:0>>, "x", 1)',
        )
        result = parse_runtime_c5_evidence(
            serial, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_enforcement"]

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["write_probe"]["syscalls"][0]["target_attribution"], "fd_path_annotation_matches")
        self.assertEqual(
            result["raw_ioctl_trace"],
            "ioctl(3</dev/vda<block 254:0>>, BLKROSET, [RO]) = 0",
        )
        self.assertEqual(result["raw_ioctl_status"], {
            "syscall": "ioctl", "result": "0", "errno": 0, "errno_name": "0",
            "target_attributed": True, "target_attribution": "ioctl_fd_path_matches",
        })
        self.assertEqual(result["raw_ioctl_evidence"][0]["trace"], result["raw_ioctl_trace"])
        self.assertTrue(result["raw_ioctl_evidence"][0]["valid"])

    def test_wrong_block_identity_is_not_attributed_for_write_or_ioctl(self) -> None:
        serial = minimal_initramfs_chain().replace(
            "ioctl(3</dev/vda>, BLKROSET, [RO]) = 0",
            "ioctl(3</dev/vdb<block 254:1>>, BLKROSET, [RO]) = 0",
        ).replace(
            'write(1</dev/vda>, "x", 1)',
            'write(1</dev/vdb<block 254:1>>, "x", 1)',
        )
        result = parse_runtime_c5_evidence(
            serial, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_enforcement"]

        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["write_probe"]["syscalls"][0]["target_attributed"])
        self.assertEqual(result["write_probe"]["syscalls"][0]["target_attribution"], "fd_path_annotation_mismatch")
        self.assertEqual(result["raw_ioctl_status"]["target_attribution"], "ioctl_fd_path_mismatch")

    def test_missing_or_malformed_nested_annotation_cannot_pass_target_write_probe(self) -> None:
        for annotation, expected_reason in (
            ("", "fd_path_annotation_missing"),
            ("</dev/vda<block 254:x>>", "fd_path_annotation_malformed"),
            ("</dev/vda<block 254:0>extra>", "fd_path_annotation_malformed"),
        ):
            with self.subTest(annotation=annotation):
                raw_fd = "1" + annotation
                serial = minimal_initramfs_chain().replace(
                    'write(1</dev/vda>, "x", 1)',
                    f'write({raw_fd}, "x", 1)',
                )
                result = parse_runtime_c5_evidence(
                    serial, qmp_hotplug_attached=False,
                    qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
                )["phases"]["initramfs_enforcement"]
                self.assertEqual(result["status"], "FAIL")
                self.assertFalse(result["write_probe"]["syscalls"][0]["target_attributed"])
                self.assertEqual(
                    result["write_probe"]["syscalls"][0]["target_attribution"],
                    expected_reason,
                )

    def test_permission_errno_is_preserved_but_cannot_prove_quarantine(self) -> None:
        serial = "\n".join((
            "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda write(1</dev/vda>, "x", 1) = -1 EACCES (Permission denied)',
        )) + "\n"
        probe = parse_runtime_c5_evidence(
            serial, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_write_probe"]
        self.assertEqual(probe["status"], "FAIL")
        self.assertEqual(probe["syscall_outcome"], "write_failed_causality_unproven")
        self.assertEqual((probe["syscalls"][0]["errno"], probe["syscalls"][0]["errno_name"]), (13, "EACCES"))

    def test_same_stage_ro_phases_must_precede_target_write(self) -> None:
        serial = "\n".join((
            'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda write(1</dev/vda>, "x", 1) = -1 EROFS (Read-only file system)',
            "AZAZEL_C5_PHASE phase=discovered stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
            "AZAZEL_C5_PHASE phase=quarantine stage=initramfs target=/dev/vda status=PASS sysfs_ro=1 blockdev_ro=1",
        )) + "\n"
        probe = parse_runtime_c5_evidence(
            serial, qmp_hotplug_attached=False,
            qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
        )["phases"]["initramfs_write_probe"]
        self.assertEqual(probe["syscall_outcome"], "write_denied_by_read_only_policy")
        self.assertEqual(probe["same_stage_correlation"]["status"], "FAIL")
        self.assertEqual(probe["status"], "FAIL")

    def test_qemu_block_write_trace_requires_both_fixture_opens_and_zero_writes(self) -> None:
        first, second = "/tmp/c5-vda.raw", "/tmp/c5-vdb.raw"
        clean_trace = "\n".join((
            f'bdrv_open_common bs 0x1 filename "{first}" flags 0x2 format_name "raw"',
            f'bdrv_open_common bs 0x2 filename "{second}" flags 0x2 format_name "raw"',
        ))
        result = parse_qemu_block_write_trace(clean_trace, (first, second))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(sum(result["write_event_counts"].values()), 0)
        self.assertIn("no block discard tracepoint found", result["scope"])
        self.assertIn("not comprehensive host-I/O evidence", result["scope"])

        write_trace = clean_trace + '\nblk_co_pwritev blk 0x3 offset 0 bytes 512 flags 0 ret 512'
        result = parse_qemu_block_write_trace(write_trace, (first, second))
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["write_event_counts"]["blk_co_pwritev"], 1)

        zeroes_trace = clean_trace + '\nbdrv_co_pwrite_zeroes blk 0x3 offset 0 bytes 512 flags 0 ret 512'
        self.assertEqual(
            parse_qemu_block_write_trace(zeroes_trace, (first, second))["status"],
            "FAIL",
        )

        missing_target = parse_qemu_block_write_trace(clean_trace.splitlines()[0], (first, second))
        self.assertEqual(missing_target["status"], "NOT_OBSERVED")

    def test_kernel_discovery_is_not_inferred_from_helper(self) -> None:
        serial = "AZAZEL_C5_PHASE phase=helper_started stage=hotplug target=/dev/vdb status=PASS\n"
        evidence = parse_runtime_c5_evidence(
            serial, qmp_hotplug_attached=True,
            qmp_add_start_serial_offset=0, qmp_add_response_serial_offset=0,
        )
        self.assertEqual(
            evidence["phases"]["hotplug"]["kernel_discovery"]["status"],
            "NOT_OBSERVED",
        )

    def test_qmp_attach_does_not_substitute_for_guest_hotplug_quarantine(self) -> None:
        evidence_result = parse_runtime_c5_evidence(
            "", qmp_hotplug_attached=True,
            qmp_add_start_serial_offset=0, qmp_add_response_serial_offset=0,
        )
        self.assertEqual(evidence_result["phases"]["hotplug"]["qmp_attach"]["status"], "PASS")
        self.assertEqual(
            evidence_result["phases"]["hotplug"]["kernel_discovery"]["status"],
            "NOT_OBSERVED",
        )
        self.assertEqual(evidence_result["verdict"], "fail")

    def test_hotplug_device_uses_an_explicit_hotpluggable_root_port(self) -> None:
        arguments = hotplug_device_arguments()
        self.assertEqual(arguments["bus"], HOTPLUG_BUS)
        self.assertEqual(arguments["addr"], "0x0")
        self.assertEqual(arguments["driver"], "virtio-blk-pci")
        self.assertEqual(arguments["serial"], "AZC5-VDB-FILE-01")
        self.assertLessEqual(len(arguments["serial"].encode("ascii")), 20)

    def test_requires_all_distinct_events_in_order_and_hotplug_after_attach(self) -> None:
        text = evidence()
        events = parse_c5_events(text)
        ordering = c5_event_ordering(text, len("\n".join(text.splitlines()[:4])) + 1)

        self.assertEqual(len(events["initramfs_quarantine"]), 1)
        self.assertEqual(len(events["fixture_initramfs"]), 1)
        self.assertEqual(len(events["userspace_persistence"]), 1)
        self.assertEqual(len(events["hotplug_quarantine"]), 1)
        self.assertTrue(parse_guest_boot_state(text)["reached_multi_user_target"])
        self.assertTrue(ordering["ordered"])
        self.assertEqual(
            list(ordering["event_offsets"]),
            [
                "initramfs_quarantine",
                "fixture_initramfs",
                "userspace_persistence",
                "multi_user",
                "hotplug_quarantine",
            ],
        )

    def test_hotplug_event_before_qmp_attach_fails(self) -> None:
        text = evidence()
        hotplug_offset = parse_c5_events(text)["hotplug_quarantine"][0]["offset"]
        ordering = c5_event_ordering(text, hotplug_offset + 1)
        self.assertFalse(ordering["ordered"])

    def test_missing_hotplug_or_userspace_state_fails_closed(self) -> None:
        without_hotplug = evidence(hotplug=False)
        self.assertFalse(c5_event_ordering(without_hotplug, len(without_hotplug))["ordered"])
        without_persistence = evidence().replace(PERSISTENCE_EVENT + "\n", "")
        self.assertFalse(c5_event_ordering(without_persistence, len(without_persistence))["ordered"])

    def test_duplicate_event_fails_closed_but_errno_value_is_not_a_gate(self) -> None:
        duplicate = evidence().replace(FIXTURE_EVENT, FIXTURE_EVENT + "\n" + FIXTURE_EVENT)
        self.assertFalse(c5_event_ordering(duplicate, len(duplicate))["ordered"])
        recorded_errno = evidence().replace(FIXTURE_EVENT, FIXTURE_EVENT + " write_errno=13")
        attach_offset = len("\n".join(recorded_errno.splitlines()[:4])) + 1
        self.assertTrue(c5_event_ordering(recorded_errno, attach_offset)["ordered"])

    def test_ansi_formatted_systemd_target_is_recognized(self) -> None:
        text = evidence().replace(
            MULTI_USER,
            "[\x1b[0;32m OK \x1b[0m] Reached target "
            "\x1b[0;1;39mmulti-user.target\x1b[0m - Multi-User System.",
        )
        self.assertTrue(parse_guest_boot_state(text)["reached_multi_user_target"])
        hotplug_offset = parse_c5_events(text)["hotplug_quarantine"][0]["offset"]
        self.assertTrue(c5_event_ordering(text, hotplug_offset)["ordered"])

    def test_initramfs_event_must_be_unique_and_have_structured_details(self) -> None:
        for invalid in (
            "AZAZEL_C5_INITRAMFS_QUARANTINE",
            "AZAZEL_C5_INITRAMFS_QUARANTINE state=failed devices=1 udev_rule=present",
            "AZAZEL_C5_INITRAMFS_QUARANTINE state=active devices=0 udev_rule=present",
            "AZAZEL_C5_INITRAMFS_QUARANTINE state=active devices=1 udev_rule=missing",
        ):
            with self.subTest(invalid=invalid):
                bad = evidence().replace(INITRAMFS_EVENT, invalid)
                self.assertFalse(c5_event_ordering(bad, len(bad))["ordered"])

    def test_qemu_artifacts_must_match_build_result_and_c5_manifest(self) -> None:
        manifest_digest = "a" * 64
        payload_digest = "b" * 64
        kernel_digest = "c" * 64
        initramfs_digest = "d" * 64
        c5_result_digest = "e" * 64
        build = {
            "build_input_manifest_digest": f"sha256:{manifest_digest}",
            "payload_digest": f"sha256:{payload_digest}",
            "kernel_digest": f"sha256:{kernel_digest}",
            "initramfs_digest": f"sha256:{initramfs_digest}",
            "c5_result_digest": f"sha256:{c5_result_digest}",
        }
        c5 = {
            "build_input_manifest_digest": f"sha256:{manifest_digest}",
            "payload_digest": f"sha256:{payload_digest}",
            "initramfs_digest": f"sha256:{initramfs_digest}",
            "order_established": True,
            "boot_image_policy_result": {"verdict": "pass"},
            "quarantine_persistence_declared_in_initramfs_and_rootfs": True,
        }
        c5_result = {"verdict": "pass", "faults": []}
        validate_build_binding(
            build, c5, c5_result, c5_result_digest,
            manifest_digest, payload_digest, kernel_digest, initramfs_digest
        )
        with self.assertRaises(ValueError):
            validate_build_binding(
                build, c5, c5_result, c5_result_digest,
                manifest_digest, payload_digest, kernel_digest, "f" * 64
            )

    def test_c5_manifest_digest_uses_build_result_sha256_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "c5-manifest.json"
            manifest.write_text('{"order_established":true}\n')
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            validate_c5_manifest_digest({"c5_manifest_digest": f"sha256:{digest}"}, manifest)
            with self.assertRaises(ValueError):
                validate_c5_manifest_digest({"c5_manifest_digest": digest}, manifest)

    def test_qemu_refuses_static_c5_failure_before_start(self) -> None:
        build = {"c5_result_digest": "sha256:" + "e" * 64}
        c5 = {
            "order_established": False,
            "boot_image_policy_result": {"verdict": "fail"},
            "quarantine_persistence_declared_in_initramfs_and_rootfs": True,
        }
        c5_result = {"verdict": "fail", "faults": ["order_not_determined"]}
        with self.assertRaisesRegex(ValueError, "QEMU inputs do not match"):
            validate_build_binding(
                build, c5, c5_result, "e" * 64,
                "a" * 64, "b" * 64, "c" * 64, "d" * 64
            )

    def test_qemu_allows_only_unmeasured_persistence_gate_to_reach_runtime_probe(self) -> None:
        manifest_digest = "a" * 64
        payload_digest = "b" * 64
        kernel_digest = "c" * 64
        initramfs_digest = "d" * 64
        result_digest = "e" * 64
        policy = {
            "verdict": "fail",
            "faults": [{"code": "quarantine_not_persistent", "detail": "not measured statically"}],
        }
        build = {
            "build_input_manifest_digest": f"sha256:{manifest_digest}",
            "payload_digest": f"sha256:{payload_digest}",
            "kernel_digest": f"sha256:{kernel_digest}",
            "initramfs_digest": f"sha256:{initramfs_digest}",
            "c5_result_digest": f"sha256:{result_digest}",
        }
        c5 = {
            "build_input_manifest_digest": f"sha256:{manifest_digest}",
            "payload_digest": f"sha256:{payload_digest}",
            "initramfs_digest": f"sha256:{initramfs_digest}",
            "order_established": True,
            "runtime_persistence_evidence_required": True,
            "quarantine_persists_into_userspace": None,
            "quarantine_persistence_declared_in_initramfs_and_rootfs": True,
            "boot_image_policy_result": policy,
        }
        c5_result = {
            "verdict": "pass",
            "evaluator_faults": [],
            "faults": ["quarantine_not_persistent"],
            "boot_image_policy_result": policy,
        }
        validate_build_binding(
            build, c5, c5_result, result_digest,
            manifest_digest, payload_digest, kernel_digest, initramfs_digest
        )

        for bad_manifest, bad_result in (
            ({key: value for key, value in c5.items()
              if key != "quarantine_persists_into_userspace"}, c5_result),
            ({**c5, "quarantine_persists_into_userspace": False}, c5_result),
            (c5, {**c5_result, "faults": ["quarantine_not_persistent", "other_fault"]}),
        ):
            with self.subTest(manifest=bad_manifest, result=bad_result):
                with self.assertRaisesRegex(ValueError, "QEMU inputs do not match"):
                    validate_build_binding(
                        build, bad_manifest, bad_result, result_digest,
                        manifest_digest, payload_digest, kernel_digest, initramfs_digest
                    )

    def test_qmp_command_timeout_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="azc5-qmp-test-") as directory:
            socket_path = Path(directory) / "qmp.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(socket_path))
            server.listen(1)

            def serve_without_second_reply() -> None:
                connection, _ = server.accept()
                with connection:
                    connection.sendall(b'{"QMP":{"version":{},"capabilities":[]}}\r\n')
                    reader = connection.makefile("r", encoding="utf-8")
                    capabilities = json.loads(reader.readline())
                    connection.sendall(
                        (json.dumps({"return": {}, "id": capabilities["id"]}) + "\r\n").encode()
                    )
                    reader.readline()  # Deliberately withhold the following command response.
                    time.sleep(0.35)
                reader.close()

            worker = threading.Thread(target=serve_without_second_reply, daemon=True)
            worker.start()
            entries = []
            client = QMPClient(socket_path, 0.2, entries)
            try:
                client.connect()
                with self.assertRaises(TimeoutError):
                    client.execute("query-status", {})
            finally:
                client.close()
                server.close()
                worker.join(timeout=1)
            self.assertTrue(any(item["kind"] == "command" for item in entries))


if __name__ == "__main__":
    unittest.main()
