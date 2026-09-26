from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from tools.payload.measure_initramfs_c5 import (
    declares_fixture_enforcement,
    evaluate_inspection,
    find_forbidden_storage_commands,
    inspect_pseudo_mount_curation,
    EXPECTED_PSEUDO_MOUNT_RULES,
    EXPECTED_PSEUDO_MOUNT_RULES_CURATED_SHA256,
    EXPECTED_PSEUDO_MOUNT_RULES_SOURCE_SHA256,
    has_automount_activation_rule,
    inspect_other_stage_orders,
    parse_stage_order,
    summarize_faults,
)
from tools.payload.run_qemu_c5_fixture import (
    fixture_passes,
    parse_fixture_event,
    parse_structured_c5_records,
)


class InitTopOrderEvidenceTests(unittest.TestCase):
    def test_userspace_probe_traces_fd_alias_and_preserves_runtime_diagnostics(self) -> None:
        root = Path(__file__).parents[1]
        probe = (root / "tools/payload/c5-persistence-probe.sh").read_text()

        # The trace preserves both target open failures and fd-attributed writes.
        self.assertIn("strace -qq -yy -e trace=openat,open,dup2,dup3,close,write", probe)
        self.assertIn('index($0, "<" target ">")', probe)
        self.assertIn('"actual_syscalls":$syscall_records', probe)
        self.assertIn('"target_syscall_count":$target_syscall_count', probe)
        self.assertIn('"mount_observation":{"status":"$mount_observation"', probe)
        self.assertIn('"mount_guard":{"status":"$mount_guard"', probe)
        self.assertIn('"mount_mode":"$mount_mode"', probe)
        self.assertIn('"point":$mount_point_json', probe)
        self.assertIn('mount_point_json=$(json_quote "$mount_point_before")', probe)
        self.assertIn('"errno":%s', probe)
        self.assertIn('AZAZEL_C5_WRITE_SYSCALL stage=userspace target=%s %s\\n', probe)
        self.assertNotIn(' phase=%s %s guest_uptime_seconds=', probe)
        self.assertIn('"kernel_log"', probe)
        self.assertIn('mount_type=$mount_type_before mount_mode=$mount_mode mount_flags=$mount_flags_before', probe)
        self.assertIn('mount_type=N/A', probe)
        self.assertIn('mount_flags=N/A', probe)
        self.assertIn('"boot_id":"$boot_id"', probe)
        self.assertIn('marker_phase=$(sed -n', probe)
        self.assertIn('[ "$marker_phase" = device_quarantined ]', probe)
        self.assertIn('udev_devpath=$udev_devpath udev_action=$udev_action', probe)
        self.assertIn('guest_uptime_seconds=', probe)
        self.assertNotIn('write_errno=30', probe)

    def test_initramfs_fixture_captures_kernel_log_around_write_probe(self) -> None:
        hook = (Path(__file__).parents[1] / "tools/payload/hooks/00-az-quarantine-block-devices").read_text()
        self.assertLess(
            hook.index("capture_kernel_lines /run/azazel/c5-initramfs-kernel-before.log before_probe"),
            hook.index("/usr/bin/strace -qq -yy"),
        )
        self.assertLess(
            hook.index("/usr/bin/strace -qq -yy"),
            hook.index("dmesg > /run/azazel/c5-initramfs-kernel-after.log"),
        )
        self.assertLess(
            hook.index("dmesg > /run/azazel/c5-initramfs-kernel-after.log"),
            hook.index('printf \'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda %s\\n\''),
        )
        self.assertLess(
            hook.index('printf \'AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda %s\\n\''),
            hook.index("capture_kernel_lines /run/azazel/c5-initramfs-kernel-after.log after_probe"),
        )
        self.assertLess(
            hook.index("capture_kernel_lines /run/azazel/c5-initramfs-kernel-after.log after_probe"),
            hook.index("AZAZEL_C5_PHASE phase=target_write"),
        )
        self.assertIn('after_probe_uptime=$(cut -d', hook)
        self.assertIn('after_probe "$after_probe_uptime"', hook)
        self.assertIn("AZAZEL_C5_KERNEL_LOG stage=initramfs", hook)

    def test_target_write_filters_accept_nested_block_fd_annotations(self) -> None:
        root = Path(__file__).parents[1]
        samples = (
            'write(1</dev/vda<block 254:0>>, "\\0", 1) = -1 EROFS (Read-only file system)',
            'write(1</dev/vda>, "\\0", 1) = 1',
            'write(1</dev/vdb<block 254:16>>, "\\0", 1) = -1 EROFS (Read-only file system)',
            'write(1</dev/vdb>, "\\0", 1) = 1',
        )
        cases = (
            (root / "tools/payload/c5-persistence-probe.sh", r'awk -v target="\$device" \'\n(.*?)\n\s*\' "\$trace" > "\$target_trace"', "/dev/vda"),
            (root / "tools/payload/hooks/00-az-quarantine-block-devices", r'awk \'\n(.*?)\n\s*\' "\$trace" > "\$target_trace"', None),
        )
        for path, pattern, target in cases:
            with self.subTest(path=path.name):
                match = re.search(pattern, path.read_text(), re.DOTALL)
                self.assertIsNotNone(match, f"could not locate production trace filter in {path}")
                result = subprocess.run(
                    ["awk"] + (["-v", f"target={target}"] if target else []) + [match.group(1)],
                    input="\n".join(samples) + "\n",
                    text=True,
                    capture_output=True,
                    check=True,
                )
                expected = target or "/dev/vda"
                self.assertIn(f"<{expected}<block ", result.stdout)
                if expected == "/dev/vda":
                    self.assertIn(f"<{expected}>", result.stdout)
                if target != "/dev/vdb":
                    self.assertNotIn("/dev/vdb", result.stdout)

    def test_quarantine_ioctl_filter_accepts_nested_block_annotation(self) -> None:
        helper = (Path(__file__).parents[1] / "tools/payload/quarantine-block-device").read_text()
        match = re.search(
            r"enforce_ioctl_line=\$\(awk -v target=\"\$device\" \\\n\s*'([^']+)'",
            helper,
        )
        self.assertIsNotNone(match)
        result = subprocess.run(
            ["awk", "-v", "target=/dev/vdb", match.group(1)],
            input=(
                "ioctl(3</dev/vdb<block 254:16>>, BLKROSET, [1]) = 0\n"
                "ioctl(3</dev/vda<block 254:0>>, BLKROSET, [1]) = 0\n"
            ),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("<block 254:16>", result.stdout)
        self.assertNotIn("<block 254:0>", result.stdout)

    def test_initramfs_dd_exit_without_target_syscall_is_not_pass(self) -> None:
        hook = (Path(__file__).parents[1] / "tools/payload/hooks/00-az-quarantine-block-devices").read_text()
        trace_start = hook.index("if /usr/bin/strace -qq -yy")
        parser_start = hook.index("probe_status=NOT_OBSERVED", trace_start)
        self.assertNotIn("probe_status=PASS", hook[trace_start:parser_start])
        self.assertIn("probe_exit=0", hook[trace_start:parser_start])
        self.assertIn("target_syscall_count=0", hook)
        self.assertIn('[ "$target_syscall_count" -gt 0 ]', hook)
        self.assertIn("probe_result=target_write_or_open_not_observed", hook)
        self.assertIn('/^(open|openat)\\(/', hook)
        self.assertIn("probe_status=PASS", hook[parser_start:])

    def test_fixture_quarantines_before_driver_load_and_again_before_write_probe(self) -> None:
        hook = (Path(__file__).parents[1] / "tools/payload/hooks/00-az-quarantine-block-devices").read_text()
        initial_marker = hook.index(': > /run/azazel/host-storage-quarantined')
        initial_phase = hook.index('phase=initial_quarantine status=PASS')
        fixture_modprobe = hook.index('/sbin/modprobe virtio_blk')
        device_wait = hook.index('while [ ! -b /dev/vda ]')
        fixture_helper = hook.index('"$helper" vda initramfs')
        device_phase = hook.index('phase=fixture_device_quarantined status=%s')
        write_probe = hook.index('azazel-c5-write-probe 2>/run/azazel/c5-initramfs-dd.stderr')
        self.assertLess(initial_marker, initial_phase)
        self.assertLess(initial_phase, fixture_modprobe)
        self.assertLess(hook.index('device_scope=currently-registered'), fixture_modprobe)
        self.assertLess(fixture_modprobe, device_wait)
        self.assertLess(device_wait, fixture_helper)
        self.assertLess(fixture_helper, device_phase)
        self.assertLess(device_phase, write_probe)
        self.assertIn('fixture_device_sysfs_ro" = 1', hook)
        self.assertIn('fixture_device_blockdev_ro" = 1', hook)
        self.assertIn('fixture_device_status" = PASS ] || exit 1', hook)
        self.assertIn('else\n      # Production path:', hook)
        production_start = hook.index('else\n      # Production path:')
        production_end = hook.index('\n    fi\n\n    if [ "$fixture_mode" = yes ]; then', production_start)
        production_branch = hook[production_start:production_end]
        self.assertNotIn('modprobe virtio_blk', production_branch)

    def test_userspace_write_guard_requires_fixture_unmounted_and_both_ro_views(self) -> None:
        probe = (Path(__file__).parents[1] / "tools/payload/c5-persistence-probe.sh").read_text()
        self.assertIn('[ "$fixture_cmdline" = PASS ]', probe)
        self.assertIn('[ "$mount_state" = not_mounted ]', probe)
        self.assertIn('[ "$sysfs_ro_before" = 1 ]', probe)
        self.assertIn('[ "$blockdev_ro_before" = 1 ]', probe)
        self.assertIn('if [ "$sysfs_ro_before" = 1 ] && [ "$blockdev_ro_before" = 1 ]; then', probe)
        self.assertIn('write:EPERM|pwrite64:EROFS|pwrite64:EPERM', probe)
        self.assertNotIn('open:EPERM', probe)

    def test_initramfs_accepts_kernel_read_only_eperm_only_for_write(self) -> None:
        hook = (Path(__file__).parents[1] / "tools/payload/hooks/00-az-quarantine-block-devices").read_text()
        self.assertIn('write:EPERM|pwrite64:EROFS|pwrite64:EPERM', hook)
        self.assertNotIn('open:EPERM', hook)

    def test_hotplug_keeps_immediate_udev_ro_enforcement_and_defers_probe_to_unit(self) -> None:
        root = Path(__file__).parents[1]
        helper = (root / "tools/payload/quarantine-block-device").read_text()
        rule = (root / "tools/payload/quarantine-udev.rules").read_text()
        service = (root / "tools/payload/c5-hotplug-write-probe@.service").read_text()
        direct = helper.index(
            'if [ "$origin" = udev ]; then',
            helper.index('enforce_method=strace-blkroset'),
        )
        strace = helper.index('elif [ -x /usr/bin/strace ]; then', direct)
        udev_enforcement = helper[direct:strace]
        enforcement = helper.index('emit_event enforce_ioctl "$enforce_ioctl"')
        post_ro = helper.index('emit_event post_ro "$mechanism_supported"')
        self.assertLess(enforcement, post_ro)
        self.assertNotIn('strace', udev_enforcement)
        self.assertIn('method=blockdev-setro', helper)
        self.assertIn('[ "$pre_sysfs" = 0 ] && [ "$pre_blockdev" = 0 ]', helper)
        self.assertIn('[ "$post_sysfs" = 1 ] && [ "$post_blockdev" = 1 ]', helper)
        self.assertIn('elif [ -x /usr/bin/strace ]; then', helper)  # initramfs path remains traced
        self.assertIn('AZAZEL_C5_ENFORCE_SYSCALL', helper)
        self.assertIn('syscall=blockdev-setro', helper)
        self.assertIn('raw_hex=NOT_OBSERVED', helper)
        self.assertIn('[ "$enforce_command_return" = 0 ]', helper)
        self.assertIn('[ "$post_sysfs" = 1 ]', helper)
        self.assertIn('[ "$post_blockdev" = 1 ]', helper)
        self.assertNotIn('denied_exact_eperm', helper)
        self.assertIn('mv -f "$handoff_tmp" "/run/azazel/c5-hotplug-vdb-$event_seqnum.ready"', helper)
        self.assertIn('run_hotplug_write_probe', helper)
        self.assertIn('"$origin" = probe', helper)
        self.assertIn('timeout 5s /usr/bin/strace', helper)
        self.assertIn("bytes([0])", helper)
        self.assertNotIn('strace', rule)
        self.assertIn('RUN+="/usr/libexec/azazel-quarantine-block %k udev"', rule)
        self.assertIn('ATTR{serial}=="AZC5-VDB-FILE-01"', rule)
        self.assertIn('ENV{SYSTEMD_WANTS}+="azazel-c5-hotplug-write-probe@vdbseq%E{SEQNUM}.service"', rule)
        self.assertIn('ExecStart=/usr/libexec/azazel-quarantine-block %i probe probe', service)
        self.assertIn('Description=Azazel C5 hotplug write-probe evidence for udev event %i', service)
        self.assertIn('event_seqnum=${invocation#vdbseq}', helper)
        self.assertIn('mode=${3:-quarantine}', helper)
        self.assertIn('case "$origin:$mode" in', helper)
        self.assertIn('initramfs:quarantine|udev:quarantine|probe:probe)', helper)
        self.assertIn('After=systemd-udevd.service', service)
        self.assertIn('udev_seqnum=$event_seqnum', helper)
        self.assertIn('"udev_seqnum":"%s"', helper)
        self.assertIn('event_seqnum=${invocation#vdbseq}', helper)

    def test_quarantine_helper_accepts_only_matching_origin_mode_pairs(self) -> None:
        helper = Path(__file__).parents[1] / "tools/payload/quarantine-block-device"
        source = helper.read_text()
        guard = re.search(r'(?ms)^case "\$origin:\$mode" in\n.*?^esac$', source)
        self.assertIsNotNone(guard)
        cases = (
            ("initramfs", "quarantine", 0),
            ("udev", "quarantine", 0),
            ("probe", "probe", 0),
            ("initramfs", "probe", 2),
            ("udev", "probe", 2),
            ("probe", "quarantine", 2),
            ("unrecognized", "quarantine", 2),
            ("udev", "unrecognized", 2),
        )
        for origin, mode, expected_exit in cases:
            with self.subTest(origin=origin, mode=mode):
                result = subprocess.run(
                    [
                        "sh",
                        "-c",
                        f'origin="$1"; mode="$2"; {guard.group(0)}',
                        "quarantine-mode-test",
                        origin,
                        mode,
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                if expected_exit:
                    self.assertIn("quarantine/probe origin and mode do not match", result.stderr)

    def test_udev_generated_probe_instance_binds_device_and_generation(self) -> None:
        root = Path(__file__).parents[1]
        helper = (root / "tools/payload/quarantine-block-device").read_text()
        parser = re.search(
            r"(?ms)^if \[ \"\$origin\" = probe \]; then\n(.*?)^fi$",
            helper,
        )
        self.assertIsNotNone(parser)
        parse_script = (
            'origin=probe\ninvocation=$1\nevent_seqnum=NOT_OBSERVED\n'
            'name=\nif [ "$origin" = probe ]; then\n'
            + parser.group(1)
            + '\nfi\nprintf "%s %s\\n" "$name" "$event_seqnum"'
        )
        # udev's %k=vdb and %E{SEQNUM}=2366 substitutions form an
        # alphanumeric-only systemd instance, avoiding dash unescaping.
        generated_instance = "vdbseq" + "2366"
        parsed = subprocess.run(
            ["sh", "-c", parse_script, "sh", generated_instance],
            text=True,
            capture_output=True,
        )
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        self.assertEqual(parsed.stdout, "vdb 2366\n")
        for invalid_instance in ("vdb-2366", "vdbseq2366x", "vdaseq2366"):
            with self.subTest(instance=invalid_instance):
                rejected = subprocess.run(
                    ["sh", "-c", parse_script, "sh", invalid_instance],
                    text=True,
                    capture_output=True,
                )
                self.assertNotEqual(rejected.returncode, 0)

    def test_hotplug_probe_records_actual_errno_without_hard_coding_expected_errno(self) -> None:
        helper = (Path(__file__).parents[1] / "tools/payload/quarantine-block-device").read_text()
        match = re.search(r"(?ms)^classify_probe_result\(\) \{\n.*?^\}", helper)
        self.assertIsNotNone(match)
        cases = (
            ("syscall=write result=-1 errno=1 errno_name=EPERM", "PASS", "read_only_policy_denial_observed", "EPERM"),
            ("syscall=write result=-1 errno=30 errno_name=EROFS", "PASS", "read_only_policy_denial_observed", "EROFS"),
            ("syscall=write result=-1 errno=5 errno_name=EIO", "FAIL", "write_failed_causality_unproven", "EIO"),
            ("syscall=write result=-1 errno=13 errno_name=EACCES", "FAIL", "write_failed_causality_unproven", "EACCES"),
            ("syscall=write result=1 errno=0 errno_name=NONE", "FAIL", "write_result_not_read_only_denial", "NONE"),
            ("syscall=open result=-1 errno=1 errno_name=EPERM", "FAIL", "open_failed_causality_unproven", "EPERM"),
            ("syscall=open result=-1 errno=5 errno_name=EIO", "FAIL", "open_failed_causality_unproven", "EIO"),
            ("syscall=probe result=-1 errno=0 errno_name=NOT_OBSERVED", "FAIL", "write_syscall_or_errno_not_observed", "NOT_OBSERVED"),
        )
        for result, expected_status, expected_classification, expected_errno in cases:
            with self.subTest(result=result):
                run = subprocess.run(
                    ["/bin/sh", "-c", match.group(0) + '\nclassify_probe_result "$1"; printf "%s|%s|%s\\n" "$probe_status" "$probe_classification" "$write_errno"', "sh", result],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                status, classification, errno_name = run.stdout.strip().split("|")
                self.assertEqual(status, expected_status)
                self.assertEqual(errno_name, expected_errno)
                self.assertEqual(classification, expected_classification)

    def test_initramfs_and_userspace_probes_write_on_the_open_target_fd(self) -> None:
        root = Path(__file__).parents[1] / "tools/payload"
        persistence = (root / "c5-persistence-probe.sh").read_text()
        initramfs = (root / "hooks/00-az-quarantine-block-devices").read_text()
        for stage, source in (("userspace", persistence), ("initramfs", initramfs)):
            with self.subTest(stage=stage):
                self.assertIn('exec 3>', source)
                self.assertIn('printf "\\\\000" >&3', source)
                self.assertIn("strace -qq -yy", source)

    def test_enforcement_diagnostic_preserves_bounded_raw_streams_without_overclaim(self) -> None:
        helper = (Path(__file__).parents[1] / "tools/payload/quarantine-block-device").read_text()
        self.assertIn('>"$enforce_stdout" 2>"$enforce_stderr"', helper)
        self.assertIn('command_return=$enforce_command_return', helper)
        self.assertIn('capture_total_bytes=$CAPTURE_TOTAL_BYTES', helper)
        self.assertIn('capture_limit=$diagnostic_limit', helper)
        self.assertIn('trace_truncated=$trace_truncated', helper)
        self.assertIn('stderr_truncated=$stderr_truncated', helper)
        self.assertIn('AZAZEL_C5_ENFORCE_DIAGNOSTIC', helper)
        # Raw streams are emitted only through capped chunk records, not inline fields.
        self.assertNotIn('stderr_errno=', helper)
        self.assertNotIn('stderr_device=', helper)
        # One direct udev invocation plus the initramfs invocation wrapped in strace.
        self.assertEqual(helper.count('/usr/sbin/blockdev --setro "$device"'), 2)
        self.assertIn('enforce_command_return=NOT_RUN', helper)

    def test_hotplug_write_probe_record_is_machine_readable(self) -> None:
        record = (
            "AZAZEL_C5_WRITE_PROBE stage=hotplug target=/dev/vdb "
            "syscall=write result=-1 errno=1 errno_name=EPERM\n"
        )
        parsed = parse_structured_c5_records(record)["write_probe"]
        self.assertEqual(len(parsed), 1)
        self.assertTrue(parsed[0]["valid"])
        self.assertEqual(parsed[0]["fields"]["target"], "/dev/vdb")
        self.assertEqual(parsed[0]["fields"]["errno_name"], "EPERM")

    def test_bounded_enforcement_diagnostic_streams_are_preserved(self) -> None:
        helper = (Path(__file__).parents[1] / "tools/payload/quarantine-block-device").read_text()
        match = re.search(r"(?ms)^file_evidence\(\) \{\n.*?^\}", helper)
        self.assertIsNotNone(match)
        cap_file_match = re.search(r"(?ms)^cap_diagnostic_file\(\) \{\n.*?^\}", helper)
        self.assertIsNotNone(cap_file_match)
        cap_streams_match = re.search(r"(?ms)^cap_diagnostic_streams\(\) \{\n.*?^\}", helper)
        self.assertIsNotNone(cap_streams_match)
        chunks_match = re.search(r"(?ms)^emit_file_chunks\(\) \{\n.*?^\}", helper)
        self.assertIsNotNone(chunks_match)
        with TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("trace", "stderr", "stdout")]
            paths[0].write_bytes(b"t" * 3000)
            paths[1].write_bytes(b"e" * 2000)
            paths[2].write_bytes(b"o" * 10)
            script = (
                'diagnostic_limit=4096; diagnostic_read="$4/read.tmp"; '
                'enforce_trace="$1"; enforce_stderr="$2"; enforce_stdout="$3"; '
                + cap_file_match.group(0) + "\n"
                + cap_streams_match.group(0) + "\n"
                + match.group(0) + "\n"
                + 'cap_diagnostic_streams; printf "%s|%s|%s|%s|%s|%s|%s\\n" '
                + '"$CAPTURE_FAILURE" "$CAPTURE_TOTAL_BYTES" "$trace_original" '
                + '"$trace_truncated" "$stderr_original" "$stderr_truncated" '
                + '"$stdout_original"; CAP_TRUNCATED="$stderr_truncated"; file_evidence "$enforce_stderr"'
            )
            result = subprocess.run(
                ["sh", "-c", script, "cap-test", *(str(path) for path in paths), directory],
                text=True,
                capture_output=True,
                check=True,
            )
            summary, evidence = result.stdout.splitlines()
            self.assertEqual(summary, "no|4096|3000|no|2000|yes|10")
            self.assertEqual(evidence, "present|1096")
            self.assertEqual(sum(path.stat().st_size for path in paths), 4096)
            self.assertEqual(paths[1].read_bytes(), b"e" * 1096)

            chunk_script = (
                'diagnostic_chunk="$1.chunk"; diagnostic_read="$1.read"; '
                + chunks_match.group(0)
                + '\nemit_event() { printf "phase=%s status=%s %s\\n" "$1" "$2" "$3"; }'
                + '\nemit_file_chunks trace "$1"'
            )
            paths[0].write_bytes(b"x" * 4096)
            result = subprocess.run(
                ["sh", "-c", chunk_script, "file-chunks-test", str(paths[0])],
                text=True,
                capture_output=True,
                check=True,
            )
            lines = result.stdout.splitlines()
            self.assertIn("total_bytes=4096 chunk_size=2048 chunk_count=2", lines[0])
            self.assertEqual(len(lines), 3)
            chunks = []
            for expected_index, line in enumerate(lines[1:]):
                self.assertIn(f"stream=trace chunk_index={expected_index} chunk_count=2", line)
                encoded = re.search(r"raw_hex=([0-9a-f]*)$", line)
                self.assertIsNotNone(encoded)
                self.assertNotIn("errno=", line)
                self.assertNotIn("device=", line)
                chunks.append(bytes.fromhex(encoded.group(1)))
            self.assertEqual(b"".join(chunks), paths[0].read_bytes())

    def test_quarantine_evidence_is_invocation_private_and_mechanism_failure_exits(self) -> None:
        helper = (Path(__file__).parents[1] / "tools/payload/quarantine-block-device").read_text()
        self.assertIn('mktemp -d /run/azazel/c5-helper.XXXXXX', helper)
        for path_name in (
            "trace", "enforce_trace", "enforce_stderr", "enforce_stdout", "target_trace",
            "dd_stderr", "kernel_before", "kernel_relevant",
        ):
            self.assertIsNotNone(re.search(rf"^{path_name}=\$invocation_dir/", helper, re.MULTILINE))
        self.assertNotIn(': > "$fixture_record"', helper)
        self.assertIn('mechanism_supported" = PASS ] && [ "$enforce_status" = PASS', helper)
        self.assertIn('read-only state lacks observed enforcement evidence', helper)

        with TemporaryDirectory() as directory:
            result = subprocess.run(
                ["sh", "-c", 'a=$(mktemp -d "$1/c5-helper.XXXXXX") && b=$(mktemp -d "$1/c5-helper.XXXXXX") && printf "%s\\n%s\\n" "$a" "$b"', "mktemp-isolation", directory],
                capture_output=True,
                text=True,
                check=True,
            )
            first, second = result.stdout.splitlines()
            self.assertNotEqual(first, second)
            self.assertTrue(Path(first).is_dir())
            self.assertTrue(Path(second).is_dir())

        guard_start = helper.index('[ "$mechanism_supported" = PASS ] && [ "$enforce_status" = PASS ] || {')
        guard_end = helper.index('\n}\n', guard_start) + 2
        guard = helper[guard_start:guard_end]
        failed = subprocess.run(["sh", "-c", 'post_sysfs=1 post_blockdev=1 mechanism_supported=FAIL enforce_status=FAIL name=vdb\n' + guard], capture_output=True, text=True)
        passed = subprocess.run(["sh", "-c", 'post_sysfs=1 post_blockdev=1 mechanism_supported=PASS enforce_status=PASS name=vdb\n' + guard], capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(passed.returncode, 0)

        with TemporaryDirectory() as directory:
            script = (
                'head() { return 1; }; diagnostic_read="$2/read.tmp"; '
                + re.search(r"(?ms)^cap_diagnostic_file\(\) \{\n.*?^\}", helper).group(0)
                + '\ncap_diagnostic_file "$1" 1'
            )
            source = Path(directory) / "over-limit"
            source.write_bytes(b"too much")
            read_failure = subprocess.run(
                ["sh", "-c", script, "read-failure", str(source), directory],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(read_failure.returncode, 0)

    def test_hotplug_unit_rechecks_fixture_unmounted_and_both_ro_states(self) -> None:
        helper = (Path(__file__).parents[1] / "tools/payload/quarantine-block-device").read_text()
        probe = helper.split('run_hotplug_write_probe() {', 1)[1].split('\n}', 1)[0]
        self.assertIn('[ "$before_sysfs" != 1 ]', probe)
        self.assertIn('[ "$before_blockdev" != 1 ]', probe)
        self.assertIn('[ "$before_mount" != not_mounted ]', probe)
        self.assertIn('[ "$handoff_devno" = "$device_devno" ]', probe)
        self.assertIn('stat -c \'%u:%a\' "$handoff"', probe)
        self.assertIn('[ "$handoff_serial" = AZC5-VDB-FILE-01 ]', probe)
        self.assertIn('[ "$handoff_devno" = "$device_devno" ]', probe)
        self.assertIn('[ "$action" = add ] && [ "$subsystem" = block ]', probe)
        self.assertIn('[ "$event_sysfs" = "$current_sysfs" ]', probe)
        self.assertIn('[ "$serial" = AZC5-VDB-FILE-01 ]', probe)
        self.assertIn('[ "$name" = vdb ]', helper)
        self.assertIn('dmi_manufacturer=$dmi_vendor', probe)
        self.assertIn('dmi_product_hex=417a617a656c2043352046696c652046697874757265', probe)
        self.assertIn(r"sed -n 's/.*errno_name=\([^ ]*\).*/\1/p'", probe)
        self.assertIn('mechanism_supported=PASS', probe)

    def test_hotplug_handoff_rejects_stale_remove_readd_generation(self) -> None:
        root = Path(__file__).parents[1]
        helper = (root / "tools/payload/quarantine-block-device").read_text()
        generation_check = re.search(
            r"(?ms)^validate_handoff_generation\(\) \{\n.*?^\}", helper
        )
        self.assertIsNotNone(generation_check)
        check_script = generation_check.group(0) + '\nvalidate_handoff_generation "$1" "$2"'
        stale = subprocess.run(
            ["sh", "-c", check_script, "sh", "100", "99"], capture_output=True
        )
        current = subprocess.run(
            ["sh", "-c", check_script, "sh", "100", "100"], capture_output=True
        )
        invalid = subprocess.run(
            ["sh", "-c", check_script, "sh", "100x", "100x"], capture_output=True
        )
        self.assertNotEqual(stale.returncode, 0)
        missing = subprocess.run(
            ["sh", "-c", check_script, "sh", "100", "NOT_OBSERVED"], capture_output=True
        )
        mismatch = subprocess.run(
            ["sh", "-c", check_script, "sh", "101", "100"], capture_output=True
        )
        self.assertEqual(current.returncode, 0)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertNotEqual(missing.returncode, 0)
        self.assertNotEqual(mismatch.returncode, 0)
        probe = helper.split('run_hotplug_write_probe() {', 1)[1].split('\n}', 1)[0]
        udev = helper.split('if [ "$origin" = udev ]; then', 1)[1].split('\nfi', 1)[0]
        self.assertIn('"/run/azazel/c5-hotplug-vdb-$event_seqnum.ready"', probe)
        self.assertIn('validate_handoff_generation "$event_seqnum" "$handoff_seqnum"', probe)
        self.assertIn('rm -f "$handoff" "$handoff.tmp"', udev)
        self.assertLess(helper.index('/usr/sbin/blockdev --setro "$device"'), helper.index('mv -f "$handoff_tmp"'))
        service = (root / "tools/payload/c5-hotplug-write-probe@.service").read_text()
        self.assertIn('ExecStart=/usr/libexec/azazel-quarantine-block %i probe probe', service)
        self.assertIn('udev_seqnum=%s', helper)

    def test_hotplug_probe_checks_fd_and_sysfs_identity_before_write(self) -> None:
        root = Path(__file__).parents[1]
        helper = (root / "tools/payload/quarantine-block-device").read_text()
        match = re.search(r"python3 -c '\n(.*?)\n' /dev/vdb \"\$event_seqnum\"", helper, re.DOTALL)
        self.assertIsNotNone(match)
        snippet = match.group(1)
        self.assertLess(snippet.index('identity()'), snippet.index('os.open(device'))
        self.assertLess(snippet.index('os.fstat(fd)'), snippet.index('os.write(fd'))
        self.assertIn('os.major(stat_result.st_rdev)', snippet)
        self.assertIn('observed_sysfs != expected_sysfs', snippet)

        with TemporaryDirectory() as directory:
            sysfs = Path(directory) / "sysfs"
            sysfs.mkdir()
            (sysfs / "dev").write_text("0:0\n")
            (sysfs / "ro").write_text("1\n")
            target = Path(directory) / "target"
            target.write_bytes(b"unchanged")
            sysfs_real = str(sysfs.resolve())

            before_open_guard = (
                "import os\n"
                "os.open = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('open reached'))\n"
                "os.write = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('write reached'))\n"
                + snippet
            )
            before = subprocess.run(
                ["python3", "-c", before_open_guard, str(target), "102", "9:9", sysfs_real, sysfs_real],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(before.returncode, 0)
            self.assertIn("identity=FAIL_BEFORE_OPEN", before.stdout)
            self.assertEqual(target.read_bytes(), b"unchanged")

            (sysfs / "dev").write_text("0:0\n")
            after_open_guard = (
                "import os, sys\n"
                "_open = os.open\n"
                "def _race(path, flags):\n"
                "    fd = _open(path, flags)\n"
                "    open(sys.argv[5] + '/dev', 'w').write('1:2\\n')\n"
                "    return fd\n"
                "os.open = _race\n"
                "os.write = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('write reached'))\n"
                + snippet
            )
            after = subprocess.run(
                ["python3", "-c", after_open_guard, str(target), "102", "0:0", sysfs_real, sysfs_real],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(after.returncode, 0)
            self.assertIn("identity=FAIL_AFTER_OPEN", after.stdout)
            self.assertEqual(target.read_bytes(), b"unchanged")

    def test_hotplug_raw_syscall_keeps_existing_parser_grammar(self) -> None:
        helper = (Path(__file__).parents[1] / "tools/payload/quarantine-block-device").read_text()
        self.assertIn(
            "AZAZEL_C5_WRITE_SYSCALL stage=hotplug target=/dev/vdb %s\\n", helper
        )
        raw = 'write(4</dev/vdb>, "x", 1) = -1 EROFS (Read-only file system)'
        parsed = parse_structured_c5_records(
            f"AZAZEL_C5_WRITE_SYSCALL stage=hotplug target=/dev/vdb {raw}\n"
        )["write_syscall"]
        self.assertEqual(len(parsed), 1)
        self.assertTrue(parsed[0]["valid"])
        self.assertEqual(parsed[0]["raw_syscall"], raw)

    def test_hotplug_probe_is_fail_closed_when_syscall_evidence_is_missing(self) -> None:
        helper = (Path(__file__).parents[1] / "tools/payload/quarantine-block-device").read_text()
        probe = helper.split('run_hotplug_write_probe() {', 1)[1].split('\n}', 1)[0]
        self.assertIn('raw_probe_count', probe)
        self.assertIn('[ "$raw_probe_count" -eq 0 ] || [ "$probe_exit" -ne 0 ]', probe)
        self.assertIn('probe_classification=target_syscall_trace_missing', probe)
        self.assertIn('probe_status=FAIL', probe)
        self.assertIn('errno=NOT_OBSERVED', probe)
        self.assertNotIn('NOT_OBSERVED"; then\n    probe_status=PASS', probe)

    def test_hotplug_handoff_inputs_are_frozen_and_installed_without_enabling_service(self) -> None:
        root = Path(__file__).parents[1]
        helper = (root / "tools/payload/quarantine-block-device").read_text()
        prepare = (root / "tools/payload/prepare_inputs.py").read_text()
        build = (root / "tools/payload/build_candidate.sh").read_text()
        self.assertIn('"hotplug_probe_service"', prepare)
        self.assertIn('c5-hotplug-write-probe@.service', prepare)
        self.assertIn('manifest_input_path hotplug_probe_service', build)
        self.assertIn('etc/systemd/system/azazel-c5-hotplug-write-probe@.service', build)
        self.assertNotIn('multi-user.target.wants/azazel-c5-hotplug-write-probe', build)
        self.assertIn('fixture_disk_serial "$sys_device/serial" /sys/devices', helper)
        self.assertIn("/sys/class/dmi/id/sys_vendor", helper)
        self.assertIn("/sys/class/dmi/id/product_name", helper)
        self.assertIn('executor=systemd-unit', helper)
        self.assertIn('classification=write_probe_guard_failed', helper)

    def test_fixture_disk_serial_must_resolve_inside_sys_devices(self) -> None:
        helper = (Path(__file__).parents[1] / "tools/payload/quarantine-block-device").read_text()
        read_match = re.search(r"(?ms)^read_bounded_attr\(\) \{\n.*?^\}", helper)
        match = re.search(r"(?ms)^fixture_disk_serial\(\) \{\n.*?^\}", helper)
        hex_match = re.search(r"(?ms)^fixture_disk_serial_hex\(\) \{\n.*?^\}", helper)
        self.assertIn('fixture_disk_serial "$sys_device/serial" /sys/devices', helper)
        self.assertNotIn("/sys/class/block/vdb/device/serial", helper)
        self.assertIsNotNone(read_match)
        self.assertIsNotNone(match)
        self.assertIsNotNone(hex_match)
        with TemporaryDirectory() as temp:
            root = Path(temp)
            block_device = root / "sys/devices/pci0000/virtio0/block/vdb"
            block_device.mkdir(parents=True)
            serial = block_device / "serial"
            serial.write_text("AZC5-VDB-FILE-01\n")
            link = root / "sys/class/block/vdb"
            link.parent.mkdir(parents=True)
            link.symlink_to(block_device, target_is_directory=True)
            serial_attribute = link / "serial"
            script = read_match.group(0) + "\n" + match.group(0) + '\nfixture_disk_serial "$1" "$2"'
            inside = subprocess.run(
                ["/bin/sh", "-c", script, "sh", str(serial_attribute), str(root / "sys/devices")],
                capture_output=True, text=True, check=True,
            )
            self.assertEqual(inside.stdout.strip(), "AZC5-VDB-FILE-01")
            inside_hex = subprocess.run(
                ["/bin/sh", "-c", hex_match.group(0) + '\nfixture_disk_serial_hex "$1" "$2"',
                 "sh", str(serial_attribute), str(root / "sys/devices")],
                capture_output=True, text=True, check=True,
            )
            self.assertEqual(inside_hex.stdout, "415a43352d5644422d46494c452d30310a")

            outside = root / "outside/serial"
            outside.parent.mkdir()
            outside.write_text("AZC5-VDB-FILE-01\n")
            link.unlink()
            link.symlink_to(outside.parent, target_is_directory=True)
            escaped = subprocess.run(
                ["/bin/sh", "-c", script, "sh", str(link / "serial"), str(root / "sys/devices")],
                capture_output=True, text=True,
            )
            self.assertNotEqual(escaped.returncode, 0)
            self.assertEqual(escaped.stdout, "")
            escaped_hex = subprocess.run(
                ["/bin/sh", "-c", hex_match.group(0) + '\nfixture_disk_serial_hex "$1" "$2"',
                 "sh", str(link / "serial"), str(root / "sys/devices")],
                capture_output=True, text=True,
            )
            self.assertNotEqual(escaped_hex.returncode, 0)
            self.assertEqual(escaped_hex.stdout, "")

            oversized = root / "oversized"
            oversized.write_bytes(b"x" * 512)
            bounded = subprocess.run(
                ["/bin/sh", "-c", read_match.group(0) + '\nread_bounded_attr "$1"', "sh", str(oversized)],
                capture_output=True, text=True, check=True,
            )
            self.assertEqual(len(bounded.stdout), 129)

    def test_udev_rule_invocation_is_recorded_at_helper_entry(self) -> None:
        helper = (Path(__file__).parents[1] / "tools/payload/quarantine-block-device").read_text()
        udev_event = helper.index('emit_event udev_rule "$udev_provenance_status"')
        enforcement_start = helper.index('emit_event enforce_ioctl_started PASS')
        self.assertLess(udev_event, enforcement_start)
        self.assertIn('udev_provenance_status=PASS', helper)
        self.assertIn('[ "$action" = add ] && [ "$subsystem" = block ]', helper)
        self.assertIn('[ "$event_sysfs" = "$expected_sysfs" ]', helper)
        self.assertIn('device_serial=$udev_device_serial', helper)
        self.assertIn('emit_event udev_rule "$udev_provenance_status"', helper)

    def test_storage_command_scan_ignores_shell_case_pattern_but_finds_real_commands(self) -> None:
        self.assertEqual(
            find_forbidden_storage_commands(
                "\tfsck.repair=no)\n"
                "\t/sbin/fsck -A\n"
                "\tmodprobe virtio_blk\n"
                "\tblockdev --setro /dev/vda\n"
            ),
            ["\t/sbin/fsck -A", "\tmodprobe virtio_blk", "\tblockdev --setro /dev/vda"],
        )

    def test_pseudo_mount_curation_is_exact_and_machine_recorded(self) -> None:
        root = Path(__file__).parents[1]
        configure = (root / "tools/payload/configure_initramfs_c5.hook.chroot").read_text()
        inspector = (root / "tools/payload/measure_initramfs_c5.py").read_text()
        self.assertIn("d63ba2ea309aadf7794a5f84b0f394c2e48fe630640aa37e9963cd9d1b769d89", configure)
        self.assertIn('"sys-fs-fuse-connections.mount"', configure)
        self.assertIn('"sys-kernel-config.mount"', configure)
        self.assertIn("udev-pseudo-mount-curation.json", configure)
        self.assertIn('"valid": udev_curation_valid', inspector)

    def test_pseudo_mount_curation_rejects_self_consistent_forged_output(self) -> None:
        with TemporaryDirectory() as directory:
            rootfs = Path(directory)
            rules = rootfs / "usr/lib/udev/rules.d/99-systemd.rules"
            evidence = rootfs / "var/lib/azazel-c5"
            rules.parent.mkdir(parents=True)
            evidence.mkdir(parents=True)
            rules.write_text("# substituted file with both offending lines absent\n")
            (evidence / "udev-pseudo-mount-curation.json").write_text(
                json.dumps({
                    "schema": "azazel-payload/c5-udev-pseudo-mount-curation@1",
                    "source_path": "/usr/lib/udev/rules.d/99-systemd.rules",
                    "source_sha256": EXPECTED_PSEUDO_MOUNT_RULES_SOURCE_SHA256,
                    "removed_lines": [
                        {"line": line, "sha256": hashlib.sha256(line.encode()).hexdigest()}
                        for line in EXPECTED_PSEUDO_MOUNT_RULES
                    ],
                    "curated_file_sha256": EXPECTED_PSEUDO_MOUNT_RULES_CURATED_SHA256,
                })
            )
            _, valid = inspect_pseudo_mount_curation(rootfs)
            self.assertFalse(valid)

    def test_order_rejects_unmeasured_executable_shell_content(self) -> None:
        with self.assertRaisesRegex(ValueError, "unrecognized executable content"):
            parse_stage_order(
                [
                    '/scripts/init-top/00-quarantine "$@"',
                    "touch /tmp/unmeasured-side-effect",
                ],
                "init-top",
            )

    def test_other_order_stage_is_parsed_with_its_stage_and_contents_checked(self) -> None:
        with TemporaryDirectory() as directory:
            scripts = Path(directory)
            stage = scripts / "local-premount"
            stage.mkdir()
            (stage / "ORDER").write_text(
                '[ -e /conf/param.conf ] && . /conf/param.conf\n'
                '/scripts/local-premount/10-fixture "$@"\n'
            )
            records = inspect_other_stage_orders(scripts)
            self.assertEqual(records[0]["stage"], "local-premount")
            self.assertEqual(records[0]["entries"], [("10-fixture", '/scripts/local-premount/10-fixture "$@"')])
            self.assertEqual(records[0]["invalid_executable_content"], [])

    def test_other_order_stage_records_unmeasured_shell_content(self) -> None:
        with TemporaryDirectory() as directory:
            scripts = Path(directory)
            stage = scripts / "local-premount"
            stage.mkdir()
            (stage / "ORDER").write_text(
                '/scripts/local-premount/10-fixture "$@"\n'
                "mount /dev/vda /target\n"
            )
            records = inspect_other_stage_orders(scripts)
            self.assertEqual(records[0]["entries"], [])
            self.assertIn("mount /dev/vda /target", records[0]["invalid_executable_content"][0])

    def test_cdrom_identification_cleanup_is_not_automount_activation(self) -> None:
        cdrom_id_rules = r'''
# Debian 60-cdrom_id.rules identification and cleanup properties.
SUBSYSTEM=="block", ENV{ID_CDROM}=="1", ENV{SYSTEMD_MOUNT_DEVICE_BOUND}="1"
ACTION=="remove", ENV{SYSTEMD_MOUNT_DEVICE_BOUND}="0"
'''
        self.assertFalse(has_automount_activation_rule(cdrom_id_rules))

    def test_real_automount_unit_request_is_detected(self) -> None:
        automount_rule = (
            'ACTION=="add", SUBSYSTEM=="block", '
            'ENV{SYSTEMD_WANTS}+="media-%k.automount"\n'
        )
        self.assertTrue(has_automount_activation_rule(automount_rule))

    def test_init_bottom_default_udev_is_removed_only_at_pinned_digest(self) -> None:
        root = Path(__file__).parents[1]
        configure = (root / "tools/payload/configure_initramfs_c5.hook.chroot").read_text()
        inspector = (root / "tools/payload/measure_initramfs_c5.py").read_text()
        self.assertIn("init_bottom_udev=$base/scripts/init-bottom/udev", configure)
        self.assertIn("5a7595d79328000420c9f641362af1ef15aa5b1bf6ce0114588b49e13f7949a6", configure)
        self.assertIn("removed-init-bottom-hooks.sha256", configure)
        self.assertIn('"udev": "5a7595d79328000420c9f641362af1ef15aa5b1bf6ce0114588b49e13f7949a6"', inspector)

    def test_c5_summary_includes_all_boot_policy_faults(self) -> None:
        self.assertEqual(
            summarize_faults(
                ["unpinned_hook", "order_changed"],
                [
                    {"code": "automount_rule_present", "detail": "fixture"},
                    {"code": "quarantine_not_persistent", "detail": "fixture"},
                    {"code": "unpinned_hook", "detail": "fixture"},
                    {"code": "hook_order_changed", "detail": "fixture"},
                ],
            ),
            [
                "automount_rule_present",
                "hook_order_changed",
                "order_changed",
                "quarantine_not_persistent",
                "unpinned_hook",
            ],
        )

    def test_read_only_fixture_is_explicit_and_fails_closed(self) -> None:
        root = Path(__file__).parents[1]
        hook = (
            Path(__file__).parents[1]
            / "tools/payload/hooks/00-az-quarantine-block-devices"
        ).read_text()
        self.assertIn("azazel.c5_fixture=QEMU-regular-file", hook)
        self.assertIn('"$helper" "$name" initramfs', hook)
        self.assertIn('[ "$sysfs_ro" = 1 ]', hook)
        self.assertIn('[ "$blockdev_ro" = 1 ]', hook)
        self.assertIn("/usr/bin/strace", hook)
        self.assertIn("strace -qq -yy -e trace=openat,open,dup2,dup3,close,write", hook)
        self.assertNotIn("-P /dev/vda", hook)
        self.assertIn("AZAZEL_C5_WRITE_SYSCALL", hook)
        self.assertIn("sysfs_ro_after=%s blockdev_ro_after=%s", hook)
        self.assertIn("mount_state_after=%s", hook)
        self.assertIn("schema=azazel-c5-handoff-v1", hook)
        self.assertNotIn("write_errno=30", hook)
        self.assertIn("/sbin/modprobe virtio_blk", hook)
        self.assertIn('[ "$attempts" -lt 50 ]', hook)
        self.assertIn("sleep 0.1", hook)
        self.assertNotIn("/dev/disk/", hook)
        helper = (root / "tools/payload/quarantine-block-device").read_text()
        self.assertIn('is_initramfs_fixture=1', helper)
        self.assertIn('emit_event helper_started PASS', helper)
        self.assertIn('emit_event enforce_ioctl "$enforce_ioctl"', helper)
        self.assertIn('emit_event post_ro "$mechanism_supported"', helper)
        self.assertIn('emit_event helper "$mechanism_supported"', helper)
        self.assertIn('emit_event ro_state "$mechanism_supported"', helper)
        self.assertIn('command_return=$enforce_command_return trace_path=$enforce_trace', helper)
        self.assertIn('raw=%s', helper)
        self.assertIn('index($0, "<" target "<block ")', helper)
        self.assertIn('AZAZEL_C5_WRITE_PROBE stage=hotplug target=/dev/vdb', helper)
        self.assertIn('sysfs_ro_before=$pre_sysfs', helper)
        self.assertIn('blockdev_ro_after=$post_blockdev', helper)
        self.assertIn('emit_event post_write "$probe_status"', helper)

    def test_initramfs_fixture_write_emits_raw_syscall_last_and_keeps_guards(self) -> None:
        root = Path(__file__).parents[1]
        hook = (root / "tools/payload/hooks/00-az-quarantine-block-devices").read_text()
        raw_emit = hook.index('AZAZEL_C5_WRITE_SYSCALL stage=initramfs target=/dev/vda %s')
        self.assertIn('index($0, "</dev/vda<block ")', hook)
        self.assertIn('probe_status=NOT_OBSERVED', hook)
        self.assertIn('[ "$mount_state" = not_mounted ]', hook)
        self.assertIn('[ "$probe_sysfs_ro" = 1 ]', hook)
        self.assertIn('[ "$probe_blockdev_ro" = 1 ]', hook)
        self.assertIn('syscall_scope=explicit-fixture', hook)
        self.assertLess(raw_emit, hook.index('printf \'AZAZEL_C5_PHASE phase=target_write'))

    def test_initramfs_copy_exec_uses_the_helper_file_path(self) -> None:
        hook = (
            Path(__file__).parents[1]
            / "tools/payload/initramfs-hooks/azazel-quarantine"
        ).read_text()
        self.assertIn(
            "copy_exec /usr/libexec/azazel-quarantine-block "
            "/usr/libexec/azazel-quarantine-block",
            hook,
        )
        self.assertNotIn(
            "copy_exec /usr/libexec/azazel-quarantine-block /usr/libexec\n",
            hook,
        )

    def test_absolute_blockdev_path_counts_as_declared_fixture_enforcement(self) -> None:
        self.assertTrue(
            declares_fixture_enforcement(
                "helper=/usr/libexec/azazel-quarantine-block\n"
                "case azazel.c5_fixture=QEMU-regular-file in\n"
                "# fixture-only sysfs_ro blockdev_ro"
            )
        )
        self.assertTrue(
            declares_fixture_enforcement(
                "quarantine-block azazel.c5_fixture=QEMU-regular-file\n"
                "fixture-only sysfs_ro blockdev_ro"
            )
        )

    def test_fixture_enforcement_declaration_does_not_require_a_fixed_errno(self) -> None:
        self.assertFalse(declares_fixture_enforcement(
            "quarantine-block azazel.c5_fixture=QEMU-regular-file fixture-only sysfs_ro"
        ))

    def test_fixture_pass_requires_read_only_rejection_and_persistence(self) -> None:
        event = parse_fixture_event(
            "AZAZEL_C5_FIXTURE_RESULT target=/dev/vda sysfs_ro=1 "
            "blockdev_ro=1 write_probe=denied_read_only"
        )
        self.assertTrue(fixture_passes(event, True, "same", "same"))
        self.assertFalse(fixture_passes(event, False, "same", "same"))
        self.assertFalse(fixture_passes(event, True, "before", "after"))
        self.assertFalse(
            fixture_passes(
                parse_fixture_event(
                    "AZAZEL_C5_FIXTURE_RESULT target=/dev/vda sysfs_ro=0 "
                    "blockdev_ro=0 write_probe=write_succeeded"
                ),
                True,
                "same",
                "same",
            )
        )

    def test_config_preamble_lines_do_not_shift_hook_call_evidence(self) -> None:
        entries = parse_stage_order(
            [
                "[ -e /conf/param.conf ] && . /conf/param.conf",
                '/scripts/init-top/00-quarantine "$@"',
                "[ -e /conf/param.conf ] && . /conf/param.conf",
                '/scripts/init-top/10-disable-resume "$@"',
                "# /scripts/init-top/not-executed",
            ],
            "init-top",
        )
        self.assertEqual(
            entries,
            [
                ("00-quarantine", '/scripts/init-top/00-quarantine "$@"'),
                ("10-disable-resume", '/scripts/init-top/10-disable-resume "$@"'),
            ],
        )

    def test_measured_manifest_uses_boot_evaluator_inspection_api(self) -> None:
        class Provenance(Enum):
            PINNED_BY_BOOT = "pinned_by_boot"

        @dataclass
        class HookEntry:
            name: str
            digest: str
            provenance: Provenance
            arguments: tuple[str, ...]

        @dataclass
        class InitramfsInspection:
            candidate: str
            build_host_id: str
            hooks: tuple[HookEntry, ...]
            order_established: bool

        seen = {}

        def evaluate(inspection):
            seen["inspection"] = inspection
            return SimpleNamespace(verdict=SimpleNamespace(value="fail"))

        evaluator = SimpleNamespace(
            Provenance=Provenance,
            HookEntry=HookEntry,
            InitramfsInspection=InitramfsInspection,
            evaluate=evaluate,
        )
        result = evaluate_inspection(
            evaluator,
            {
                "candidate": "live-build-evaluation-only",
                "build_host_id": "build-a",
                "order_established": True,
                "hooks": [
                    {
                        "name": "az-quarantine-block-devices",
                        "digest": "sha256:" + "a" * 64,
                        "provenance": "pinned_by_boot",
                        "arguments": [],
                    }
                ],
            },
        )
        self.assertEqual(result.verdict.value, "fail")
        self.assertIsInstance(seen["inspection"], InitramfsInspection)
        self.assertEqual(seen["inspection"].hooks[0].provenance, Provenance.PINNED_BY_BOOT)


if __name__ == "__main__":
    unittest.main()
