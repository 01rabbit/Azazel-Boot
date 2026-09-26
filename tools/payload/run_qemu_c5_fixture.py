#!/usr/bin/env python3
"""Measure initramfs, userspace, and hotplug C5 behavior using QEMU file fixtures."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


FIXTURE_SIZE = 32 * 1024 * 1024
FIXTURE_EVENT = (
    "AZAZEL_C5_FIXTURE_INITRAMFS target=/dev/vda sysfs_ro=1 blockdev_ro=1"
)
PERSISTENCE_EVENT = (
    "AZAZEL_C5_USERSPACE_PERSISTENCE target=/dev/vda sysfs_ro=1 blockdev_ro=1"
)
HOTPLUG_EVENT = (
    "AZAZEL_C5_HOTPLUG_QUARANTINED target=/dev/vdb sysfs_ro=1 "
    "blockdev_ro=1"
)
HOTPLUG_BUS = "azazel_c5_hotplug_port"
QEMU_SMBIOS_MANUFACTURER = "QEMU"
QEMU_SMBIOS_PRODUCT = "Azazel C5 File Fixture"
HOTPLUG_DEVICE_SERIAL = "AZC5-VDB-FILE-01"
MULTI_USER_TARGET = re.compile(r"Reached target\s+multi-user\.target(?:\s|$)")
KERNEL_VDB_LINE = re.compile(r"^\[\s*(?P<uptime>[0-9]+(?:\.[0-9]+)?)\]\s+.*\[vdb\](?:\s|$)")
KERNEL_VDA_LINE = re.compile(r"^\[\s*(?P<uptime>[0-9]+(?:\.[0-9]+)?)\]\s+.*\[vda\](?:\s|$)")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_OSC_ESCAPE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.DOTALL)
STRUCTURED_PREFIXES = {
    "phase": "AZAZEL_C5_PHASE ",
    "write_probe": "AZAZEL_C5_WRITE_PROBE ",
    "write_syscall": "AZAZEL_C5_WRITE_SYSCALL ",
    "enforce_syscall": "AZAZEL_C5_ENFORCE_SYSCALL ",
    "hotplug": "AZAZEL_C5_HOTPLUG_QUARANTINED ",
    "kernel_log": "AZAZEL_C5_KERNEL_LOG ",
}
EVIDENCE_STATUSES = {"PASS", "FAIL", "NOT_OBSERVED"}
# Linux 6.12 returns EPERM from blkdev_write_iter when bdev_read_only is true;
# EROFS is also used by other read-only block paths. EPERM is accepted only for
# an observed target write, never an open failure, and only alongside the
# separately measured BLKROSET/RO-state/identity/order evidence below.
READ_ONLY_WRITE_DENIAL_ERRNOS = {"EROFS", "EPERM"}
READ_ONLY_OPEN_DENIAL_ERRNOS = {"EROFS"}
PERSISTENCE_PHASES = (
    "discovered",
    "mount_observation",
    "mount_guard",
    "marker_present",
    "marker_valid",
    "session_binding_valid",
    "write_probe",
    "handoff_valid",
)
INITRAMFS_RO_PHASES = ("discovered", "quarantine")
QEMU_BLOCK_TRACE_EVENTS = (
    "bdrv_open_common",
    "blk_co_pwritev",
    "bdrv_co_pwritev_part",
    "virtio_blk_handle_write",
    "bdrv_co_pwrite_zeroes",
)
def clean_serial(serial_text: str) -> str:
    # Terminal OSC sequences (including xterm's OSC 104 reset emitted by
    # Debian's console setup) can be interleaved with serial evidence lines.
    # Remove both BEL- and ST-terminated OSC controls before CSI controls so
    # structured records and kernel registration lines remain line-anchored.
    return ANSI_ESCAPE.sub("", ANSI_OSC_ESCAPE.sub("", serial_text))


def parse_structured_c5_records(serial_text: str) -> dict[str, list[dict[str, Any]]]:
    """Parse newline-delimited C5 records without interpreting prose as evidence."""
    records: dict[str, list[dict[str, Any]]] = {
        "phase": [], "write_probe": [], "write_syscall": [],
        "enforce_syscall": [], "hotplug": [], "kernel_log": []
    }
    offset = 0
    for raw_line in clean_serial(serial_text).splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        for kind, prefix in STRUCTURED_PREFIXES.items():
            if not line.startswith(prefix):
                continue
            fields: dict[str, str] = {}
            malformed: list[str] = []
            if kind not in {"write_syscall", "enforce_syscall"}:
                field_text = line[len(prefix):]
                raw_match = re.search(r"(?:^| )raw=", field_text)
                raw_tail = None
                if raw_match:
                    raw_tail = field_text[raw_match.end():]
                    field_text = field_text[:raw_match.start()].rstrip()
                for token in field_text.split():
                    if "=" not in token:
                        malformed.append(token)
                        continue
                    key, value = token.split("=", 1)
                    if not key or not value:
                        malformed.append(token)
                        continue
                    if key in fields:
                        if fields[key] != value:
                            malformed.append(token)
                        continue
                    fields[key] = value
                if raw_tail is not None:
                    fields["raw"] = raw_tail
            valid = not malformed
            raw_syscall = None
            if kind == "phase":
                valid = valid and fields.get("status") in EVIDENCE_STATUSES and bool(
                    fields.get("phase") and fields.get("stage") in
                    {"initramfs", "userspace", "hotplug"}
                )
            elif kind == "write_syscall":
                # The first two tokens bind the raw strace record to a fixture
                # and boot phase; preserve the remainder verbatim for audit.
                match = re.match(r"stage=(\S+) target=(\S+) (.*)$", line[len(prefix):])
                raw_syscall = match.group(3) if match else ""
                fields = {}
                if match:
                    fields = {"stage": match.group(1), "target": match.group(2)}
                else:
                    malformed.append("stage/target/raw")
                fields["raw_syscall"] = raw_syscall
                parsed = _parse_strace_syscall(raw_syscall)
                if parsed is not None:
                    fields.update(parsed)
                    if kind == "enforce_syscall":
                        attributed, attribution_reason = _strace_target_attribution(
                            raw_syscall, fields.get("target", "")
                        )
                        fields["target_attributed"] = attributed
                        fields["target_attribution"] = attribution_reason
                valid = (
                    not malformed
                    and fields.get("stage") in {"initramfs", "userspace", "hotplug"}
                    and fields.get("target", "").startswith("/dev/")
                    and parsed is not None
                )
            elif kind == "enforce_syscall":
                # Current shell records carry key/value diagnostics before the
                # raw strace line. Keep each diagnostic independently machine
                # readable; older records with an inline syscall remain valid.
                field_text = line[len(prefix):]
                raw_match = re.search(r"(?:^| )raw=", field_text)
                raw_syscall = None
                if raw_match:
                    raw_syscall = field_text[raw_match.end():]
                    field_text = field_text[:raw_match.start()].rstrip()
                tokens = field_text.split()
                key_value_mode = all("=" in token for token in tokens)
                if key_value_mode:
                    for token in tokens:
                        key, value = token.split("=", 1)
                        if not key or not value or key in fields:
                            malformed.append(token)
                            continue
                        fields[key] = value
                else:
                    # Compatibility with the pre-diagnostic grammar:
                    # stage=<stage> target=<device> <raw strace syscall>.
                    match = re.match(r"stage=(\S+) target=(\S+) (.*)$", field_text)
                    if match:
                        fields.update({"stage": match.group(1), "target": match.group(2)})
                        raw_syscall = match.group(3)
                    else:
                        malformed.append("stage/target/raw")
                if raw_syscall is not None:
                    fields["raw"] = raw_syscall
                    fields["raw_syscall"] = raw_syscall
                elif fields.get("raw_hex") not in (None, "NOT_OBSERVED"):
                    try:
                        decoded = bytes.fromhex(fields["raw_hex"]).decode("utf-8")
                    except (ValueError, UnicodeDecodeError):
                        malformed.append("raw_hex")
                    else:
                        fields["raw"] = decoded
                        fields["raw_syscall"] = decoded
                        raw_syscall = decoded
                parsed = _parse_strace_syscall(raw_syscall or "")
                if parsed is not None:
                    fields.update(parsed)
                    attributed, attribution_reason = _strace_target_attribution(
                        raw_syscall or "", fields.get("target", "")
                    )
                    fields["target_attributed"] = attributed
                    fields["target_attribution"] = attribution_reason
                try:
                    command_return = int(fields.get("command_return", ""))
                except ValueError:
                    command_return = None
                fields["command_return_parsed"] = command_return
                valid = (
                    not malformed
                    and fields.get("stage") in {"initramfs", "userspace", "hotplug"}
                    and fields.get("target", "").startswith("/dev/")
                    and (parsed is not None or fields.get("raw_hex") == "NOT_OBSERVED")
                )
            elif kind == "write_probe":
                valid = valid and all(fields.get(key) for key in (
                    "target", "stage", "syscall", "result", "errno", "errno_name"
                )) and fields.get("stage") in {"initramfs", "userspace", "hotplug"}
                try:
                    int(fields.get("errno", ""))
                except ValueError:
                    valid = False
            elif kind == "hotplug":
                valid = valid and fields.get("target") == "/dev/vdb"
            else:
                valid = valid and fields.get("stage") in {"initramfs", "userspace", "hotplug"} \
                    and fields.get("target", "").startswith("/dev/") \
                    and bool(fields.get("phase")) and "raw" in fields
            records[kind].append({
                "offset": offset + len(raw_line) - len(raw_line.lstrip()),
                "line": line,
                "fields": fields,
                "valid": bool(valid),
                "malformed_tokens": malformed,
                "newline_terminated": raw_line.endswith(("\n", "\r")),
                **({"raw_syscall": raw_syscall} if raw_syscall is not None else {}),
            })
            break
        offset += len(raw_line)
    return records


def has_complete_hotplug_quarantine_record(serial_text: str) -> bool:
    """True once a complete newline-delimited final hotplug record is present."""
    return any(
        record["newline_terminated"]
        for record in parse_structured_c5_records(serial_text)["hotplug"]
    )


def _parse_strace_syscall(raw_line: str) -> dict[str, Any] | None:
    """Extract one complete strace syscall result and resolve symbolic errno."""
    match = re.fullmatch(
        r"(?P<syscall>[A-Za-z_][A-Za-z0-9_]*)\(.*\)\s+=\s+"
        r"(?P<result>-?[0-9]+)"
        r"(?P<result_annotation><(?P<result_fd_path>/[^<>]+)"
        r"(?:<block [0-9]+:[0-9]+>)?>)?"
        r"(?:\s+(?P<errno>[A-Z][A-Z0-9_]*))?"
        r"(?:\s+\(.*\))?",
        raw_line,
    )
    if match is None:
        return None
    errno_name = match.group("errno")
    if errno_name:
        errno_number = getattr(errno, errno_name, None)
        if not isinstance(errno_number, int):
            return None
    else:
        errno_number = 0
        errno_name = "0"
    parsed = {
        "syscall": match.group("syscall"),
        "result": match.group("result"),
        "errno": errno_number,
        "errno_name": errno_name,
    }
    if match.group("result_annotation") is not None:
        parsed["result_annotation"] = match.group("result_annotation")
        parsed["result_fd_path"] = match.group("result_fd_path")
    return parsed


def _phase_observation(
    records: list[dict[str, Any]], phase: str, stage: str, *, target: str | None = None
) -> dict[str, Any]:
    matches = [
        record for record in records
        if record["fields"].get("phase") == phase
        and record["fields"].get("stage") == stage
        and (target is None or record["fields"].get("target") == target)
    ]
    if len(matches) != 1:
        return {
            "status": "NOT_OBSERVED" if not matches else "FAIL",
            "reason": "missing" if not matches else "duplicate",
            "observations": matches,
        }
    record = matches[0]
    if not record["valid"] or not record["newline_terminated"]:
        reason = "malformed_record" if not record["valid"] else "unterminated_record"
        return {"status": "FAIL", "reason": reason, "observation": record}
    return {
        "status": record["fields"]["status"],
        "observation": record,
    }


def _validate_persistence_phase(
    phase: str, observation: dict[str, Any], all_phases: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Bind PASS labels to the target and measured state for each phase."""
    if observation.get("status") != "PASS":
        return observation
    record = observation.get("observation", {})
    fields = record.get("fields", {})
    if fields.get("target") != "/dev/vda" or fields.get("path") != "/dev/vda":
        return {**observation, "status": "FAIL", "reason": "persistence_target_mismatch"}
    consistent = True
    if phase == "mount_observation":
        consistent = fields.get("mount_state") in {"mounted", "not_mounted"}
    elif phase == "mount_guard":
        consistent = (
            fields.get("mount_state") == "not_mounted"
            and fields.get("required_state") == "not_mounted"
        )
    elif phase == "marker_present":
        marker = fields.get("marker_contents", "")
        parts = marker.rstrip("|").split("|")
        consistent = (
            fields.get("marker_path") == "/run/azazel/host-storage-quarantined"
            and len(parts) == 4
            and parts[0] == "schema=azazel-c5-handoff-v1"
            and parts[1].startswith("session_id=")
            and parts[2] == "phase=device_quarantined"
            and parts[3] == "device=/dev/vda"
        )
    elif phase == "marker_valid":
        marker_phase = all_phases.get("marker_present", {}).get("observation", {}).get("fields", {})
        marker_parts = marker_phase.get("marker_contents", "").rstrip("|").split("|")
        consistent = (
            fields.get("schema") == "azazel-c5-handoff-v1"
            and len(marker_parts) == 4
            and fields.get("marker_session_id") == marker_parts[1].removeprefix("session_id=")
            and marker_parts[2] == "phase=device_quarantined"
            and marker_parts[3] == "device=/dev/vda"
            and re.fullmatch(r"[0-9a-fA-F-]{36}", fields.get("marker_session_id", "")) is not None
        )
    elif phase == "session_binding_valid":
        consistent = (
            fields.get("boot_id") == fields.get("marker_session_id")
            and re.fullmatch(r"[0-9a-fA-F-]{36}", fields.get("boot_id", "")) is not None
        )
    elif phase == "handoff_valid":
        consistent = (
            fields.get("sysfs_ro_after") == "1"
            and fields.get("blockdev_ro_after") == "1"
            and fields.get("mount_state_after") == "not_mounted"
        )
    if not consistent:
        return {**observation, "status": "FAIL", "reason": f"{phase}_state_inconsistent"}
    return observation


def _validate_udev_provenance(observation: dict[str, Any]) -> dict[str, Any]:
    if observation.get("status") != "PASS":
        return observation
    fields = observation.get("observation", {}).get("fields", {})
    devpath = fields.get("devpath", "")
    sysfs_devno = fields.get("sysfs_devno", "")
    valid = bool(
        fields.get("origin") == "udev"
        and fields.get("udev_provenance") == "PASS"
        and fields.get("action") == "add"
        and fields.get("subsystem") == "block"
        and fields.get("target") == "/dev/vdb"
        and fields.get("kernel_name") == "vdb"
        and fields.get("device_serial") == HOTPLUG_DEVICE_SERIAL
        and re.fullmatch(r"/devices/(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_./:-]+/vdb", devpath) is not None
        and isinstance(sysfs_devno, str)
        and re.fullmatch(r"[0-9]+:[0-9]+", sysfs_devno) is not None
    )
    return observation if valid else {
        **observation, "status": "FAIL", "reason": "udev_event_provenance_missing_or_invalid",
    }


def parse_runtime_c5_evidence(
    serial_text: str, *, qmp_hotplug_attached: bool,
    qmp_add_start_serial_offset: int | None,
    qmp_add_response_serial_offset: int | None,
    qmp_add_response_elapsed_seconds: float | None = None,
    qmp_add_response_host_monotonic_seconds: float | None = None,
    qmp_add_start_host_monotonic_seconds: float | None = None,
) -> dict[str, Any]:
    """Build strict phase evidence; QMP attachment alone never proves quarantine."""
    records = parse_structured_c5_records(serial_text)
    phase_records = records["phase"]
    initial_quarantine = _phase_observation(
        phase_records, "initial_quarantine", "initramfs"
    )
    fixture_device_quarantined = _phase_observation(
        phase_records, "fixture_device_quarantined", "initramfs", target="/dev/vda"
    )
    kernel_vda_registration = _kernel_vda_registration(serial_text)
    initramfs_target_write = _phase_observation(
        phase_records, "target_write", "initramfs", target="/dev/vda"
    )
    init_quarantine = _phase_observation(
        phase_records, "quarantine", "initramfs", target="/dev/vda"
    )
    init_ro = _ro_evidence_observation(
        phase_records, "initramfs", "/dev/vda", INITRAMFS_RO_PHASES
    )
    init_write_records = [
        item for item in records["write_probe"]
        if item["fields"].get("stage") == "initramfs"
        and item["fields"].get("target") == "/dev/vda"
    ]
    init_write_records.extend(
        item for item in records["write_syscall"]
        if item["fields"].get("stage") == "initramfs"
        and item["fields"].get("target") == "/dev/vda"
    )
    init_write = _write_probe_observation(init_write_records, init_ro)
    initramfs_kernel_log_candidates = [
        item for item in records["kernel_log"]
        if item["fields"].get("stage") == "initramfs"
    ]
    initramfs_kernel_log = []
    for item in initramfs_kernel_log_candidates:
        fields = item["fields"]
        try:
            uptime = float(fields.get("guest_uptime_seconds", ""))
        except ValueError:
            uptime = None
        if (
            item["valid"] and item["newline_terminated"]
            and fields.get("target") == "/dev/vda"
            and fields.get("phase") in {"before_probe", "after_probe"}
            and uptime is not None and uptime >= 0
            and bool(fields.get("raw", "").strip())
        ):
            initramfs_kernel_log.append({**item, "guest_uptime_seconds": uptime})
    kernel_log_phases = {
        item["fields"]["phase"] for item in initramfs_kernel_log
    }
    kernel_before = [
        item for item in initramfs_kernel_log
        if item["fields"].get("phase") == "before_probe"
    ]
    kernel_after = [
        item for item in initramfs_kernel_log
        if item["fields"].get("phase") == "after_probe"
    ]
    initramfs_probe_offsets = [
        item.get("offset") for item in init_write_records
        if isinstance(item.get("offset"), int)
    ]
    kernel_ordered_around_probe = bool(
        kernel_before and kernel_after and initramfs_probe_offsets
        and max(item["offset"] for item in kernel_before) < min(initramfs_probe_offsets)
        and max(initramfs_probe_offsets) < min(item["offset"] for item in kernel_after)
        and max(item["guest_uptime_seconds"] for item in kernel_before)
        <= min(item["guest_uptime_seconds"] for item in kernel_after)
    )
    kernel_log_status = (
        "PASS" if len(initramfs_kernel_log) == len(initramfs_kernel_log_candidates)
        and {"before_probe", "after_probe"}.issubset(kernel_log_phases)
        and kernel_ordered_around_probe
        else "FAIL" if initramfs_kernel_log_candidates else "NOT_OBSERVED"
    )
    persistence = {
        phase: _phase_observation(phase_records, phase, "userspace", target="/dev/vda")
        for phase in PERSISTENCE_PHASES
    }
    persistence = {
        phase: _validate_persistence_phase(phase, observation, persistence)
        for phase, observation in persistence.items()
    }
    userspace_write_records = [
        record for record in records["write_syscall"]
        if record["fields"].get("stage") == "userspace"
        and record["fields"].get("target") == "/dev/vda"
    ]
    persistence["write_probe"] = _userspace_write_probe_observation(
        persistence["write_probe"], userspace_write_records
    )
    kernel_discovery = _kernel_vdb_discovery(serial_text)
    hotplug_device = kernel_discovery
    hotplug_helper_started = _phase_observation(
        phase_records, "helper_started", "hotplug", target="/dev/vdb"
    )
    hotplug_udev_rule = _phase_observation(
        phase_records, "udev_rule", "hotplug", target="/dev/vdb"
    )
    hotplug_udev_rule = _validate_udev_provenance(hotplug_udev_rule)
    hotplug_helper_completed = _phase_observation(
        phase_records, "helper", "hotplug", target="/dev/vdb"
    )
    hotplug_ro = _phase_observation(
        phase_records, "ro_state", "hotplug", target="/dev/vdb"
    )
    hotplug_raw_syscalls = [
        item for item in records["write_syscall"]
        if item["fields"].get("stage") == "hotplug"
        and item["fields"].get("target") == "/dev/vdb"
    ]
    hotplug_ro_evidence = _ro_evidence_observation(
        phase_records, "hotplug", "/dev/vdb", ("ro_state",)
    )
    if hotplug_ro["status"] == "PASS":
        fields = hotplug_ro.get("observation", {}).get("fields", {})
        if fields.get("sysfs_ro_after", fields.get("sysfs_ro")) != "1" or \
           fields.get("blockdev_ro_after", fields.get("blockdev_ro")) != "1":
            hotplug_ro = {
                "status": "FAIL",
                "reason": "read_only_state_not_confirmed",
                "observation": hotplug_ro.get("observation"),
            }
    hotplug_write = _write_probe_observation(hotplug_raw_syscalls, hotplug_ro_evidence)
    if hotplug_write["status"] == "PASS" and not any(
        item.get("raw_syscall") for item in hotplug_raw_syscalls
    ):
        hotplug_write = {
            **hotplug_write,
            "status": "FAIL",
            "reason": "raw_hotplug_syscall_not_observed",
            "quarantine_causality": "UNPROVEN",
        }
    init_enforcement = _stage_enforcement_evidence(
        phase_records, records["enforce_syscall"], records["write_syscall"], "initramfs", "/dev/vda"
    )
    hotplug_enforcement = _stage_enforcement_evidence(
        phase_records, records["enforce_syscall"], records["write_syscall"],
        "hotplug", "/dev/vdb", structured_probe_records=records["write_probe"],
    )
    hotplug_events = records["hotplug"]
    hotplug_event = hotplug_events[0] if len(hotplug_events) == 1 else None
    hotplug_quarantine = {
        "status": "NOT_OBSERVED" if not hotplug_events else "FAIL",
        "reason": "missing" if not hotplug_events else "duplicate",
        "observation": hotplug_event,
    }
    if hotplug_event is not None:
        fields = hotplug_event["fields"]
        good = bool(
            hotplug_event["valid"]
            and fields.get("sysfs_ro") == "1"
            and fields.get("blockdev_ro") == "1"
            and hotplug_enforcement["status"] == "PASS"
        )
        hotplug_quarantine = {
            "status": "PASS" if good else "FAIL",
            "reason": None if good else "required_hotplug_fields_missing_or_false",
            "observation": hotplug_event,
        }
    qmp_attach = {
        "status": "PASS" if qmp_hotplug_attached else "FAIL",
        "command_start_serial_offset": qmp_add_start_serial_offset,
        "command_start_offset_clock_domain": "host_serial_log_character_offset_after_ANSI_normalization",
        "response_serial_offset": qmp_add_response_serial_offset,
        "response_offset_clock_domain": "host_serial_log_character_offset_after_ANSI_normalization",
        "response_elapsed_seconds": qmp_add_response_elapsed_seconds,
        "response_elapsed_clock_domain": "host_monotonic_elapsed_since_qmp_client_start",
        "response_host_monotonic_seconds": qmp_add_response_host_monotonic_seconds,
        "response_host_monotonic_clock_domain": "host_monotonic_seconds",
        "command_start_host_monotonic_seconds": qmp_add_start_host_monotonic_seconds,
        "command_start_host_monotonic_clock_domain": "host_monotonic_seconds",
    }
    chain_offsets = [
        qmp_add_start_serial_offset,
        _observation_offset(hotplug_device),
        _observation_offset(hotplug_udev_rule),
        _observation_offset(hotplug_helper_started),
        _observation_offset(hotplug_enforcement["enforce_ioctl"]),
        _observation_offset(hotplug_enforcement["post_ro"]),
        _observation_offset(hotplug_helper_completed),
        _observation_offset(hotplug_ro),
        _observation_offset(hotplug_write),
        _observation_offset(hotplug_enforcement["post_probe"]),
        _observation_offset(hotplug_quarantine),
    ]
    chain_ordered = bool(
        all(value is not None for value in chain_offsets)
        and chain_offsets == sorted(chain_offsets)
    )
    multi_user_events = _line_offsets(clean_serial(serial_text), MULTI_USER_TARGET)
    persistence_offsets = [_observation_offset(persistence[name]) for name in PERSISTENCE_PHASES]
    initramfs_offsets = [
        _observation_offset(init_quarantine), _observation_offset(init_write)
    ]
    first_action_offsets = [
        _observation_offset(initial_quarantine),
        _observation_offset(kernel_vda_registration),
        _observation_offset(fixture_device_quarantined),
        _observation_offset(initramfs_target_write),
    ]
    first_action_offsets_ordered = bool(
        all(isinstance(value, int) for value in first_action_offsets)
        and first_action_offsets == sorted(first_action_offsets)
        and len(set(first_action_offsets)) == len(first_action_offsets)
    )
    first_action_evidence_valid = bool(
        initial_quarantine.get("status") == "PASS"
        and initial_quarantine.get("observation", {}).get("fields", {}).get("devices") == "0"
        and kernel_vda_registration.get("status") == "PASS"
        and fixture_device_quarantined.get("status") == "PASS"
        and fixture_device_quarantined.get("observation", {}).get("fields", {}).get("sysfs_ro") == "1"
        and fixture_device_quarantined.get("observation", {}).get("fields", {}).get("blockdev_ro") == "1"
        and initramfs_target_write.get("status") == "PASS"
        and init_write.get("status") == "PASS"
    )
    first_action_ordered = first_action_offsets_ordered and first_action_evidence_valid
    initial_device_count = (
        initial_quarantine.get("observation", {}).get("fields", {}).get("devices")
    )
    lifecycle_ordered = bool(
        len(multi_user_events) == 1
        and all(value is not None for value in initramfs_offsets + persistence_offsets)
        and initramfs_offsets[0] < initramfs_offsets[1]
        and initramfs_offsets[1] < persistence_offsets[0]
        and persistence_offsets == sorted(persistence_offsets)
        and persistence_offsets[-1] < multi_user_events[0]["offset"]
        and multi_user_events[0]["offset"] <= (qmp_add_start_serial_offset or -1)
    )
    phases = {
        "initramfs_quarantine": init_quarantine,
        "initial_quarantine": initial_quarantine,
        "kernel_vda_registration": kernel_vda_registration,
        "fixture_device_quarantined": fixture_device_quarantined,
        "initramfs_enforcement": init_enforcement,
        "initramfs_write_probe": init_write,
        "initramfs_kernel_log": {
            "status": kernel_log_status,
            "events": initramfs_kernel_log,
            "required_phases": ["before_probe", "after_probe"],
            "observed_phases": sorted(kernel_log_phases),
            "ordered_around_probe": kernel_ordered_around_probe,
            "probe_syscall_offsets": initramfs_probe_offsets,
        },
        "persistence": persistence,
        "hotplug": {
            "qmp_attach": qmp_attach,
            "kernel_discovery": hotplug_device,
            "helper_started": hotplug_helper_started,
            "udev_rule": hotplug_udev_rule,
            "helper_completed": hotplug_helper_completed,
            "read_only_state": hotplug_ro,
            "enforcement": hotplug_enforcement,
            "write_probe": hotplug_write,
            "quarantine_event": hotplug_quarantine,
            "chain_ordered": chain_ordered,
            "chain_event_offsets": chain_offsets,
        },
        "lifecycle_ordering": {
            "ordered": lifecycle_ordered,
            "initramfs_event_offsets": initramfs_offsets,
            "persistence_event_offsets": persistence_offsets,
            "multi_user_event_offsets": [event["offset"] for event in multi_user_events],
            "qmp_add_start_serial_offset": qmp_add_start_serial_offset,
            "qmp_add_response_serial_offset": qmp_add_response_serial_offset,
        },
        "first_action_ordering": {
            "ordered": first_action_ordered,
            "offsets_ordered": first_action_offsets_ordered,
            "evidence_valid": first_action_evidence_valid,
            "pre_registration_quarantine": {
                "status": "NOT_OBSERVED",
                "reason": (
                    "initial_marker_observed_with_zero_devices"
                    if initial_device_count == "0"
                    else "no_device_identity_bound_quarantine_before_kernel_registration"
                ),
            },
            "fixture_device_quarantine_timing": "after_kernel_registration",
            "events": [
                "initial_quarantine_marker", "kernel_vda_registration",
                "fixture_device_quarantined_after_registration", "target_write",
            ],
            "event_offsets": first_action_offsets,
            "claim": (
                f"initial marker device count={initial_device_count or 'NOT_OBSERVED'}; "
                "the fixture device was quarantined only after kernel registration, "
                "before the target write probe; pre-registration device quarantine "
                "was not observed"
            ),
        },
    }
    statuses = [
        init_quarantine["status"], initial_quarantine["status"], kernel_vda_registration["status"],
        fixture_device_quarantined["status"], initramfs_target_write["status"],
        init_write["status"], init_enforcement["status"], kernel_log_status,
    ]
    statuses.extend(value["status"] for value in persistence.values())
    statuses.extend((
        qmp_attach["status"], hotplug_device["status"],
        hotplug_helper_started["status"], hotplug_helper_completed["status"],
        hotplug_udev_rule["status"],
        hotplug_ro["status"], hotplug_write["status"], hotplug_quarantine["status"],
        hotplug_enforcement["status"],
    ))
    return {
        "schema": "azazel-c5-runtime-evidence@1",
        "verdict": "pass" if all(value == "PASS" for value in statuses) and chain_ordered and lifecycle_ordered and first_action_ordered else "fail",
        "phases": phases,
        "records": records,
    }


def _kernel_vda_registration(serial_text: str) -> dict[str, Any]:
    """Observe the fixture disk's kernel registration line without inferring it."""
    clean = clean_serial(serial_text)
    matches = []
    offset = 0
    for raw_line in clean.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n").strip()
        match = KERNEL_VDA_LINE.match(line)
        if match:
            matches.append({
                "offset": offset + len(raw_line) - len(raw_line.lstrip()),
                "line": line,
                "guest_uptime_seconds": float(match.group("uptime")),
                "clock_domain": "guest_kernel_uptime_seconds",
            })
        offset += len(raw_line)
    if len(matches) != 1:
        return {
            "status": "NOT_OBSERVED" if not matches else "FAIL",
            "reason": "kernel_vda_registration_line_missing" if not matches else "duplicate_kernel_vda_registration_lines",
            "matching_kernel_lines": matches,
        }
    return {
        "status": "PASS",
        "observation": matches[0],
        "serial_offset_clock_domain": "host_serial_log_character_offset",
    }


def _kernel_vdb_discovery(serial_text: str) -> dict[str, Any]:
    clean = clean_serial(serial_text)
    offset = 0
    matches = []
    for raw_line in clean.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n").strip()
        match = KERNEL_VDB_LINE.match(line)
        if match:
            matches.append({
                "offset": offset + len(raw_line) - len(raw_line.lstrip()),
                "line": line,
                "guest_uptime_seconds": float(match.group("uptime")),
                "clock_domain": "guest_kernel_uptime_seconds",
            })
        offset += len(raw_line)
    if not matches:
        return {"status": "NOT_OBSERVED", "reason": "kernel_vdb_registration_line_missing"}
    # The first matching kernel line is the observed registration point; retain
    # all matches so later activity cannot be mistaken for the initial discovery.
    return {
        "status": "PASS",
        "observation": matches[0],
        "matching_kernel_lines": matches,
        "serial_offset_clock_domain": "host_serial_log_character_offset",
    }


def _field_passed(value: str | None) -> bool:
    return value in {"1", "true", "yes", "present", "PASS", "completed"}


def _ro_evidence_observation(
    records: list[dict[str, Any]], stage: str, target: str,
    required_phases: tuple[str, ...],
) -> dict[str, Any]:
    observations = {
        phase: _phase_ro_observation(records, phase, stage, target)
        for phase in required_phases
    }
    offsets = [
        observations[phase].get("observation", {}).get("offset")
        for phase in required_phases
    ]
    ordered = all(isinstance(value, int) for value in offsets) and offsets == sorted(offsets)
    missing = any(item["status"] == "NOT_OBSERVED" for item in observations.values())
    passed = all(item["status"] == "PASS" for item in observations.values()) and ordered
    return {
        "status": "PASS" if passed else "NOT_OBSERVED" if missing else "FAIL",
        "reason": None if passed else (
            "required_read_only_phase_missing" if missing else
            "read_only_phase_duplicate_or_not_confirmed"
            if not all(item["status"] == "PASS" for item in observations.values()) else
            "read_only_phases_out_of_order"
        ),
        "stage": stage,
        "target": target,
        "required_phases": list(required_phases),
        "phases": observations,
        "phase_offsets": offsets,
        "ordered": ordered,
    }


def _phase_ro_observation(
    records: list[dict[str, Any]], phase: str, stage: str, target: str,
) -> dict[str, Any]:
    matches = [
        record for record in records
        if record["fields"].get("phase") == phase
        and record["fields"].get("stage") == stage
        and record["fields"].get("target") == target
        and any(key in record["fields"] for key in (
            "sysfs_ro", "blockdev_ro", "sysfs_ro_after", "blockdev_ro_after",
        ))
    ]
    if not matches:
        return {"status": "NOT_OBSERVED", "reason": "missing", "observations": []}
    if len(matches) != 1:
        return {"status": "FAIL", "reason": "duplicate", "observations": matches}
    record = matches[0]
    fields = record["fields"]
    # Runtime records may report only the state transition's post-state. Never
    # infer quarantine from the pre-state; only the explicit `*_after` values
    # can fill a missing steady-state field.
    sysfs_ro = fields.get("sysfs_ro", fields.get("sysfs_ro_after", "NOT_OBSERVED"))
    blockdev_ro = fields.get("blockdev_ro", fields.get("blockdev_ro_after", "NOT_OBSERVED"))
    passed = (
        record["valid"] and fields.get("status") == "PASS"
        and sysfs_ro == "1" and blockdev_ro == "1"
    )
    return {
        "status": "PASS" if passed else "FAIL",
        "reason": None if passed else "read_only_state_not_confirmed",
        "sysfs_ro": sysfs_ro,
        "blockdev_ro": blockdev_ro,
        "observation": record,
    }


def _stage_enforcement_evidence(
    phase_records: list[dict[str, Any]],
    enforcement_records: list[dict[str, Any]],
    syscall_records: list[dict[str, Any]],
    stage: str,
    target: str,
    *, structured_probe_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Require successful BLKROSET, post-enforcement RO, denied probe, and post-state."""
    enforce = _phase_observation(phase_records, "enforce_ioctl", stage, target=target)
    post_ro = _phase_observation(phase_records, "post_ro", stage, target=target)
    post_probe_candidates = [
        phase for phase in ("post_probe", "target_write")
        if any(
            record["fields"].get("phase") == phase
            and record["fields"].get("stage") == stage
            and record["fields"].get("target") == target
            for record in phase_records
        )
    ]
    if len(post_probe_candidates) == 1:
        post_probe = _phase_observation(
            phase_records, post_probe_candidates[0], stage, target=target
        )
    elif not post_probe_candidates:
        post_probe = {"status": "NOT_OBSERVED", "reason": "missing"}
    else:
        post_probe = {"status": "FAIL", "reason": "duplicate_or_ambiguous_phase"}

    ioctl_fields = enforce.get("observation", {}).get("fields", {})
    raw_ioctl_records = [
        record for record in enforcement_records
        if record["fields"].get("stage") == stage
        and record["fields"].get("target") == target
    ]
    raw_ioctl_record = raw_ioctl_records[0] if len(raw_ioctl_records) == 1 else None
    raw_ioctl_fields = raw_ioctl_record["fields"] if raw_ioctl_record else {}
    raw_ioctl = raw_ioctl_fields.get("raw_syscall", "")
    if stage == "hotplug":
        # udev's sandbox can deny ptrace, so hotplug has a distinct structured
        # evidence contract. It proves the exact fixture target and an observed
        # RO transition; all other stages continue to require raw BLKROSET.
        ioctl_match = None
        ioctl_path = None
        ioctl_is_success = bool(
            target == "/dev/vdb"
            and enforce["status"] == "PASS"
            and enforce.get("observation", {}).get("valid") is True
            and ioctl_fields.get("target") == "/dev/vdb"
            and ioctl_fields.get("method") == "blockdev-setro"
            and ioctl_fields.get("command_return") == "0"
            and ioctl_fields.get("sysfs_ro_before") == "0"
            and ioctl_fields.get("blockdev_ro_before") == "0"
            and ioctl_fields.get("sysfs_ro_after") == "1"
            and ioctl_fields.get("blockdev_ro_after") == "1"
        )
        raw_ioctl_record = None
        raw_ioctl_fields = {}
        raw_ioctl = ""
    else:
        ioctl_match = re.match(
            r"ioctl\(\d+<(?P<annotation>/[^,]*?)>,\s*BLKROSET\b.*\)\s+=\s+0(?:\s|$)",
            raw_ioctl,
        )
        ioctl_path = (
            _strace_annotated_fd_path(ioctl_match.group("annotation"))
            if ioctl_match is not None else None
        )
        ioctl_is_success = bool(
            enforce["status"] == "PASS"
            and ioctl_fields.get("syscall") == "ioctl"
            and ioctl_fields.get("result") == "0"
            and ioctl_fields.get("errno") in {"0", "NOT_OBSERVED"}
            and ioctl_fields.get("command_return") in {None, "0"}
            and len(raw_ioctl_records) == 1
            and raw_ioctl_record["valid"]
            and raw_ioctl_fields.get("syscall") == "ioctl"
            and raw_ioctl_fields.get("result") == "0"
            and raw_ioctl_fields.get("errno") == 0
            and ioctl_match is not None
            and ioctl_path == target
            and raw_ioctl_fields.get("target_attributed") is True
            and _observation_offset(enforce) > raw_ioctl_record.get("offset", -1)
        )
    enforce["status"] = "PASS" if ioctl_is_success else (
        "NOT_OBSERVED" if enforce["status"] == "NOT_OBSERVED" else "FAIL"
    )
    enforce["reason"] = None if ioctl_is_success else "successful_target_blkroset_not_proven"

    def post_state(observation: dict[str, Any]) -> bool:
        fields = observation.get("observation", {}).get("fields", {})
        return bool(
            observation.get("status") == "PASS"
            and fields.get("sysfs_ro_after", fields.get("sysfs_ro")) == "1"
            and fields.get("blockdev_ro_after", fields.get("blockdev_ro")) == "1"
        )

    for observation in (post_ro, post_probe):
        state_ok = post_state(observation)
        if observation.get("status") == "PASS" and not state_ok:
            observation.update(status="FAIL", reason="post_enforcement_ro_state_not_confirmed")

    probe_source = structured_probe_records if stage == "hotplug" else syscall_records
    writes = [
        record for record in (probe_source or [])
        if record["fields"].get("stage") == stage
        and record["fields"].get("target") == target
    ]
    ro_evidence = {
        "status": "PASS" if post_ro.get("status") == "PASS" and post_state(post_ro) else post_ro.get("status"),
        "stage": stage,
        "target": target,
        "phase_offsets": [_observation_offset(enforce), _observation_offset(post_ro)],
    }
    probe = _write_probe_observation(writes, ro_evidence)
    enforce_offset = _observation_offset(enforce)
    post_ro_offset = _observation_offset(post_ro)
    probe_offsets = [
        item.get("offset")
        for item in probe.get("syscalls", [])
        if item.get("syscall") in {
            "open", "openat", "openat2", "creat",
            "write", "pwrite", "pwrite64", "writev", "pwritev",
        }
        and item.get("target_attributed")
    ]
    post_probe_offset = _observation_offset(post_probe)
    hotplug_gate = _phase_observation(
        phase_records, "target_write_started", "hotplug", target="/dev/vdb"
    ) if stage == "hotplug" else None
    hotplug_gate_fields = (
        hotplug_gate.get("observation", {}).get("fields", {})
        if hotplug_gate is not None else {}
    )
    hotplug_gate_offset = _observation_offset(hotplug_gate) if hotplug_gate else None
    hotplug_probe = writes[0] if len(writes) == 1 else None
    hotplug_probe_fields = hotplug_probe["fields"] if hotplug_probe else {}
    hotplug_probe_offset = hotplug_probe.get("offset") if hotplug_probe else None
    hotplug_probe_exact = bool(
        stage != "hotplug" or (
            target == "/dev/vdb"
            and len(writes) == 1
            and hotplug_probe is not None
            and hotplug_probe["valid"]
            and hotplug_probe_fields.get("target") == "/dev/vdb"
            and hotplug_probe_fields.get("stage") == "hotplug"
            and hotplug_probe_fields.get("syscall") in {"write", "open"}
            and hotplug_probe_fields.get("result") == "-1"
            and hotplug_probe_fields.get("errno_name") in READ_ONLY_WRITE_DENIAL_ERRNOS
            and hotplug_probe_fields.get("errno") == str(
                getattr(errno, hotplug_probe_fields.get("errno_name", ""), -1)
            )
        )
    )
    hotplug_gate_valid = bool(
        stage != "hotplug" or (
            hotplug_gate is not None
            and hotplug_gate.get("status") == "PASS"
            and hotplug_gate.get("observation", {}).get("valid") is True
            and hotplug_gate_fields.get("mount_state") == "not_mounted"
            and hotplug_gate_fields.get("sysfs_ro_before") == "1"
            and hotplug_gate_fields.get("blockdev_ro_before") == "1"
            and hotplug_gate_fields.get("mechanism_supported") == "PASS"
            and hotplug_gate_fields.get("fixture_disk_serial") == HOTPLUG_DEVICE_SERIAL
            and hotplug_gate_fields.get("dmi_manufacturer") == QEMU_SMBIOS_MANUFACTURER
            and hotplug_gate_fields.get("dmi_product_hex") == "417a617a656c2043352046696c652046697874757265"
        )
    )
    ordered = bool(
        enforce_offset is not None and post_ro_offset is not None
        and enforce_offset < post_ro_offset
        and probe_offsets and all(post_ro_offset < value < (post_probe_offset or -1) for value in probe_offsets)
        and post_probe_offset is not None
        and (
            stage != "hotplug" or (
                hotplug_gate_valid
                and hotplug_gate_offset is not None
                and post_ro_offset < hotplug_gate_offset
                and hotplug_gate_offset < (hotplug_probe_offset or -1)
                and (hotplug_probe_offset or -1) < (post_probe_offset or -1)
            )
        )
    )
    good = bool(
        ioctl_is_success and post_ro.get("status") == "PASS"
        and post_probe.get("status") == "PASS" and post_state(post_ro)
        and post_state(post_probe) and probe.get("status") == "PASS" and ordered
        and hotplug_probe_exact and hotplug_gate_valid
    )
    return {
        "status": "PASS" if good else "FAIL",
        "stage": stage,
        "target": target,
        "enforce_ioctl": enforce,
        "enforce_syscall": raw_ioctl_record,
        "raw_ioctl_trace": raw_ioctl or None,
        "raw_ioctl_status": ({
            "syscall": raw_ioctl_fields.get("syscall"),
            "result": raw_ioctl_fields.get("result"),
            "errno": raw_ioctl_fields.get("errno"),
            "errno_name": raw_ioctl_fields.get("errno_name"),
            "target_attributed": raw_ioctl_fields.get("target_attributed", False),
            "target_attribution": raw_ioctl_fields.get("target_attribution"),
        } if raw_ioctl_record is not None else None),
        "raw_ioctl_evidence": [
            {
                "trace": record["fields"].get("raw_syscall"),
                "status": {
                    "syscall": record["fields"].get("syscall"),
                    "result": record["fields"].get("result"),
                    "errno": record["fields"].get("errno"),
                    "errno_name": record["fields"].get("errno_name"),
                    "target_attributed": record["fields"].get("target_attributed", False),
                    "target_attribution": record["fields"].get("target_attribution"),
                },
                "valid": record["valid"],
                "offset": record.get("offset"),
            }
            for record in raw_ioctl_records
        ],
        "post_ro": post_ro,
        "write_probe": probe,
        "post_probe": post_probe,
        "write_probe_record": hotplug_probe if stage == "hotplug" else None,
        "write_probe_gate": hotplug_gate if stage == "hotplug" else None,
        "write_probe_exact_contract": hotplug_probe_exact if stage == "hotplug" else None,
        "ordered": ordered,
        "ordering_offsets": [enforce_offset, post_ro_offset, *probe_offsets, post_probe_offset],
    }


def _strace_target_attribution(raw_syscall: str, target: str) -> tuple[bool, str]:
    """Require an explicit path or strace -yy fd annotation for target identity."""
    open_call = re.match(r"(?:open|openat|openat2|creat)\(.*", raw_syscall)
    if open_call:
        path_match = re.search(r'(?<!\\)"((?:\\.|[^"\\])*)"', raw_syscall)
        if path_match:
            path = bytes(path_match.group(1), "utf-8").decode("unicode_escape")
            return (path == target, "path_argument_matches" if path == target else "path_argument_mismatch")
    write_match = re.match(
        r"(?:write|pwrite|pwrite64|writev|pwritev)\((\d+)(?:<(/[^,]*?)>)?,",
        raw_syscall,
    )
    if write_match:
        annotation = write_match.group(2)
        if annotation is None:
            return False, "fd_path_annotation_missing"
        annotated_path = _strace_annotated_fd_path(annotation)
        if annotated_path is None:
            return False, "fd_path_annotation_malformed"
        return (
            annotated_path == target,
            "fd_path_annotation_matches" if annotated_path == target else "fd_path_annotation_mismatch",
        )
    ioctl_match = re.match(r"ioctl\((\d+)<(/[^,]*?)>,\s*BLKROSET\b", raw_syscall)
    if ioctl_match:
        annotated_path = _strace_annotated_fd_path(ioctl_match.group(2))
        if annotated_path is None:
            return False, "ioctl_fd_path_annotation_malformed"
        return (
            annotated_path == target,
            "ioctl_fd_path_matches" if annotated_path == target else "ioctl_fd_path_mismatch",
        )
    return False, "syscall_does_not_identify_target_path"


def _strace_annotated_fd_path(annotation: str) -> str | None:
    """Return an exact fd path, optionally followed by strace's block identity."""
    match = re.fullmatch(r"(?P<path>/[^<>]+)(?:<block [0-9]+:[0-9]+>)?", annotation)
    return match.group("path") if match else None


def parse_qemu_block_write_trace(
    trace_text: str, fixture_paths: tuple[str, ...],
) -> dict[str, Any]:
    """Require trace initialization on each fixture and no QEMU write request."""
    lines = [line for line in trace_text.splitlines() if line.strip()]
    write_lines = {
        event: [line for line in lines if line.split(None, 1)[0] == event]
        for event in QEMU_BLOCK_TRACE_EVENTS[1:]
    }
    opened_paths = {
        path: [
            line for line in lines
            if line.startswith("bdrv_open_common ") and f'filename "{path}"' in line
        ]
        for path in fixture_paths
    }
    target_trace_initialized = bool(lines) and all(opened_paths.values())
    write_counts = {event: len(matches) for event, matches in write_lines.items()}
    write_records = [line for matches in write_lines.values() for line in matches]
    if not target_trace_initialized:
        status, reason = "NOT_OBSERVED", "trace_or_fixture_backend_open_missing"
    elif write_records:
        status, reason = "FAIL", "qemu_block_write_request_observed"
    else:
        status, reason = "PASS", None
    return {
        "status": status,
        "reason": reason,
        "trace_initialized": bool(lines),
        "fixture_backend_open_counts": {
            path: len(matches) for path, matches in opened_paths.items()
        },
        "write_event_counts": write_counts,
        "write_records": write_records,
        "fixture_paths": list(fixture_paths),
        "trace_events": list(QEMU_BLOCK_TRACE_EVENTS),
        "scope": (
            "Monitors only the QEMU tracepoints listed in trace_events; this build exposes "
            "blk_co_pwritev, bdrv_co_pwritev_part, bdrv_co_pwrite_zeroes, and "
            "virtio_blk_handle_write for write/write-zeroes paths, with no block discard "
            "tracepoint found. This is not comprehensive host-I/O evidence."
        ),
    }


def _write_probe_observation(
    records: list[dict[str, Any]], ro_evidence: dict[str, Any]
) -> dict[str, Any]:
    if not records:
        return {
            "status": "NOT_OBSERVED",
            "reason": "missing",
            "observations": records,
        }
    if any(not record["valid"] for record in records):
        return {
            "status": "NOT_OBSERVED",
            "reason": "unparsed_or_incomplete_strace_record",
            "observations": records,
        }
    syscall_evidence = []
    for record in records:
        fields = record["fields"]
        try:
            syscall_result = int(fields.get("result", ""))
            errno_number = int(fields.get("errno", ""))
        except (TypeError, ValueError):
            return {
                "status": "NOT_OBSERVED",
                "classification": "syscall_result_unparsed",
                "syscall_outcome": "NOT_OBSERVED",
                "ro_evidence": ro_evidence,
                "observations": records,
            }
        raw_syscall = record.get("raw_syscall")
        if raw_syscall is not None:
            attributed, attribution_reason = _strace_target_attribution(
                raw_syscall, fields.get("target", "")
            )
        else:
            attributed = fields.get("target") == ro_evidence.get("target")
            attribution_reason = "structured_target_matches" if attributed else "structured_target_mismatch"
        syscall_evidence.append({
            "syscall": fields.get("syscall"),
            "result": syscall_result,
            "errno": errno_number,
            "errno_name": fields.get("errno_name"),
            "raw_syscall": raw_syscall,
            "target_attributed": attributed,
            "target_attribution": attribution_reason,
            "stage": fields.get("stage"),
            "offset": record.get("offset"),
        })

    if not syscall_evidence:
        return {
            "status": "NOT_OBSERVED",
            "classification": "no_target_syscall_observed",
            "syscall_outcome": "NOT_OBSERVED",
            "ro_evidence": ro_evidence,
            "observations": records,
        }
    write_names = {"write", "pwrite", "pwrite64", "writev", "pwritev"}
    open_names = {"open", "openat", "openat2", "creat"}
    probe_names = write_names | open_names
    attributed_writes = [
        item for item in syscall_evidence
        if item["target_attributed"] and item["syscall"] in write_names
    ]
    attributed_opens = [
        item for item in syscall_evidence
        if item["target_attributed"] and item["syscall"] in open_names
    ]
    attributed_probe_calls = attributed_writes + attributed_opens
    prerequisite_offsets = ro_evidence.get("phase_offsets", [])
    ro_last_offset = max(prerequisite_offsets) if prerequisite_offsets and all(
        isinstance(value, int) for value in prerequisite_offsets
    ) else None
    same_stage_ordered = bool(
        ro_evidence.get("status") == "PASS"
        and ro_evidence.get("stage") == (syscall_evidence[0].get("stage") if syscall_evidence else None)
        and ro_last_offset is not None
        and attributed_probe_calls
        and all(isinstance(item.get("offset"), int) and item["offset"] > ro_last_offset for item in attributed_probe_calls)
    )
    ro_verified = ro_evidence["status"] == "PASS" and same_stage_ordered
    if any(item["result"] >= 0 for item in attributed_writes):
        outcome = "write_succeeded"
    elif any(not item["target_attributed"] and item["syscall"] in probe_names for item in syscall_evidence):
        outcome = "target_write_identity_unverified"
    elif attributed_writes and all(
        item["result"] == -1 and item["errno_name"] in READ_ONLY_WRITE_DENIAL_ERRNOS
        for item in attributed_writes
    ):
        outcome = "write_denied_by_read_only_policy"
    elif attributed_writes:
        outcome = "write_failed_causality_unproven"
    elif attributed_opens and attributed_opens[-1]["result"] == -1:
        failed_open = attributed_opens[-1]
        outcome = (
            "open_denied_by_read_only_policy"
            if failed_open["errno_name"] in READ_ONLY_OPEN_DENIAL_ERRNOS
            else "open_failed_causality_unproven"
        )
    elif attributed_opens and attributed_opens[-1]["result"] >= 0:
        outcome = "open_succeeded_without_write_observed"
    else:
        outcome = "target_write_identity_unverified"
    if not ro_verified:
        classification = (
            "ro_evidence_missing" if ro_evidence["status"] == "NOT_OBSERVED"
            else "ro_evidence_failed"
        )
    else:
        classification = outcome
    passed = outcome in {"write_denied_by_read_only_policy", "open_denied_by_read_only_policy"} and ro_verified
    return {
        "status": "PASS" if passed else "FAIL",
        "classification": classification,
        "syscall_outcome": outcome,
        "quarantine_causality": "SUPPORTED_BY_MEASURED_READ_ONLY_STATE" if passed else "UNPROVEN",
        "syscalls": syscall_evidence,
        "ro_evidence": ro_evidence,
        "same_stage_correlation": {
            "status": "PASS" if same_stage_ordered else "FAIL",
            "stage": ro_evidence.get("stage"),
            "required_ro_offset": ro_last_offset,
            "probe_offsets": [item.get("offset") for item in syscall_evidence if item["target_attributed"] and item["syscall"] in probe_names],
            "write_offsets": [item.get("offset") for item in attributed_writes],
        },
        "reason": None if passed else "write_denial_and_same_stage_ordering_not_proven",
        "observations": records,
    }


def _userspace_write_probe_observation(
    phase_observation: dict[str, Any], syscall_records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Bind the phase summary to exact target open/write syscalls and state."""
    phase_record = phase_observation.get("observation")
    phase_fields = phase_record.get("fields", {}) if isinstance(phase_record, dict) else {}
    probe_calls = []
    for record in syscall_records:
        fields = record["fields"]
        raw = record.get("raw_syscall", "")
        parsed = _parse_strace_syscall(raw)
        attributed, reason = _strace_target_attribution(raw, "/dev/vda")
        if parsed is None:
            continue
        item = {
            **parsed,
            "result": int(parsed["result"]),
            "raw_syscall": raw,
            "target_attributed": attributed,
            "target_attribution": reason,
            "stage": fields.get("stage"),
            "record_valid": record["valid"],
            "offset": record.get("offset"),
        }
        if parsed["syscall"] in {"open", "openat", "openat2", "creat", "write", "pwrite", "pwrite64", "writev", "pwritev"}:
            probe_calls.append(item)

    writes = [item for item in probe_calls if item["syscall"] in {"write", "pwrite", "pwrite64", "writev", "pwritev"}]
    try:
        expected_write_count = int(phase_fields.get("syscall_count", ""))
        expected_target_count = int(phase_fields.get("target_syscall_count", ""))
        probe_exit = int(phase_fields.get("probe_exit", ""))
    except (TypeError, ValueError):
        expected_write_count = -1
        expected_target_count = -1
        probe_exit = 0
    phase_offset = phase_record.get("offset") if isinstance(phase_record, dict) else None
    ordered = bool(
        isinstance(phase_offset, int)
        and probe_calls
        and all(isinstance(item.get("offset"), int) and item["offset"] < phase_offset for item in probe_calls)
    )
    deny_calls = [
        item for item in probe_calls
        if item["record_valid"] and item["target_attributed"] and item["result"] == -1
        and item["errno"] > 0 and item["errno_name"] in READ_ONLY_WRITE_DENIAL_ERRNOS
    ]
    generic_failures = [
        item for item in probe_calls
        if item["record_valid"] and item["target_attributed"] and item["result"] == -1
        and (item["errno"] <= 0 or item["errno_name"] not in READ_ONLY_WRITE_DENIAL_ERRNOS)
    ]
    if any(item["result"] >= 0 for item in writes):
        outcome = "write_succeeded"
    elif generic_failures:
        outcome = "write_or_open_failed_causality_unproven"
    elif len(deny_calls) == 1 and deny_calls[0]["syscall"] in {"open", "openat", "openat2", "creat"} and not writes:
        outcome = "open_denied_by_read_only_policy"
    elif len(deny_calls) == 1 and deny_calls[0]["syscall"] in {"write", "pwrite", "pwrite64", "writev", "pwritev"}:
        outcome = "write_denied_by_read_only_policy"
    else:
        outcome = "denial_not_uniquely_observed"
    state_verified = bool(
        phase_fields.get("status") == "PASS"
        and phase_fields.get("observation") in {
            "target_write_denied_by_read_only_policy",
            "target_open_denied_by_read_only_policy",
        }
        and phase_fields.get("sysfs_ro_before") == "1"
        and phase_fields.get("blockdev_ro_before") == "1"
        and phase_fields.get("sysfs_ro_after") == "1"
        and phase_fields.get("blockdev_ro_after") == "1"
        and phase_fields.get("mount_state_after") == "not_mounted"
        and phase_fields.get("target") == "/dev/vda"
        and phase_fields.get("path") == "/dev/vda"
    )
    passed = bool(
        phase_observation.get("status") == "PASS"
        and state_verified
        and probe_exit != 0
        and expected_write_count == len(writes)
        and expected_target_count == len(probe_calls)
        and len(deny_calls) == 1
        and outcome in {"open_denied_by_read_only_policy", "write_denied_by_read_only_policy"}
        and phase_fields.get("observation") == (
            "target_open_denied_by_read_only_policy"
            if outcome == "open_denied_by_read_only_policy"
            else "target_write_denied_by_read_only_policy"
        )
        and ordered
    )
    return {
        "status": "PASS" if passed else "FAIL" if phase_observation.get("status") != "NOT_OBSERVED" else "NOT_OBSERVED",
        "reason": None if passed else "userspace_phase_not_bound_to_single_denied_target_write",
        "syscall_outcome": outcome,
        "quarantine_causality": "SUPPORTED_BY_MEASURED_READ_ONLY_STATE" if passed else "UNPROVEN",
        "observation": phase_record,
        "syscall_count_reported": expected_write_count,
        "target_syscall_count_reported": expected_target_count,
        "probe_exit": probe_exit,
        "read_only_state_verified": state_verified,
        "syscalls": writes,
        "probe_syscalls": probe_calls,
        "ordered_before_summary": ordered,
        "observations": syscall_records,
    }


def _observation_offset(observation: dict[str, Any]) -> int | None:
    record = observation.get("observation")
    if isinstance(record, dict):
        return record.get("offset")
    records = observation.get("observations")
    if isinstance(records, list) and records and all(
        isinstance(item, dict) and isinstance(item.get("offset"), int) for item in records
    ):
        # A probe can span open()+write(); its observation point is the final
        # syscall record, not merely the successful open preceding it.
        return records[-1]["offset"]
    return None


def hotplug_device_arguments() -> dict[str, str]:
    return {
        "driver": "virtio-blk-pci",
        "drive": "c5hotplug_file",
        "id": "c5hotplug",
        "serial": HOTPLUG_DEVICE_SERIAL,
        "bus": HOTPLUG_BUS,
        "addr": "0x0",
    }


def cold_boot_fixture_attached(command: list[str], fixture: Path) -> bool:
    """Require the file-backed vda to be wired before guest kernel startup."""

    try:
        kernel_index = command.index("-kernel")
    except ValueError:
        return False
    drives = [
        (index, command[index + 1])
        for index, item in enumerate(command[:-1])
        if item == "-drive"
    ]
    devices = [
        (index, command[index + 1])
        for index, item in enumerate(command[:-1])
        if item == "-device"
    ]
    return bool(
        any(index < kernel_index and f"file={fixture},format=raw" in drive for index, drive in drives)
        and any(index < kernel_index and "serial=azc5-vda" in device for index, device in devices)
    )


def _line_offsets(serial_text: str, expected: str | re.Pattern[str]) -> list[dict[str, Any]]:
    found = []
    offset = 0
    for line in serial_text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        if (expected.search(content) if isinstance(expected, re.Pattern) else content == expected):
            found.append({"offset": offset + len(line) - len(line.lstrip()), "line": content.strip()})
        offset += len(line)
    return found


def parse_c5_events(serial_text: str) -> dict[str, list[dict[str, Any]]]:
    """Return legacy or current structured C5 lifecycle events and offsets."""
    clean = clean_serial(serial_text)
    legacy = {
        "initramfs_quarantine": _line_offsets(
            clean,
            re.compile(
                r"^AZAZEL_C5_INITRAMFS_QUARANTINE state=active "
                r"devices=[1-9][0-9]* udev_rule=present$"
            ),
        ),
        "fixture_initramfs": _line_offsets(
            clean, re.compile(
                r"^AZAZEL_C5_FIXTURE_INITRAMFS target=/dev/vda sysfs_ro=1 "
                r"blockdev_ro=1(?: write_errno=\S+)?$"
            )
        ),
        "userspace_persistence": _line_offsets(
            clean, re.compile(
                r"^AZAZEL_C5_USERSPACE_PERSISTENCE target=/dev/vda sysfs_ro=1 "
                r"blockdev_ro=1(?: write_errno=\S+)?$"
            )
        ),
        "multi_user": _line_offsets(clean, MULTI_USER_TARGET),
        "hotplug_quarantine": _line_offsets(
            clean, re.compile(r"^AZAZEL_C5_HOTPLUG_QUARANTINED target=/dev/vdb(?:\s|$)")
        ),
    }
    records = parse_structured_c5_records(clean)["phase"]

    def current_phase(
        phase: str, stage: str, *, target: str | None = None,
        require_read_only: bool = False,
    ) -> list[dict[str, Any]]:
        found = []
        for record in records:
            fields = record["fields"]
            if (
                not record["valid"]
                or fields.get("phase") != phase
                or fields.get("stage") != stage
                or fields.get("status") != "PASS"
                or (target is not None and fields.get("target") != target)
                or (
                    require_read_only
                    and (
                        fields.get("sysfs_ro", fields.get("sysfs_ro_after")) != "1"
                        or fields.get("blockdev_ro", fields.get("blockdev_ro_after")) != "1"
                    )
                )
            ):
                continue
            found.append({"offset": record["offset"], "line": record["line"]})
        return found

    structured = {
        "initramfs_quarantine": current_phase("initial_quarantine", "initramfs"),
        "fixture_initramfs": current_phase(
            "target_write", "initramfs", target="/dev/vda", require_read_only=True
        ),
        "userspace_persistence": current_phase(
            "handoff_valid", "userspace", target="/dev/vda", require_read_only=True
        ),
        "hotplug_quarantine": current_phase(
            "quarantine", "hotplug", target="/dev/vdb", require_read_only=True
        ),
    }
    phase_records = parse_structured_c5_records(clean)["phase"]

    def phase_seen(phase: str, stage: str, target: str | None = None) -> bool:
        return any(
            record["fields"].get("phase") == phase
            and record["fields"].get("stage") == stage
            and (target is None or record["fields"].get("target") == target)
            for record in phase_records
        )

    structured_phase_seen = {
        "initramfs_quarantine": phase_seen("initial_quarantine", "initramfs"),
        "fixture_initramfs": phase_seen("target_write", "initramfs", "/dev/vda"),
        "userspace_persistence": phase_seen("handoff_valid", "userspace", "/dev/vda"),
    }
    runtime = parse_runtime_c5_evidence(
        clean, qmp_hotplug_attached=False,
        qmp_add_start_serial_offset=None, qmp_add_response_serial_offset=None,
    )
    if runtime["phases"]["initramfs_write_probe"].get("status") != "PASS":
        structured["fixture_initramfs"] = []
    persistence = runtime["phases"]["persistence"]
    if (
        persistence.get("write_probe", {}).get("status") != "PASS"
        or persistence.get("handoff_valid", {}).get("status") != "PASS"
    ):
        structured["userspace_persistence"] = []
    # Prefer complete current phase records per event; continue accepting the
    # exact legacy markers for old fixtures and archived evidence.
    result = {
        key: structured[key] if structured[key] or structured_phase_seen.get(key, False) else legacy[key]
        for key in (
            "initramfs_quarantine", "fixture_initramfs", "userspace_persistence"
        )
    }
    result["multi_user"] = legacy["multi_user"]
    result["hotplug_quarantine"] = (
        structured["hotplug_quarantine"]
        if structured["hotplug_quarantine"] else legacy["hotplug_quarantine"]
    )
    return result


def c5_event_ordering(
    serial_text: str, hotplug_attach_serial_offset: int | None
) -> dict[str, Any]:
    """Require distinct ordered events, with hotplug after QMP attach and multi-user."""
    events = parse_c5_events(serial_text)
    counts = {key: len(value) for key, value in events.items()}
    initramfs = events["initramfs_quarantine"]
    fixture = events["fixture_initramfs"]
    persistence = events["userspace_persistence"]
    multi_user = events["multi_user"]
    hotplug = events["hotplug_quarantine"]
    ordered = bool(
        all(counts[key] == 1 for key in counts)
        and hotplug_attach_serial_offset is not None
        and initramfs[0]["offset"] < fixture[0]["offset"]
        and fixture[0]["offset"] < persistence[0]["offset"]
        and persistence[0]["offset"] < multi_user[0]["offset"]
        and multi_user[0]["offset"] <= hotplug_attach_serial_offset
        and hotplug_attach_serial_offset <= hotplug[0]["offset"]
    )
    return {
        "ordered": ordered,
        "event_counts": counts,
        "event_offsets": {
            name: values[0]["offset"] if len(values) == 1 else None
            for name, values in events.items()
        },
        "event_offset_unit": "serial_log_character_offset_after_ANSI_normalization",
        "qmp_hotplug_attach_serial_offset": hotplug_attach_serial_offset,
    }


def parse_guest_boot_state(serial_text: str) -> dict[str, bool | str | None]:
    reached = MULTI_USER_TARGET.search(clean_serial(serial_text)) is not None
    return {
        "reached_multi_user_target": reached,
        "state": "reached_multi_user_target" if reached else "not_observed",
    }


# Retained for existing source-level tests; the v2 runner never treats these
# legacy strings as evidence for its verdict.
_LEGACY_EVENT = re.compile(
    r"AZAZEL_C5_FIXTURE_RESULT target=/dev/vda sysfs_ro=(\d+) "
    r"blockdev_ro=(\d+) write_probe=([a-z_]+)"
)


def parse_fixture_event(serial_text: str) -> dict[str, str] | None:
    match = _LEGACY_EVENT.search(serial_text)
    if match is None:
        return None
    return {
        "sysfs_ro": match.group(1),
        "blockdev_ro": match.group(2),
        "write_probe": match.group(3),
        "line": match.group(0),
    }


def fixture_passes(
    event: dict[str, str] | None,
    persistence_marker: bool,
    fixture_digest_before: str,
    fixture_digest_after: str,
) -> bool:
    return bool(
        event
        and event["sysfs_ro"] == "1"
        and event["blockdev_ro"] == "1"
        and event["write_probe"] == "denied_read_only"
        and persistence_marker
        and fixture_digest_before == fixture_digest_after
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_c5_manifest_digest(build_result: dict[str, Any], manifest: Path) -> None:
    expected = f"sha256:{sha256(manifest)}"
    if build_result.get("c5_manifest_digest") != expected:
        raise ValueError("C5 manifest digest does not match the build result")


def c5_persistence_pending_runtime_evidence(
    c5_manifest: dict[str, Any], c5_result: dict[str, Any],
) -> bool:
    """Allow measurement to start only when persistence is explicitly unmeasured.

    Static inspection cannot establish runtime handoff persistence. A pending
    gate may proceed to QEMU only when that is the sole policy fault; the final
    fixture verdict still requires the userspace persistence probe to pass.
    """
    policy = c5_manifest.get("boot_image_policy_result", {})
    policy_faults = policy.get("faults", [])
    return bool(
        c5_manifest.get("runtime_persistence_evidence_required") is True
        and "quarantine_persists_into_userspace" in c5_manifest
        and c5_manifest.get("quarantine_persists_into_userspace") is None
        and c5_manifest.get("quarantine_persistence_declared_in_initramfs_and_rootfs") is True
        and policy.get("verdict") == "fail"
        and len(policy_faults) == 1
        and policy_faults[0].get("code") == "quarantine_not_persistent"
        and c5_result.get("verdict") == "pass"
        and c5_result.get("evaluator_faults") == []
        and c5_result.get("faults") == ["quarantine_not_persistent"]
        and c5_result.get("boot_image_policy_result") == policy
    )


def validate_build_binding(
    build_result: dict[str, Any], c5_manifest: dict[str, Any],
    c5_result: dict[str, Any], c5_result_digest: str,
    input_manifest_digest: str, payload_digest: str,
    kernel_digest: str, initramfs_digest: str,
) -> None:
    """Refuse to boot a mixed or stale payload/evidence set."""
    expected = {
        "build_input_manifest_digest": f"sha256:{input_manifest_digest}",
        "payload_digest": f"sha256:{payload_digest}",
        "kernel_digest": f"sha256:{kernel_digest}",
        "initramfs_digest": f"sha256:{initramfs_digest}",
    }
    mismatches = {
        key: {"expected": value, "actual": build_result.get(key)}
        for key, value in expected.items()
        if build_result.get(key) != value
    }
    if c5_manifest.get("build_input_manifest_digest") != expected["build_input_manifest_digest"]:
        mismatches["c5_manifest.build_input_manifest_digest"] = {
            "expected": expected["build_input_manifest_digest"],
            "actual": c5_manifest.get("build_input_manifest_digest"),
        }
    if c5_manifest.get("payload_digest") != expected["payload_digest"]:
        mismatches["c5_manifest.payload_digest"] = {
            "expected": expected["payload_digest"],
            "actual": c5_manifest.get("payload_digest"),
        }
    if c5_manifest.get("initramfs_digest") != expected["initramfs_digest"]:
        mismatches["c5_manifest.initramfs_digest"] = {
            "expected": expected["initramfs_digest"],
            "actual": c5_manifest.get("initramfs_digest"),
        }
    expected_c5_result_digest = f"sha256:{c5_result_digest}"
    if build_result.get("c5_result_digest") != expected_c5_result_digest:
        mismatches["build_result.c5_result_digest"] = {
            "expected": expected_c5_result_digest,
            "actual": build_result.get("c5_result_digest"),
        }
    pending_persistence = c5_persistence_pending_runtime_evidence(c5_manifest, c5_result)
    if (
        c5_result.get("verdict") != "pass"
        or (c5_result.get("faults") != [] and not pending_persistence)
    ):
        mismatches["c5_result.verdict"] = {
            "expected": {
                "verdict": "pass",
                "faults": [],
                "or_exact_pending_runtime_persistence_gate": pending_persistence,
            },
            "actual": {"verdict": c5_result.get("verdict"), "faults": c5_result.get("faults")},
        }
    if c5_manifest.get("order_established") is not True:
        mismatches["c5_manifest.order_established"] = {
            "expected": True, "actual": c5_manifest.get("order_established")
        }
    if c5_manifest.get("boot_image_policy_result", {}).get("verdict") != "pass" and not pending_persistence:
        mismatches["c5_manifest.boot_image_policy_result"] = {
            "expected": "pass or exact pending runtime persistence gate",
            "actual": c5_manifest.get("boot_image_policy_result", {}).get("verdict"),
        }
    if c5_manifest.get("quarantine_persistence_declared_in_initramfs_and_rootfs") is not True:
        mismatches["c5_manifest.quarantine_persistence_declared"] = {
            "expected": True,
            "actual": c5_manifest.get("quarantine_persistence_declared_in_initramfs_and_rootfs"),
        }
    if mismatches:
        raise ValueError(f"QEMU inputs do not match their build and C5 evidence: {mismatches}")


def create_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        block = bytes(range(256)) * 4096
        for _ in range(FIXTURE_SIZE // len(block)):
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"fixture is not a regular file: {path}")


class QMPClient:
    """Small fail-closed QMP client with bounded line and command waits."""

    def __init__(self, path: Path, timeout_seconds: float, log: list[dict[str, Any]]):
        self.path = path
        self.timeout_seconds = timeout_seconds
        self.log = log
        self.sock: socket.socket | None = None
        self.reader: Any = None
        self.next_id = 1
        self.started = time.monotonic()

    def connect(self) -> None:
        deadline = time.monotonic() + self.timeout_seconds
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            try:
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(min(1.0, self.timeout_seconds))
                connection.connect(str(self.path))
                self.sock = connection
                self.reader = connection.makefile("r", encoding="utf-8", newline="\n")
                greeting = self._read_message(deadline)
                if "QMP" not in greeting:
                    raise RuntimeError("QMP greeting missing")
                self.log.append(self._entry("greeting", greeting))
                self.execute("qmp_capabilities", {}, deadline=deadline)
                return
            except (OSError, TimeoutError) as exc:
                last_error = exc
                if self.sock is not None:
                    self.close()
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        raise TimeoutError(f"QMP socket did not become ready: {last_error}")

    def _entry(self, kind: str, data: Any) -> dict[str, Any]:
        return {"elapsed_seconds": round(time.monotonic() - self.started, 6), "kind": kind, "data": data}

    def _read_message(self, deadline: float) -> dict[str, Any]:
        if self.reader is None or self.sock is None:
            raise RuntimeError("QMP is not connected")
        while time.monotonic() < deadline:
            self.sock.settimeout(min(0.5, max(0.01, deadline - time.monotonic())))
            try:
                line = self.reader.readline()
            except socket.timeout:
                continue
            if not line:
                raise RuntimeError("QMP connection closed")
            try:
                return json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError("invalid JSON from QMP") from exc
        raise TimeoutError("QMP response timeout")

    def execute(
        self, execute: str, arguments: dict[str, Any], *, deadline: float | None = None
    ) -> dict[str, Any]:
        if self.sock is None:
            raise RuntimeError("QMP is not connected")
        end = deadline or time.monotonic() + self.timeout_seconds
        command_id = self.next_id
        self.next_id += 1
        command = {"execute": execute, "arguments": arguments, "id": command_id}
        self.log.append(self._entry("command", command))
        self.sock.sendall((json.dumps(command, separators=(",", ":")) + "\r\n").encode())
        while time.monotonic() < end:
            message = self._read_message(end)
            if "event" in message:
                self.log.append(self._entry("event", message))
                continue
            if message.get("id") != command_id:
                self.log.append(self._entry("unmatched_response", message))
                continue
            self.log.append(self._entry("response", message))
            if "error" in message:
                raise RuntimeError(f"QMP {execute} failed: {message['error']}")
            return message.get("return", {})
        raise TimeoutError(f"QMP command timed out: {execute}")

    def close(self) -> None:
        if self.reader is not None:
            self.reader.close()
            self.reader = None
        if self.sock is not None:
            self.sock.close()
            self.sock = None


def _read_serial(path: Path) -> str:
    return path.read_text(errors="replace") if path.exists() else ""


def _require_regular_input(path: Path, label: str) -> Path:
    """Reject symlinks, devices, FIFOs, and other non-regular QEMU inputs."""
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{label} is unavailable: {path}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(f"{label} must be a non-symlink regular file: {path}")
    return path.resolve(strict=True)


def _qemu_version(binary: str) -> str:
    result = subprocess.run(
        [binary, "--version"], check=True, capture_output=True, text=True, timeout=10
    )
    return result.stdout.splitlines()[0]


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run(args: argparse.Namespace) -> dict[str, Any]:
    output = args.output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError(f"evidence output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    payload = _require_regular_input(args.payload, "payload")
    kernel = _require_regular_input(args.kernel, "kernel")
    initramfs = _require_regular_input(args.initramfs, "initramfs")
    manifest = _require_regular_input(args.input_manifest, "input manifest")
    build_result_path = _require_regular_input(args.build_result, "build result")
    c5_manifest_path = _require_regular_input(args.c5_manifest, "C5 manifest")
    c5_result_path = _require_regular_input(args.c5_result, "C5 result")
    manifest_digest = sha256(manifest)
    sidecar = manifest.with_suffix(".sha256")
    if sidecar.read_text().split() != [manifest_digest, "build-input-manifest.json"]:
        raise ValueError("input manifest digest sidecar is invalid")
    build_result = json.loads(build_result_path.read_text())
    c5_manifest = json.loads(c5_manifest_path.read_text())
    c5_result = json.loads(c5_result_path.read_text())
    validate_c5_manifest_digest(build_result, c5_manifest_path)
    payload_digest = sha256(payload)
    kernel_digest = sha256(kernel)
    initramfs_digest = sha256(initramfs)
    validate_build_binding(
        build_result, c5_manifest, c5_result, sha256(c5_result_path),
        manifest_digest, payload_digest,
        kernel_digest, initramfs_digest,
    )

    fixture_a = output / "quarantine-fixture-vda.raw"
    fixture_b = output / "quarantine-fixture-vdb.raw"
    serial_log = output / "serial.log"
    qemu_stderr_log = output / "qemu-stderr.log"
    qemu_trace_log = output / "qemu-block-trace.log"
    qemu_trace_events = output / "qemu-block-trace-events.txt"
    qmp_log_path = output / "qmp-commands.json"
    result_path = output / "result.json"
    create_fixture(fixture_a)
    create_fixture(fixture_b)
    fixture_a_before = sha256(fixture_a)
    fixture_b_before = sha256(fixture_b)
    qemu_trace_events.write_text("\n".join(QEMU_BLOCK_TRACE_EVENTS) + "\n")

    qmp_log: list[dict[str, Any]] = []
    add_start_offset: int | None = None
    add_response_offset: int | None = None
    add_response_elapsed_seconds: float | None = None
    add_response_host_monotonic_seconds: float | None = None
    add_start_host_monotonic_seconds: float | None = None
    hotplug_attached = False
    qmp_error: str | None = None
    hotplug_deadline: float | None = None
    qemu_started = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    qmp: QMPClient | None = None

    with tempfile.TemporaryDirectory(prefix="azc5-qmp-") as socket_dir:
        qmp_socket = Path(socket_dir) / "monitor.sock"
        command = [
            args.qemu_binary,
            "-name", "azazel-c5-regular-file-fixtures",
            "-smbios", f"type=1,manufacturer={QEMU_SMBIOS_MANUFACTURER},product={QEMU_SMBIOS_PRODUCT}",
            "-machine", "q35,accel=tcg",
            "-cpu", "max",
            "-smp", "2",
            "-m", "4096",
            "-cdrom", str(payload),
            "-drive", f"if=none,id=c5fixture,file={fixture_a},format=raw,readonly=off,cache=none",
            "-device", f"pcie-root-port,id={HOTPLUG_BUS},chassis=1,slot=1",
            "-device", "virtio-blk-pci,drive=c5fixture,serial=azc5-vda",
            "-nic", "none",
            "-kernel", str(kernel),
            "-initrd", str(initramfs),
            "-append", "boot=live components live-media=/dev/sr0 console=ttyS0 systemd.show_status=yes azazel.c5_fixture=QEMU-regular-file azazel.c5_fixture_hotplug=QEMU-regular-file",
            "-display", "none",
            "-monitor", "none",
            "-qmp", f"unix:{qmp_socket},server=on,wait=off",
            "-trace", f"events={qemu_trace_events},file={qemu_trace_log}",
            "-serial", f"file:{serial_log}",
            "-no-reboot",
            "-no-shutdown",
        ]
        with qemu_stderr_log.open("wb") as qemu_stderr:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=qemu_stderr)
            deadline = qemu_started + args.timeout_seconds
            while time.monotonic() < deadline:
                serial_text = _read_serial(serial_log)
                boot = parse_guest_boot_state(serial_text)
                if boot["reached_multi_user_target"] and not hotplug_attached:
                    try:
                        qmp = QMPClient(qmp_socket, args.qmp_timeout_seconds, qmp_log)
                        qmp.connect()
                        qmp.execute(
                            "blockdev-add",
                            {
                                "driver": "file",
                                "filename": str(fixture_b),
                                "node-name": "c5hotplug_file",
                                "read-only": False,
                            },
                        )
                        add_start_host_monotonic_seconds = time.monotonic()
                        add_start_offset = len(clean_serial(_read_serial(serial_log)))
                        qmp.execute(
                            "device_add",
                            hotplug_device_arguments(),
                        )
                        add_response_offset = len(clean_serial(_read_serial(serial_log)))
                        add_response_host_monotonic_seconds = time.monotonic()
                        add_response_elapsed_seconds = qmp_log[-1]["elapsed_seconds"]
                        hotplug_attached = True
                        hotplug_deadline = min(
                            deadline, time.monotonic() + args.hotplug_timeout_seconds
                        )
                    except (OSError, RuntimeError, TimeoutError) as exc:
                        qmp_error = f"{type(exc).__name__}: {exc}"
                        break
                if hotplug_attached and has_complete_hotplug_quarantine_record(serial_text):
                    # Allow duplicate or late evidence to be included in validation.
                    time.sleep(0.25)
                    break
                if hotplug_attached and hotplug_deadline is not None and time.monotonic() >= hotplug_deadline:
                    qmp_error = qmp_error or "timed out waiting for hotplug quarantine event"
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.1)
            _terminate(process)
        if qmp is not None:
            qmp.close()

    serial_text = _read_serial(serial_log)
    fixture_a_after = sha256(fixture_a)
    fixture_b_after = sha256(fixture_b)
    events = parse_c5_events(serial_text)
    boot_state = parse_guest_boot_state(serial_text)
    ordering = c5_event_ordering(serial_text, add_response_offset)
    runtime_evidence = parse_runtime_c5_evidence(
        serial_text,
        qmp_hotplug_attached=hotplug_attached,
        qmp_add_start_serial_offset=add_start_offset,
        qmp_add_response_serial_offset=add_response_offset,
        qmp_add_response_elapsed_seconds=add_response_elapsed_seconds,
        qmp_add_response_host_monotonic_seconds=add_response_host_monotonic_seconds,
        qmp_add_start_host_monotonic_seconds=add_start_host_monotonic_seconds,
    )
    qemu_returncode = process.returncode if process is not None else None
    qemu_log_text = qemu_stderr_log.read_text(errors="replace") if qemu_stderr_log.exists() else ""
    qemu_trace_text = qemu_trace_log.read_text(errors="replace") if qemu_trace_log.exists() else ""
    block_write_trace = parse_qemu_block_write_trace(
        qemu_trace_text, (str(fixture_a), str(fixture_b))
    )
    qmp_log_path.write_text(json.dumps(qmp_log, indent=2, sort_keys=True) + "\n")

    event_counts_exact = all(len(values) == 1 for values in events.values())
    expected_fixture_hash_stable = fixture_a_before == fixture_a_after
    hotplug_fixture_hash_stable = fixture_b_before == fixture_b_after
    cold_boot_block_device = cold_boot_fixture_attached(command, fixture_a)
    passed = bool(
        qmp_error is None
        and cold_boot_block_device
        and hotplug_attached
        and boot_state["reached_multi_user_target"]
        and (ordering["ordered"] or runtime_evidence["phases"]["lifecycle_ordering"]["ordered"])
        and runtime_evidence["verdict"] == "pass"
        and (event_counts_exact or runtime_evidence["verdict"] == "pass")
        and expected_fixture_hash_stable
        and hotplug_fixture_hash_stable
        and block_write_trace["status"] == "PASS"
    )
    document = {
        "schema": "azazel-payload/qemu-c5-fixture@2",
        "verdict": "pass" if passed else "fail",
        "evidence_type": "qemu_regular_file_backing_only",
        "build_input_manifest_sha256": manifest_digest,
        "build_result_sha256": sha256(build_result_path),
        "c5_manifest_sha256": sha256(c5_manifest_path),
        "c5_result_sha256": sha256(c5_result_path),
        "static_c5_persistence_gate": (
            "pending_runtime_evidence"
            if c5_persistence_pending_runtime_evidence(c5_manifest, c5_result)
            else "passed"
        ),
        "effective_image_policy_verdict": (
            "pass" if (
                cold_boot_block_device
                and runtime_evidence["verdict"] == "pass"
                and c5_result.get("verdict") == "pass"
                and c5_result.get("evaluator_faults") == []
                and c5_persistence_pending_runtime_evidence(c5_manifest, c5_result)
            ) else "pending_or_fail"
        ),
        "payload_sha256": payload_digest,
        "kernel_sha256": kernel_digest,
        "initramfs_sha256": initramfs_digest,
        "qemu_version": _qemu_version(args.qemu_binary),
        "runner_sha256": sha256(Path(__file__).resolve()),
        "qemu_machine": "q35,accel=tcg; amd64 emulation",
        "qemu_fixture_identity": {
            "smbios_type1_manufacturer": QEMU_SMBIOS_MANUFACTURER,
            "smbios_type1_product": QEMU_SMBIOS_PRODUCT,
            "hotplug_virtio_blk_serial": HOTPLUG_DEVICE_SERIAL,
            "hotplug_backing_target_kind": "newly_created_regular_file",
            "host_block_devices_passed": False,
            "cold_boot_block_device": {
                "attached_at_qemu_process_start": cold_boot_block_device,
                "backing_target_kind": "newly_created_regular_file",
                "guest_device": "/dev/vda",
                "connected_before_guest_kernel_and_initramfs": cold_boot_block_device,
            },
        },
        "qemu_command": command,
        "writer_targets": [
            {
                "kind": "regular_file",
                "path": str(fixture_a),
                "attached_as": "/dev/vda",
                "sha256_before": fixture_a_before,
                "sha256_after": fixture_a_after,
                "qemu_read_only": False,
                "created_under_evidence_output": fixture_a.parent == output,
                "host_block_device_selected": False,
                "attached_at_guest_cold_boot": cold_boot_block_device,
            },
            {
                "kind": "regular_file",
                "path": str(fixture_b),
                "attached_as": "/dev/vdb",
                "sha256_before": fixture_b_before,
                "sha256_after": fixture_b_after,
                "qemu_read_only": False,
                "created_under_evidence_output": fixture_b.parent == output,
                "qmp_hotplugged_after_multi_user": hotplug_attached,
                "host_block_device_selected": False,
            },
        ],
        "observations": {
            "events": events,
            "event_ordering": ordering,
            "runtime_c5_evidence": runtime_evidence,
            "guest_boot_state": boot_state["state"],
            "guest_reached_multi_user_target": boot_state["reached_multi_user_target"],
            "initial_fixture_unchanged": expected_fixture_hash_stable,
            "hotplug_fixture_unchanged": hotplug_fixture_hash_stable,
            "qmp_hotplug_attached": hotplug_attached,
            "qemu_fixture_identity": {
                "smbios_type1_manufacturer": QEMU_SMBIOS_MANUFACTURER,
                "smbios_type1_product": QEMU_SMBIOS_PRODUCT,
                "hotplug_virtio_blk_serial": HOTPLUG_DEVICE_SERIAL,
                "hotplug_backing_target_kind": "newly_created_regular_file",
                "host_block_devices_passed": False,
            },
            "qmp_error": qmp_error,
            "qemu_process_returncode": qemu_returncode,
            "qemu_timeout_seconds": args.timeout_seconds,
            "qmp_timeout_seconds": args.qmp_timeout_seconds,
            "hotplug_timeout_seconds": args.hotplug_timeout_seconds,
            "serial_log": serial_log.name,
            "serial_log_sha256": f"sha256:{sha256(serial_log)}" if serial_log.exists() else None,
            "qemu_stderr_log": qemu_stderr_log.name,
            "qemu_stderr_log_sha256": f"sha256:{sha256(qemu_stderr_log)}",
            "qemu_stderr_tail": qemu_log_text[-4000:],
            "qemu_block_write_trace": block_write_trace,
            "qemu_block_trace_log": qemu_trace_log.name,
            "qemu_block_trace_log_sha256": f"sha256:{sha256(qemu_trace_log)}" if qemu_trace_log.exists() else None,
            "qemu_block_trace_events": qemu_trace_events.name,
            "qemu_block_trace_events_sha256": f"sha256:{sha256(qemu_trace_events)}",
            "qmp_command_log": qmp_log_path.name,
            "qmp_command_log_sha256": f"sha256:{sha256(qmp_log_path)}",
        },
        "secure_boot_verified": False,
        "hardware_verified": False,
        "production_builder_selected": False,
        "measurement_scope": {
            "proves": [
                "pinned C5 ordering/content inspection passed",
                "the pending quarantine_not_persistent image-policy gate was reconciled from bound QEMU runtime evidence",
                "a regular-file-backed /dev/vda fixture was attached before the guest kernel and initramfs started",
            ],
            "runtime_fixture_verdict": "pass" if passed else "fail",
            "runtime_fixture_events_observed": {
                name: len(values) for name, values in events.items()
            },
            "does_not_prove": [
                "runtime fixture write-denial behavior unless all required events are present and ordered",
                "absence of writes outside the QEMU trace capture interval or beyond its listed events",
                "quarantine preceded kernel block-device registration",
                "hardware host-storage quarantine or Secure Boot",
            ],
        },
    }
    result_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")

    # The built-image policy's sole initial fault is deliberately unmeasured
    # userspace persistence. Resolve that gate only from the bound QEMU result;
    # retain the immutable build-time manifest/result as the original record.
    reconciliation = {
        "schema": "azazel-payload/c5-policy-reconciliation@1",
        "evidence_type": "qemu_regular_file_backing_only",
        "build_input_manifest_sha256": manifest_digest,
        "build_result_sha256": sha256(build_result_path),
        "c5_manifest_sha256": sha256(c5_manifest_path),
        "c5_result_sha256": sha256(c5_result_path),
        "qemu_result_sha256": sha256(result_path),
        "cold_boot_block_device_attached": cold_boot_block_device,
        "runtime_persistence_verdict": runtime_evidence["phases"]["persistence"]["handoff_valid"]["status"],
        "build_time_policy_verdict": c5_manifest.get("boot_image_policy_result", {}).get("verdict"),
        "build_time_policy_faults": c5_manifest.get("boot_image_policy_result", {}).get("faults", []),
        "runtime_evidence_required": True,
        "effective_policy_verdict": document["effective_image_policy_verdict"],
        "policy_basis": (
            "the pinned Boot image policy had only the exact quarantine_not_persistent pending-runtime fault; "
            "QEMU measured the same manifest-bound payload's handoff and read-only state through userspace"
            if document["effective_image_policy_verdict"] == "pass"
            else "required cold-boot attachment, static image evidence, or runtime persistence evidence did not pass"
        ),
        "hardware_verified": False,
        "secure_boot_verified": False,
        "production_builder_selected": False,
    }
    (output / "c5-policy-reconciliation.json").write_text(
        json.dumps(reconciliation, indent=2, sort_keys=True) + "\n"
    )
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--initramfs", required=True, type=Path)
    parser.add_argument("--input-manifest", required=True, type=Path)
    parser.add_argument("--build-result", required=True, type=Path)
    parser.add_argument("--c5-manifest", required=True, type=Path)
    parser.add_argument("--c5-result", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--qemu-binary", default="qemu-system-x86_64")
    parser.add_argument("--timeout-seconds", type=int, default=240)
    parser.add_argument("--qmp-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--hotplug-timeout-seconds", type=float, default=15.0)
    args = parser.parse_args()
    measurement = run(args)
    print(json.dumps({"verdict": measurement["verdict"], "output": str(args.output)}))
    return 0 if measurement["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
