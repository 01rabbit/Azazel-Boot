"""The deliberately ephemeral boot composition used by the prototype image.

This process is started once by systemd after initramfs handoff. The initramfs
marker must name the same kernel boot id before the runtime is composed. It
owns one Quarantine and one BootSession for its lifetime; storage/key
commissioning is not implemented, so persistence is fixed to ephemeral before
any acquisition or recovery workflow can be called.

The initramfs shell/udev path remains the C5 enforcement mechanism. This
runtime records Boot policy decisions for discovered devices; it does not
claim that its Python verdicts alone enforce kernel I/O or resist modification
by other code in this process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import time
from pathlib import Path

from azazel_boot.quarantine import Action, Device, DeviceClass, Quarantine, Verdict
from azazel_boot.session_mode import ATTEMPT_BUDGET, BootSession

RUN = Path("/run/azazel")
MARKER = RUN / "host-storage-quarantined"
EVIDENCE = RUN / "boot-runtime.json"
SYS_BLOCK = Path("/sys/class/block")
BOOT_ID_FILE = Path("/proc/sys/kernel/random/boot_id")
HANDOFF_SCHEMA = "azazel-c5-handoff-v1"
RUNTIME_SCHEMA = "azazel-boot/runtime-evidence@1"
POLL_SECONDS = 0.5
_STOP = False


def _stop(_signum: int, _frame: object) -> None:
    global _STOP
    _STOP = True


def _marker_values(path: Path, boot_id: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    if values.get("schema") != HANDOFF_SCHEMA:
        raise ValueError("initramfs handoff schema is missing or unsupported")
    if values.get("session_id") != boot_id:
        raise ValueError("initramfs handoff belongs to a different kernel boot")
    phase = values.get("phase")
    if phase not in {"initial_quarantine", "device_quarantined"}:
        raise ValueError("initramfs handoff phase is not a quarantine event")
    if phase == "device_quarantined":
        device = values.get("device", "")
        parts = device.split("/")
        if (
            not device.startswith("/dev/")
            or len(parts) != 3
            or not parts[2]
            or parts[2] in {".", ".."}
        ):
            raise ValueError("device quarantine handoff does not name a safe device")
    return values


def _handoff_device_is_read_only(values: dict[str, str]) -> bool | None:
    """Verify the named initramfs device still has kernel read-only state."""

    if values.get("phase") != "device_quarantined":
        return None
    name = values["device"].removeprefix("/dev/")
    state = SYS_BLOCK / name
    try:
        return (
            (state / "dev").is_file()
            and (state / "ro").read_text(encoding="ascii").strip() == "1"
        )
    except OSError:
        return False


def _major_minor(path: Path) -> str | None:
    try:
        major, minor = path.read_text(encoding="ascii").strip().split(":", 1)
    except (OSError, ValueError):
        return None
    if not major.isdecimal() or not minor.isdecimal():
        return None
    return f"{major}:{minor}"


def _identity(sys_path: Path) -> str:
    resolved = sys_path.resolve(strict=True)
    parent = resolved.parent if (resolved / "partition").is_file() else resolved
    serial = ""
    for candidate in (parent / "device/wwid", parent / "device/serial"):
        try:
            serial = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if serial:
            break
    # Keep raw device identifiers in memory only. Evidence contains counts and
    # verdicts, not serials, names, or sysfs paths.
    material = f"{parent.as_posix()}\0{serial}".encode()
    return "sysfs-sha256:" + hashlib.sha256(material).hexdigest()


def _boot_medium_identity(boot_id: str) -> str:
    """Resolve the live medium from its mounted source, or return no identity."""

    devno: str | None = None
    try:
        for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if len(fields) < 10 or fields[4].replace("\\040", " ") != "/run/live/medium":
                continue
            devno = fields[2]
            break
    except OSError:
        pass
    if devno is None:
        return ""
    try:
        sys_path = (Path("/sys/dev/block") / devno).resolve(strict=True)
    except OSError:
        return ""
    return _identity(sys_path)


def _discover() -> dict[str, Device]:
    devices: dict[str, Device] = {}
    try:
        paths = sorted(SYS_BLOCK.iterdir())
    except OSError:
        return devices
    for path in paths:
        if path.name.startswith(("ram", "zram", "loop")):
            continue
        try:
            if not (path / "dev").is_file():
                continue
            identity = _identity(path)
        except OSError:
            continue
        devices[identity] = Device(identity=identity, device_class=DeviceClass.UNKNOWN)
    return devices


def run(*, once: bool = False) -> int:
    try:
        boot_id = BOOT_ID_FILE.read_text(encoding="ascii").strip()
        if not boot_id or len(boot_id) > 64:
            raise ValueError("kernel boot id is unavailable")
        handoff = _marker_values(MARKER, boot_id)
        handoff_device_read_only = _handoff_device_is_read_only(handoff)
        if handoff_device_read_only is False:
            raise ValueError("initramfs quarantine state did not survive userspace handoff")
    except (OSError, ValueError) as exc:
        print(f"AZAZEL_BOOT_RUNTIME state=refused reason={type(exc).__name__}", flush=True)
        return 1

    medium_identity = _boot_medium_identity(boot_id)
    quarantine = Quarantine(session_id=boot_id, boot_medium_identity=medium_identity)
    session = BootSession(boot_id, quarantine, None)
    mode = session.select_ephemeral()
    seen: set[str] = set()
    decisions: dict[str, int] = {}
    hotplug_devices = 0
    initial_scan = True
    started = time.monotonic()

    def snapshot() -> dict[str, object]:
        return {
            "schema": RUNTIME_SCHEMA,
            "boot_id_matches_initramfs": handoff["session_id"] == boot_id,
            "initramfs_phase": handoff["phase"],
            "handoff_device_read_only_verified": handoff_device_read_only,
            "boot_session_created_once_in_runtime": True,
            "owner_lifetime_scope": "post-initramfs-userspace-process",
            "initramfs_python_owner_survives_handoff": False,
            "boot_session_mode": mode.mode.value,
            "safe_persistence_path_available": False,
            "acquisition_enabled": False,
            "edge_activation": False,
            "network_default_on": False,
            "owner_pid": os.getpid(),
            "quarantine_instance_count": 1,
            "observed_device_count": len(seen),
            "hotplug_device_count": hotplug_devices,
            "boot_medium_identity_resolved": bool(medium_identity),
            "policy_blocked_decision_counts": decisions,
            "attempt_budget_per_boot": ATTEMPT_BUDGET,
            "attempt_count_exposed": False,
            "uptime_seconds": round(time.monotonic() - started, 3),
        }

    def persist() -> None:
        temporary = EVIDENCE.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(snapshot(), sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, EVIDENCE)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    RUN.mkdir(mode=0o755, parents=True, exist_ok=True)
    ready_reported = False
    while not _STOP:
        discovered = _discover()
        for identity in discovered:
            if identity in seen:
                continue
            device = Device(
                identity=identity,
                device_class=(
                    DeviceClass.BOOT_MEDIUM
                    if identity == medium_identity and medium_identity
                    else DeviceClass.HOST_STORAGE
                ),
            )
            disposition = quarantine.observe(device)
            seen.add(identity)
            if not initial_scan:
                hotplug_devices += 1
            # Record the whole relevant policy surface for this observed device.
            # These are policy decisions, not syscall or hardware enforcement.
            for action in Action:
                verdict = quarantine.evaluate(device, action)
                if verdict is Verdict.BLOCKED:
                    decisions[action.value] = decisions.get(action.value, 0) + 1
            print(
                "AZAZEL_BOOT_RUNTIME_DEVICE "
                f"disposition={disposition.value} policy_decisions=recorded",
                flush=True,
            )
        persist()
        if not ready_reported:
            print(
                "AZAZEL_BOOT_RUNTIME state=active schema=azazel-boot/runtime-evidence@1 "
                f"session=initramfs-boot-id-matched mode={mode.mode.value} "
                f"boot_medium_identity_resolved={str(bool(medium_identity)).lower()} "
                f"owner_pid={os.getpid()} observed_devices={len(seen)}",
                flush=True,
            )
            ready_reported = True
        initial_scan = False
        if once:
            break
        time.sleep(POLL_SECONDS)
    persist()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="scan once for a test fixture")
    raise SystemExit(run(once=parser.parse_args().once))
