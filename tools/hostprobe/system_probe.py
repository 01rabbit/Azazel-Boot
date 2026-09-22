"""The one module that touches the machine, and it lives outside `tools.builder`.

`tests/unit/test_builder_tooling_boundary.py` refuses `subprocess`, `os`,
`socket` and `urllib` anywhere under `tools/builder/`. That guard predates this
work, it comes from `ADR-0009` D4, and it is not relaxed to make room for a
host probe — the probe is here instead, so `tools.builder` remains unable to
reach the machine at all and the guard keeps meaning what it said.

Everything in `tools.builder` — `doctor`, `prepare`, `host_bootstrap`,
`hostports` — is decision and description. That guarantee is only worth
something if the module that *does* reach the system is small enough to read in
one sitting and obviously read-only, so this file is deliberately both.

**It reads. It does not act.** It runs `which`-style lookups and a few list
commands, reads `/etc/os-release` and `/proc`, and asks the filesystem how much
room is left. It installs nothing, creates nothing, downloads nothing and
escalates nothing — `can_escalate_privilege` *reports* whether escalation is
available and never performs it. The executor half of
`tools.builder.hostports` is **not implemented here**, and no implementation of
it exists in this repository yet: `prepare-host` has nothing to run with until
one is written, reviewed and given an eligible host.

Every subprocess call is a fixed argument list with no shell, a timeout, and a
failure that becomes "unknown" rather than an exception — a `doctor` that
crashes on an unusual host tells the operator less than one that says what it
could not determine.

**Nothing here has been run against an eligible build host.** It has been run
against this session's own container, which it correctly reports as a shared
kernel host.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from tools.builder.hostports import Backend, HostFacts, SharedKernelMarker

#: How long any single probe command may take. A `doctor` that hangs on a
#: misbehaving hypervisor socket is a `doctor` nobody runs.
PROBE_TIMEOUT_SECONDS = 5

#: What each backend is detected by. Presence of the executable only — a
#: backend that is installed but unusable is reported as available and fails
#: later, visibly, rather than being guessed about here.
BACKEND_EXECUTABLES = {
    Backend.LIBVIRT: "virsh",
    Backend.QEMU_SYSTEM_X86_64: "qemu-system-x86_64",
    Backend.LIMA: "limactl",
    Backend.UTM: "utmctl",
}

#: Listing commands, per backend. Read-only by construction: each is a fixed
#: argument vector naming a list subcommand, never a shell string.
#: Every command this module may run, as argv[0]. A test asserts that no other
#: executable name appears in a command tuple here: "read-only" is then a
#: property somebody can check rather than a claim in a docstring.
READ_ONLY_COMMANDS = ("virsh", "limactl", "utmctl", "curl")

BACKEND_LIST_COMMANDS = {
    Backend.LIBVIRT: ("virsh", "list", "--all", "--name"),
    Backend.LIMA: ("limactl", "list", "--quiet"),
    Backend.UTM: ("utmctl", "list"),
}


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _capture(command: tuple[str, ...]) -> str:
    """Run a read-only command, or return nothing.

    No shell, a fixed argument vector, a timeout, and every failure mode folded
    into the empty string. A probe that raises turns "I could not tell" into a
    crash, and the operator learns less.
    """

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command,
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _os_release() -> tuple[str, str]:
    fields: dict[str, str] = {}
    for line in _read("/etc/os-release").splitlines():
        if "=" in line:
            name, _, value = line.partition("=")
            fields[name.strip()] = value.strip().strip('"')
    return fields.get("ID", "unknown"), fields.get("VERSION_ID", "unknown")


def _shared_kernel_markers() -> tuple[SharedKernelMarker, ...]:
    """Whether this process is on a machine of its own.

    Four cheap signals, any of which is enough. None of them is conclusive
    about the absence of a container — which is why the refusal they drive is
    one-directional: a marker refuses, and no marker is not a guarantee of a
    bare machine. `docs/p2-builder-cli.md` says so.
    """

    found: list[SharedKernelMarker] = []
    if Path("/.dockerenv").exists():
        found.append(SharedKernelMarker.DOCKER_ENV_FILE)
    if os.environ.get("container"):
        found.append(SharedKernelMarker.CONTAINER_ENV_VARIABLE)
    cgroup = _read("/proc/1/cgroup")
    if any(marker in cgroup for marker in ("docker", "lxc", "kubepods", "containerd")):
        found.append(SharedKernelMarker.CGROUP_NAMESPACE)
    try:
        if os.stat("/").st_dev != os.stat("/proc/1/root/.").st_dev:
            found.append(SharedKernelMarker.CHROOT_ROOT_DEVICE)
    except OSError:
        pass
    return tuple(found)


def _existing_vm_names(backend: Backend | None) -> tuple[str, ...]:
    if backend is None or backend not in BACKEND_LIST_COMMANDS:
        return ()
    output = _capture(BACKEND_LIST_COMMANDS[backend])
    return tuple(line.strip() for line in output.splitlines() if line.strip())


class SystemProbe:
    """A :class:`~tools.builder.hostports.HostProbe` over the real machine.

    It has exactly one public method, because the Protocol has exactly one.
    Adding a second would be the moment to ask whether it reads or acts.
    """

    def __init__(
        self,
        *,
        free_space_path: str = ".",
        network_probe_url: str = "https://deb.debian.org/debian/dists/trixie/Release",
    ) -> None:
        self._free_space_path = free_space_path
        self._network_probe_url = network_probe_url

    def facts(self) -> HostFacts:
        os_id, os_version_id = _os_release()
        available = tuple(
            backend
            for backend, executable in BACKEND_EXECUTABLES.items()
            if shutil.which(executable)
        )
        selected = available[0] if available else None
        try:
            usage = shutil.disk_usage(self._free_space_path)
            free_bytes = usage.free
        except OSError:
            free_bytes = 0
        return HostFacts(
            os_id=os_id,
            os_version_id=os_version_id,
            machine=os.uname().machine,
            available_backends=available,
            free_bytes=free_bytes,
            network_reachable=_reachable(self._network_probe_url),
            existing_vm_names=_existing_vm_names(selected),
            # Reported, never exercised. Running as root is not escalating, and
            # this module never escalates either way.
            can_escalate_privilege=os.geteuid() == 0 or bool(shutil.which("sudo")),
            shared_kernel_markers=_shared_kernel_markers(),
            # Nothing is configured until `prepare-host` creates a VM, and it
            # creates one with neither. A future adapter that inspects an
            # existing VM fills these in; until then the honest answer is zero.
            shared_folders_configured=0,
            usb_passthrough_configured=0,
        )


def _reachable(url: str) -> bool:
    """True when a HEAD request succeeds. Any failure is False, never a raise."""

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ("curl", "-fsS", "-I", "--max-time", str(PROBE_TIMEOUT_SECONDS), url),
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS + 2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0
