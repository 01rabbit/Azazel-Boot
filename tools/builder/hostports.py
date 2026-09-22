"""The ports the builder CLI reaches the world through, and what they may say.

Two ports, separated by what they are allowed to do, because that separation is
the whole of `doctor`'s read-only guarantee:

:class:`HostProbe` **reads**. Every method answers a question and changes
nothing, and the Protocol has no method that could do otherwise — there is no
`run`, `write`, `install`, `create`, `download` or `remove` on it. `doctor` is
given one of these and nothing else, so "doctor is read-only" is a property of
the type it depends on rather than a promise about the code inside it.

:class:`Executor` **acts**. Downloading, creating a VM and installing a package
inside one are the three things `prepare-host` can do, and each is a separate
method so that an approval can be checked per act rather than per session.

Neither Protocol is implemented here. `tools/builder/system_probe.py` is the one
module that touches the machine, and it is deliberately the only place in this
package that imports `subprocess` or `shutil`.

Nothing in this file has run against a real host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable


class Backend(Enum):
    """A virtualisation backend, named only when the host actually has it.

    The set is closed: a backend absent from here cannot be selected, and a
    backend present here is still only selected when the probe reports it
    installed. Nothing in this package installs one.
    """

    QEMU_SYSTEM_X86_64 = "qemu-system-x86_64"
    LIBVIRT = "libvirt"
    LIMA = "lima"
    UTM = "utm"


#: Preference order, used only to break a tie between backends the host
#: **already has**. It expresses nothing about what a host should install.
BACKEND_PREFERENCE = (
    Backend.LIBVIRT,
    Backend.QEMU_SYSTEM_X86_64,
    Backend.LIMA,
    Backend.UTM,
)


class Execution(Enum):
    """Whether the guest runs on the host's own instruction set, or emulated.

    `EMULATED_AMD64_ON_ARM64` exists so that an Apple silicon run cannot be
    recorded as anything else. A Debian 13 / amd64 guest on an arm64 Mac is
    emulation, it is slower by a large and unmeasured factor, and calling it a
    native build would make a performance or reproducibility reading of the
    result look supported when it is not.
    """

    NATIVE_AMD64 = "native_amd64"
    EMULATED_AMD64_ON_ARM64 = "emulated_amd64_on_arm64"


class SignatureCheck(Enum):
    """Did a signature verify. `NOT_ATTEMPTED` is not a pass."""

    VERIFIED = "verified"
    FAILED = "failed"
    NOT_ATTEMPTED = "not_attempted"


class DigestCheck(Enum):
    """Did the bytes match. Independent of the signature, deliberately.

    A digest says two files are the same file. A signature says Debian
    published it. Either alone answers half the question, so both are recorded
    and both are required.
    """

    MATCHED = "matched"
    MISMATCHED = "mismatched"
    NOT_ATTEMPTED = "not_attempted"


class SharedKernelMarker(Enum):
    """Evidence that this process is not on a machine of its own.

    A chroot, a container and a namespace all share the kernel of whatever
    they run on, so a build host is not what any of them is.
    """

    DOCKER_ENV_FILE = "docker_env_file"
    CONTAINER_ENV_VARIABLE = "container_env_variable"
    CGROUP_NAMESPACE = "cgroup_namespace"
    CHROOT_ROOT_DEVICE = "chroot_root_device"


@dataclass(frozen=True)
class HostFacts:
    """What a probe found. Facts only; no judgement and no recommendation.

    Every field is something a check below consumes. `free_bytes` is a number
    rather than a path plus a number on purpose: the path is the operator's
    machine and the report never prints it.
    """

    os_id: str
    os_version_id: str
    machine: str
    #: Backends the host **already has**, as measured. Never inferred from the
    #: platform: a Mac does not imply UTM, and a Linux host does not imply KVM.
    available_backends: tuple[Backend, ...] = ()
    free_bytes: int = 0
    network_reachable: bool = False
    #: Names of VMs the selected backend already knows about, so a collision is
    #: reported rather than discovered by overwriting one.
    existing_vm_names: tuple[str, ...] = ()
    #: Whether the caller could escalate. Reported, never used to escalate.
    can_escalate_privilege: bool = False
    shared_kernel_markers: tuple[SharedKernelMarker, ...] = field(default_factory=tuple)
    #: Shared folders and USB passthrough already configured for a VM of this
    #: name. Both are refusals, not warnings.
    shared_folders_configured: int = 0
    usb_passthrough_configured: int = 0

    def __repr__(self) -> str:
        """Redacted where a field would otherwise carry the operator's machine.

        `existing_vm_names` are names a person chose and `free_bytes` is a fact
        about their disk. A `doctor` report is pasted into issues.
        """

        return (
            f"HostFacts(os_id={self.os_id!r}, os_version_id={self.os_version_id!r}, "
            f"machine={self.machine!r}, "
            f"available_backends={tuple(b.value for b in self.available_backends)!r}, "
            "free_bytes=<redacted>, existing_vm_names=<redacted>, "
            f"network_reachable={self.network_reachable!r}, "
            f"shared_kernel_markers={tuple(m.value for m in self.shared_kernel_markers)!r})"
        )


@runtime_checkable
class HostProbe(Protocol):
    """Reads the host. **Has no method that changes it.**

    `doctor` depends on this and on nothing else, which is what makes its
    read-only claim checkable rather than asserted:
    `tests/unit/test_builder_cli.py` asserts the method set against an
    allowlist and refuses any name that reads as an action.
    """

    def facts(self) -> HostFacts:
        """Everything the checks need, gathered in one pass."""


@dataclass(frozen=True)
class VmSpec:
    """What a VM must be, stated so that the unsafe options cannot be omitted.

    `shared_folders`, `usb_passthrough` and `host_disk_mounts` are fields with
    a fixed value rather than absent options, because an absent option is a
    default somebody else chooses. A spec that asked for any of them could be
    constructed; `require_disposable` refuses it, and the executor is given the
    spec only after that.
    """

    name: str
    architecture: str
    disk_bytes: int
    iso_path: str
    shared_folders: tuple[str, ...] = ()
    usb_passthrough: tuple[str, ...] = ()
    host_disk_mounts: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return (
            f"VmSpec(name={self.name!r}, architecture={self.architecture!r}, "
            f"shared_folders={len(self.shared_folders)}, "
            f"usb_passthrough={len(self.usb_passthrough)}, "
            f"host_disk_mounts={len(self.host_disk_mounts)}, "
            "iso_path=<redacted>, disk_bytes=<redacted>)"
        )


@dataclass(frozen=True)
class DownloadOutcome:
    """What a download produced, and what was checked about it.

    The two checks are separate fields. A caller that verified only one has a
    record saying so, and `require_verified_image` refuses it.
    """

    stored_at: str
    signature: SignatureCheck
    digest: DigestCheck
    digest_value: str


@runtime_checkable
class Executor(Protocol):
    """Performs the three acts `prepare-host` can perform, and no others.

    There is no `delete_vm`, no `install_on_host`, no `attach_usb` and no
    `mount_host_disk`. Those are absent rather than guarded: the owner's rule
    is that this tool does not do them, and a method that does not exist cannot
    be called by a later contributor who did not read that rule.
    """

    def download_and_verify(self, source: str, into: str) -> DownloadOutcome:
        """Fetch the image and its signed checksums, then verify both."""

    def create_vm(self, spec: VmSpec) -> str:
        """Create the VM and return the handle the backend gave it."""

    def install_in_vm(self, vm_handle: str, package: str) -> str:
        """Install one package **inside** the VM. Returns its version."""

    def remove_created_file(self, path: str) -> None:
        """Remove a file this session created. Used only for cleanup."""
