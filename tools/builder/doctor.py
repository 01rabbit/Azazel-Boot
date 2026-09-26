"""`azazel-boot-builder doctor` — can this host drive a P2 evaluation, and what is missing.

[ADR-0009](../../docs/adr/0009-builder-and-writer-contract.md) D1 fixes what
this verb is: it "reports whether this host can drive the other six verbs, and
what is missing. Changes nothing."

**Read-only is a property of the type, not of the code.** This module is given
a :class:`~tools.builder.hostports.HostProbe`, whose Protocol has no method that
writes, and it imports nothing that could reach the machine another way — no
`subprocess`, no `os`, no `shutil`, no `socket`, no `urllib`, and no `open`.
`tests/unit/test_builder_cli.py` asserts each of those against the syntax tree,
so a later contributor cannot add a single convenient call without a red test.

**The report is a classification, not a description.** Each finding is a
`(check, status, reason)` triple drawn from three closed vocabularies. It
carries no path, no hostname, no VM name, no byte count and no backend version
— a `doctor` report is the thing an operator pastes into an issue when asking
for help, and the owner's rule is that raw host identity does not go there.
`Finding` cannot hold such a value: there is no free-text field on it.

Nothing here has run against a real host.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .hostports import BACKEND_PREFERENCE, Backend, HostFacts, HostProbe

#: The build host P2 requires. Restated from `candidates.py` as this module's
#: target; a test pins the two together rather than letting them drift.
REQUIRED_OS_ID = "debian"
REQUIRED_OS_VERSION_ID = "13"
REQUIRED_GUEST_ARCHITECTURE = "x86_64"

#: Enough room for a Debian 13 installation image, the VM's disk, and the
#: evaluation build's output inside it. A floor, stated as a number so the
#: refusal is not a matter of opinion.
MINIMUM_FREE_BYTES = 48 * 1024**3

#: The VM this tool would create. Fixed, so a collision is a real collision
#: rather than an operator's naming choice.
VM_NAME = "azazel-evaluation"


class Check(Enum):
    """The questions `doctor` answers, in the order it answers them."""

    SHARED_KERNEL = "shared_kernel"
    HOST_PLATFORM = "host_platform"
    VIRTUALISATION_BACKEND = "virtualisation_backend"
    FREE_SPACE = "free_space"
    NETWORK_REACHABILITY = "network_reachability"
    EXISTING_VM_COLLISION = "existing_vm_collision"
    PRIVILEGE = "privilege"
    NO_SHARED_FOLDER = "no_shared_folder"
    NO_USB_PASSTHROUGH = "no_usb_passthrough"


class Status(Enum):
    """Three answers, and `MISSING` is not `REFUSED`.

    `MISSING` is something an operator can supply — install a backend, free
    some disk, connect a network. `REFUSED` is something they cannot: this
    machine shares a kernel, or a VM of this name already exists with a USB
    device attached to it. Collapsing the two would turn "go and fix this" and
    "not on this machine" into one message.
    """

    READY = "ready"
    MISSING = "missing"
    REFUSED = "refused"


class Reason(Enum):
    """Why, from a closed vocabulary. No value from the host appears here."""

    OK = "ok"
    SHARED_KERNEL_HOST = "shared_kernel_host"
    HOST_BACKEND_UNAVAILABLE = "host_backend_unavailable"
    INSUFFICIENT_FREE_SPACE = "insufficient_free_space"
    NETWORK_UNREACHABLE = "network_unreachable"
    VM_NAME_ALREADY_IN_USE = "vm_name_already_in_use"
    PRIVILEGE_UNAVAILABLE = "privilege_unavailable"
    SHARED_FOLDER_CONFIGURED = "shared_folder_configured"
    USB_PASSTHROUGH_CONFIGURED = "usb_passthrough_configured"
    GUEST_ARCHITECTURE_EMULATED = "guest_architecture_emulated"


@dataclass(frozen=True)
class Finding:
    """One answer. Three enums and nothing else.

    There is no `detail`, `message`, `path` or `value` field. A free-text field
    is how a host's identity reaches a report that gets pasted into an issue,
    and the rule is that it does not.
    """

    check: Check
    status: Status
    reason: Reason


@dataclass(frozen=True)
class DoctorReport:
    """Every finding, and the one conclusion drawn from them."""

    findings: tuple[Finding, ...]
    #: The backend that would be used, when one is available. `None` is the
    #: `HOST_BACKEND_UNAVAILABLE` case, and it is not a default to fall back on.
    backend: Backend | None

    @property
    def refusals(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.status is Status.REFUSED)

    @property
    def missing(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.status is Status.MISSING)

    @property
    def can_prepare_a_host(self) -> bool:
        """True only when every check is `READY`.

        Not "no refusals": a missing backend is not a refusal and still means
        nothing can be prepared. The three statuses answer different questions
        and this one needs all of them.
        """

        return all(f.status is Status.READY for f in self.findings)


def select_backend(facts: HostFacts) -> Backend | None:
    """The backend the host **already has**, or `None`.

    It never infers one from the platform and never installs one. A Mac does
    not imply UTM and a Linux host does not imply libvirt; both are measured.
    `BACKEND_PREFERENCE` only breaks a tie between backends already present.
    """

    for candidate in BACKEND_PREFERENCE:
        if candidate in facts.available_backends:
            return candidate
    return None


def examine(probe: HostProbe) -> DoctorReport:
    """Run every check against one set of facts. Changes nothing."""

    facts = probe.facts()
    backend = select_backend(facts)
    findings: list[Finding] = []

    findings.append(
        Finding(
            Check.SHARED_KERNEL,
            Status.REFUSED if facts.shared_kernel_markers else Status.READY,
            Reason.SHARED_KERNEL_HOST if facts.shared_kernel_markers else Reason.OK,
        )
    )

    # The host's own platform is not required to be Debian — the *guest* is.
    # What matters here is whether an amd64 guest runs natively or emulated,
    # because the answer goes into the evidence and bounds what may be claimed.
    emulated = facts.machine not in (REQUIRED_GUEST_ARCHITECTURE, "amd64")
    findings.append(
        Finding(
            Check.HOST_PLATFORM,
            # Emulation is permitted and recorded. It is not a refusal: an
            # Apple silicon Mac is a legitimate evaluation host as long as
            # nothing later reads the result as a native build.
            Status.READY,
            Reason.GUEST_ARCHITECTURE_EMULATED if emulated else Reason.OK,
        )
    )

    findings.append(
        Finding(
            Check.VIRTUALISATION_BACKEND,
            Status.READY if backend is not None else Status.MISSING,
            Reason.OK if backend is not None else Reason.HOST_BACKEND_UNAVAILABLE,
        )
    )

    enough_space = facts.free_bytes >= MINIMUM_FREE_BYTES
    findings.append(
        Finding(
            Check.FREE_SPACE,
            Status.READY if enough_space else Status.MISSING,
            Reason.OK if enough_space else Reason.INSUFFICIENT_FREE_SPACE,
        )
    )

    findings.append(
        Finding(
            Check.NETWORK_REACHABILITY,
            Status.READY if facts.network_reachable else Status.MISSING,
            Reason.OK if facts.network_reachable else Reason.NETWORK_UNREACHABLE,
        )
    )

    collision = VM_NAME in facts.existing_vm_names
    findings.append(
        Finding(
            Check.EXISTING_VM_COLLISION,
            # A refusal rather than something missing: this tool does not
            # delete a VM, so an operator's existing machine of this name is
            # theirs to resolve.
            Status.REFUSED if collision else Status.READY,
            Reason.VM_NAME_ALREADY_IN_USE if collision else Reason.OK,
        )
    )

    findings.append(
        Finding(
            Check.PRIVILEGE,
            Status.READY if facts.can_escalate_privilege else Status.MISSING,
            Reason.OK if facts.can_escalate_privilege else Reason.PRIVILEGE_UNAVAILABLE,
        )
    )

    findings.append(
        Finding(
            Check.NO_SHARED_FOLDER,
            Status.REFUSED if facts.shared_folders_configured else Status.READY,
            Reason.SHARED_FOLDER_CONFIGURED
            if facts.shared_folders_configured
            else Reason.OK,
        )
    )

    findings.append(
        Finding(
            Check.NO_USB_PASSTHROUGH,
            Status.REFUSED if facts.usb_passthrough_configured else Status.READY,
            Reason.USB_PASSTHROUGH_CONFIGURED
            if facts.usb_passthrough_configured
            else Reason.OK,
        )
    )

    return DoctorReport(findings=tuple(findings), backend=backend)


def render(report: DoctorReport) -> tuple[str, ...]:
    """The report as lines, carrying only the three classifications.

    Every line is built from enum values this module defines. Nothing from the
    host is interpolated, which is why a `doctor` report is safe to paste into
    an issue — and why a test can check that property by searching the output
    for values the probe was given.
    """

    lines = [f"{f.check.value}: {f.status.value} ({f.reason.value})" for f in report.findings]
    lines.append(
        f"backend: {report.backend.value}" if report.backend else "backend: none available"
    )
    lines.append(
        "conclusion: prepare-host may run"
        if report.can_prepare_a_host
        else "conclusion: prepare-host may not run"
    )
    return tuple(lines)
