"""The plan `doctor` shows before anything creates a build host.

The owner's rule for P2 is that **every operation needing a new build host, an
external package download, or a privilege escalation is shown as a `doctor`
plan before it runs**. `doctor` reports and changes nothing
([ADR-0009](../../docs/adr/0009-builder-and-writer-contract.md) D1), so this
module is the reporting half: it produces the plan as data, and it performs no
step in it.

That separation is structural rather than a matter of discipline. This module
imports no `subprocess`, no `os`, no `shutil`; it opens no file for writing; and
`tests/unit/test_host_bootstrap.py` asserts each of those against the syntax
tree. A plan that could execute itself would make "shown before it runs" a
property of whoever called it.

**A chroot is not a build host.** It was considered and rejected: a chroot
shares the kernel of the machine it runs on, so an initramfs measured inside one
is evidence about that kernel's environment, not about an isolated Debian 13
host. The owner decided a disposable VM, and `HostKind` has no value for a
chroot, a container or the session's own machine — a value the type cannot hold
is one a caller cannot record.

**One VM is not evidence of anything but itself.** `BootstrapPlan` reports
`reproducibility_established`, `supported` and `selects_a_builder` as `False`
unconditionally, the same way `C5Result` does, because building a machine that
can run a measurement is not the measurement and is not a selection.

Nothing here has run. No VM has been created, no image has been downloaded, no
package has been installed, and no evaluation build has been performed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

#: Stamped into anything this plan would produce, for the reason
#: `evaluation.STAMP` exists: a record that cannot carry a release claim cannot
#: be read as making one.
STAMP = "NON-RELEASABLE / EVALUATION ONLY"

#: What `check_build_host` must find once the VM exists. Restated here as the
#: plan's *target*, not as a second source of truth — a test pins the two
#: together.
TARGET_OS_ID = "debian"
TARGET_OS_VERSION_ID = "13"
TARGET_ARCHITECTURE = "x86_64"


class HostKind(Enum):
    """Where an evaluation build may run.

    There is deliberately **no value** for a chroot, a container, a namespace or
    the session's own machine. All four share the kernel of whatever they run
    on, and the owner's decision was that such a result is not isolation
    evidence for a builder selection. The refusal is therefore not a check
    somebody has to remember to write; there is nothing to record it with.
    """

    DISPOSABLE_VM_ON_LINUX = "disposable_vm_on_linux"
    DISPOSABLE_VM_ON_MACOS = "disposable_vm_on_macos"


class StepKind(Enum):
    """What a step *does*, classified by what the owner asked to see first.

    The three that require showing this plan beforehand are named explicitly so
    that a step needing approval cannot be added without picking one of them.
    """

    #: Reads something and changes nothing. Needs no approval.
    INSPECT = "inspect"
    #: Brings a build host into existence.
    CREATE_HOST = "create_host"
    #: Fetches bytes from outside this machine.
    EXTERNAL_DOWNLOAD = "external_download"
    #: Needs root, or anything equivalent to it.
    PRIVILEGE_ESCALATION = "privilege_escalation"
    #: Writes, but only inside the VM's own tree.
    WRITE_INSIDE_THE_VM = "write_inside_the_vm"


#: The step kinds that may not run until this plan has been shown.
NEEDS_APPROVAL_FIRST = (
    StepKind.CREATE_HOST,
    StepKind.EXTERNAL_DOWNLOAD,
    StepKind.PRIVILEGE_ESCALATION,
)


class Refusal(Enum):
    NOT_A_DISPOSABLE_VM = "not_a_disposable_vm"
    HOST_PATH_USED_FOR_BUILD_IO = "host_path_used_for_build_io"
    UNSIGNED_IMAGE_SOURCE = "unsigned_image_source"
    EVIDENCE_FIELD_MISSING = "evidence_field_missing"
    STAMP_MISSING = "stamp_missing"
    TOUCHES_A_MEDIUM_OR_A_RELEASE = "touches_a_medium_or_a_release"


class BootstrapRefused(Exception):
    """The plan is not one that may be shown, let alone run.

    The detail names the rule. It does not echo a path, a URL or a digest: a
    plan is assembled from a caller's configuration, and a refusal that quotes
    it puts that input on a console.
    """

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


#: Evidence the owner requires recorded about the VM itself. Every one is
#: required: a missing field is refused rather than defaulted, because the point
#: of the record is to say which machine a later measurement came from, and a
#: blank there reads as "any machine" three months later.
REQUIRED_VM_EVIDENCE_FIELDS = (
    "image_source",
    "image_digest",
    "image_signature_verified",
    "created_at",
    "cpu_architecture",
    "debian_version_id",
    "builder_tool_version",
)

#: Field names this evidence must never grow, for `evaluation.py`'s reason: a
#: record that cannot carry a release claim cannot be read as making one.
FORBIDDEN_EVIDENCE_FIELDS = (
    "compatibility_claim",
    "signature",
    "signed_artifact_digest",
    "release_channel",
    "supported",
    "reproducible",
    "selected_builder",
)


@dataclass(frozen=True)
class VmEvidence:
    """What must be recorded about the machine a measurement ran on.

    `image_signature_verified` is separate from `image_digest` on purpose. A
    digest says two files are the same file; a verified signature says Debian
    published it. An evaluation built from an image whose signature nobody
    checked is evidence about a download, and the owner's constraint is that
    only signed Debian inputs are used.
    """

    image_source: str
    image_digest: str
    image_signature_verified: bool
    created_at: str
    cpu_architecture: str
    debian_version_id: str
    builder_tool_version: str
    host_kind: HostKind
    stamp: str = STAMP

    def __repr__(self) -> str:
        """Redacted where it would otherwise carry the operator's machine.

        `image_source` is a URL or a path the operator typed and `created_at` is
        a timestamp on their machine; neither belongs in a traceback that may be
        pasted into an issue. The fields stay readable as data.
        """

        return (
            f"VmEvidence(host_kind={self.host_kind.value}, "
            f"debian_version_id={self.debian_version_id!r}, "
            f"cpu_architecture={self.cpu_architecture!r}, "
            f"image_signature_verified={self.image_signature_verified!r}, "
            "image_source=<redacted>, image_digest=<redacted>, "
            "created_at=<redacted>)"
        )


@dataclass(frozen=True)
class BootstrapStep:
    """One operation, described and **not performed**.

    `command` is the text an operator would run. It is a string in a dataclass:
    nothing in this package executes it, and a test asserts the package imports
    no means of doing so.
    """

    step_id: str
    title: str
    kind: StepKind
    command: str
    #: Why this step exists, in one sentence an operator can disagree with.
    because: str
    #: What this step does **not** do. Present on every step, because the
    #: constraints being honoured are invisible in a command line.
    does_not: tuple[str, ...] = field(default_factory=tuple)

    @property
    def needs_approval_first(self) -> bool:
        return self.kind in NEEDS_APPROVAL_FIRST


@dataclass(frozen=True)
class BootstrapPlan:
    """The whole plan, as `doctor` would print it.

    The three report fields are `False` and cannot be anything else. Creating
    one VM establishes that a VM exists. It does not establish that a build is
    reproducible ([ADR-0002](../../docs/adr/0002-image-builder.md) D1.3 needs two
    independent builders), that a tool is supported, or that a builder is
    selected (D8 P7 is an ADR, never a measurement).
    """

    host_kind: HostKind
    steps: tuple[BootstrapStep, ...]
    stamp: str = STAMP

    @property
    def reproducibility_established(self) -> bool:
        return False

    @property
    def supported(self) -> bool:
        return False

    @property
    def selects_a_builder(self) -> bool:
        return False

    @property
    def steps_needing_approval(self) -> tuple[BootstrapStep, ...]:
        return tuple(step for step in self.steps if step.needs_approval_first)


def require_isolated_host(kind: object) -> HostKind:
    """Accept only a disposable VM, and say why the other answers are absent.

    A caller reaching for a chroot finds no value to pass. This function exists
    for the caller who passes a string anyway.
    """

    if not isinstance(kind, HostKind):
        raise BootstrapRefused(
            Refusal.NOT_A_DISPOSABLE_VM,
            "an evaluation build runs in a disposable VM; a chroot, a container "
            "or this session's own machine shares a kernel, and a measurement "
            "taken there is evidence about that kernel",
        )
    return kind


def require_vm_evidence(evidence: VmEvidence) -> None:
    """Every required field present, and the image actually signed."""

    for name in REQUIRED_VM_EVIDENCE_FIELDS:
        value = getattr(evidence, name)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise BootstrapRefused(
                Refusal.EVIDENCE_FIELD_MISSING,
                "a record that cannot say which machine a measurement ran on "
                "reads as any machine; the field name is in the model, not here",
            )
    if evidence.stamp != STAMP:
        raise BootstrapRefused(
            Refusal.STAMP_MISSING,
            "anything this plan produces is evaluation-only and says so in its "
            "own record",
        )
    if not evidence.image_signature_verified:
        raise BootstrapRefused(
            Refusal.UNSIGNED_IMAGE_SOURCE,
            "only signed Debian inputs are used; a digest says two files match, "
            "a verified signature says Debian published it",
        )
    require_isolated_host(evidence.host_kind)


def require_build_io_inside_the_vm(paths: tuple[str, ...]) -> None:
    """Refuse a build input or output on the operator's own machine.

    The owner's constraint is that nothing is unpacked to an arbitrary host
    path. A shared folder is the ordinary way this is broken — it is convenient,
    it is how a build reads a file nobody pinned, and it is how an evaluation
    output ends up in a Git working tree, which
    [`evaluation.py`](evaluation.py) refuses for its own reasons.

    The check is by construction: a path is accepted only when it is stated to
    be inside the VM's own filesystem, so an unannotated path refuses.
    """

    for path in paths:
        if not path.startswith(VM_BUILD_ROOT):
            raise BootstrapRefused(
                Refusal.HOST_PATH_USED_FOR_BUILD_IO,
                "build inputs and outputs live inside the VM; a shared folder "
                "makes the operator's machine part of the build",
            )


#: The one tree a build reads from and writes to, inside the VM.
VM_BUILD_ROOT = "/srv/azazel-evaluation/"


def plan(host_kind: HostKind) -> BootstrapPlan:
    """Assemble the plan. Runs nothing, creates nothing, downloads nothing.

    The steps are concrete — an operator can read a command and disagree with
    it — and each one states what it does not do, because the constraints being
    honoured here are exactly the ones a command line does not show.
    """

    require_isolated_host(host_kind)
    hypervisor = (
        "qemu-system-x86_64 (libvirt)"
        if host_kind is HostKind.DISPOSABLE_VM_ON_LINUX
        else "UTM or Lima (QEMU backend, x86_64 emulation on Apple silicon)"
    )

    steps = (
        BootstrapStep(
            step_id="P2-B1",
            title="Record what the operator's own machine is",
            kind=StepKind.INSPECT,
            command="uname -m; sw_vers 2>/dev/null || cat /etc/os-release",
            because=(
                "the evidence has to say which machine hosted the VM, and this "
                "is read before anything exists to confuse it with"
            ),
            does_not=(
                "does not create anything",
                "does not leave the operator's machine",
            ),
        ),
        BootstrapStep(
            step_id="P2-B2",
            title="Fetch the Debian 13 / amd64 installation image and its signed checksums",
            kind=StepKind.EXTERNAL_DOWNLOAD,
            command=(
                "curl -fsSLO https://cdimage.debian.org/debian-cd/current/amd64/"
                "iso-cd/debian-13.<point>.0-amd64-netinst.iso\n"
                "curl -fsSLO .../SHA512SUMS\n"
                "curl -fsSLO .../SHA512SUMS.sign"
            ),
            because=(
                "an evaluation build runs on Debian 13 / amd64 and on nothing "
                "else; this is the only external fetch outside the VM"
            ),
            does_not=(
                "does not write to any block device",
                "does not touch a release channel or a signed product artifact",
            ),
        ),
        BootstrapStep(
            step_id="P2-B3",
            title="Verify the image against the Debian CD signing key before using it",
            kind=StepKind.INSPECT,
            command=(
                "gpg --verify SHA512SUMS.sign SHA512SUMS\n"
                "sha512sum -c --ignore-missing SHA512SUMS"
            ),
            because=(
                "only signed Debian inputs are used; an unverified image makes "
                "every later measurement evidence about a download"
            ),
            does_not=(
                "does not proceed on a failed signature — the plan stops here",
                "does not accept a checksum file that is merely present",
            ),
        ),
        BootstrapStep(
            step_id="P2-B4",
            title=f"Create the disposable VM with {hypervisor}",
            kind=StepKind.CREATE_HOST,
            command=(
                "# no shared folder, no host passthrough, no USB passthrough\n"
                "<hypervisor> create --arch x86_64 --disk 40G --no-shared-folder "
                "--no-usb-passthrough --iso debian-13.<point>.0-amd64-netinst.iso"
            ),
            because=(
                "a VM is the isolation the owner decided on; a chroot shares "
                "this machine's kernel and is not evidence about an isolated host"
            ),
            does_not=(
                "does not pass through any USB device",
                "does not mount a host folder into the VM",
                "does not reuse an existing VM — a reused one is not disposable",
            ),
        ),
        BootstrapStep(
            step_id="P2-B5",
            title="Record the VM evidence before installing anything into it",
            kind=StepKind.INSPECT,
            command=(
                "# image source, image digest, signature verified, created at,\n"
                "# CPU architecture, Debian VERSION_ID, builder tool version"
            ),
            because=(
                "the record says which machine a later measurement came from, "
                "and it is written while those facts are still observable"
            ),
            does_not=(
                "does not record a hostname, a serial or an asset tag",
                "does not claim the VM is supported, reproducible or selected",
            ),
        ),
        BootstrapStep(
            step_id="P2-B6",
            title="Install the candidate builder inside the VM",
            kind=StepKind.PRIVILEGE_ESCALATION,
            command="sudo apt-get install --no-install-recommends live-build",
            because=(
                "the candidate has to exist before C5 can be measured against "
                "an initramfs it built"
            ),
            does_not=(
                "does not run on the operator's machine — inside the VM only",
                "does not add a repository, a mirror or a URL an operator typed "
                "(ADR-0009 D4)",
            ),
        ),
        BootstrapStep(
            step_id="P2-B7",
            title="Confirm the VM is the build host the gate requires",
            kind=StepKind.INSPECT,
            command=(
                "python3 -c \"from tools.builder.candidates import check_build_host\""
            ),
            because=(
                "the existing gate answers this, and an evaluation build that "
                "ran somewhere else would be evidence about that somewhere else"
            ),
            does_not=(
                "does not soften the gate for a VM",
                "does not make the answer depend on who is asking",
            ),
        ),
        BootstrapStep(
            step_id="P2-B8",
            title=f"Run the evaluation build inside {VM_BUILD_ROOT}",
            kind=StepKind.WRITE_INSIDE_THE_VM,
            command=f"lb config && lb build   # cwd {VM_BUILD_ROOT}",
            because=(
                "C5 is measured against a built initramfs; nothing else "
                "produces one"
            ),
            does_not=(
                "does not write to a USB device or an internal disk",
                "does not produce a release, a signature or a compatibility claim",
                "does not unpack any input or output to a path on the host",
            ),
        ),
        BootstrapStep(
            step_id="P2-B9",
            title="Destroy the VM once the measurement is recorded",
            kind=StepKind.INSPECT,
            command="<hypervisor> delete --purge azazel-evaluation",
            because=(
                "disposable means it goes; a kept VM becomes an environment "
                "nobody can describe by the time it matters"
            ),
            does_not=(
                "does not delete the recorded evidence",
                "does not run before the C5 result is written out",
            ),
        ),
    )
    return BootstrapPlan(host_kind=host_kind, steps=steps)
