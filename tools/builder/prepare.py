"""`azazel-boot-builder prepare-host` — the three acts, each approved on its own.

The owner's rule: the plan is shown first, and **external download, VM creation
and in-VM package installation are each confirmed explicitly**. This module is
what makes that a property of the program rather than of whoever runs it.

**An approval is issued, never asserted.** :class:`Approval` is minted only by
:meth:`PrepareSession.approve`, which refuses unless the plan has been shown and
the operator typed that phase's own confirmation phrase. :meth:`run` checks the
approval it is handed **by identity** (`is`) against what this session issued,
so a forged one, a copy, a pickle or an approval for a different phase is not
the approval. Four earlier rounds of review on `azazel_boot.writer` and
`azazel_boot.persistence` defeated every weaker shape of this — a token a caller
could construct, a nonce beaten by `dataclasses.replace`, an enum constant — and
this is the shape that survived.

**Nothing external happens before that.** `PrepareSession` holds no executor
until :meth:`run`; building a session, showing a plan and asking for approval
cannot reach the network, create a VM or escalate anything, because the object
that could do those things is not in scope yet.

**The acts that are not offered are absent, not guarded.**
:class:`~tools.builder.hostports.Executor` has no `delete_vm`, no
`install_on_host`, no `attach_usb` and no `mount_host_disk`. A later
contributor cannot call a method that does not exist.

**Cleanup never removes a VM.** A failure part-way leaves a
:class:`CleanupOutcome` naming what this session removed — only files it
created itself — and what it is leaving for the operator. Deleting a VM is one
of the things the owner said this tool does not do, and a failure is not an
exception to that.

Nothing here has run. No image has been downloaded, no VM created, no package
installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .host_bootstrap import STAMP, HostKind, VmEvidence
from .hostports import (
    Backend,
    DigestCheck,
    DownloadOutcome,
    Execution,
    Executor,
    SignatureCheck,
    VmSpec,
)


class Phase(Enum):
    """The three acts, in the only order they may run."""

    EXTERNAL_DOWNLOAD = "external_download"
    CREATE_VM = "create_vm"
    INSTALL_IN_VM = "install_in_vm"


PHASE_ORDER = (Phase.EXTERNAL_DOWNLOAD, Phase.CREATE_VM, Phase.INSTALL_IN_VM)

#: What the operator must type, per phase. Distinct per phase on purpose: a
#: single "yes" would let one confirmation stand for all three, which is the
#: thing the owner asked to avoid.
CONFIRMATION_PHRASE = {
    Phase.EXTERNAL_DOWNLOAD: "download the debian image",
    Phase.CREATE_VM: "create the disposable vm",
    Phase.INSTALL_IN_VM: "install live-build inside the vm",
}


class Refusal(Enum):
    PLAN_NOT_SHOWN = "plan_not_shown"
    CONFIRMATION_DID_NOT_MATCH = "confirmation_did_not_match"
    NOT_AN_ISSUED_APPROVAL = "not_an_issued_approval"
    APPROVAL_FOR_ANOTHER_PHASE = "approval_for_another_phase"
    APPROVAL_ALREADY_SPENT = "approval_already_spent"
    PHASE_OUT_OF_ORDER = "phase_out_of_order"
    HOST_BACKEND_UNAVAILABLE = "host_backend_unavailable"
    HOST_NOT_ELIGIBLE = "host_not_eligible"
    SIGNATURE_NOT_VERIFIED = "signature_not_verified"
    DIGEST_NOT_MATCHED = "digest_not_matched"
    VM_WOULD_NOT_BE_DISPOSABLE = "vm_would_not_be_disposable"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"
    NOT_A_FILE_THIS_SESSION_CREATED = "not_a_file_this_session_created"


class PrepareRefused(Exception):
    """The act did not happen.

    The detail names the rule and never a path, a URL, a VM name or a digest:
    these messages reach a terminal and a log, and the values come from the
    operator's own machine.
    """

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


class Approval:
    """Permission for **one** phase, of **one** session, spendable **once**.

    It carries no data a caller would want and cannot be usefully constructed:
    what makes it an approval is that `PrepareSession` is holding this exact
    object, checked with `is`. Copying, pickling and `dataclasses.replace` all
    produce something that is not it.
    """

    __slots__ = ("_phase",)

    def __init__(self, phase: Phase) -> None:
        object.__setattr__(self, "_phase", phase)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("an Approval is fixed when it is issued")

    def __reduce__(self):
        raise TypeError(
            "an Approval is not serialisable; it is permission held by one "
            "session, not a token that travels"
        )

    def __repr__(self) -> str:
        return f"Approval(phase={self._phase.value})"

    @property
    def phase(self) -> Phase:
        return self._phase


@dataclass(frozen=True)
class CleanupOutcome:
    """What a failure left behind, and who is removing it.

    `left_for_the_operator` is not a shortcoming. This tool does not delete a
    VM, and a failure is not an exception to that rule — a half-created machine
    on someone's laptop is theirs to inspect before it is destroyed.
    """

    removed: tuple[str, ...]
    left_for_the_operator: tuple[str, ...]

    def __repr__(self) -> str:
        return (
            f"CleanupOutcome(removed={len(self.removed)}, "
            f"left_for_the_operator={len(self.left_for_the_operator)})"
        )


def require_disposable(spec: VmSpec) -> None:
    """Refuse a VM that would not be disposable and isolated.

    All three are refusals for the same reason in different clothes: a shared
    folder makes the operator's filesystem part of the build, a host disk mount
    makes their storage part of it, and USB passthrough puts a real device
    within reach of an evaluation build — which is the B5 boundary, and it is
    not open.
    """

    if spec.shared_folders or spec.host_disk_mounts or spec.usb_passthrough:
        raise PrepareRefused(
            Refusal.VM_WOULD_NOT_BE_DISPOSABLE,
            "the evaluation VM has no shared folder, no host disk mount and no "
            "USB passthrough; the rule is the same one in three places",
        )


def require_verified_image(outcome: DownloadOutcome) -> None:
    """Both checks, independently, and `NOT_ATTEMPTED` is not a pass.

    A digest says two files are the same file. A signature says Debian
    published it. Checking one and reporting the other as satisfied is the
    failure this separation exists to prevent, so the two are separate fields
    and both are read here.
    """

    if outcome.signature is not SignatureCheck.VERIFIED:
        raise PrepareRefused(
            Refusal.SIGNATURE_NOT_VERIFIED,
            "only signed Debian inputs are used; an unverified image makes "
            "every later measurement evidence about a download",
        )
    if outcome.digest is not DigestCheck.MATCHED:
        raise PrepareRefused(
            Refusal.DIGEST_NOT_MATCHED,
            "the bytes on disk are not the bytes the signed checksum names",
        )


def execution_for(host_machine: str) -> Execution:
    """Native or emulated, decided from the host's own instruction set.

    An amd64 guest on an arm64 Mac is emulation. Recording it as native would
    let a later reader take a timing or a reproducibility conclusion from a run
    that cannot support one.
    """

    return (
        Execution.NATIVE_AMD64
        if host_machine in ("x86_64", "amd64")
        else Execution.EMULATED_AMD64_ON_ARM64
    )


class PrepareSession:
    """One preparation, on one host, with three approvals to collect.

    Not a dataclass and not a value: the issued approvals and the phases
    already run are its authority, and a caller that could assign to them would
    be the authority instead. `azazel_boot.quarantine` states the limit this
    shares — `object.__setattr__` writes the slot regardless, and Python has no
    way to prevent it. This is defence against a careless caller, not against
    code already running in the process.
    """

    __slots__ = (
        "_host_kind",
        "_backend",
        "_host_machine",
        "_plan_shown",
        "_issued",
        "_spent",
        "_completed",
        "_created_files",
        "_created_vms",
        "_sealed",
    )

    def __init__(
        self, host_kind: HostKind, backend: Backend | None, host_machine: str
    ) -> None:
        object.__setattr__(self, "_sealed", False)
        if backend is None:
            raise PrepareRefused(
                Refusal.HOST_BACKEND_UNAVAILABLE,
                "no virtualisation backend is installed on this host; one is "
                "never selected by inference and never installed by this tool",
            )
        if not isinstance(host_kind, HostKind):
            raise PrepareRefused(
                Refusal.HOST_NOT_ELIGIBLE,
                "an evaluation build runs in a disposable VM; a chroot, a "
                "container or this session's own machine shares a kernel",
            )
        self._host_kind = host_kind
        self._backend = backend
        self._host_machine = host_machine
        self._plan_shown = False
        self._issued: list[Approval] = []
        self._spent: list[Approval] = []
        self._completed: list[Phase] = []
        self._created_files: list[str] = []
        self._created_vms: list[str] = []
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            if name == "_plan_shown" and value is True:
                object.__setattr__(self, name, True)
                return
            raise AttributeError(
                "a PrepareSession is sealed after construction; the approvals "
                "it issued and the phases it ran cannot be replaced"
            )
        object.__setattr__(self, name, value)

    def __reduce__(self):
        raise TypeError("a PrepareSession is not serialisable")

    def __repr__(self) -> str:
        return (
            f"PrepareSession(backend={self._backend.value}, "
            f"plan_shown={self._plan_shown}, completed={len(self._completed)})"
        )

    @property
    def backend(self) -> Backend:
        return self._backend

    @property
    def execution(self) -> Execution:
        return execution_for(self._host_machine)

    def show_plan(self, lines: tuple[str, ...]) -> tuple[str, ...]:
        """Record that the plan was shown, and hand it back for printing.

        This is the only state change a session accepts from outside, and it is
        one-way. Approval is impossible before it.
        """

        self._plan_shown = True
        return lines

    def approve(self, phase: Phase, confirmation: str) -> Approval:
        """Mint permission for one phase. Refuses before the plan is shown."""

        if not self._plan_shown:
            raise PrepareRefused(
                Refusal.PLAN_NOT_SHOWN,
                "the plan is shown before anything is approved; an approval "
                "given without it is a confirmation of nothing",
            )
        expected = CONFIRMATION_PHRASE[phase]
        if confirmation.strip().lower() != expected:
            raise PrepareRefused(
                Refusal.CONFIRMATION_DID_NOT_MATCH,
                "each phase has its own confirmation phrase, so one answer "
                "cannot stand for all three",
            )
        approval = Approval(phase)
        self._issued.append(approval)
        return approval

    def run(
        self,
        phase: Phase,
        approval: Approval,
        executor: Executor,
        **arguments: object,
    ) -> object:
        """Perform one approved phase, in order, once.

        The executor arrives **here** and nowhere earlier: a session that has
        not reached this call has no object capable of reaching the network or
        creating a machine.
        """

        self._require_approval(phase, approval)
        self._require_in_order(phase)

        if phase is Phase.EXTERNAL_DOWNLOAD:
            result = self._download(executor, arguments)
        elif phase is Phase.CREATE_VM:
            result = self._create(executor, arguments)
        else:
            result = self._install(executor, arguments)

        self._spent.append(approval)
        self._completed.append(phase)
        return result

    def cleanup(self, executor: Executor) -> CleanupOutcome:
        """Remove what this session created, except a VM.

        A half-created VM is left for the operator, named, rather than deleted.
        Deleting one is not something this tool does, and a failure does not
        make it something it does.
        """

        removed: list[str] = []
        for path in tuple(self._created_files):
            if path not in self._created_files:
                raise PrepareRefused(
                    Refusal.NOT_A_FILE_THIS_SESSION_CREATED,
                    "cleanup removes what this session made and nothing else",
                )
            executor.remove_created_file(path)
            removed.append(path)
        self._created_files.clear()
        return CleanupOutcome(
            removed=tuple(removed), left_for_the_operator=tuple(self._created_vms)
        )

    def evidence(self, **fields: object) -> VmEvidence:
        """Assemble the record, with the two fields this session already knows.

        `backend` and `execution` are not the caller's to supply: they are what
        this session measured and selected, and a record that took them as
        arguments would let a run on an emulated host be written up as native.
        """

        return VmEvidence(
            host_kind=self._host_kind,
            backend=self._backend,
            execution=self.execution,
            stamp=STAMP,
            **fields,  # type: ignore[arg-type]
        )

    # -- internals ---------------------------------------------------------

    def _require_approval(self, phase: Phase, approval: Approval) -> None:
        if not any(issued is approval for issued in self._issued):
            raise PrepareRefused(
                Refusal.NOT_AN_ISSUED_APPROVAL,
                "an approval is the object this session minted, not one that "
                "looks like it; a copy, a pickle and a rebuild are not it",
            )
        if any(spent is approval for spent in self._spent):
            raise PrepareRefused(
                Refusal.APPROVAL_ALREADY_SPENT,
                "one approval permits one act; re-running a phase is a new "
                "confirmation",
            )
        if approval.phase is not phase:
            raise PrepareRefused(
                Refusal.APPROVAL_FOR_ANOTHER_PHASE,
                "permission to download is not permission to create a machine",
            )

    def _require_in_order(self, phase: Phase) -> None:
        expected = PHASE_ORDER[len(self._completed)] if len(self._completed) < 3 else None
        if phase is not expected:
            raise PrepareRefused(
                Refusal.PHASE_OUT_OF_ORDER,
                "a VM is created from a verified image and a package is "
                "installed into a VM that exists",
            )

    def _download(self, executor: Executor, arguments: dict) -> DownloadOutcome:
        outcome = executor.download_and_verify(
            str(arguments["source"]), str(arguments["into"])
        )
        # Recorded before verification: a file that arrived and failed its
        # checks is exactly the file cleanup has to be able to remove.
        self._created_files.append(outcome.stored_at)
        require_verified_image(outcome)
        return outcome

    def _create(self, executor: Executor, arguments: dict) -> str:
        spec = arguments["spec"]
        assert isinstance(spec, VmSpec)
        require_disposable(spec)
        handle = executor.create_vm(spec)
        self._created_vms.append(handle)
        return handle

    def _install(self, executor: Executor, arguments: dict) -> str:
        return executor.install_in_vm(
            str(arguments["vm_handle"]), str(arguments["package"])
        )


@dataclass(frozen=True)
class PreparePlan:
    """What `prepare-host` would do, shown before any of it is approved."""

    backend: Backend
    execution: Execution
    lines: tuple[str, ...] = field(default_factory=tuple)


def plan_lines(backend: Backend, execution: Execution) -> tuple[str, ...]:
    """The plan, as lines, carrying no value from the operator's machine.

    The backend and the execution class are this tool's own vocabulary, so they
    are safe to print; a path, a VM name or a URL is not, and none appears.
    """

    lines = [
        f"backend: {backend.value}",
        f"execution: {execution.value}",
        f"stamp: {STAMP}",
        "",
        "three acts, each confirmed on its own:",
    ]
    for index, phase in enumerate(PHASE_ORDER, start=1):
        lines.append(f"  {index}. {phase.value} — type: {CONFIRMATION_PHRASE[phase]!r}")
    lines += [
        "",
        "this command does not:",
        "  install anything on this host",
        "  escalate privilege on this host",
        "  delete a VM, yours or its own",
        "  touch a USB device, an internal disk or a release",
    ]
    if execution is Execution.EMULATED_AMD64_ON_ARM64:
        lines += [
            "",
            "this host runs the amd64 guest emulated. the build is an "
            "evaluation; no timing, reproducibility or support conclusion "
            "follows from it",
        ]
    return tuple(lines)
