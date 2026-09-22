"""A snapshot inside the partition, a preflight that refuses, and a recovery
that produces a **candidate** rather than a usable volume.

[ADR-0010](../../docs/adr/0010-persistence-key-and-migration.md) D6, D7 and D8,
implemented. Azazel-Boot#42.

## The one rule everything here is built around

**Recovery does not lift the quarantine. Nothing here does.**

A recovery that succeeded produces a :class:`RecoveryCandidate`, and a
candidate is not a volume. It cannot be read, written, exported or mounted. The
`Quarantine` that judged the medium stays quarantined afterwards — after a
success, after a failure, after an interruption, without exception and without
a call that would change it.

Getting back to ordinary use means a **different session**, starting over:
commissioning, the media binding, key acquisition, integrity verification and
an operator confirmation, all from the beginning. That is not an inconvenience
to be optimised away later. A recovery workflow that ended the quarantine would
*be* the unquarantine call ADR-0010 D4 refuses, wearing four gates as a
disguise, and the gates would be the only thing standing between a torn volume
and ordinary use.

So `tests/unit/test_snapshot.py` checks it structurally rather than trusting the
prose: there is no call here that clears a quarantine or a fence, no module-level
function whose name suggests one, and a test drives a completed recovery and
then asserts the original quarantine still refuses every ordinary act.

## What this module does not do

**It performs no I/O at all.** It reads no device, opens no volume, writes no
snapshot and measures no free space. The caller performs those acts and reports
what it saw, in the closed vocabularies below, and what is here is the
judgement about whether the next act is permitted. That is the same division
`azazel_boot.persistence` states, in the same words, for the same reason: this
package may not touch a device
([#1](https://github.com/01rabbit/Azazel-Boot/issues/1), enforced by
`tests/unit/test_boundary_static.py`).

So **no storage behaviour here is implemented or demonstrated.** No snapshot
has been written, no migration run, no trial interrupted, no restore attempted,
on any device. The real key acquisition and the real LUKS unlock do not exist
either ([ADR-0011](../../docs/adr/0011-unlock-helper-boundary.md)), so a
recovery cannot complete outside a test in any case.

## Nothing leaves the partition

No second partition, no host disk, no network, no USB export, and no temporary
file anywhere — not "just while the migration runs". ADR-0010 D9 forbids it and
D6 keeps the snapshot inside the single existing encrypted persistence
partition so that [ADR-0008](../../docs/adr/0008-debian-13-live-baseline.md)
D4.1's three-partition layout is not revised.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .commissioning import SessionBinding, binding_applies
from .inventory import InterfaceObservation
from .quarantine import Quarantine
from .session_mode import AttemptOutcome, KeyAcquisition, PassphraseChannel

#: The snapshot container formats this module can read. An unknown version is
#: refused, never guessed at: a snapshot whose layout nobody here knows is a
#: sequence of bytes with a hopeful name on it.
#:
#: A tuple, pinned literally, rather than a range. `<= LATEST` would accept
#: every version anyone ever writes, including the ones written after this code
#: was last read.
KNOWN_CONTAINER_VERSIONS = (1,)


class SnapshotIntegrity(Enum):
    """Whether the snapshot verified **on its own**.

    ADR-0010 D6 requires it to be verifiable without the live data it exists to
    replace: a snapshot that can only be judged by the thing it would restore
    is not a snapshot. Nothing in this module takes the live data and the
    snapshot together, and a test asserts that on the signatures.
    """

    VERIFIED = "verified"
    FAILED = "failed"
    #: The check could not be completed. Not "probably fine" — see D7.
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class SnapshotDescriptor:
    """What a snapshot says about itself. Versioned, and judged alone.

    `fingerprint` is **opaque**: a value the caller computed, which this module
    compares and never interprets. It is not a device identity, not a path and
    not a key, and the audit carries it only because "which snapshot" has to be
    answerable without naming anything about the medium.
    """

    container_version: int
    schema_version: int
    integrity: SnapshotIntegrity
    fingerprint: str

    def __post_init__(self) -> None:
        # Checked where it is built. `azazel_boot.dirty_write` learned this the
        # expensive way: an annotation is not a check, and a review built its
        # observation out of three strings naming the worst faults there are
        # and got a clean write.
        if not isinstance(self.integrity, SnapshotIntegrity):
            raise TypeError("integrity must be a member of SnapshotIntegrity")
        for name, value in (
            ("container_version", self.container_version),
            ("schema_version", self.schema_version),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise TypeError(f"{name} must be a positive integer version")
        if not isinstance(self.fingerprint, str) or not self.fingerprint.strip():
            raise TypeError("fingerprint must be a non-empty opaque string")

    def __repr__(self) -> str:
        """Redacted. A fingerprint in a repr is a fingerprint in every traceback."""

        return (
            f"SnapshotDescriptor(container_version={self.container_version}, "
            f"schema_version={self.schema_version}, "
            f"integrity={self.integrity.value}, fingerprint=<redacted>)"
        )


@dataclass(frozen=True)
class CapacityReport:
    """Space, as the caller measured it. **These numbers never reach an audit.**

    They describe the operator's medium — how much they are carrying and how
    much of it is used — and ADR-0010 D10's rule about the audit is that it
    holds classifications. Which check refused is a classification; how many
    bytes were short is a measurement of somebody's hardware.
    """

    required: int
    available: int

    def __post_init__(self) -> None:
        for name, value in (("required", self.required), ("available", self.available)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TypeError(f"{name} must be a non-negative integer")

    def __repr__(self) -> str:
        return "CapacityReport(<redacted>)"


class PreflightCheck(Enum):
    """The closed vocabulary of what a preflight refuses on.

    Each failing check refuses with its **own** member, so an operator learns
    which one — ADR-0010 D7 — without learning any figure behind it.
    """

    SNAPSHOT_ABSENT = "snapshot_absent"
    SNAPSHOT_CONTAINER_UNKNOWN = "snapshot_container_unknown"
    SNAPSHOT_INTEGRITY = "snapshot_integrity"
    REQUIRED_SPACE = "required_space"
    SCHEMA_COMPATIBILITY = "schema_compatibility"
    BINDING = "binding"
    GENERATION = "generation"
    IMAGE_DIGEST = "image_digest"
    MEDIUM_FENCED = "medium_fenced"
    VOLUME_QUARANTINED = "volume_quarantined"


class PreflightVerdict:
    """Read-only, and the whole of what a preflight produces.

    `refused_by` is `None` when every check passed. There is no `PASSED`
    member, for the reason `azazel_boot.dirty_write.classify` returns `None`
    rather than a `CLEAN`: a member meaning "fine" is a value later code
    compares against and proceeds on.

    **It is minted by `preflight` and checked by identity**, like
    `azazel_boot.session_mode.CommissionedMode`. It was a plain frozen
    dataclass first, and a review pointed out what that meant: the only object
    saying "a migration may run" was constructible by exactly the caller the
    preflight exists to gate. `MigrationLedger` read `may_migrate` and nothing
    else, so `PreflightVerdict(None)` handed to it authorised a migration over
    a snapshot whose integrity had **failed**, with no preflight ever having
    run. That is the same "rebuild the object a legitimate caller holds" attack
    that defeated the fence and then the volume quarantine.

    So a verdict carries a token this module mints, and
    `verdict_was_minted_here` is what a consumer asks.
    """

    __slots__ = ("_refused_by", "_token")

    def __init__(self, refused_by: PreflightCheck | None) -> None:
        """No `token` parameter. It used to take one, and that was the hole.

        `preflight` stamped the sentinel through this signature, so every
        verdict a caller was handed — **including a refusal** — carried it on
        `_token`, readable with one attribute access. A re-review read it off a
        refused verdict, built `PreflightVerdict(None, stolen)`, and authorised
        a migration over a snapshot whose integrity had **failed**, recorded as
        written. A token a caller is given is not a token.

        The sentinel is now stamped by `_mint`, which is module-private and is
        the only thing that writes `_token`.
        """

        object.__setattr__(self, "_refused_by", refused_by)
        object.__setattr__(self, "_token", None)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("a PreflightVerdict is fixed when it is minted")

    def __reduce__(self):
        raise TypeError("a PreflightVerdict is not serialisable")

    def __repr__(self) -> str:
        decided = self._refused_by.value if self._refused_by is not None else "may_migrate"
        return f"PreflightVerdict({decided})"

    @property
    def refused_by(self) -> PreflightCheck | None:
        return self._refused_by

    @property
    def may_migrate(self) -> bool:
        """Whether the checks passed. **Not whether this module said so** —
        that is `verdict_was_minted_here`, and a consumer asks it first."""

        return self._refused_by is None

    @property
    def authority(self) -> tuple[()]:
        """Empty. A passed preflight permits a migration; it authorises nothing."""

        return ()


#: The token `_mint` stamps into the verdicts this module produces. A
#: module-private object with no constructor a caller can reach: identity is
#: the whole of it.
_MINTED_HERE = object()


def _mint(refused_by: PreflightCheck | None) -> PreflightVerdict:
    """Build a verdict and stamp it. The only thing that writes `_token`."""

    verdict = PreflightVerdict(refused_by)
    object.__setattr__(verdict, "_token", _MINTED_HERE)
    return verdict


def verdict_was_minted_here(verdict: PreflightVerdict) -> bool:
    """Whether this module produced that verdict. Checked by identity.

    A hand-built `PreflightVerdict(None)` is not one, and `MigrationLedger`
    refuses it rather than reading `may_migrate` and believing it.
    """

    return (
        isinstance(verdict, PreflightVerdict)
        and type(verdict) is PreflightVerdict
        and verdict._token is _MINTED_HERE
    )


#: Schema versions this build can migrate **to**. A downgrade is not on it.
SUPPORTED_SCHEMA_VERSIONS = (1, 2)


def schema_is_compatible(*, current: int, target: int) -> bool:
    """Forward, by one known step, and never backwards.

    A downgrade is refused rather than attempted: the old schema continuing to
    work is D7's safe outcome, and writing an older layout over a newer one is
    the opposite of keeping it.
    """

    if current not in SUPPORTED_SCHEMA_VERSIONS or target not in SUPPORTED_SCHEMA_VERSIONS:
        return False
    return target > current


def preflight(
    quarantine: Quarantine,
    *,
    snapshot: SnapshotDescriptor | None,
    capacity: CapacityReport,
    current_schema: int,
    target_schema: int,
    binding_holds: bool,
    generation_holds: bool,
    image_digest_holds: bool,
) -> PreflightVerdict:
    """Check everything, change nothing, and refuse on the first failure.

    **Read-only by construction**: it takes reports and returns a verdict. It
    has no port to write through, and a refused migration has written nothing
    because nothing here writes at all.

    The order is fixed and part of the contract. The fence is asked **first** —
    ADR-0010 D9 says a version upgrade is not a way round it, and asking a
    removed medium about its free space would mean reasoning about a device
    that is not there. Then the snapshot, because D7's rule is that **there is
    no migration without one**, and checking capacity before establishing that
    a way back exists would put the cheap answer in front of the load-bearing
    one.
    """

    # Checked, not merely annotated. The descriptor learned that lesson and
    # these did not — including the **quarantine**, which was the one input
    # nothing checked at all: a re-review passed a two-attribute stand-in
    # (`is_fenced = False`, `volume_is_quarantined = True`) and both gates that
    # precede D8's four were satisfied by class attributes.
    if not isinstance(quarantine, Quarantine):
        raise TypeError("quarantine must be a Quarantine; a stand-in is not one")
    for name, value in (
        ("binding_holds", binding_holds),
        ("generation_holds", generation_holds),
        ("image_digest_holds", image_digest_holds),
    ):
        if not isinstance(value, bool):
            raise TypeError(f"{name} must be a bool; a truthy object is not a check")
    if not isinstance(capacity, CapacityReport):
        raise TypeError("capacity must be a CapacityReport")
    if snapshot is not None and not isinstance(snapshot, SnapshotDescriptor):
        raise TypeError("snapshot must be a SnapshotDescriptor or None")

    if quarantine.is_fenced:
        return _mint(PreflightCheck.MEDIUM_FENCED)
    if quarantine.volume_is_quarantined:
        # The recovery path treated a quarantined volume as load-bearing and
        # this one treated it as invisible, which a review caught. ADR-0010 D4
        # stops the **whole volume** on a suspected torn write, and a schema
        # migration is a large write to exactly that volume.
        return _mint(PreflightCheck.VOLUME_QUARANTINED)

    if snapshot is None:
        # D7: no flag, no acceptance, no emergency state. An operator cannot
        # consent to this, because what they would be consenting to is the loss
        # of the only path back — so there is no parameter to consent with.
        return _mint(PreflightCheck.SNAPSHOT_ABSENT)
    if snapshot.container_version not in KNOWN_CONTAINER_VERSIONS:
        return _mint(PreflightCheck.SNAPSHOT_CONTAINER_UNKNOWN)
    if snapshot.integrity is not SnapshotIntegrity.VERIFIED:
        # `INDETERMINATE` lands here with `FAILED`. D7: ambiguity refuses the
        # migration, and there is no third answer that proceeds.
        return _mint(PreflightCheck.SNAPSHOT_INTEGRITY)

    if capacity.available < capacity.required:
        # No degraded migration, no "we can fit most of it". A medium too small
        # keeps the old schema and keeps working.
        return _mint(PreflightCheck.REQUIRED_SPACE)

    if not schema_is_compatible(current=current_schema, target=target_schema):
        return _mint(PreflightCheck.SCHEMA_COMPATIBILITY)

    if not binding_holds:
        return _mint(PreflightCheck.BINDING)
    if not generation_holds:
        return _mint(PreflightCheck.GENERATION)
    if not image_digest_holds:
        return _mint(PreflightCheck.IMAGE_DIGEST)

    return _mint(None)


class RecoveryStage(Enum):
    """Where a recovery is. One direction, and no stage is skipped.

    There is no `AUTOMATIC` and no `RETRY`: ADR-0010 D8 refuses an automatic
    restore because it means writing at the moment the state is least
    understood, and a background retry is an automatic restore with a delay.
    """

    NOT_STARTED = "not_started"
    PREFLIGHT_PASSED = "preflight_passed"
    TRIAL_OPEN = "trial_open"
    COMMITTED = "committed"
    REFUSED = "refused"
    INTERRUPTED = "interrupted"


#: The stages a recovery cannot leave. Reaching one of these ends the workflow
#: for good — there is no call that restarts it, because restarting is a new
#: workflow that runs every gate again from the beginning.
TERMINAL_STAGES = (
    RecoveryStage.COMMITTED,
    RecoveryStage.REFUSED,
    RecoveryStage.INTERRUPTED,
)


class RecoveryGate(Enum):
    """ADR-0010 D8's four, in D8's order, plus the two that precede them.

    The fence and the quarantine are asked before the four, not instead of
    them: a recovery is *for* a quarantined volume, so the quarantine is not a
    refusal here — but a **fenced** medium is, and a volume nobody quarantined
    has nothing to recover.
    """

    MEDIUM_FENCED = "medium_fenced"
    NOTHING_TO_RECOVER = "nothing_to_recover"
    TARGET_BINDING = "target_binding"
    KEY_ACQUISITION = "key_acquisition"
    INTEGRITY_VERIFICATION = "integrity_verification"
    OPERATOR_CONFIRMATION = "operator_confirmation"


class Refusal(Enum):
    """Why an act did not happen. Each names a **rule**, never a value."""

    MIGRATION_REFUSED_BY_PREFLIGHT = "migration_refused_by_preflight"
    RECOVERY_NOT_STARTED_BY_AN_OPERATOR = "recovery_not_started_by_an_operator"
    STAGE_SKIPPED = "stage_skipped"
    WORKFLOW_ALREADY_FINISHED = "workflow_already_finished"
    GATE_REFUSED = "gate_refused"
    SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW = "snapshot_changed_under_the_workflow"
    NOT_THIS_SITTING = "not_this_sitting"
    VERDICT_NOT_MINTED_BY_A_PREFLIGHT = "verdict_not_minted_by_a_preflight"


class RecoveryRefused(Exception):
    """The act did not happen, and the message names the rule.

    It never carries a fingerprint, a schema version, a capacity figure, a
    device identity, a path or an operator identifier: these strings reach a
    console and a log on media that travels through uncontrolled hands.
    """

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


class SnapshotAuditEvent(Enum):
    """The transitions this module may record. Classifications, nothing else."""

    MIGRATION_REFUSED = "migration_refused"
    SNAPSHOT_WRITTEN = "snapshot_written"
    RECOVERY_STARTED = "recovery_started"
    RECOVERY_TRIAL_OPENED = "recovery_trial_opened"
    RECOVERY_COMPLETED = "recovery_completed"
    RECOVERY_REFUSED = "recovery_refused"
    RECOVERY_INTERRUPTED = "recovery_interrupted"
    #: The substitution this design exists to notice. It used to raise and
    #: leave no trace, so the workflow could simply be retried with the
    #: original snapshot and nothing recorded that a swap had been attempted.
    RECOVERY_SNAPSHOT_SUBSTITUTED = "recovery_snapshot_substituted"


@dataclass(frozen=True)
class SnapshotAuditEntry:
    """A classification, and at most which check or gate it concerns.

    There is **no** field for snapshot contents, a byte count, a free-space
    figure, a capacity, a raw key, a passphrase, a device identity, a path or
    an operator identifier. `schema_version` is here because ADR-0010's list of
    permitted payload names it, and `fingerprint` because "which snapshot" has
    to be answerable — it is the caller's opaque value, never an identity.
    """

    event: SnapshotAuditEvent
    check: PreflightCheck | None = None
    gate: RecoveryGate | None = None
    schema_version: int | None = None
    fingerprint: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        """Redacting, because **this** is the object destined for a log.

        `SnapshotDescriptor.__repr__` redacted the fingerprint with the comment
        that one in a repr is one in every traceback — and then the same value
        rendered verbatim through the generated repr of this class, which is
        what an operator-facing log actually holds. A review found it by
        rendering `repr(workflow.audit())`, which the absence test had not.
        """

        parts = [f"event={self.event.value}"]
        if self.check is not None:
            parts.append(f"check={self.check.value}")
        if self.gate is not None:
            parts.append(f"gate={self.gate.value}")
        if self.schema_version is not None:
            parts.append(f"schema_version={self.schema_version}")
        if self.fingerprint is not None:
            parts.append("fingerprint=<redacted>")
        return f"SnapshotAuditEntry({', '.join(parts)})"


class RecoveryCandidate:
    """What a completed recovery produces. **It is not a volume.**

    It cannot be read, written, exported or mounted, and there is no method
    here that does any of those. It says which schema version a restore **would
    reach** and which snapshot it came from, and its `authority` is `()`.

    Not "was restored": nothing has been restored, by this module or by
    anything else in this repository. `RECOVERY_COMPLETED` classifies what a
    caller reported, not an act performed here.

    **The medium it came from is still quarantined.** Holding one of these does
    not change that and is not meant to: returning to ordinary use means a
    different session, from the beginning — commissioning, the media binding,
    key acquisition, integrity verification and an operator confirmation. A
    candidate is the evidence that a restore *could* be made, handed to whoever
    decides whether to start that.

    Minted by one workflow and checked by identity, like
    `azazel_boot.session_mode.CommissionedMode` — and, unlike the first
    version of this class, there is now something that can *do* the checking.
    That version carried the sentence and shipped no checker, so "checked by
    identity" described a thing nobody could perform; a constructed candidate
    answered every question exactly as a minted one did.

    **Reading `schema_version` is not asking whether a workflow minted this.**
    Anyone can build a `RecoveryCandidate(99, …)` and it will answer `99`,
    because the property reads the field it was handed. Ask
    :func:`candidate_applies_to` first — the same rule
    `CommissionedMode.is_persistent` states, in the same words, for the same
    reason.
    """

    __slots__ = ("_schema_version", "_fingerprint")

    def __init__(self, schema_version: int, fingerprint: str) -> None:
        object.__setattr__(self, "_schema_version", schema_version)
        object.__setattr__(self, "_fingerprint", fingerprint)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(
            "a RecoveryCandidate is fixed when it is minted; what it says was "
            "restored cannot be edited afterwards"
        )

    def __reduce__(self):
        raise TypeError(
            "a RecoveryCandidate is not serialisable; it belongs to one "
            "workflow in one session, not to a file that outlives it"
        )

    def __repr__(self) -> str:
        return (
            f"RecoveryCandidate(schema_version={self._schema_version}, "
            f"fingerprint=<redacted>)"
        )

    @property
    def schema_version(self) -> int:
        return self._schema_version

    @property
    def authority(self) -> tuple[()]:
        """Empty. A candidate is evidence, not permission.

        A subclass can override this and nothing type-checks a candidate, which
        is why :func:`candidate_applies_to` refuses anything that is not
        exactly this class rather than merely an instance of it.
        """

        return ()


class RecoveryWorkflow:
    """Operator-started, one-way, and it never lifts the quarantine.

    Every stage is entered explicitly by a caller acting for an operator. There
    is no automatic start, no retry, no background attempt and no resumption
    after a terminal stage — a resumed workflow is a new workflow that runs
    every gate again, which is what starting one does.

    The gates are re-checked **before the trial opens and again before the
    commit**, not once at the start. The medium can be pulled and the snapshot
    can change while an operator reads a confirmation screen, and a gate
    checked once is a gate checked at a moment that has passed.
    """

    __slots__ = (
        "_quarantine",
        "_binding",
        "_session_id",
        "_stage",
        "_audit",
        "_snapshot",
        "_candidate",
        "_sealed",
    )

    def __init__(
        self, quarantine: Quarantine, binding: SessionBinding, *, session_id: str
    ) -> None:
        if not isinstance(quarantine, Quarantine):
            raise TypeError("quarantine must be a Quarantine; a stand-in is not one")
        if not isinstance(binding, SessionBinding):
            raise TypeError("binding must be a SessionBinding")
        if not isinstance(session_id, str) or not session_id.strip():
            raise TypeError("session_id must be a non-empty string")

        object.__setattr__(self, "_sealed", False)
        self._quarantine = quarantine
        self._binding = binding
        self._session_id = session_id
        self._stage = RecoveryStage.NOT_STARTED
        self._snapshot: SnapshotDescriptor | None = None
        self._candidate: RecoveryCandidate | None = None
        self._audit: list[SnapshotAuditEntry] = []
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError(
                "a RecoveryWorkflow is sealed after construction; the stage "
                "advances through its own methods and the quarantine, the "
                "binding and the sitting cannot be replaced"
            )
        object.__setattr__(self, name, value)

    def __reduce__(self):
        raise TypeError("a RecoveryWorkflow is not serialisable")

    def __repr__(self) -> str:
        return f"RecoveryWorkflow(stage={self._stage.value})"

    @property
    def stage(self) -> RecoveryStage:
        return self._stage

    def audit(self) -> tuple[SnapshotAuditEntry, ...]:
        return tuple(self._audit)

    # -- the workflow, one stage at a time ---------------------------------

    def start(
        self,
        snapshot: SnapshotDescriptor,
        observations: tuple[InterfaceObservation, ...],
        *,
        session_id: str,
        started_by_operator: bool,
    ) -> None:
        """An operator starts this. Nothing else does.

        `started_by_operator` is a required keyword with no default, so a
        caller cannot reach this by omission. A default of `True` would make
        the automatic start ADR-0010 D8 refuses the easiest thing to write, and
        a default of `False` would make it a flag somebody flips.

        The fence and the quarantine are checked here, and **again** before the
        trial and before the commit. A medium can be pulled while an operator
        reads a screen.
        """

        self._require_stage(RecoveryStage.NOT_STARTED)
        self._require_this_sitting(session_id)
        if not started_by_operator:
            # Audited, and terminal. It used to take the silent `_refuse`, so
            # three refused automatic starts left `stage=NOT_STARTED, audit=()`
            # and a real start then succeeded with no record that D8's central
            # prohibition had been exercised — the same reasoning that made a
            # snapshot substitution terminal and audited. A start nothing
            # started is an event, not a typo.
            self._sealed_assign("_stage", RecoveryStage.REFUSED)
            self._record(SnapshotAuditEvent.RECOVERY_REFUSED)
            self._refuse(
                Refusal.RECOVERY_NOT_STARTED_BY_AN_OPERATOR,
                "a restore is something an operator begins deliberately; "
                "nothing here starts one on its own, retries one, or resumes "
                "one in the background",
            )
        self._require_the_gates(snapshot, observations, session_id=session_id)

        self._sealed_assign("_snapshot", snapshot)
        self._sealed_assign("_stage", RecoveryStage.PREFLIGHT_PASSED)
        self._record(
            SnapshotAuditEvent.RECOVERY_STARTED,
            schema_version=snapshot.schema_version,
            fingerprint=snapshot.fingerprint,
        )

    def open_trial(
        self,
        snapshot: SnapshotDescriptor,
        observations: tuple[InterfaceObservation, ...],
        *,
        session_id: str,
    ) -> None:
        """Open the trial, with every gate asked again.

        The snapshot is passed again and compared against the one the workflow
        started on. A snapshot that changed under the workflow is refused
        rather than used: an older snapshot substituted between the start and
        the trial is the substitution this whole design exists to notice.
        """

        self._require_stage(RecoveryStage.PREFLIGHT_PASSED)
        self._require_this_sitting(session_id)
        self._require_the_same_snapshot(snapshot)
        self._require_the_gates(snapshot, observations, session_id=session_id)

        self._sealed_assign("_stage", RecoveryStage.TRIAL_OPEN)
        self._record(SnapshotAuditEvent.RECOVERY_TRIAL_OPENED)

    def commit(
        self,
        snapshot: SnapshotDescriptor,
        observations: tuple[InterfaceObservation, ...],
        *,
        session_id: str,
        acquisition: KeyAcquisition,
        confirmed: bool,
    ) -> RecoveryCandidate:
        """Finish, and produce a **candidate**. The quarantine does not move.

        This is the whole of what a successful recovery yields: an object
        saying which schema version was restored and which snapshot it came
        from. The `Quarantine` is exactly as quarantined afterwards as before,
        the fence is untouched, and no capability rises.

        All four of D8's gates run here, in D8's order, because this is the
        act: target binding, key acquisition, integrity verification, operator
        confirmation.
        """

        self._require_stage(RecoveryStage.TRIAL_OPEN)
        self._require_this_sitting(session_id)
        self._require_the_same_snapshot(snapshot)
        self._require_the_gates(
            snapshot, observations, session_id=session_id, acquisition=acquisition
        )
        if not confirmed:
            self._refuse_gate(RecoveryGate.OPERATOR_CONFIRMATION)

        self._sealed_assign("_stage", RecoveryStage.COMMITTED)
        self._record(
            SnapshotAuditEvent.RECOVERY_COMPLETED,
            schema_version=snapshot.schema_version,
            fingerprint=snapshot.fingerprint,
        )
        minted = RecoveryCandidate(snapshot.schema_version, snapshot.fingerprint)
        self._sealed_assign("_candidate", minted)
        return minted

    def holds(self, candidate: RecoveryCandidate) -> bool:
        """Whether this workflow minted that candidate. Checked by identity.

        The `is not None` is not redundant: without it an uncommitted workflow
        answers `True` for `None`, and `None` is what `_candidate` is until a
        commit — the trap `azazel_boot.persistence.PersistenceSession.holds`
        was found in.
        """

        return self._candidate is not None and self._candidate is candidate

    def interrupt(self) -> None:
        """The operator stopped, or the machine did. Terminal, and fail-closed.

        Nothing is partially restored and nothing is retried. The volume stays
        quarantined, which it was before this workflow and is after it.
        """

        if self._stage in TERMINAL_STAGES:
            self._refuse(
                Refusal.WORKFLOW_ALREADY_FINISHED,
                "this workflow has ended; a further attempt is a new workflow "
                "that runs every gate again",
            )
        self._sealed_assign("_stage", RecoveryStage.INTERRUPTED)
        self._record(SnapshotAuditEvent.RECOVERY_INTERRUPTED)

    # -- internals ---------------------------------------------------------

    def _require_this_sitting(self, session_id: str) -> None:
        """The workflow's own sitting, enforced rather than merely stored.

        `_session_id` was assigned in `__init__` and read nowhere, while
        `__setattr__` claimed "the quarantine, the binding and the sitting
        cannot be replaced". A field whose presence implies a check that does
        not exist is worse than no field: a review committed a workflow built
        for one sitting by passing another one's id to every stage.
        """

        if session_id != self._session_id:
            self._refuse(
                Refusal.NOT_THIS_SITTING,
                "this workflow belongs to one sitting; a stage asked for "
                "another is refused rather than answered",
            )

    def _require_stage(self, expected: RecoveryStage) -> None:
        if self._stage in TERMINAL_STAGES:
            self._refuse(
                Refusal.WORKFLOW_ALREADY_FINISHED,
                "this workflow has ended; a further attempt is a new workflow "
                "that runs every gate again",
            )
        if self._stage is not expected:
            self._refuse(
                Refusal.STAGE_SKIPPED,
                "a recovery advances one stage at a time and skips none; "
                "the stage this was asked for is not the stage it is in",
            )

    def _require_the_same_snapshot(self, snapshot: SnapshotDescriptor) -> None:
        """Terminal and audited, because a swap is an event, not a typo.

        This used to raise without touching the stage or the audit, so a caller
        could present a substituted snapshot, be refused, and simply retry with
        the original — with nothing recording that a substitution had been
        attempted. The module called this "the substitution this whole design
        exists to notice", and nothing was left that had noticed it.
        """

        if self._snapshot is None or snapshot != self._snapshot:
            self._sealed_assign("_stage", RecoveryStage.REFUSED)
            self._record(SnapshotAuditEvent.RECOVERY_SNAPSHOT_SUBSTITUTED)
            self._refuse(
                Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW,
                "the snapshot presented now is not the one this workflow "
                "started on; a substituted snapshot is refused, not restored",
            )

    def _require_the_gates(
        self,
        snapshot: SnapshotDescriptor,
        observations: tuple[InterfaceObservation, ...],
        *,
        session_id: str,
        acquisition: KeyAcquisition | None = None,
    ) -> None:
        """D8's gates, in D8's order, with the two that precede them.

        Each is driven failing on its own in `tests/unit/test_snapshot.py` to
        show the next is not reached, because an order nobody tests is an order
        that holds until someone tidies the function.
        """

        if self._quarantine.is_fenced:
            self._refuse_gate(RecoveryGate.MEDIUM_FENCED)
        if not self._quarantine.volume_is_quarantined:
            # A volume nobody quarantined has nothing to recover, and running
            # this workflow over a healthy one would be a restore of live data
            # from a snapshot — the write ADR-0010 D8 refuses to make
            # automatically, made deliberately over something that was fine.
            self._refuse_gate(RecoveryGate.NOTHING_TO_RECOVER)

        if not binding_applies(self._binding, observations, session_id=session_id):
            self._refuse_gate(RecoveryGate.TARGET_BINDING)

        if acquisition is not None:
            if acquisition.channel is not PassphraseChannel.LOCAL_HIDDEN_PROMPT:
                self._refuse_gate(RecoveryGate.KEY_ACQUISITION)
            if acquisition.attempt() is not AttemptOutcome.OPENED:
                # D1's sources under D2's limit, reused rather than
                # reimplemented: the acquisition is the same Protocol
                # `session_mode` defines, and what crosses back is the same
                # single enum value. This module never sees a passphrase.
                self._refuse_gate(RecoveryGate.KEY_ACQUISITION)

        if snapshot.integrity is not SnapshotIntegrity.VERIFIED:
            self._refuse_gate(RecoveryGate.INTEGRITY_VERIFICATION)
        if snapshot.container_version not in KNOWN_CONTAINER_VERSIONS:
            self._refuse_gate(RecoveryGate.INTEGRITY_VERIFICATION)

    def _refuse_gate(self, gate: RecoveryGate) -> None:
        self._sealed_assign("_stage", RecoveryStage.REFUSED)
        self._record(SnapshotAuditEvent.RECOVERY_REFUSED, gate=gate)
        _raise_gate_refused()

    def _refuse(self, refusal: Refusal, detail: str) -> None:
        raise RecoveryRefused(refusal, detail)

    def _record(
        self,
        event: SnapshotAuditEvent,
        *,
        check: PreflightCheck | None = None,
        gate: RecoveryGate | None = None,
        schema_version: int | None = None,
        fingerprint: str | None = None,
    ) -> None:
        self._audit.append(
            SnapshotAuditEntry(
                event=event,
                check=check,
                gate=gate,
                schema_version=schema_version,
                fingerprint=fingerprint,
            )
        )

    def _sealed_assign(self, name: str, value: object) -> None:
        object.__setattr__(self, name, value)


def candidate_applies_to(flow: RecoveryWorkflow, candidate: RecoveryCandidate) -> bool:
    """Whether this workflow minted that candidate, by identity.

    `type(...) is` rather than `isinstance`, because a subclass can override
    `authority` and nothing else type-checks a candidate. A constructed one, a
    subclassed one and one from another workflow are all answered `False`.

    Callers ask this **before** reading `schema_version`, for the reason
    `azazel_boot.session_mode.mode_applies_to` exists: the fields say what they
    were handed, and what makes a candidate an answer is that a workflow
    produced it.
    """

    return type(candidate) is RecoveryCandidate and flow.holds(candidate)


def _raise_gate_refused() -> None:
    """Raise from a frame holding nothing.

    No gate, no snapshot, no binding and no sitting are locals here, so a
    captured-locals traceback of this refusal has none of them to render. The
    limit `azazel_boot.session_mode` states applies unchanged: the frames above
    still hold what they were handed, and a frame cannot forget its own
    argument.
    """

    raise RecoveryRefused(
        Refusal.GATE_REFUSED,
        "a recovery passes every gate in order or it does not happen; the "
        "volume stays quarantined either way",
    )


class MigrationLedger:
    """What a migration recorded, and the refusal that keeps the old schema.

    It holds no port and writes nothing. `may_migrate` answers, and
    `note_snapshot_written` records what the caller reports **after** acting.

    They were one method, `record`, which both answered "may this run" and
    asserted the write had happened — in a repository whose every document says
    no snapshot has been written. A review pointed out that the audit's only
    positive classification was a claim about an act that had not occurred and
    might never occur. (The docstring also named these two methods while the
    class shipped neither; that is fixed by making them real rather than by
    correcting the sentence.)

    There is deliberately **no** `migrate_without_snapshot`, no `force`, no
    `accept_degraded` and no `overwrite_snapshot`. ADR-0010 D7 refuses a
    migration without a snapshot under any acceptance, so there is no parameter
    to accept with, and overwriting the snapshot would consume the only path
    back at the moment it is needed.
    """

    __slots__ = ("_audit", "_sealed")

    def __init__(self) -> None:
        object.__setattr__(self, "_sealed", False)
        self._audit: list[SnapshotAuditEntry] = []
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("a MigrationLedger is sealed after construction")
        object.__setattr__(self, name, value)

    def __reduce__(self):
        raise TypeError("a MigrationLedger is not serialisable")

    def __repr__(self) -> str:
        return "MigrationLedger()"

    def audit(self) -> tuple[SnapshotAuditEntry, ...]:
        return tuple(self._audit)

    def may_migrate(self, verdict: PreflightVerdict) -> bool:
        """Say whether a migration may run, and record a refusal.

        The verdict must be one **this module minted**. A hand-built
        `PreflightVerdict(None)` authorised a migration over a snapshot whose
        integrity had failed, with no preflight ever having run, because this
        read `may_migrate` and believed it — the "rebuild the object a
        legitimate caller holds" attack, for the third time in this codebase.

        A refusal records **which check** and nothing behind it: no figure, no
        capacity, no fingerprint of a snapshot that was not used. The old
        schema keeps working, which is D7's safe outcome rather than a degraded
        one, and a test asserts it is still usable afterwards.
        """

        if not verdict_was_minted_here(verdict):
            raise RecoveryRefused(
                Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT,
                "a migration runs on a verdict this module produced; a value "
                "that merely has the right shape is not one",
            )

        if not verdict.may_migrate:
            self._audit.append(
                SnapshotAuditEntry(
                    event=SnapshotAuditEvent.MIGRATION_REFUSED, check=verdict.refused_by
                )
            )
            return False
        return True

    def note_snapshot_written(
        self, verdict: PreflightVerdict, snapshot: SnapshotDescriptor
    ) -> None:
        """Record that the caller wrote a snapshot. **After** it did.

        Separate from :meth:`may_migrate` because recording the write at
        permission time asserts an act that has not happened. The verdict is
        re-checked here so that this cannot be reached without one.
        """

        if not verdict_was_minted_here(verdict) or not verdict.may_migrate:
            raise RecoveryRefused(
                Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT,
                "a snapshot is recorded against the preflight that permitted "
                "it; there is no way to record one without a passed verdict",
            )
        if not isinstance(snapshot, SnapshotDescriptor):
            raise TypeError("note_snapshot_written takes a SnapshotDescriptor")

        self._audit.append(
            SnapshotAuditEntry(
                event=SnapshotAuditEvent.SNAPSHOT_WRITTEN,
                schema_version=snapshot.schema_version,
                fingerprint=snapshot.fingerprint,
            )
        )
