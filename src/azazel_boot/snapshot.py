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
from weakref import WeakSet as _WeakSet

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
            # `type(...) is int`, not `isinstance`: a round-four review built
            # this object through this constructor with `int` subclasses that
            # answered `7` and compared as anything, and the field-by-field
            # substitution check compared the subclass's answers.
            if type(value) is not int or value < 1:
                raise TypeError(f"{name} must be a positive integer version")
        if type(self.fingerprint) is not str or not self.fingerprint.strip():
            raise TypeError("fingerprint must be a non-empty opaque string")

    def __reduce__(self):
        raise TypeError("a SnapshotDescriptor is not serialisable")

    def __getstate__(self):
        raise TypeError("a SnapshotDescriptor is not serialisable")

    def __repr__(self) -> str:
        """Redacted. A fingerprint in a repr is a fingerprint in every traceback."""

        return (
            f"SnapshotDescriptor(container_version={self.container_version}, "
            f"schema_version={self.schema_version}, "
            f"integrity={self.integrity.value}, fingerprint=<redacted>)"
        )


def _require_two_measurements(
    *, required_is_a_count: bool, available_is_a_count: bool
) -> None:
    """Raise from a frame holding two booleans and nothing else.

    Neither figure is in scope here, so a captured-locals traceback of either
    refusal carries no measurement of anybody's medium.
    """

    if not required_is_a_count:
        raise TypeError("required must be a non-negative integer")
    if not available_is_a_count:
        raise TypeError("available must be a non-negative integer")


class CapacityReport:
    """Space, as the caller measured it. **These numbers never render.**

    They describe the operator's medium — how much they are carrying and how
    much of it is used — and ADR-0010 D10's rule about the audit is that it
    holds classifications. Which check refused is a classification; how many
    bytes were short is a measurement of somebody's hardware.

    **The limit, stated rather than claimed away**: the refusal below is raised
    from a frame holding two booleans, but *this* frame holds what it was
    handed, so a captured-locals traceback of a construction that refused shows
    the caller's own arguments. `azazel_boot.session_mode` states the same
    limit about the passphrase, in the same words: a frame cannot forget its
    own argument.

    The figures sit in `__slots__` and are reachable as ordinary private
    attributes, as anything in a Python object is. What is closed is every
    **public** rendering — `dataclasses.asdict`, `astuple`, `vars()`,
    `__getstate__`, `copy`, `pickle` — and the constructor's own traceback.

    **Not a dataclass**, which is the whole of the difference. It was one, with
    a redacting `__repr__`, and the claim in this docstring was "these numbers
    never reach an audit" while `dataclasses.asdict`, `astuple`, `vars()` and
    `__getstate__` all handed them back — a review printed both figures through
    four public paths. A `__repr__` is a rendering, not a boundary. The values
    live in slots nothing here exposes, the one question this module asks is
    asked inside the class, and the serialisation hooks refuse.
    """

    __slots__ = ("_required", "_available")

    def __init__(self, *, required: int, available: int) -> None:
        # Refused from a frame holding **two booleans**. Validating inline left
        # the figures as locals, so a caller whose free-space probe returned
        # `None` got a `TypeError` whose captured-locals traceback rendered the
        # other, real figure — on an ordinary path, in the constructor of the
        # class whose docstring says these numbers never render.
        _require_two_measurements(
            required_is_a_count=type(required) is int and required >= 0,
            available_is_a_count=type(available) is int and available >= 0,
        )
        object.__setattr__(self, "_required", required)
        object.__setattr__(self, "_available", available)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("a CapacityReport is fixed when it is built")

    def __reduce__(self):
        raise TypeError("a CapacityReport is not serialisable")

    def __getstate__(self):
        raise TypeError("a CapacityReport does not hand back its figures")

    def __repr__(self) -> str:
        return "CapacityReport(<redacted>)"

    def has_room_for_the_snapshot(self) -> bool:
        """The one question. Asked here, so the figures answer it and travel
        nowhere: what leaves this object is a `bool`."""

        return self._available >= self._required


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

    __slots__ = ("_refused_by", "_snapshot", "_evaluated", "_judged", "__weakref__")

    def __init__(self, refused_by: PreflightCheck | None) -> None:
        """No token, and nothing to read off a verdict at all.

        It used to take a `token` parameter, and round two removed the
        parameter. Round four pointed out that removing the *write* path left
        the *read* path exactly as it was: `preflight` returned a verdict whose
        `_token` **was** the live sentinel, on refusals as well as passes, one
        attribute access away. A review read it off a refused verdict, stamped
        it onto a fresh one, and recorded `SNAPSHOT_WRITTEN` against a snapshot
        whose integrity had failed.

        So there is no token. Which verdicts this module minted is a fact this
        module keeps, in `_MINTED_HERE` — a `WeakSet` the verdict does not
        point at and a caller holding one cannot read. A value that is not on
        the object cannot be copied off it.
        """

        object.__setattr__(self, "_refused_by", refused_by)
        object.__setattr__(self, "_snapshot", None)
        object.__setattr__(self, "_evaluated", ())
        object.__setattr__(self, "_judged", None)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("a PreflightVerdict is fixed when it is minted")

    def __reduce__(self):
        raise TypeError("a PreflightVerdict is not serialisable")

    def __getstate__(self):
        raise TypeError("a PreflightVerdict does not hand back its fields")

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

    @property
    def evaluated(self) -> tuple[PreflightCheck, ...]:
        """Which checks were **asked**, in the order they were asked.

        A passing verdict used to be `refused_by is None` and nothing else, so
        a verdict from a `preflight` that ran three gates was indistinguishable
        from one that ran all ten — by repr, by `refused_by`, by `may_migrate`
        and by the whole public surface. That is the structural reason a review
        could permute the gate order with the suite green: correctness of the
        gate *set* lived entirely in test parametrisation, and neither the
        ledger nor the audit could notice a gate that stopped running.

        Complete, in the sense `Azazel-Knowledge`'s scorer means it: the checks
        that passed are named as well as the one that refused, so "not
        evaluated" and "passed" are different answers.
        """

        return self._evaluated


#: The verdicts this module minted. Membership is the whole of it, and the
#: verdict does not point back — so reading a verdict, by any means, yields
#: nothing that can be stamped onto another one. Weak, so a verdict a caller
#: dropped is not kept alive by having been judged.
#:
#: **This is careless-caller defence, not a capability boundary.** An earlier
#: comment here said "no constructor a caller can reach", which claimed more
#: than Python can give: this module is importable, and
#: `_MINTED_HERE.add(PreflightVerdict(None))` produces a verdict
#: `verdict_was_minted_here` accepts. `azazel_boot.quarantine` states the same
#: limit about its own seal, in the same words, and the honest sentence is that
#: one. What changed is narrower and real: it is no longer reachable from a
#: verdict a caller was legitimately handed.
_MINTED_HERE: _WeakSet = _WeakSet()

#: The verdicts a write has already been recorded against, in any ledger. Kept
#: here rather than on the ledger because a verdict replayed into a *second*
#: ledger is the same false count as one replayed into the first.
_ALREADY_SPENT: _WeakSet = _WeakSet()

#: And the **snapshots**, by value, across every ledger in the process. Marking
#: the verdict spent was exactly one `preflight()` call wide: a preflight is
#: free, read-only and unlimited, so a review minted a fresh verdict per ledger
#: and recorded four writes for one judged snapshot — with the per-ledger list
#: below satisfied every time, because each ledger was new.
#:
#: `(sitting, the snapshot's four values)` for every write recorded in this
#: process. It was a `WeakSet` of descriptors, and both halves of that were
#: wrong: dropping the last reference evaporated the entry, so a review
#: recorded five writes for one snapshot value through the public API alone —
#: and an entry for one sitting refused an unrelated later sitting's own write,
#: because the key said nothing about whose medium it was.
#:
#: Strong, so "once" is a property of this module rather than of the garbage
#: collector. The residue is one short tuple of immutable values per write
#: actually recorded in a boot, and nothing about the medium.
_SNAPSHOTS_RECORDED: list[tuple[object, ...]] = []

#: The order the gates are asked in, named once so that it is a contract rather
#: than the order the lines happen to sit in. A review permuted eight adjacent
#: pairs and six demotions-to-last with the suite green: no bad input passed —
#: `preflight` short-circuits, so permutation cannot change the passing set —
#: but the *classification* an operator is given changed, which is exactly what
#: ADR-0010 D7 promises. An operator whose medium had been **pulled** was told
#: `volume_quarantined`.
PREFLIGHT_ORDER = (
    PreflightCheck.MEDIUM_FENCED,
    PreflightCheck.VOLUME_QUARANTINED,
    PreflightCheck.SNAPSHOT_ABSENT,
    PreflightCheck.SNAPSHOT_CONTAINER_UNKNOWN,
    PreflightCheck.SNAPSHOT_INTEGRITY,
    PreflightCheck.REQUIRED_SPACE,
    PreflightCheck.SCHEMA_COMPATIBILITY,
    PreflightCheck.BINDING,
    PreflightCheck.GENERATION,
    PreflightCheck.IMAGE_DIGEST,
)

#: The only four fields a recovery moves. `_sealed_assign` writes these and
#: nothing else — not the quarantine, not the binding, not the sitting, and
#: not once the stage is terminal.
_MOVES_DURING_A_RECOVERY = frozenset({"_stage", "_snapshot", "_pinned", "_candidate"})

#: The edges the stage may travel. Naming the fields that move was not enough:
#: `_stage` and `_pinned` were both on the list above and `NOT_STARTED` and
#: `TRIAL_OPEN` are both non-terminal, so a review jumped straight between them
#: and minted a candidate whose entire audit was `['recovery_completed']` — no
#: start, no operator, no trial — through a bound method on every instance.
#: Written once, when the workflow starts, and never again.
_PINNED_AT_THE_START = frozenset({"_snapshot", "_pinned"})

#: Issued by `_require_the_gates` when every gate has just passed, and consumed
#: by the one transition that may follow. Naming the fields that move and the
#: edges the stage may travel was not enough: `trial_open -> committed` is a
#: legal edge, and D8's key acquisition and operator confirmation live inside
#: `commit` rather than in the graph, so a review took that edge with
#: `_sealed_assign` and minted an accepted candidate for schema 99 with no
#: acquisition ever constructed and no operator ever asked — with an audit
#: **byte-identical** to a legitimate commit.
#:
#: Issued, not asserted: the value is this object, and nothing a caller can
#: name produces it.
_GATES_JUST_PASSED = object()

#: The clearance a stage that asks no acquisition gets. `start` and
#: `open_trial` legitimately have none, so `acquisition=None` there is honest —
#: and a review used the same `None` to call `_require_the_gates` directly and
#: reach `COMMITTED` without D8's gates 2 and 4. A clearance now says **which**
#: it is: only a run that asked an acquisition and a confirmation issues the
#: one a commit spends.
_PRE_TRIAL_GATES_PASSED = object()

_STAGE_EDGES = frozenset(
    {
        ("not_started", "preflight_passed"),
        ("not_started", "refused"),
        ("not_started", "interrupted"),
        ("preflight_passed", "trial_open"),
        ("preflight_passed", "refused"),
        ("preflight_passed", "interrupted"),
        ("trial_open", "committed"),
        ("trial_open", "refused"),
        ("trial_open", "interrupted"),
    }
)


def _require_a_real_quarantine(quarantine: object) -> None:
    """`type(...) is`, not `isinstance`.

    `isinstance` was the fix for a two-attribute stand-in, and a re-review
    then subclassed `Quarantine` and overrode `is_fenced` and
    `volume_is_quarantined` as properties: the object genuinely *was* fenced
    (`Quarantine.is_fenced.fget(q)` answered True) and the whole workflow ran
    to a minted candidate over it. The same stand-in, wearing the class the
    `isinstance` was added to demand.

    `PreflightVerdict` and `RecoveryCandidate` are already checked this way.
    The quarantine is the input the two gates before D8's four read, so it gets
    the same treatment.
    """

    if type(quarantine) is not Quarantine:
        raise TypeError(
            "quarantine must be a Quarantine exactly; a stand-in and a "
            "subclass that overrides its answers are both refused"
        )


def _require_a_real_snapshot(snapshot: object) -> None:
    """The workflow never checked this, and the pin depended on it.

    A stand-in with three class attributes satisfied both integrity gates, and
    an `__eq__` returning `True` walked through the substitution check this
    module calls "the substitution this whole design exists to notice". So a
    workflow started on a real descriptor could be trialled and committed on a
    substitute, with no `RECOVERY_SNAPSHOT_SUBSTITUTED` recorded.
    """

    if type(snapshot) is not SnapshotDescriptor:
        raise TypeError(
            "snapshot must be a SnapshotDescriptor exactly; a stand-in whose "
            "__eq__ decides the substitution check is not one"
        )


def _require_an_exact_int(name: str, value: object) -> None:
    """`type(...) is int`, because an `int` subclass answers for itself.

    A round-four review built a genuine `SnapshotDescriptor` — public
    constructor, no `object.__setattr__` — whose `container_version` was an
    `int` subclass answering `7`, and whose `__eq__` said whatever it liked.
    It passed the substitution check and the container-version half of the
    integrity gate, and committed on an unknown container format. `isinstance`
    admits the subclass; the check the field comparison rests on has to not.
    """

    if type(value) is not int:
        raise TypeError(f"{name} must be an int exactly; a subclass may answer for itself")


def _require_an_exact_str(name: str, value: object) -> None:
    """`type(...) is str`, for the same reason and a sharper case.

    A `str` subclass whose `__ne__` answers `False` decided
    `_require_this_sitting` for the caller — the caller's own operand is on
    the left of the `!=` — and Python's reflected-priority rule handed it
    `binding_applies`'s session half as well. Four lines, any sitting.
    """

    if type(value) is not str:
        raise TypeError(f"{name} must be a str exactly; a subclass may answer for itself")


def _require_real_observations(observations: object) -> None:
    """The one input to the gates that nothing pinned.

    `binding_applies` re-derives the host fingerprint from these rather than
    re-comparing a field it was handed, so a stand-in does not forge a host —
    but it does decide what this module believes it was handed, and every
    other input to the gates is pinned. This is not a secret-bearing check; it
    is the missing member of a set.
    """

    if type(observations) is not tuple:
        raise TypeError("observations must be a tuple exactly")
    for observation in observations:
        if type(observation) is not InterfaceObservation:
            raise TypeError("each observation must be an InterfaceObservation exactly")


def _fields_of(snapshot: SnapshotDescriptor) -> tuple[object, ...]:
    """The four values a substitution check has to compare against.

    Named rather than spelled inline so that the comparison and the pin cannot
    drift apart; `tests/unit/test_snapshot.py` derives the field names from
    this function's source and asserts they are the dataclass's own, so a
    fifth field cannot be added and silently left uncompared.
    """

    return (
        snapshot.container_version,
        snapshot.schema_version,
        snapshot.integrity,
        snapshot.fingerprint,
    )


def _require_an_acquisition(acquisition: object) -> None:
    """`None` skipped D8's second gate entirely, and left no trace.

    `_require_the_gates` takes an optional acquisition because `start` and
    `open_trial` legitimately have none, and `commit` forwarded whatever it was
    handed into an `if acquisition is not None:`. A commit with
    `acquisition=None` produced an audit **byte-identical** to a legitimate
    one, so nothing downstream could tell a recovery that unlocked the volume
    from one where nobody was ever prompted. A caller reaches that by mistake,
    not by malice, which is what makes it the worst of the four.
    """

    if acquisition is None:
        raise TypeError(
            "commit requires a key acquisition; there is no recovery without "
            "one, and no value that means 'skip the gate'"
        )


def _require_an_actual_bool(name: str, value: object) -> None:
    """D8's two operator gates took any truthy object.

    `preflight` checks its three flags with the comment "a truthy object is not
    a check", and the two flags the whole operator-started doctrine rests on
    were not checked at all: a recovery reached `COMMITTED` and minted a
    candidate with `started_by_operator="no"` and `confirmed="declined"`.
    """

    if type(value) is not bool:
        raise TypeError(f"{name} must be a bool; a truthy object is not a check")


def _mint(
    refused_by: PreflightCheck | None,
    snapshot: SnapshotDescriptor | None = None,
    evaluated: tuple[PreflightCheck, ...] = (),
    judged: Quarantine | None = None,
) -> PreflightVerdict:
    """Build a verdict, stamp it, and record **which snapshot it judged**.

    The verdict named no snapshot, so `note_snapshot_written` could only
    re-check that *some* passing verdict existed: a re-review recorded
    `SNAPSHOT_WRITTEN` against a snapshot whose integrity was `FAILED`, on a
    verdict minted for a different, verified one. Both objects were real and
    the verdict was legitimately minted; nothing tied them together.
    """

    verdict = PreflightVerdict(refused_by)
    object.__setattr__(verdict, "_snapshot", snapshot)
    object.__setattr__(verdict, "_evaluated", tuple(evaluated))
    object.__setattr__(verdict, "_judged", judged)
    _MINTED_HERE.add(verdict)
    return verdict


def verdict_was_minted_here(verdict: PreflightVerdict) -> bool:
    """Whether this module produced that verdict. Checked by identity.

    A hand-built `PreflightVerdict(None)` is not one, and `MigrationLedger`
    refuses it rather than reading `may_migrate` and believing it.

    Membership, not a stamp: there is nothing on a verdict that says it was
    minted, so there is nothing to read off one and reuse. The `isinstance`
    that used to stand in front of the `type(...) is` is gone — it was implied
    by it, and two checks where there is one is how a later reader decides the
    second is redundant. That is how round three's regression happened.
    """

    return type(verdict) is PreflightVerdict and verdict in _MINTED_HERE


#: Schema versions this build can migrate **to**. A downgrade is not on it.
SUPPORTED_SCHEMA_VERSIONS = (1, 2)


def schema_is_compatible(*, current: int, target: int) -> bool:
    """Forward, to a version this build knows, and never backwards.

    Not "by one step": the body asks membership of `SUPPORTED_SCHEMA_VERSIONS`
    and then `target > current`, which is any forward target in the set. The
    two readings coincide while the set is `(1, 2)` and would part on the day
    it is not, so the sentence is the one the code implements.

    A downgrade is refused rather than attempted: the old schema continuing to
    work is D7's safe outcome, and writing an older layout over a newer one is
    the opposite of keeping it.
    """

    if current not in SUPPORTED_SCHEMA_VERSIONS or target not in SUPPORTED_SCHEMA_VERSIONS:
        return False
    return target > current


def _gate_fails(
    check: PreflightCheck,
    quarantine: Quarantine,
    snapshot: SnapshotDescriptor | None,
    capacity: CapacityReport,
    *,
    current_schema: int,
    target_schema: int,
    binding_holds: bool,
    generation_holds: bool,
    image_digest_holds: bool,
) -> bool:
    """One check, asked. The **order** is `PREFLIGHT_ORDER`'s, not this
    function's: nothing here decides what runs next, so reordering these
    branches is not a reordering of the gates.

    The snapshot-reading branches are reachable only after `SNAPSHOT_ABSENT`
    has passed, which `PREFLIGHT_ORDER` places before them.
    """

    if check is PreflightCheck.MEDIUM_FENCED:
        return quarantine.is_fenced
    if check is PreflightCheck.VOLUME_QUARANTINED:
        # The recovery path treated a quarantined volume as load-bearing and
        # this one treated it as invisible, which a review caught. ADR-0010 D4
        # stops the **whole volume** on a suspected torn write, and a schema
        # migration is a large write to exactly that volume.
        return quarantine.volume_is_quarantined
    if check is PreflightCheck.SNAPSHOT_ABSENT:
        # D7: no flag, no acceptance, no emergency state. An operator cannot
        # consent to this, because what they would be consenting to is the loss
        # of the only path back — so there is no parameter to consent with.
        return snapshot is None
    if check is PreflightCheck.SNAPSHOT_CONTAINER_UNKNOWN:
        return snapshot.container_version not in KNOWN_CONTAINER_VERSIONS
    if check is PreflightCheck.SNAPSHOT_INTEGRITY:
        # `INDETERMINATE` lands here with `FAILED`. D7: ambiguity refuses the
        # migration, and there is no third answer that proceeds.
        return snapshot.integrity is not SnapshotIntegrity.VERIFIED
    if check is PreflightCheck.REQUIRED_SPACE:
        # No degraded migration, no "we can fit most of it". A medium too small
        # keeps the old schema and keeps working.
        return not capacity.has_room_for_the_snapshot()
    if check is PreflightCheck.SCHEMA_COMPATIBILITY:
        return not schema_is_compatible(current=current_schema, target=target_schema)
    if check is PreflightCheck.BINDING:
        return not binding_holds
    if check is PreflightCheck.GENERATION:
        return not generation_holds
    return not image_digest_holds


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
    _require_a_real_quarantine(quarantine)
    for name, value in (
        ("binding_holds", binding_holds),
        ("generation_holds", generation_holds),
        ("image_digest_holds", image_digest_holds),
    ):
        _require_an_actual_bool(name, value)
    # The two schema versions were annotated and unchecked, so an object whose
    # `__eq__`/`__gt__` always answer True produced a **legitimately minted**
    # passing verdict for a step that is in no supported set — and `True`
    # passed as version 1, the exact case `SnapshotDescriptor.__post_init__`
    # goes out of its way to refuse.
    for name, value in (
        ("current_schema", current_schema),
        ("target_schema", target_schema),
    ):
        _require_an_exact_int(name, value)
    if type(capacity) is not CapacityReport:
        raise TypeError("capacity must be a CapacityReport exactly")
    if snapshot is not None:
        _require_a_real_snapshot(snapshot)

    # Driven from `PREFLIGHT_ORDER`, so the order is the constant rather than
    # the order these lines happen to sit in. A review permuted fourteen of
    # sixteen adjacent pairs and demotions with the suite green — no bad input
    # passed, because this short-circuits, but the classification an operator
    # is given changed, and that classification is what ADR-0010 D7 promises.
    # Rewriting `_gate_fails`'s branches now changes nothing at all.
    asked: list[PreflightCheck] = []
    for check in PREFLIGHT_ORDER:
        asked.append(check)
        if _gate_fails(
            check,
            quarantine,
            snapshot,
            capacity,
            current_schema=current_schema,
            target_schema=target_schema,
            binding_holds=binding_holds,
            generation_holds=generation_holds,
            image_digest_holds=image_digest_holds,
        ):
            return _mint(check, None, tuple(asked), quarantine)

    return _mint(None, snapshot, tuple(asked), quarantine)


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

#: The two stages a workflow reaches without passing anything: a refusal and
#: an interruption. Every other stage is arrived at by passing the gates.
_REACHED_WITHOUT_GATES = frozenset(
    {RecoveryStage.REFUSED, RecoveryStage.INTERRUPTED}
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
    #: **Which medium is being recovered**, asked of the quarantine through its
    #: own question. A review committed a recovery over a quarantine that had
    #: never observed *any* device, and over two different media identities in
    #: turn, because nothing in the workflow ever asked what it was recovering.
    #: No device identity enters this module to ask it.
    MEDIUM_NOT_RECOGNISED = "medium_not_recognised"
    #: The host and the sitting — what `commissioning.binding_applies` answers.
    #: It carried D8 gate 1's name until a review pointed out that the name
    #: belongs to the *media* binding, which this is not.
    HOST_BINDING = "host_binding"
    #: **ADR-0010 D8 gate 1**: ADR-0008 D4.1.1's key-protected media binding.
    #: The caller re-derives it — `azazel_boot.persistence.media_binding_applies`
    #: over a `MediaClaim` under a `BindingKey` — and reports the answer, in
    #: the same shape `preflight` takes its three. The key does not come here:
    #: a decision module that holds key material is a decision module the
    #: secret arrives at, and `session_mode` fixed that boundary for the
    #: passphrase in exactly this way.
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
    #: One preflight judged one snapshot, so one write is recordable against
    #: it. Nothing marked a verdict spent, and a review recorded four
    #: `SNAPSHOT_WRITTEN` classifications across two ledgers from one judged
    #: write — for an audit whose only positive classification is "a snapshot
    #: was written", n records for one write is a false count.
    VERDICT_ALREADY_SPENT = "verdict_already_spent"
    #: The medium moved between the preflight and the act. A verdict carries no
    #: session, no medium, no boot and no clock, so a review held one minted
    #: before a fence and spent it after — a durable bearer token for a large
    #: write to a volume since judged torn, which is what ADR-0010 D9 refuses.
    MEDIUM_MOVED_SINCE_THE_PREFLIGHT = "medium_moved_since_the_preflight"
    #: A passing verdict that names fewer than the ten checks. `evaluated`
    #: reports honestly what was asked; until something asked it back, a
    #: rebound `PREFLIGHT_ORDER` produced a pass over a fenced, quarantined,
    #: binding-failing medium from a single check.
    VERDICT_DID_NOT_ASK_EVERY_CHECK = "verdict_did_not_ask_every_check"


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
    #: A stage asked for a sitting this workflow does not belong to. Recorded
    #: and terminal for the same reason as the two above: the module treats a
    #: swap as an event rather than a typo, and an unbounded, unrecorded probe
    #: against a live `TRIAL_OPEN` workflow was the one swap it did not.
    RECOVERY_FOREIGN_SITTING = "recovery_foreign_sitting"


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

    def __post_init__(self) -> None:
        """Checked here, because the repr renders what it is handed.

        A re-review reached this through a snapshot stand-in whose
        `schema_version` was the string
        `"capacity_available=… medium=usb-SN-…"` — a capacity figure and a
        medium identity, the two things ADR-0010 D10 names specifically,
        rendered into the object this module's own docstring calls "the object
        destined for a log". Fixing the reachability is `_require_a_real_snapshot`;
        this removes the class of it.
        """

        if not isinstance(self.event, SnapshotAuditEvent):
            raise TypeError("event must be a SnapshotAuditEvent")
        if self.check is not None and not isinstance(self.check, PreflightCheck):
            raise TypeError("check must be a PreflightCheck or None")
        if self.gate is not None and not isinstance(self.gate, RecoveryGate):
            raise TypeError("gate must be a RecoveryGate or None")
        # Exactly `int` and exactly `str`. `isinstance` admitted an `int`
        # subclass whose `__format__` rendered
        # `"capacity_available=… medium=usb-SN-…"` through the f-string below
        # — a capacity figure and a medium identity, which is the leak this
        # method was written to remove, arriving through the check itself.
        if self.schema_version is not None:
            _require_an_exact_int("schema_version", self.schema_version)
        if self.fingerprint is not None:
            _require_an_exact_str("fingerprint", self.fingerprint)

    def __reduce__(self):
        raise TypeError("a SnapshotAuditEntry is not serialisable")

    def __getstate__(self):
        raise TypeError("a SnapshotAuditEntry is not serialisable")

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

    def __getstate__(self):
        raise TypeError("a RecoveryCandidate does not hand back its fields")

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
        "_pinned",
        "_candidate",
        "_cleared",
        "_sealed",
    )

    def __init__(
        self, quarantine: Quarantine, binding: SessionBinding, *, session_id: str
    ) -> None:
        _require_a_real_quarantine(quarantine)
        if type(binding) is not SessionBinding:
            raise TypeError("binding must be a SessionBinding")
        _require_an_exact_str("session_id", session_id)
        if not session_id.strip():
            raise TypeError("session_id must be a non-empty string")

        object.__setattr__(self, "_sealed", False)
        self._quarantine = quarantine
        self._binding = binding
        self._session_id = session_id
        self._stage = RecoveryStage.NOT_STARTED
        self._snapshot: SnapshotDescriptor | None = None
        self._pinned: SnapshotDescriptor | None = None
        self._cleared: object | None = None
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

    def __getstate__(self):
        raise TypeError("a RecoveryWorkflow does not hand back its fields")

    def __repr__(self) -> str:
        """Survives a half-built instance, because that is when it is called.

        `__init__` validates before it assigns, so a `TypeError` from one of
        its checks left an object with no `_stage` — and the traceback
        machinery, asked for captured locals, died inside the redacting repr
        with an `AttributeError`. A clean message-only refusal became a crash
        in the code written to keep refusals clean.
        """

        stage = getattr(self, "_stage", None)
        return f"RecoveryWorkflow(stage={stage.value if stage is not None else 'unbuilt'})"

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
        media_binding_holds: bool,
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

        _require_a_real_snapshot(snapshot)
        _require_real_observations(observations)
        _require_an_actual_bool("started_by_operator", started_by_operator)
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
        self._require_the_gates(
            snapshot,
            observations,
            session_id=session_id,
            media_binding_holds=media_binding_holds,
            acquisition=None,
            confirmed=None,
        )

        self._sealed_assign("_snapshot", snapshot)
        # The **values**, not the object. `held = self._snapshot` was the same
        # object the caller passed in and passed again, so the four field
        # comparisons compared an object with itself: a review mutated the
        # frozen descriptor in place between the stages, committed on a
        # different schema version and fingerprint, and the audit recorded two
        # fingerprints across one workflow with no substitution between them.
        # A **copy**, built here from the values read at this moment. Holding
        # the caller's object made the comparison a self-comparison; holding a
        # tuple of its fields fixed that, and this goes one further so that
        # what the commit mints comes from an object the caller never had a
        # reference to.
        self._sealed_assign("_pinned", SnapshotDescriptor(*_fields_of(snapshot)))
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
        media_binding_holds: bool,
    ) -> None:
        """Open the trial, with every gate asked again.

        The snapshot is passed again and compared against the one the workflow
        started on. A snapshot that changed under the workflow is refused
        rather than used: an older snapshot substituted between the start and
        the trial is the substitution this whole design exists to notice.
        """

        _require_a_real_snapshot(snapshot)
        _require_real_observations(observations)
        self._require_stage(RecoveryStage.PREFLIGHT_PASSED)
        self._require_this_sitting(session_id)
        self._require_the_same_snapshot(snapshot)
        self._require_the_gates(
            snapshot,
            observations,
            session_id=session_id,
            media_binding_holds=media_binding_holds,
            acquisition=None,
            confirmed=None,
        )

        self._sealed_assign("_stage", RecoveryStage.TRIAL_OPEN)
        self._record(SnapshotAuditEvent.RECOVERY_TRIAL_OPENED)

    def commit(
        self,
        snapshot: SnapshotDescriptor,
        observations: tuple[InterfaceObservation, ...],
        *,
        session_id: str,
        media_binding_holds: bool,
        acquisition: KeyAcquisition,
        confirmed: bool,
    ) -> RecoveryCandidate:
        """Finish, and produce a **candidate**. The quarantine does not move.

        This is the whole of what a successful recovery yields: an object
        saying which schema version a restore would reach and which snapshot it
        came
        from. The `Quarantine` is exactly as quarantined afterwards as before,
        the fence is untouched, and no capability rises.

        All four of D8's gates run here, in D8's order, because this is the
        act: target binding, key acquisition, integrity verification, operator
        confirmation.
        """

        _require_a_real_snapshot(snapshot)
        _require_real_observations(observations)
        _require_an_acquisition(acquisition)
        _require_an_actual_bool("confirmed", confirmed)
        self._require_stage(RecoveryStage.TRIAL_OPEN)
        self._require_this_sitting(session_id)
        self._require_the_same_snapshot(snapshot)
        self._require_the_gates(
            snapshot,
            observations,
            session_id=session_id,
            media_binding_holds=media_binding_holds,
            acquisition=acquisition,
            confirmed=confirmed,
        )
        # **Again, after the prompt.** The two quarantine flags were re-read
        # after `attempt()` and the pin was not, so a review mutated the frozen
        # descriptor from inside the acquisition and committed on a different
        # schema version and fingerprint — reaching `COMMITTED`, minting a
        # candidate `candidate_applies_to` accepted, and recording a
        # `recovery_completed` naming a snapshot no gate had judged, with no
        # `RECOVERY_SNAPSHOT_SUBSTITUTED` anywhere. The substitution this whole
        # design exists to notice, through the one wait in the function.
        self._require_the_same_snapshot(snapshot)
        # `attempt()` is caller code called mid-gate, and a review interrupted
        # the workflow from inside it. The stage move then raised
        # `AttributeError` from the seal — outside this module's refusal
        # vocabulary, so a caller writing `except RecoveryRefused` crashed.
        # `WORKFLOW_ALREADY_FINISHED` exists for exactly this.
        self._require_stage(RecoveryStage.TRIAL_OPEN)

        # The candidate is minted and held **before** the stage becomes
        # terminal, because `_sealed_assign` refuses to move anything once it
        # is. The order is the rule's, not a preference: a terminal workflow
        # moves nothing, including the field that would record its own answer.
        # From `_pinned`, not from the argument: the values judged at the
        # start, held in an object the caller never had. Re-reading the
        # argument here is what let a mutation during the prompt into both the
        # candidate and the audit.
        judged = self._pinned
        minted = RecoveryCandidate(judged.schema_version, judged.fingerprint)
        self._sealed_assign("_candidate", minted)
        self._sealed_assign("_stage", RecoveryStage.COMMITTED)
        self._record(
            SnapshotAuditEvent.RECOVERY_COMPLETED,
            schema_version=judged.schema_version,
            fingerprint=judged.fingerprint,
        )
        return minted

    def holds(self, candidate: RecoveryCandidate) -> bool:
        """Whether this workflow minted that candidate. Checked by identity.

        The `is not None` is not redundant: without it an uncommitted workflow
        answers `True` for `None`, and `None` is what `_candidate` is until a
        commit — the trap `azazel_boot.persistence.PersistenceSession.holds`
        was found in.
        """

        return self._candidate is not None and self._candidate is candidate

    def interrupt(self, *, session_id: str) -> None:
        """The operator stopped, or the machine did. Terminal, and fail-closed.

        Nothing is partially restored and nothing is retried. The volume stays
        quarantined, which it was before this workflow and is after it.

        `session_id` is required here as it is everywhere else. This was the
        one stage method exempt from it, so any holder of the object, from any
        sitting, could end the workflow. Fail-closed, so the exemption only
        ever bought a denial — and a denial is still an outcome somebody else
        chose.
        """

        _require_an_exact_str("session_id", session_id)
        if self._stage in TERMINAL_STAGES:
            self._refuse(
                Refusal.WORKFLOW_ALREADY_FINISHED,
                "this workflow has ended; a further attempt is a new workflow "
                "that runs every gate again",
            )
        self._require_this_sitting(session_id)
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

        # The caller's operand was on the left of a `!=`, so a `str` subclass
        # whose `__ne__` answered `False` decided this check for the caller —
        # and Python's reflected-priority rule handed it `binding_applies`'s
        # session half as well, from the same four lines. Pinning the type
        # first is what makes the comparison below a comparison.
        _require_an_exact_str("session_id", session_id)
        if session_id != self._session_id:
            # Unconditional. This used to be wrapped in `if self._stage not in
            # TERMINAL_STAGES:`, which can never be false: every caller passes
            # `_require_stage` — or, in `interrupt`, its own terminal check —
            # before reaching here. A review narrowed the condition to
            # `NOT_STARTED` and four foreign probes against a live `TRIAL_OPEN`
            # workflow left no record and no terminal stage, with the suite
            # green. A guard that cannot fail for its own reason is not a
            # guard; the recording is what this rule is.
            self._sealed_assign("_stage", RecoveryStage.REFUSED)
            self._record(SnapshotAuditEvent.RECOVERY_FOREIGN_SITTING)
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

        # Against the **values** taken at `start`, not against the object
        # still held: `held = self._snapshot` was the object the caller
        # presented, so the comparison compared it with itself and an in-place
        # mutation of the frozen descriptor passed unnoticed. The field types
        # are pinned to exactly `int` and exactly `str` in `__post_init__`, so
        # neither operand can answer for the comparison either.
        pinned = self._pinned
        same = pinned is not None and _fields_of(snapshot) == _fields_of(pinned)
        if not same:
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
        media_binding_holds: bool,
        acquisition: KeyAcquisition | None,
        confirmed: bool | None,
    ) -> None:
        """D8's gates, in D8's order, with the three that precede them.

        `acquisition` and `confirmed` are **required**, and `None` means "this
        stage has none" rather than "skip the gate". They had defaults, and a
        review called this method directly — it is a bound method at the same
        reach as `_sealed_assign`, which the clearance exists to blunt — with
        `acquisition=None`, obtained a clearance without D8's gates 2 and 4,
        and moved the stage. Reaching this function is now reaching all of D8.

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

        # D8 gate 1 is about the **target**: which medium this recovery is
        # for. `medium_is_bound()` is the quarantine's own question — has this
        # medium been seen this session — and it answers `False` after a fence,
        # so no identity crosses into this module to ask it. What is *not*
        # checked here is ADR-0008 D4.1.1's key-protected media binding, which
        # needs a `BindingKey`; bringing key material into a decision module
        # would break the rule that the secret never arrives, so that check
        # stays with `azazel_boot.persistence` and is named in the docs as a
        # limit rather than claimed here.
        if not self._quarantine.medium_is_bound():
            self._refuse_gate(RecoveryGate.MEDIUM_NOT_RECOGNISED)
        # And the quarantine has to be this sitting's. `PersistenceSession`
        # refuses the identical pairing with `QUARANTINE_FROM_ANOTHER_SESSION`;
        # this module type-checked the quarantine, the binding and the sitting
        # and never compared the first with the third.
        if self._quarantine.session_id != self._session_id:
            self._refuse_gate(RecoveryGate.MEDIUM_NOT_RECOGNISED)

        if not binding_applies(self._binding, observations, session_id=session_id):
            self._refuse_gate(RecoveryGate.HOST_BINDING)

        # D8 gate 1, re-derived by the caller and reported here. A stored
        # answer would be the thing ADR-0008 D4.1.1 refuses; a `BindingKey`
        # passed in would be the thing `session_mode` refuses. So it arrives as
        # the caller's report, checked as a `bool` and asked again at every
        # stage — the medium can be swapped while an operator reads a screen.
        _require_an_actual_bool("media_binding_holds", media_binding_holds)
        if not media_binding_holds:
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
            # **Again, after the prompt.** `attempt()` is the operator typing a
            # passphrase — the one step in this workflow that blocks on a
            # human — and the fence is raised by device monitoring when the
            # medium is pulled. Reading the flags only above put the last read
            # on the wrong side of the only wait, and a review pulled the
            # medium during the prompt and committed over a fenced one. The
            # class docstring already said a gate checked once is a gate
            # checked at a moment that has passed; this is that moment.
            if self._quarantine.is_fenced:
                self._refuse_gate(RecoveryGate.MEDIUM_FENCED)
            if not self._quarantine.volume_is_quarantined:
                self._refuse_gate(RecoveryGate.NOTHING_TO_RECOVER)

        if snapshot.integrity is not SnapshotIntegrity.VERIFIED:
            self._refuse_gate(RecoveryGate.INTEGRITY_VERIFICATION)
        if snapshot.container_version not in KNOWN_CONTAINER_VERSIONS:
            self._refuse_gate(RecoveryGate.INTEGRITY_VERIFICATION)

        # Every gate passed, just now. The token is spent by the next stage
        # transition and by nothing else.
        # D8 gate 4, here rather than in `commit`, so that reaching this
        # function is reaching all of D8. `None` means "this stage does not ask
        # it"; `False` is an operator who declined.
        if confirmed is not None and not confirmed:
            self._refuse_gate(RecoveryGate.OPERATOR_CONFIRMATION)

        # Every gate passed, just now — and the clearance names which set.
        # The commit's is issued only where D8's gates 2 and 4 were asked.
        asked_all_of_d8 = acquisition is not None and confirmed is not None
        object.__setattr__(
            self,
            "_cleared",
            _GATES_JUST_PASSED if asked_all_of_d8 else _PRE_TRIAL_GATES_PASSED,
        )

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
        """The seal's one writer, and it is not a general one.

        `__setattr__` refuses ordinary assignment with the words "the
        quarantine, the binding and the sitting cannot be replaced", and this
        method — a bound method on every instance — replaced any of them, at
        the same reach as a typo in a `self._…` line. A review used it to
        resume after `interrupt`, to swap the quarantine for an unfenced one,
        and to jump from `NOT_STARTED` to `TRIAL_OPEN` and mint a candidate
        whose whole audit was `['recovery_completed']`.

        This does not claim to be a capability boundary: `object.__setattr__`
        is not defensible in Python and this module says so about the
        quarantine. What it removes is the accidental reach — the four fields
        that legitimately move are named, and a terminal workflow moves none
        of them.
        """

        if name not in _MOVES_DURING_A_RECOVERY:
            raise AttributeError(
                "only the stage, the snapshot, its pinned fields and the "
                "candidate move; the quarantine, the binding and the sitting "
                "cannot be replaced"
            )
        if self._stage in TERMINAL_STAGES:
            raise AttributeError(
                "this workflow has ended; a terminal stage is terminal, and a "
                "further attempt is a new workflow that runs every gate again"
            )
        if name == "_stage" and (self._stage.value, value.value) not in _STAGE_EDGES:
            raise AttributeError(
                "the stage travels its own graph; a jump between stages is not "
                "a stage this workflow reached"
            )
        # A stage the gates lead to is reached by passing them. `REFUSED` and
        # `INTERRUPTED` are the two a refusal and an interruption reach, and
        # they are the only ones a workflow moves to without a clearance.
        if name == "_stage" and value not in _REACHED_WITHOUT_GATES:
            # `COMMITTED` spends the clearance only a full D8 run issues; the
            # earlier stages accept either, because they legitimately ask no
            # acquisition and no confirmation.
            wanted = (
                (_GATES_JUST_PASSED,)
                if value is RecoveryStage.COMMITTED
                else (_GATES_JUST_PASSED, _PRE_TRIAL_GATES_PASSED)
            )
            if self._cleared not in wanted:
                raise AttributeError(
                    "this stage is reached by passing the gates; a workflow "
                    "does not arrive at one it did not pass"
                )
            object.__setattr__(self, "_cleared", None)
        if name == "_candidate" and self._cleared is not _GATES_JUST_PASSED:
            raise AttributeError(
                "a candidate is minted by a commit whose gates passed"
            )
        if name in _PINNED_AT_THE_START and self._stage is not RecoveryStage.NOT_STARTED:
            raise AttributeError(
                "the snapshot a workflow judges is pinned when it starts and "
                "not afterwards"
            )
        if name == "_candidate" and self._stage is not RecoveryStage.TRIAL_OPEN:
            raise AttributeError(
                "a candidate is minted by a commit and by nothing else"
            )
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

    # **Both operands.** The sentence above says "a constructed one, a
    # subclassed one and one from another workflow are all answered `False`",
    # unconditionally — and a stand-in with a `holds` that returns `True`
    # answered `True` for a candidate nobody minted.
    return (
        type(flow) is RecoveryWorkflow
        and type(candidate) is RecoveryCandidate
        and flow.holds(candidate)
    )


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

    __slots__ = ("_audit", "_written", "_sealed")

    def __init__(self) -> None:
        object.__setattr__(self, "_sealed", False)
        self._audit: list[SnapshotAuditEntry] = []
        #: The snapshots this ledger has already recorded a write for, by
        #: value. Marking the *verdict* spent was one `preflight()` call wide:
        #: a preflight is free, read-only and unlimited, so four of them over
        #: one snapshot minted four spendable verdicts and this ledger recorded
        #: four writes for one write. Spent-ness belongs to the snapshot.
        self._written: list[tuple[object, ...]] = []
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("a MigrationLedger is sealed after construction")
        object.__setattr__(self, name, value)

    def __reduce__(self):
        raise TypeError("a MigrationLedger is not serialisable")

    def __getstate__(self):
        raise TypeError("a MigrationLedger does not hand back its fields")

    def __repr__(self) -> str:
        return "MigrationLedger()"

    def audit(self) -> tuple[SnapshotAuditEntry, ...]:
        return tuple(self._audit)

    def may_migrate(self, verdict: PreflightVerdict, *, quarantine: Quarantine) -> bool:
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
        self._require_the_medium_now(verdict, quarantine)
        self._require_every_gate_was_asked(verdict)

        if not verdict.may_migrate:
            self._audit.append(
                SnapshotAuditEntry(
                    event=SnapshotAuditEvent.MIGRATION_REFUSED, check=verdict.refused_by
                )
            )
            return False
        return True

    def _require_every_gate_was_asked(self, verdict: PreflightVerdict) -> None:
        """A passing verdict names all ten checks, or it is not a pass.

        `evaluated` was added so that "not evaluated" and "passed" stop being
        the same answer — and a review pointed out that nothing consumed it, so
        the honesty bought nothing: rebinding `PREFLIGHT_ORDER` produced a
        legitimately minted passing verdict that had been asked **one** check,
        over a medium that was fenced, quarantined and failing its binding, and
        this ledger accepted it. Asking is what makes the completeness a check
        rather than a note.
        """

        # Against **`PreflightCheck` itself**, not against `PREFLIGHT_ORDER`.
        # The rebound global was the attack, and comparing with the same global
        # is tautologically true while the rebind is live: a review asked one
        # check and this accepted it. The enum cannot be shortened by an
        # assignment, so "every check, once" is a question the attacker's own
        # value cannot answer.
        asked = verdict.evaluated
        complete = len(asked) == len(PreflightCheck) and set(asked) == set(PreflightCheck)
        if verdict.may_migrate and not complete:
            raise RecoveryRefused(
                Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK,
                "a passing verdict is one that was asked every check; a "
                "shorter one answers a question nobody finished",
            )
        # **And a refusal names the check that refused, last.** This ran only
        # on the passing half, so a rebound order produced a refusal whose
        # classification was a check the run never got to — and that
        # classification is the whole of what an operator is told and what the
        # audit keeps. The word "in order" is gone from the message above,
        # because set equality is what it checks; the order is pinned by
        # `tests/unit/test_snapshot.py`'s ten-position drive.
        if not verdict.may_migrate:
            stopped_at = None
            for check in asked:
                stopped_at = check
            named = stopped_at is verdict.refused_by
            if not named or len(set(asked)) != len(asked):
                raise RecoveryRefused(
                    Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK,
                    "a refusal names the check it stopped at; a classification "
                    "the run never reached is not one",
                )

    def _require_the_medium_now(
        self, verdict: PreflightVerdict, quarantine: Quarantine
    ) -> None:
        """The fence and the quarantine, **at the moment of use**.

        `preflight` asks them first, and `PREFLIGHT_ORDER`'s table justifies
        the fence with ADR-0010 D9 — a version upgrade is not a way round it.
        A verdict, though, has no session, no medium, no boot and no clock: a
        review held one minted before a fence, fenced the medium, quarantined
        the volume, and the ledger still answered `True` and recorded a write.
        A durable bearer token for "a large write to this volume may run" is
        exactly what D9 refuses.

        `RecoveryWorkflow` re-reads its gates before the trial, before the
        commit and again after the prompt, for this reason. The migration path
        re-read nothing.
        """

        _require_a_real_quarantine(quarantine)
        # **The one it judged.** This re-read whatever quarantine the caller
        # handed in on this call and never asked whether that was the one the
        # preflight looked at, while the doc claimed it re-read "as the
        # workflow's gates do" — and the workflow binds its quarantine at
        # construction. A review spent a verdict minted over one medium in one
        # sitting against a different medium in a different sitting.
        if verdict._judged is not None and verdict._judged is not quarantine:
            raise RecoveryRefused(
                Refusal.MEDIUM_MOVED_SINCE_THE_PREFLIGHT,
                "a verdict is spent against the medium its preflight judged; "
                "another medium is another question",
            )
        if quarantine.is_fenced or quarantine.volume_is_quarantined:
            self._audit.append(
                SnapshotAuditEntry(
                    event=SnapshotAuditEvent.MIGRATION_REFUSED,
                    check=(
                        PreflightCheck.MEDIUM_FENCED
                        if quarantine.is_fenced
                        else PreflightCheck.VOLUME_QUARANTINED
                    ),
                )
            )
            raise RecoveryRefused(
                Refusal.MEDIUM_MOVED_SINCE_THE_PREFLIGHT,
                "the medium is fenced or the volume is quarantined now; a "
                "verdict is not a permission that outlives what it judged",
            )

    def note_snapshot_written(
        self,
        verdict: PreflightVerdict,
        snapshot: SnapshotDescriptor,
        *,
        quarantine: Quarantine,
    ) -> None:
        """Record that the caller wrote a snapshot. **After** it did.

        Separate from :meth:`may_migrate` because recording the write at
        permission time asserts an act that has not happened. The verdict is
        re-checked here so that this cannot be reached without one.

        **Once.** One preflight judged one snapshot, so one write is
        recordable against it. A review replayed a single verdict into two
        ledgers and recorded four writes for one judged snapshot; the
        spent-ness is kept module-side rather than per-ledger, because a second
        ledger is not a second write.
        """

        _require_a_real_snapshot(snapshot)
        self._require_the_medium_now(verdict, quarantine)
        if (
            not verdict_was_minted_here(verdict)
            or not verdict.may_migrate
            or verdict._snapshot is not snapshot
        ):
            raise RecoveryRefused(
                Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT,
                "a snapshot is recorded against the preflight that judged "
                "that snapshot; a passing verdict for a different one is not "
                "permission to record this one",
            )
        # Asked here as well, after the verdict is known to be one of ours. It
        # was enforced on the **permission** path and not on the **recording**
        # path, so a verdict `may_migrate` had refused for asking one check was
        # still accepted as the record of a write.
        self._require_every_gate_was_asked(verdict)
        written = _fields_of(snapshot)
        recorded = (quarantine.session_id, written)
        if (
            verdict in _ALREADY_SPENT
            or written in self._written
            or recorded in _SNAPSHOTS_RECORDED
        ):
            raise RecoveryRefused(
                Refusal.VERDICT_ALREADY_SPENT,
                "this snapshot's write is already recorded; a second record "
                "against it would be a second write that did not happen",
            )
        _ALREADY_SPENT.add(verdict)
        self._written.append(written)
        _SNAPSHOTS_RECORDED.append(recorded)

        self._audit.append(
            SnapshotAuditEntry(
                event=SnapshotAuditEvent.SNAPSHOT_WRITTEN,
                schema_version=snapshot.schema_version,
                fingerprint=snapshot.fingerprint,
            )
        )
