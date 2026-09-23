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

import threading
from enum import Enum
from weakref import WeakKeyDictionary as _WeakKeyDictionary
from weakref import WeakSet as _WeakSet
from weakref import ref as _weakref

from .commissioning import SessionBinding, binding_applies
from .inventory import InterfaceObservation
from .quarantine import Quarantine
from .refusals import Refused
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


class SnapshotDescriptor:
    """What a snapshot says about itself. Versioned, and judged alone.

    `fingerprint` is **opaque**: a value the caller computed, which this module
    compares and never interprets. It is not a device identity, not a path and
    not a key, and the audit carries it only because "which snapshot" has to be
    answerable without naming anything about the medium.

    **Not a dataclass**, for the reason `CapacityReport` gives for itself: it
    was one, `__getstate__` and `__reduce__` raised, and `dataclasses.asdict`
    still handed the fingerprint back — `asdict` walks `dataclasses.fields()`
    directly and does not go through either hook. A review printed it that
    way, through the one object every stage of a recovery holds. Four fields
    in `__slots__`, a hand-written `__init__` doing what `__post_init__` did,
    and a class that is not a dataclass at all closes `asdict`, `astuple` and
    `vars()` at once, the same as `CapacityReport`.
    """

    __slots__ = ("_container_version", "_schema_version", "_integrity", "_fingerprint")

    def __init__(
        self,
        container_version: int,
        schema_version: int,
        integrity: SnapshotIntegrity,
        fingerprint: str,
    ) -> None:
        # Checked where it is built. `azazel_boot.dirty_write` learned this the
        # expensive way: an annotation is not a check, and a review built its
        # observation out of three strings naming the worst faults there are
        # and got a clean write.
        if not isinstance(integrity, SnapshotIntegrity):
            raise TypeError("integrity must be a member of SnapshotIntegrity")
        for name, value in (
            ("container_version", container_version),
            ("schema_version", schema_version),
        ):
            # `type(...) is int`, not `isinstance`: a round-four review built
            # this object through this constructor with `int` subclasses that
            # answered `7` and compared as anything, and the field-by-field
            # substitution check compared the subclass's answers.
            if type(value) is not int or value < 1:
                raise TypeError(f"{name} must be a positive integer version")
        if type(fingerprint) is not str or not fingerprint.strip():
            raise TypeError("fingerprint must be a non-empty opaque string")
        # And **shaped** like one. "Opaque" was a word here and a check
        # nowhere: this value is the single caller-supplied string the audit
        # carries, and a review put a capacity figure, a device serial and a
        # host path through this constructor into an audit entry in which
        # every other value is redacted.
        _require_an_opaque_value("fingerprint", fingerprint)
        object.__setattr__(self, "_container_version", container_version)
        object.__setattr__(self, "_schema_version", schema_version)
        object.__setattr__(self, "_integrity", integrity)
        object.__setattr__(self, "_fingerprint", fingerprint)

    @property
    def container_version(self) -> int:
        return self._container_version

    @property
    def schema_version(self) -> int:
        return self._schema_version

    @property
    def integrity(self) -> SnapshotIntegrity:
        return self._integrity

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("a SnapshotDescriptor is fixed when it is built")

    def __delattr__(self, name: str) -> None:
        """`__setattr__` here is unconditional, not gated on a seal.

        This class has no `_sealed` slot to delete — its `__setattr__`
        refuses every assignment from the moment the object exists. What this
        closes is `del x.<field>` reaching the same slots by a different
        dunder.
        """

        raise AttributeError("a SnapshotDescriptor is fixed when it is built")

    def __reduce__(self):
        raise TypeError("a SnapshotDescriptor is not serialisable")

    def __getstate__(self):
        raise TypeError("a SnapshotDescriptor is not serialisable")

    def __repr__(self) -> str:
        """Redacted. A fingerprint in a repr is a fingerprint in every traceback.

        Also survives a half-built instance, the same way
        `RecoveryWorkflow.__repr__` does and for the same reason: `__init__`
        validates every field before assigning any of them, so a `TypeError`
        from one of its checks leaves an object with none of its slots set.
        A round-22 review found that asking `traceback.TracebackException`
        for captured locals on exactly that `TypeError` — the ordinary shape
        of `pytest --showlocals` and most crash reporters — called this
        unguarded repr and died inside it with a second, unhandled
        `AttributeError`, turning a clean refusal into a crash.
        """

        container_version = getattr(self, "_container_version", None)
        if container_version is None:
            return "SnapshotDescriptor(unbuilt)"
        return (
            f"SnapshotDescriptor(container_version={container_version}, "
            f"schema_version={self.schema_version}, "
            f"integrity={self.integrity.value}, fingerprint=<redacted>)"
        )

    def __eq__(self, other: object) -> bool:
        """By value, over the exact type — the dataclass default this replaces.

        `type(other) is type(self)`, not `isinstance`: this class is checked
        the same way everywhere else in this module, and an `__eq__` that
        admits a subclass is an `__eq__` a subclass can answer on the real
        object's behalf. Nothing in this module *uses* this for a decision —
        `_require_the_same_snapshot` compares `_fields_of()` tuples on
        purpose, so a hostile `__eq__` cannot decide a substitution — this
        exists for the ordinary convenience a value type is expected to have.

        **Both operands, not only the right one.** `type(other) is not
        SnapshotDescriptor` checking only the argument left the reflected
        case open: `Fake(SnapshotDescriptor): pass` has no `__eq__` of its
        own, so `fake == descriptor` first tries `descriptor.__eq__(fake)` —
        refused, correctly — and Python then tries the reflected
        `fake.__eq__(descriptor)`, which is this *same* method, inherited,
        now running with `self` bound to the `Fake` instance. From there
        `type(other) is SnapshotDescriptor` is true, and the comparison
        answered `True` for two objects of different exact types. Checking
        `type(self)` as well closes the reflected case the same way.
        """

        if type(self) is not SnapshotDescriptor or type(other) is not SnapshotDescriptor:
            return NotImplemented
        mine = self._fields_if_built()
        theirs = other._fields_if_built()
        if mine is None or theirs is None:
            # A half-built instance — `__init__` validated some field and
            # raised before assigning any of them (round 22's `__repr__` fix
            # is the same shape; round 23's security review found `__eq__`
            # and `__hash__` shared the gap). There is no value here to be
            # equal *of*, so it is never equal to anything, itself included.
            return False
        return mine == theirs

    def _fields_if_built(self) -> tuple[object, ...] | None:
        """`_fields_of(self)`, or `None` for an instance `__init__` never finished."""

        if getattr(self, "_container_version", None) is None:
            return None
        return _fields_of(self)

    def __hash__(self) -> int:
        fields = self._fields_if_built()
        if fields is None:
            raise TypeError("a half-built SnapshotDescriptor is not hashable")
        return hash((SnapshotDescriptor, *fields))


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

    def __delattr__(self, name: str) -> None:
        """`__setattr__` here is unconditional, not gated on a seal.

        This class has no `_sealed` slot to delete — its `__setattr__`
        refuses **every** assignment from the moment the object exists, so
        there was never a flag to remove. What `__delattr__` closes is
        `del x.<field>`, which reaches the same slots by a different dunder:
        the sibling classes that gate on `_sealed` needed this because
        deleting the gate reopened assignment; this class needed it because
        the field would otherwise simply be gone, and a caller reading it
        afterward would meet `AttributeError` for the wrong reason.

        `azazel_boot.media.DeviceIdentity` already refused this shape; the
        idiom was in the codebase and in one class of twelve.
        """

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

    **Declared in the order they are asked in**, because that order is now
    load-bearing twice over. `PREFLIGHT_ORDER` below is the tuple `preflight`
    iterates, and a module global is a thing a caller can rebind: a review
    rebound it, obtained a legitimately minted verdict that had been asked one
    check, and `MigrationLedger` accepted it. The ledger asks its completeness
    question against **this class**, which no assignment shortens or permutes,
    so the declaration order here is what `PREFLIGHT_ORDER` is checked against
    rather than a matter of taste. `tests/unit/test_snapshot.py` asserts the
    two agree, so they cannot drift apart in the source either.
    """

    MEDIUM_FENCED = "medium_fenced"
    VOLUME_QUARANTINED = "volume_quarantined"
    SNAPSHOT_ABSENT = "snapshot_absent"
    SNAPSHOT_CONTAINER_UNKNOWN = "snapshot_container_unknown"
    SNAPSHOT_INTEGRITY = "snapshot_integrity"
    REQUIRED_SPACE = "required_space"
    SCHEMA_COMPATIBILITY = "schema_compatibility"
    BINDING = "binding"
    GENERATION = "generation"
    IMAGE_DIGEST = "image_digest"


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

    __slots__ = ("_refused_by", "_snapshot", "_evaluated", "__weakref__")

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

        **What that sentence covers, exactly.** It is about the token and the
        medium, and it was written as though it covered everything: a verdict
        does hold `_snapshot`, the `SnapshotDescriptor` its preflight judged,
        so `verdict._snapshot.fingerprint` reads back. That is deliberate — the
        tie is what `note_snapshot_written` checks with `is` — and it discloses
        nothing new, because the descriptor is the caller's own object, passed
        in by the caller, whose `__repr__` redacts. What is **not** here is a
        mintedness token and a `Quarantine`; the fingerprint is.

        Round eight found that sentence false again, and worse than the token
        was. `_judged` held the **live `Quarantine`**: `fence()`,
        `quarantine_volume()`, the sitting and the medium identity, one
        attribute access from anyone a verdict was legitimately handed — on
        refusals as well as passes, through an object whose own docstring said
        there was nothing to read off it. Which medium a verdict judged is now
        kept the way mintedness is, in `_JUDGED_BY`, and the sentence is true
        again for the same reason it was written.
        """

        # **Checked here, for the same reason every other field in this
        # module is.** `refused_by` had no type check at all — `preflight`
        # only ever passes `None` or a genuine `PreflightCheck` member, but
        # the public constructor took anything. A round-24 security review
        # built `PreflightVerdict("nonsense")`, which constructed cleanly and
        # then crashed `__repr__` with a bare `AttributeError` reading
        # `"nonsense".value`; worse, a hostile object whose own `.value`
        # returns caller-chosen text rendered that text verbatim through
        # `__repr__`, the exact disclosure class `_require_an_exact_str`/
        # `_require_an_opaque_value` exist elsewhere in this file to refuse.
        if refused_by is not None and not isinstance(refused_by, PreflightCheck):
            raise TypeError("refused_by must be a PreflightCheck or None")
        object.__setattr__(self, "_refused_by", refused_by)
        object.__setattr__(self, "_snapshot", None)
        object.__setattr__(self, "_evaluated", ())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("a PreflightVerdict is fixed when it is minted")

    def __delattr__(self, name: str) -> None:
        """`__setattr__` here is unconditional, not gated on a seal.

        This class has no `_sealed` slot to delete — its `__setattr__`
        refuses **every** assignment from the moment the object exists, so
        there was never a flag to remove. What `__delattr__` closes is
        `del x.<field>`, which reaches the same slots by a different dunder:
        the sibling classes that gate on `_sealed` needed this because
        deleting the gate reopened assignment; this class needed it because
        the field would otherwise simply be gone, and a caller reading it
        afterward would meet `AttributeError` for the wrong reason.

        `azazel_boot.media.DeviceIdentity` already refused this shape; the
        idiom was in the codebase and in one class of twelve.
        """

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


#: Where a `_WeakIdentityIndex`'s per-instance `(weak reference, value)`
#: store actually lives — **round eleven's fix, replacing an instance
#: attribute.** It was `self._by_id`, and two independent reviews (security,
#: doctrine) broke that the same way from different directions:
#:
#: - `gc.get_referents(idx)` — stdlib, always available, no private name
#:   anywhere in the call — walks an object's own `__slots__` and hands back
#:   whatever is stored there. For `__slots__ = ("_by_id",)` that is the
#:   live dict itself, not a copy: `list(gc.get_referents(_JUDGED_BY))[0]`
#:   recovered every `(weakref, Quarantine)` pair the index held, and a
#:   handful of lines of stdlib-only code turned that into a forged
#:   `PreflightVerdict` accepted by `MigrationLedger.may_migrate` with none
#:   of the ten gates run.
#: - The class defined no `__setattr__`, so `idx._by_id = {...}` — ordinary
#:   dot assignment, the weakest reach in the language — rebound it
#:   outright. The docstring used to claim this needed "`object.__setattr__`
#:   -grade access"; it did not, and saying so was simply wrong.
#:
#: Both routes exploited the same fact: **a value stored as an instance's
#: own attribute is that instance's attribute**, reachable however Python
#: reaches attributes. There is no fix that keeps storing it there. Instead
#: `_WeakIdentityIndex` keeps `__slots__ = ("__weakref__",)` — no attribute
#: for either route to reach — and the dict for each instance lives here,
#: keyed by the instance itself. `gc.get_referents(idx)` now yields only
#: `type(idx)`, and `idx._by_id = {...}` — with or without
#: `object.__setattr__` — raises `AttributeError`, because there is no such
#: slot to assign into on the instance at all.
#:
#: This module's own global-reachability rule still applies to
#: `_INDEX_STORAGE` itself, exactly as it does to `_MINTED_HERE` and every
#: other module-level name here: reaching it by that name, or by walking
#: this module's own `__dict__`, is the disclosed "careless-caller defence,
#: not a capability boundary" limit stated throughout this file, not a new
#: one. What changed, and is real, is that the index no longer falls
#: *short* of that limit — a caller who does not know `_INDEX_STORAGE`'s
#: name and never imported this module could not previously reach a
#: judged medium through this class's own logic at all; now they still
#: cannot, through it.
#:
#: **A round-twelve review found a deeper limit no rename reaches: `gc.
#: get_objects()` needs no name at all.** It is a full heap walk, and
#: filtering its result by `isinstance(x, weakref.WeakKeyDictionary)` finds
#: `_INDEX_STORAGE` directly — no `import azazel_boot.snapshot`, no private
#: spelling, nothing this module controls. And that is not even the
#: shortest path: `weakref.ref` objects are themselves walked by `gc.
#: get_objects()`, so the entries this class stores are reachable that way
#: too, without ever finding `_INDEX_STORAGE` first — and shorter still,
#: **a live `Quarantine`, wherever it is held, is a member of `gc.
#: get_objects()` in its own right**: `[o for o in gc.get_objects() if
#: type(o).__name__ == "Quarantine"]` finds one with no weak reference, no
#: index and no import of this module anywhere in the chain. No amount of
#: moving where this class keeps its store changes that, because the thing
#: being found is not the store — it is any live object in the same OS
#: process, which `gc` exists to enumerate irrespective of what holds it.
#:
#: So this class's claims are narrowed to what they can actually deliver:
#: no *call this module exposes* — no method, no return value, no
#: exception, no repr, no log line — hands a caller a medium it did not
#: already hold. That is a claim about this module's own surface. It was
#: never, and could not be, a claim that a `Quarantine` is invisible to
#: other code sharing the interpreter: nothing running inside one OS
#: process can hide a live object's existence from `gc` in that same
#: process, with or without this module, with or without Python. Treating
#: that as a gap in `_WeakIdentityIndex` and continuing to hunt for a
#: narrower store would be chasing a door that was never the one open.
_INDEX_STORAGE: _WeakKeyDictionary = _WeakKeyDictionary()


class _WeakIdentityIndex:
    """Maps an object, by identity, to a value — with no way to enumerate
    the objects back out.

    `_JUDGED_BY` and `_SNAPSHOTS_RECORDED` were both `WeakKeyDictionary`
    instances, keyed by the live `Quarantine`. That was the wrong container:
    `.keys()` on a `WeakKeyDictionary` dereferences every live weak key and
    hands back the real objects — no prior possession of one required, only
    `import azazel_boot.snapshot` and a call to an entirely ordinary public
    method. A review read `list(_JUDGED_BY.keys())` and got back every
    medium any preflight in the process had judged, live, through the exact
    container chosen specifically to avoid handing one back.

    This closes that door by never using the object as a dict key at all.
    The store, keyed by `id(obj)`, holds `(weak reference, value)` pairs —
    an opaque integer key with no path back to the object, verified by the
    weak reference on every lookup so a collected object's slot, re-used by
    an unrelated later object at the same address, cannot answer for it.
    `get` and `__contains__` dereference the stored weak reference and
    compare it with `is` against the object presented, so a coincidental
    `id()` collision with a *different*, still-live object answers `False`,
    not `True`.

    No method here returns the object, iterates it, or exposes the
    underlying dict — there is nothing analogous to `.keys()` to call.
    **The store is not this instance's own attribute** — see
    `_INDEX_STORAGE` above for why, and for what that does and does not
    close. `__slots__` holds only `__weakref__`, so `gc.get_referents` on an
    instance yields nothing but its type, and any attempt to assign a
    `_by_id`-shaped attribute onto the instance — by any route, ordinary or
    `object.__setattr__` — fails with `AttributeError` for the same reason:
    there is no such slot to hold it.
    """

    __slots__ = ("__weakref__",)

    def __init__(self) -> None:
        _INDEX_STORAGE[self] = {}

    def get(self, obj: object) -> object | None:
        entry = _INDEX_STORAGE.get(self).get(id(obj))
        if entry is None:
            return None
        alive, value = entry
        return value if alive() is obj else None

    def __setitem__(self, obj: object, value: object) -> None:
        oid = id(obj)
        store = _INDEX_STORAGE.get(self)

        def _cleanup(_dead_ref: object, oid: int = oid, store: dict = store) -> None:
            store.pop(oid, None)

        store[oid] = (_weakref(obj, _cleanup), value)

    def __contains__(self, obj: object) -> bool:
        entry = _INDEX_STORAGE.get(self).get(id(obj))
        if entry is None:
            return False
        alive, _value = entry
        return alive() is obj


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

#: Which verdicts each medium's preflights judged — kept **beside** the
#: verdict rather than on it. It was a `_judged` slot, and that slot handed the
#: live `Quarantine` to every holder of a verdict: `fence()`,
#: `quarantine_volume()`, the sitting and the boot medium identity, one
#: attribute access away, on refusals as well as passes. The same reasoning
#: `_MINTED_HERE` rests on applies unchanged — a value that is not on the
#: object cannot be read off it.
#:
#: **Keyed by the medium, not by the verdict**, which is the other half of the
#: same lesson. Keyed the other way round, the answer to "which medium?" was a
#: `Quarantine` coming *out* of this module's own index — and the static walk
#: that holds every quarantine here to four reads finds them by the name they
#: travel under, so a `Quarantine` bound to a local from an index was outside
#: it. A review harvested the sitting id and the boot medium identity out of
#: this module through exactly that, with the whole suite green. Inverted,
#: nothing that comes out of either index is a medium: this one answers with
#: verdicts and the other with values.
#:
#: Weak on both sides: the medium is the key, so remembering something about it
#: does not keep it alive, and the verdicts are held in a `WeakSet`.
#:
#: **A `_WeakIdentityIndex`, not a `WeakKeyDictionary`.** It was one, and
#: `.keys()` on a `WeakKeyDictionary` dereferences every live weak key and
#: hands back the real objects — no possession required, only
#: `import azazel_boot.snapshot` and a call to a completely ordinary public
#: method. A review read `list(_JUDGED_BY.keys())` and got back every
#: `Quarantine` any preflight in the process had judged, live, through the
#: exact container this module chose specifically to avoid handing one back.
#: The paragraph above said "nothing that comes out of either index is a
#: medium"; `.keys()` came out of it a medium. See `_WeakIdentityIndex` below.
_JUDGED_BY: _WeakIdentityIndex = _WeakIdentityIndex()

#: The verdicts `_mint` produced, which is to say the verdicts that judged some
#: medium. `_MINTED_HERE` is the careless-caller list a caller can add to;
#: this one is written only where a real `Quarantine` was supplied, so "this
#: verdict judged no medium at all" stays answerable without asking the index
#: above, which would mean walking media.
_JUDGED_SOMETHING: _WeakSet = _WeakSet()

#: And the four values the snapshot had **at the moment it was judged**.
#: `note_snapshot_written` re-derived them from the descriptor it was handed,
#: which asks the object as it is *now*: `object.__setattr__` rewrites a frozen
#: dataclass's field, so one judged snapshot produced a second key and the
#: "once" below counted the second record as a first write.
_JUDGED_FIELDS: _WeakKeyDictionary = _WeakKeyDictionary()

#: And the **snapshots**, by value, across every ledger in the process. Marking
#: the verdict spent was exactly one `preflight()` call wide: a preflight is
#: free, read-only and unlimited, so a review minted a fresh verdict per ledger
#: and recorded four writes for one judged snapshot — with the per-ledger list
#: below satisfied every time, because each ledger was new.
#:
#: The snapshot values a write has been recorded for, **per medium**. It was a
#: `WeakSet` of descriptors, and both halves of that were wrong: dropping the
#: last reference evaporated the entry, so a review recorded five writes for
#: one snapshot value through the public API alone — and an entry for one
#: sitting refused an unrelated later sitting's own write, because the key said
#: nothing about whose medium it was.
#:
#: The sitting id was the first attempt at "whose medium", and it is not one: a
#: sitting has one `PersistenceSession` and can hold more than one quarantined
#: medium, so two media in one boot collided and a genuine second write was
#: refused with "a second write that did not happen" — the exact failure the
#: paragraph above diagnoses, one level up. The key is the `Quarantine`
#: **object**, compared by identity, because that is what "this medium, in this
#: sitting" is.
#:
#: It was a list of `(medium, values)` pairs, which meant iterating it bound a
#: live `Quarantine` to a loop variable — a medium coming *out* of this
#: module's own bookkeeping, where the walk that bounds every quarantine here
#: cannot see it. Keyed by the medium instead, what comes out is a list of
#: value tuples and nothing else.
#:
#: Weak, and that is not the garbage-collector dependence the earlier note
#: rejected: the key is an object identity, so a medium nobody holds any more
#: is a medium that cannot be presented again. What the collector takes is an
#: answer to a question nobody can ask. What it leaves is that this module
#: holds no medium alive, anywhere, for the life of the process.
#:
#: A `_WeakIdentityIndex`, for the same reason `_JUDGED_BY` is one: a
#: `WeakKeyDictionary`'s `.keys()` handed the medium straight back.
_SNAPSHOTS_RECORDED: _WeakIdentityIndex = _WeakIdentityIndex()

#: The checks, in the order they are declared, **taken once at import**. The
#: ledger's completeness rule used to build this fresh on every call, out of
#: `tuple(PreflightCheck)`, on the argument that "the enum cannot be shortened
#: by an assignment". That is false: `PreflightCheck._member_names_ = [...]` is
#: accepted, and `tuple(PreflightCheck)` then returns whatever was left — so a
#: review shortened the enum *and* `PREFLIGHT_ORDER` with two assignments and
#: authorised a migration over a snapshot whose integrity had failed, to an
#: unsupported schema, with no room and no binding, having asked one check of
#: ten. Both operands resolved out of the same namespace; the guard had moved
#: from one rebindable global to another.
#:
#: A tuple built at import is not shortened by a later rebind of the enum, and
#: the two are compared on every use, so a rebind is **detected** rather than
#: obeyed. This is not a capability boundary — the constant is a module global
#: like any other, and this module says the same thing about
#: `object.__setattr__`. What it buys is that the attack now needs two
#: coordinated rebinds instead of one, and that the shortening leaves a
#: refusal rather than a permission.
_EVERY_CHECK = tuple(PreflightCheck)

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

#: The only three fields a recovery moves. `_sealed_assign` writes these and
#: nothing else — not the quarantine, not the binding, not the sitting, and
#: not once the stage is terminal. It was four: `_snapshot` held the caller's
#: own descriptor, was read nowhere, and was what a review moved the commit's
#: mint onto to commit a substituted snapshot with the suite green.
_MOVES_DURING_A_RECOVERY = frozenset({"_stage", "_pinned", "_candidate"})

#: The edges the stage may travel. Naming the fields that move was not enough:
#: `_stage` and `_pinned` were both on the list above and `NOT_STARTED` and
#: `TRIAL_OPEN` are both non-terminal, so a review jumped straight between them
#: and minted a candidate whose entire audit was `['recovery_completed']` — no
#: start, no operator, no trial — through a bound method on every instance.
#: Written once, when the workflow starts, and never again.
_PINNED_AT_THE_START = frozenset({"_pinned"})

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


def _require_an_opaque_value(name: str, value: str) -> None:
    """A fingerprint is opaque, and "opaque" was a word rather than a check.

    `SnapshotAuditEntry.fingerprint` is the one caller-supplied string this
    module writes into an audit — the object a log actually holds — and the
    confidentiality claim around it is about the *fields* the entry has. A
    review pointed out that the field's **contents** are whatever the caller
    chose, and put `"capacity_available=17179869184 medium=usb-SN-AA11BB22
    host=/dev/nvme0n1p3"` through `_require_an_exact_str` and into an audit
    entry, where every other value is redacted.

    This narrows rather than guarantees, and the difference is the point: a
    path, a rendered `key=value` blob and a multi-line value are refused, and
    a caller who puts a device serial in an opaque-looking token still can.
    What a fingerprint means is the caller's to keep; what it may *look* like
    is checkable, and an unbounded string in a log was not.

    "Multi-line" is asked with `str.splitlines()` rather than a fixed list of
    forbidden characters. `\n`/`\r` alone missed `\x0b`, `\x0c`, `\x85` and
    the two Unicode line/paragraph separators — every boundary
    `str.splitlines()` itself recognises, and the same boundaries a
    `.splitlines()`-based log viewer would split on. A review put three
    "lines" through as one value, joined by a form feed and a paragraph
    separator instead of `\n`, and each rendered as a separate line wherever
    the audit was read back. Asking the same function the value would later
    be split by is what makes the check and the rendering agree.
    """

    if len(value) > 128:
        raise TypeError(f"{name} must be an opaque token, not a rendered record")
    if len(value.splitlines()) > 1:
        raise TypeError(
            f"{name} must be an opaque token; a multi-line value is not one"
        )
    for forbidden in (" ", "\t", "/", "\\", "="):
        if forbidden in value:
            raise TypeError(
                f"{name} must be an opaque token; a path, a rendered field or "
                "a line of text is not one"
            )


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
    this function's source and asserts they are `SnapshotDescriptor`'s own
    `__slots__`, so a fifth field cannot be added and silently left
    uncompared.
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


#: Guards `_remember_the_medium`'s check-then-record over `_JUDGED_BY` and
#: `_JUDGED_SOMETHING` — the sibling of `_WRITE_LOCK`, added at round
#: nineteen. `preflight()` is documented elsewhere in this module as "free,
#: read-only and unlimited," an explicit invitation to call it as often and
#: as concurrently as a caller likes; two real threads doing exactly that
#: over the *same* `Quarantine`, the first time it is judged, could each see
#: `_JUDGED_BY.get(quarantine) is None`, each build their own fresh
#: `_WeakSet`, and each write it — the second write silently discarding the
#: first thread's set, and the verdict it held, from `_JUDGED_BY`.
#: `_MINTED_HERE` still answers for the dropped verdict (a different index,
#: written earlier in `_mint`, unaffected by this race), so
#: `verdict_was_minted_here` stays `True` for it — but `_medium_was_judged`
#: then answers `False` for a verdict that genuinely did judge exactly this
#: medium, and `may_migrate`/`note_snapshot_written` refuse it with
#: `MEDIUM_MOVED_SINCE_THE_PREFLIGHT`, a classification that is simply false.
#: Fails closed — a legitimate migration is wrongly refused, never wrongly
#: permitted — but it is still a real misclassification of exactly the kind
#: D7's checks exist to get right, so it is fixed the same way
#: `_SNAPSHOTS_RECORDED`'s check-then-record was: one critical section, one
#: lock.
_JUDGED_LOCK: threading.Lock = threading.Lock()


def _remember_the_medium(verdict: PreflightVerdict, quarantine: Quarantine) -> None:
    """The index's one write, named so that the travel is visible.

    `tests/unit/test_snapshot.py` holds every quarantine in this module to four
    reads and a short list of places it may travel to unread. Putting the
    write behind a name puts it on that list deliberately rather than as a
    shape the walk happens not to look at.

    The medium is the **key**. Nothing this function or its readers hand back
    is a `Quarantine`, so no later line can bind one to a local the walk does
    not look at.
    """

    with _JUDGED_LOCK:
        judged = _JUDGED_BY.get(quarantine)
        if judged is None:
            judged = _WeakSet()
            _JUDGED_BY[quarantine] = judged
        judged.add(verdict)
        _JUDGED_SOMETHING.add(verdict)


def _a_medium_was_judged(verdict: PreflightVerdict) -> bool:
    """Whether this verdict judged **any** medium.

    Asked separately from the identity question so that the two get different
    classifications. `_mint` requires a medium, so a verdict with none is one
    somebody put on `_MINTED_HERE` rather than one a preflight produced, and
    telling an operator "the medium moved since the preflight" about a call
    that never had a preflight is the misclassification this module refuses to
    make elsewhere.

    Asked of its own list rather than of `_JUDGED_BY`, because asking that one
    would mean walking media — which is the shape this module has just stopped
    doing.
    """

    return verdict in _JUDGED_SOMETHING


def _medium_was_judged(verdict: PreflightVerdict, quarantine: Quarantine) -> bool:
    """Whether this verdict's preflight judged **this** medium. By identity.

    Not "is not a different one": a verdict with no medium recorded answers
    `False` here, where the `is not None` this replaces answered "fine". The
    identity is the dictionary's own key lookup, so nothing here holds a medium
    or hands one back.
    """

    judged = _JUDGED_BY.get(quarantine)
    return judged is not None and verdict in judged


#: Guards one check-then-record critical section: `_SNAPSHOTS_RECORDED`. It
#: was two separate module functions — `_a_write_is_recorded` then
#: `_remember_a_write` — called one after the other from
#: `note_snapshot_written`, with nothing between the check and the record but
#: ordinary Python statements a second thread can land between. A
#: round-eighteen review drove two real threads through `note_snapshot_written`
#: for the same verdict, the same medium and the same judged values, and both
#: observed "not yet recorded" before either wrote — two `SNAPSHOT_WRITTEN`
#: audit entries for one preflight authorization, contradicting the method's
#: own "once" the docstring promises. This is not the vocabulary-break class
#: `_sealed_assign`'s terminal-stage guard closes elsewhere in this module: no
#: exception raced here at all, the state itself was wrong — a second write
#: really was recorded — so a re-check that only changes which exception type
#: escapes cannot fix it. It needs the check and the record to be one
#: uninterruptible act, which is what a lock is for.
#:
#: **Not "the one critical section this module has" — a round-nineteen
#: doctrine review caught an earlier draft of this comment overclaiming
#: that.** `_remember_the_medium`, below, has the identical shape over the
#: *other* module-side index and needed the same fix; see `_JUDGED_LOCK`.
#: The two are separate locks rather than one shared lock because they guard
#: independent state (`_SNAPSHOTS_RECORDED` here, `_JUDGED_BY`/
#: `_JUDGED_SOMETHING` there) reached from independent call paths
#: (`note_snapshot_written` here, every `preflight()` call there) — sharing
#: one lock would serialise those two unrelated operations against each
#: other for no reason this module's own state needs.
_WRITE_LOCK: threading.Lock = threading.Lock()


def _remember_a_write_if_new(quarantine: Quarantine, fields: tuple[object, ...]) -> bool:
    """Record a write over this medium, for these values — atomically.

    Replaces `_a_write_is_recorded` followed by `_remember_a_write`: that was
    a check and a record as two separate calls, and a second thread landing
    between them saw the same "not yet recorded" answer the first thread had
    already acted on. Merged into one critical section under `_WRITE_LOCK`,
    the check and the record happen as one act; the caller is told whether
    *this* call is the one that recorded it, and refuses when it is not.

    The medium is the key, so its identity is the lookup; the values are
    compared by equality, because two media in one sitting are two media and
    the same snapshot value written over each is two writes.
    """

    with _WRITE_LOCK:
        written = _SNAPSHOTS_RECORDED.get(quarantine)
        if written is None:
            written = []
            _SNAPSHOTS_RECORDED[quarantine] = written
        if fields in written:
            return False
        written.append(fields)
        return True


def _raise_already_spent() -> None:
    """Raise from a frame holding nothing derived from the snapshot.

    This refusal was raised from `note_snapshot_written`, whose locals at that
    moment held `written` and `recorded` — tuples built out of the descriptor's
    four values, which is exactly what `SnapshotDescriptor.__repr__` redacts
    and what `_raise_gate_refused` exists to keep out of a captured-locals
    traceback. The fingerprint and the sitting rendered in plaintext in a
    module that builds two helpers to stop precisely that.

    The limit `azazel_boot.session_mode` states applies unchanged: the frame
    above still holds what it was handed, and a frame cannot forget its own
    argument.
    """

    raise RecoveryRefused(
        Refusal.VERDICT_ALREADY_SPENT,
        "this snapshot's write is already recorded; a second record against "
        "it would be a second write that did not happen",
    )


def _mint(
    refused_by: PreflightCheck | None,
    quarantine: Quarantine,
    snapshot: SnapshotDescriptor | None = None,
    evaluated: tuple[PreflightCheck, ...] = (),
) -> PreflightVerdict:
    """Build a verdict and record **which medium and which snapshot it judged**.

    The verdict named no snapshot, so `note_snapshot_written` could only
    re-check that *some* passing verdict existed: a re-review recorded
    `SNAPSHOT_WRITTEN` against a snapshot whose integrity was `FAILED`, on a
    verdict minted for a different, verified one. Both objects were real and
    the verdict was legitimately minted; nothing tied them together.

    The medium is a **required positional** rather than a keyword with a
    `None` default, because the default was the whole of the hole downstream:
    `_require_the_medium_now` could only ask "not a *different* one", and a
    verdict minted without a medium passed that question over any medium at
    all. There is no verdict here that judged nothing.

    It is spelled `quarantine` for a second reason. The static walk in
    `tests/unit/test_snapshot.py` holds every quarantine in this module to four
    reads **by the name it travels under** — `self._quarantine` or the bare
    `quarantine` — so a quarantine spelled `judged` was outside the rule that
    exists to bound exactly this. A guard keyed on a spelling is one rename
    wide, and this parameter was the rename.
    """

    _require_a_real_quarantine(quarantine)
    verdict = PreflightVerdict(refused_by)
    object.__setattr__(verdict, "_snapshot", snapshot)
    object.__setattr__(verdict, "_evaluated", tuple(evaluated))
    _MINTED_HERE.add(verdict)
    _remember_the_medium(verdict, quarantine)
    if snapshot is not None:
        _JUDGED_FIELDS[verdict] = _fields_of(snapshot)
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
    # passed as version 1, the exact case `SnapshotDescriptor.__init__`
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
            return _mint(check, quarantine, None, tuple(asked))

    return _mint(None, quarantine, snapshot, tuple(asked))


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
    """ADR-0010 D8's four, in D8's order, plus the four that precede them.

    The fence and the quarantine are asked before D8's four, not instead of
    them: a recovery is *for* a quarantined volume, so the quarantine is not a
    refusal here — but a **fenced** medium is, and a volume nobody quarantined
    has nothing to recover. Then which medium is being recovered
    (`MEDIUM_NOT_RECOGNISED`) and whose sitting it is bound to
    (`HOST_BINDING`), asked before D8's own four begin at `TARGET_BINDING`.

    (R12 doctrine review: this docstring said "the two that precede them"
    from before a review split what was one combined gate into
    `MEDIUM_NOT_RECOGNISED` and `HOST_BINDING`, and was never updated when
    that made it four. `docs/snapshot-and-recovery.md` already had the
    count right; this brings the two back into agreement.)
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
    """Why an act did not happen. Each names a **rule**, never a value.

    (R14 doctrine/test-suite review: `MIGRATION_REFUSED_BY_PREFLIGHT` was
    removed here. `may_migrate` communicates a preflight's own refusal as a
    `bool` and a `SnapshotAuditEvent.MIGRATION_REFUSED` entry, not as a
    raised `RecoveryRefused` — that is a deliberate, documented choice
    (`may_migrate`'s own docstring: "Say whether a migration may run, and
    record a refusal"), not an omission. The member named a `Refusal` no
    code path ever raised, matched by no test, a classification claim
    resting on nothing — the same "absent vocabulary over guarded
    vocabulary" reasoning this module applies to its module-level indexes
    applies here: a member this class cannot produce is a member it should
    not hold.)
    """

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


class RecoveryRefused(Refused):
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


class SnapshotAuditEntry:
    """A classification, and at most which check or gate it concerns.

    There is **no** field for snapshot contents, a byte count, a free-space
    figure, a capacity, a raw key, a passphrase, a device identity, a path or
    an operator identifier. ADR-0010 D10 states the boundary in general terms
    — "the classification of what happened and nothing more: which condition
    was detected, which transition occurred, which refusal fired" — and does
    not itself enumerate fields; `schema_version` and `fingerprint` are this
    module's own reading of that boundary: `schema_version` is a classifying
    fact about the transition (which schema a migration moved toward, or a
    recovery would reach), not a measurement, and `fingerprint` is here
    because "which snapshot" has to be answerable — it is the caller's opaque
    value, never an identity.

    **Not a dataclass**, for the same reason `SnapshotDescriptor` is not one:
    this is "the object actually destined for a log", by this module's own
    words, and `dataclasses.asdict` walked past both raising hooks and handed
    the fingerprint back regardless. A plain class with `__slots__` closes
    `asdict`, `astuple` and `vars()` because there is no dataclass and no
    `__dict__` to walk.
    """

    __slots__ = ("_event", "_check", "_gate", "_schema_version", "_fingerprint")

    def __init__(
        self,
        *,
        event: SnapshotAuditEvent,
        check: PreflightCheck | None = None,
        gate: RecoveryGate | None = None,
        schema_version: int | None = None,
        fingerprint: str | None = None,
    ) -> None:
        """Checked here, because the repr renders what it is handed.

        A re-review reached this through a snapshot stand-in whose
        `schema_version` was the string
        `"capacity_available=… medium=usb-SN-…"` — a capacity figure and a
        medium identity, the two things ADR-0010 D10 names specifically,
        rendered into the object this module's own docstring calls "the object
        destined for a log". Fixing the reachability is `_require_a_real_snapshot`;
        this removes the class of it.
        """

        if not isinstance(event, SnapshotAuditEvent):
            raise TypeError("event must be a SnapshotAuditEvent")
        if check is not None and not isinstance(check, PreflightCheck):
            raise TypeError("check must be a PreflightCheck or None")
        if gate is not None and not isinstance(gate, RecoveryGate):
            raise TypeError("gate must be a RecoveryGate or None")
        # Exactly `int` and exactly `str`. `isinstance` admitted an `int`
        # subclass whose `__format__` rendered
        # `"capacity_available=… medium=usb-SN-…"` through the f-string below
        # — a capacity figure and a medium identity, which is the leak this
        # method was written to remove, arriving through the check itself.
        if schema_version is not None:
            _require_an_exact_int("schema_version", schema_version)
        if fingerprint is not None:
            _require_an_exact_str("fingerprint", fingerprint)
            _require_an_opaque_value("fingerprint", fingerprint)
        object.__setattr__(self, "_event", event)
        object.__setattr__(self, "_check", check)
        object.__setattr__(self, "_gate", gate)
        object.__setattr__(self, "_schema_version", schema_version)
        object.__setattr__(self, "_fingerprint", fingerprint)

    @property
    def event(self) -> SnapshotAuditEvent:
        return self._event

    @property
    def check(self) -> PreflightCheck | None:
        return self._check

    @property
    def gate(self) -> RecoveryGate | None:
        return self._gate

    @property
    def schema_version(self) -> int | None:
        return self._schema_version

    @property
    def fingerprint(self) -> str | None:
        return self._fingerprint

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("a SnapshotAuditEntry is fixed when it is built")

    def __delattr__(self, name: str) -> None:
        """`__setattr__` here is unconditional, not gated on a seal.

        This class has no `_sealed` slot to delete — its `__setattr__`
        refuses every assignment from the moment the object exists. What this
        closes is `del x.<field>` reaching the same slots by a different
        dunder.
        """

        raise AttributeError("a SnapshotAuditEntry is fixed when it is built")

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

        Also survives a half-built instance, for the same reason
        `SnapshotDescriptor.__repr__` and `RecoveryWorkflow.__repr__` do:
        `__init__` validates every field before assigning any of them, so a
        rejected fingerprint — the exact leak this constructor's own
        docstring describes finding — left an object with no `_event` slot,
        and the redacting repr above died reading it before it ever reached
        the fingerprint it exists to redact.
        """

        event = getattr(self, "_event", None)
        if event is None:
            return "SnapshotAuditEntry(unbuilt)"
        parts = [f"event={event.value}"]
        if self.check is not None:
            parts.append(f"check={self.check.value}")
        if self.gate is not None:
            parts.append(f"gate={self.gate.value}")
        if self.schema_version is not None:
            parts.append(f"schema_version={self.schema_version}")
        if self.fingerprint is not None:
            parts.append("fingerprint=<redacted>")
        return f"SnapshotAuditEntry({', '.join(parts)})"

    def _fields(self) -> tuple[object, ...]:
        return (self.event, self.check, self.gate, self.schema_version, self.fingerprint)

    def __eq__(self, other: object) -> bool:
        """By value, over the exact type — the dataclass default this replaces.

        Both operands, for the reason `SnapshotDescriptor.__eq__` states in
        full: checking only `other` leaves the *reflected* comparison — a
        subclass's inherited `__eq__`, called with `self` bound to the
        subclass instance — free to answer using this class's own logic
        against `type(self)` rather than the subclass.
        """

        if type(self) is not SnapshotAuditEntry or type(other) is not SnapshotAuditEntry:
            return NotImplemented
        mine = self._fields_if_built()
        theirs = other._fields_if_built()
        if mine is None or theirs is None:
            # Same half-built gap `SnapshotDescriptor.__eq__` states in full,
            # found for this class in the same round-23 security review.
            return False
        return mine == theirs

    def _fields_if_built(self) -> tuple[object, ...] | None:
        """`self._fields()`, or `None` for an instance `__init__` never finished."""

        if getattr(self, "_event", None) is None:
            return None
        return self._fields()

    def __hash__(self) -> int:
        fields = self._fields_if_built()
        if fields is None:
            raise TypeError("a half-built SnapshotAuditEntry is not hashable")
        return hash((SnapshotAuditEntry, *fields))


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

    def __delattr__(self, name: str) -> None:
        """`__setattr__` here is unconditional, not gated on a seal.

        This class has no `_sealed` slot to delete — its `__setattr__`
        refuses **every** assignment from the moment the object exists, so
        there was never a flag to remove. What `__delattr__` closes is
        `del x.<field>`, which reaches the same slots by a different dunder:
        the sibling classes that gate on `_sealed` needed this because
        deleting the gate reopened assignment; this class needed it because
        the field would otherwise simply be gone, and a caller reading it
        afterward would meet `AttributeError` for the wrong reason.

        `azazel_boot.media.DeviceIdentity` already refused this shape; the
        idiom was in the codebase and in one class of twelve.
        """

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
        """Redacted, and defensive about the one field it does render.

        `__init__` takes `schema_version` with no validation at all, by
        design — the class docstring's own point is that anyone can build a
        `RecoveryCandidate(99, …)` and it will answer `99`. That is fine for
        `schema_version`; it is not fine for what `f"{...}"` does with it.
        A round-24 security review built a `schema_version` whose own
        `__format__` returned caller-chosen text — a capacity figure, a
        device identity, anything — and it rendered verbatim through this
        repr, the one place this class exists to keep opaque. Rendered only
        when it is genuinely `int`; anything else renders a fixed
        placeholder instead of calling back into the hostile object.
        """

        schema_version = self._schema_version
        rendered = schema_version if type(schema_version) is int else "<non-int>"
        return (
            f"RecoveryCandidate(schema_version={rendered}, "
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
        "_pinned",
        "_candidate",
        "_cleared",
        "_sealed",
        "_lock",
    )

    def __init__(
        self, quarantine: Quarantine, binding: SessionBinding, *, session_id: str
    ) -> None:
        # **Sealed from the instant this method starts, not once validation
        # has passed.** A round-24 security review pointed out that every
        # other field write below this comment used the sealed `__setattr__`
        # (`self._quarantine = quarantine`, and so on) while `_sealed` itself
        # was only set to `False` — "not yet sealed, writes still permitted"
        # — after all the validation above had already run. A `TypeError`
        # raised by any of those checks (a wrong-typed `quarantine`, a
        # `binding` whose fields fail the pin, an empty `session_id` — every
        # one of them a caller-controlled input to this public constructor)
        # left a genuinely-typed, live `RecoveryWorkflow` with no `_sealed`
        # slot at all, and `__setattr__` gates on `getattr(self, "_sealed",
        # False)` — `False` by default when the slot was never set, meaning
        # "unsealed". Anyone holding that half-built `self` — reached the
        # same way this suite's own `_half_built` helper reaches one, or by
        # a debugger evaluating an expression at a breakpoint — could then
        # write `_stage`, `_candidate` and `_quarantine` by ordinary
        # assignment, entirely bypassing every gate, the stage graph and the
        # audit trail: `candidate_applies_to`/`holds` check `type(flow) is
        # RecoveryWorkflow` and read `_stage`/`_candidate` straight off the
        # instance, with nothing to tell a forged-by-write one from a
        # genuinely minted one. Sealing first, and switching every
        # assignment below to `object.__setattr__` (matching
        # `SnapshotDescriptor`'s idiom: validate with plain functions, then
        # assign past the seal) closes the window completely — a validation
        # failure now leaves an object that refuses every ordinary write from
        # the moment it exists, the same as a `TypeError` from `__init__`
        # leaves any of this module's other sealed classes.
        object.__setattr__(self, "_sealed", True)
        _require_a_real_quarantine(quarantine)
        if type(binding) is not SessionBinding:
            raise TypeError("binding must be a SessionBinding")
        # **The container's type is not its fields' types.** `SessionBinding`
        # is a public `@dataclass` with no field validation of its own, and
        # `binding_applies` (`commissioning.py`) decides `HOST_BINDING` with
        # `binding.host_fingerprint == observed and binding.session_id ==
        # session_id` — the caller's own operand on the left, exactly the
        # shape `_require_an_exact_str`'s own docstring names for the
        # `session_id` *parameter*. A round-thirteen review built a genuine
        # `SessionBinding` — public constructor, no `object.__setattr__` —
        # whose `host_fingerprint` was a `str` subclass answering `True` to
        # every `==`, passed it here, and committed a full recovery for a
        # host the real fingerprint never matched. Pinned here, on the
        # binding this class was actually handed, for the same reason
        # `SnapshotDescriptor` pins its own fields rather than trusting its
        # constructor's caller.
        _require_an_exact_str("binding.host_fingerprint", binding.host_fingerprint)
        _require_an_exact_str("binding.session_id", binding.session_id)
        # **The same gap, one field over.** `_require_a_real_quarantine`
        # pins `type(quarantine) is Quarantine`, the container, and
        # `_require_the_gates` later decides `MEDIUM_NOT_RECOGNISED` with
        # `self._quarantine.session_id != self._session_id` — the
        # quarantine's own field on the *left* of `!=`, where its `__ne__`
        # is asked first. `Quarantine.__init__` performs no validation of
        # its own on `session_id` (`azazel_boot.quarantine`, tracked
        # separately as issue #51, out of this file's ownership), so a
        # genuine `Quarantine`, built only through its public constructor,
        # can hold a `str` subclass whose `__ne__` always answers `False` —
        # a round-fourteen review built exactly that, reached `COMMITTED`
        # and minted a real `RecoveryCandidate` for a quarantine whose
        # honest `session_id` was a different sitting entirely, defeating
        # the gate `MEDIUM_NOT_RECOGNISED`'s own comment says exists
        # precisely to catch that pairing. This module does not have to
        # wait on `quarantine.py`'s own fix to close its end: pinned here,
        # on the value this class is about to compare, the same way
        # `binding`'s fields are pinned two lines up.
        _require_an_exact_str("quarantine.session_id", quarantine.session_id)
        _require_an_exact_str("session_id", session_id)
        if not session_id.strip():
            raise TypeError("session_id must be a non-empty string")

        # Every write below is `object.__setattr__`, not plain assignment:
        # `_sealed` is already `True` by this point (set above, before any
        # of the validation that could raise), and the sealed `__setattr__`
        # refuses ordinary assignment unconditionally once it is.
        object.__setattr__(self, "_quarantine", quarantine)
        object.__setattr__(self, "_binding", binding)
        object.__setattr__(self, "_session_id", session_id)
        object.__setattr__(self, "_stage", RecoveryStage.NOT_STARTED)
        object.__setattr__(self, "_pinned", None)
        object.__setattr__(self, "_cleared", None)
        object.__setattr__(self, "_candidate", None)
        object.__setattr__(self, "_audit", [])
        # **One workflow, one operation at a time — a round-nineteen fix.**
        # Round eighteen made a *losing* thread's write meet `RecoveryRefused`
        # instead of a bare `AttributeError`, but it never serialised the
        # winners: two threads racing `commit()` (or any pair of `start`/
        # `open_trial`/`commit`/`interrupt`) could both pass every check
        # before either wrote anything, because nothing stopped both from
        # reading the same pre-write state at once. A round-nineteen review
        # drove this directly — two concurrent, entirely legitimate
        # `commit()` calls on one `TRIAL_OPEN` workflow — and got a genuine
        # double commit: two honestly-minted candidates, two
        # `RECOVERY_COMPLETED` audit entries for a workflow whose whole
        # design is one-way and audited once, and one of the two candidates
        # returned from a `commit()` call that did **not** raise failing
        # `holds()` anyway, because the losing write clobbered `_candidate`
        # after the winner had already read it back. A second, unrelated bare
        # `AttributeError` leak was found the same way, through `_cleared`
        # being read in one statement and reset in a later one, both inside
        # `_sealed_assign`'s own `_stage` branch. Reentrant, an `RLock`
        # around each of `start`/`open_trial`/`interrupt`'s whole body, all
        # but one call inside `commit`'s (a round-twenty refinement — see
        # the comment above `commit`'s call into `_require_the_gates`), and
        # `_sealed_assign`'s own body for a caller who reaches it directly,
        # makes the read-then-write parts of each a single atomic operation
        # per workflow, so no second call — same method or a different one,
        # same thread or a different one — ever observes state a first call
        # has not finished changing, in the parts that matter. The same
        # thread reentering through `_refuse_gate` (which calls back into
        # `_sealed_assign`) while `start`/`open_trial` still hold the lock
        # for their whole body still succeeds, the same as before this lock
        # existed: an `RLock` only blocks a *different* thread. `attempt()`
        # calling back into `interrupt()` is a different case, not a
        # reentrancy one: round twenty's split means `commit` holds no lock
        # at all while `attempt()` runs, so that `interrupt()` call acquires
        # a lock nobody is holding — it would succeed even with a plain,
        # non-reentrant `Lock`.
        object.__setattr__(self, "_lock", threading.RLock())

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError(
                "a RecoveryWorkflow is sealed after construction; the stage "
                "advances through its own methods and the quarantine, the "
                "binding and the sitting cannot be replaced"
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """The seal's other door. `__setattr__` alone left it open.

        Every seal in this package gates on `getattr(self, "_sealed", False)`,
        and `_sealed` is an ordinary slot: `del x._sealed` removes it with
        plain syntax, no dunder call and nothing for a static scan to see, and
        every later assignment is then an ordinary one. A review deleted it and
        wrote a stage, a candidate, a quarantine and a sitting onto a workflow
        by assignment — reaching `COMMITTED` with a forged candidate and an
        **empty audit**, past the moving-fields allowlist, the stage graph and
        the clearance interlock at once. A defence is not deeper than its floor.

        `azazel_boot.media.DeviceIdentity` already refused this; the idiom was
        in the codebase and in one class of twelve.
        """

        raise AttributeError("a RecoveryWorkflow is sealed after construction")

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

        with self._lock:
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

            # **The values, and only the values.** There was a `_snapshot` slot
            # here as well, holding the caller's own descriptor. It was written in
            # `__init__` and in `start` and **read nowhere** — a field whose
            # presence implies a check that does not exist, which is the sin this
            # module names in `_require_this_sitting`. A review changed the
            # commit's one line from `self._pinned` to `self._snapshot` and the
            # suite stayed green: the workflow committed on a descriptor mutated
            # from inside the passphrase prompt, minted a candidate for schema 99,
            # and recorded a `recovery_completed` naming it, with no
            # `RECOVERY_SNAPSHOT_SUBSTITUTED` anywhere — because the substitution
            # check compares the argument against `_pinned` and never looked at
            # `_snapshot` at all. The slot is gone rather than compared: there is
            # nothing left to swap the mint over to.
            #
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
            self._require_an_unfenced_medium()
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

        with self._lock:
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

            self._require_an_unfenced_medium()
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
        with self._lock:
            self._require_stage(RecoveryStage.TRIAL_OPEN)
            self._require_this_sitting(session_id)
            self._require_the_same_snapshot(snapshot)
        # **`self._lock` is not held across this call — round twenty found the
        # reason it must not be.** `_require_the_gates` is where `attempt()`
        # lives, "the one step in this workflow that blocks on a human," and
        # holding a lock across a human-speed wait turns an operator screen
        # into a lock an unrelated `interrupt()` call queues behind. A
        # round-twenty review built exactly that: a device-pull handler that
        # calls `interrupt()` first (to record the interruption before tearing
        # anything down) and only then releases whatever `attempt()` was
        # waiting on — a genuine circular wait, `interrupt()` blocked on
        # `self._lock`, `commit()` blocked inside `attempt()` waiting for a
        # signal `interrupt()` was supposed to send. Nothing here needs the
        # lock held across `attempt()`: gates 1-4, above, only read the
        # quarantine, the binding and the sitting, none of which this lock
        # protects (`fence()` is `Quarantine`'s own method, called from device
        # monitoring, entirely outside `self._lock`); `_require_the_gates`'s
        # own `_cleared` write, at its very end, is unconditionally the same
        # sentinel for identical inputs — so two threads racing to write it
        # concurrently cannot disagree about what they write, whatever
        # order they write it in. (A round-21 doctrine review caught an
        # earlier draft of this comment overclaiming further, that the
        # race "cannot happen" because only one racing `commit()` "can
        # still be sitting at `TRIAL_OPEN`" once another reaches
        # `COMMITTED`: false, and beside the point — both can genuinely be
        # concurrently inside `_require_the_gates`/`attempt()`, both still
        # at `TRIAL_OPEN`, well before either reaches `COMMITTED`, which is
        # exactly the window this whole paragraph is about. The safety
        # here rests only on the sentinel being deterministic, not on the
        # race being impossible.) What genuinely changed during the wait is
        # exactly what the re-checks immediately below exist to catch, the
        # same "again, after the prompt" reasoning round 7 built this pattern
        # for in the first place, single-threaded reentrancy included.
        self._require_the_gates(
            snapshot,
            observations,
            session_id=session_id,
            media_binding_holds=media_binding_holds,
            acquisition=acquisition,
            confirmed=confirmed,
        )
        with self._lock:
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
            # **Before the candidate is minted**, not between the two writes. A
            # refusal after the candidate is held would leave a workflow that is
            # not `COMMITTED` holding one, which is why `holds` asks the stage as
            # well as the object.
            self._require_an_unfenced_medium()
            judged = self._pinned
            minted = RecoveryCandidate(judged.schema_version, judged.fingerprint)
            self._sealed_assign("_candidate", minted)
            # **A real second thread, not only reentrant caller code.** Every
            # re-check above this line is for a single-threaded reentrancy
            # window — `attempt()` calling back into caller code while this
            # method waits. A round-seventeen review found a genuine two-thread
            # race in the different, narrower window that opens right here:
            # nothing stops an `interrupt()` running on another thread between
            # the candidate write above and the stage write below. It closed
            # that window with a `_require_stage(TRIAL_OPEN)` re-check
            # immediately above this comment — and a round-eighteen review
            # proved a re-check can never fully close it: the re-check and the
            # write it guards are still two separate statements, so the same
            # race just re-opens one call-frame narrower, forever. There is no
            # finite number of re-checks that closes a gap of this shape.
            #
            # Round eighteen moved the close to `_sealed_assign` itself: its
            # own terminal-stage guard answers `RecoveryRefused` rather than
            # a bare `AttributeError`, so a *losing* thread's write is safe
            # whether or not a race lands in front of it, without needing a
            # re-check here at all. The round-seventeen re-check is gone
            # rather than kept alongside it — a guard that cannot fail is
            # not a guard, and this module says so about
            # `_require_this_sitting`.
            #
            # **That was still not the actual close.** A round-nineteen
            # review found it answers "which exception a loser meets", not
            # "can two winners both write" — two genuinely concurrent
            # `commit()` calls, both passing every check before either
            # reached this line, both write here, and round eighteen's own
            # guard has nothing to say about that, because neither call is
            # racing a workflow that has *already* gone terminal; both are
            # racing to be the one that does. `self._lock` (`__init__`,
            # above) is what actually makes this line safe: from here
            # through the write below, a second call, on any thread, cannot
            # even be inside `commit` while this one is. (Round twenty split
            # this method's locking into two sections rather than one
            # continuous hold, for an unrelated reason — see the comment
            # above `_require_the_gates` — but this second section, covering
            # every remaining write, is unbroken.)
            #
            # **Same-thread reentrancy is still an "accidental reach," not a
            # capability boundary, and can still confuse a caller.** A
            # round-twenty review built an `acquisition.attempt()` that
            # calls `commit()` again, on the same thread — the `RLock`
            # allows it, and doctrine holds (one candidate, one audit
            # entry, quarantine untouched): the inner call mints and
            # commits honestly, and the outer call's own re-check above
            # then meets the now-terminal workflow and is refused. But the
            # outer caller — the one who actually invoked `commit()` — sees
            # only that refusal; the real candidate went to whatever ran
            # inside `attempt()`. This needs a hostile or buggy
            # `KeyAcquisition` with a `flow` reference to trigger at all —
            # the same trust boundary `_require_the_gates` already states
            # for a direct call — so it is not fixed here, only named.
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

        **And the stage, not only the object.** `commit` writes the candidate
        and then moves the stage, and anything raising between those two
        writes — the fence going up is the one that can — left a workflow
        stuck at `TRIAL_OPEN` answering `True` for a candidate no commit
        finished. A candidate is what a *completed* recovery produced, so that
        is what is asked.
        """

        return (
            self._stage is RecoveryStage.COMMITTED
            and self._candidate is not None
            and self._candidate is candidate
        )

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

        with self._lock:
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
        # mutation of the sealed descriptor passed unnoticed. The field types
        # are pinned to exactly `int` and exactly `str` in `__init__`, so
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
        """D8's gates, in D8's order, with the four that precede them.

        (R14 doctrine review: this said "the three that precede them" —
        stale since the same commit that split what was one combined gate
        into `MEDIUM_NOT_RECOGNISED` and `HOST_BINDING` made it four,
        matching `RecoveryGate`'s own class docstring, corrected for the
        same miscount at round twelve; this sibling occurrence was missed
        then.)

        `acquisition` and `confirmed` are **required**, and `None` means "this
        stage has none" rather than "skip the gate". They had defaults, and a
        review called this method directly — it is a bound method at the same
        reach as `_sealed_assign`, which the clearance exists to blunt — with
        `acquisition=None`, obtained a clearance without D8's gates 2 and 4,
        and moved the stage. Reaching this function is now reaching all of D8.

        Each is driven failing on its own in `tests/unit/test_snapshot.py` to
        show the next is not reached, because an order nobody tests is an order
        that holds until someone tidies the function.

        **And its inputs are checked here, not only at the three entrances.**
        Making `acquisition` and `confirmed` required closed the way to a
        clearance without D8's gates 2 and 4 and left the rest of the direct
        call open: every other input — the snapshot the integrity gate reads,
        the observations the host binding is derived from, the sitting — was
        checked in `start`, `open_trial` and `commit` and nowhere the direct
        caller passes through. A review called this method on a live workflow
        with a two-attribute snapshot stand-in, a forged observation tuple and
        another sitting's id, took the clearance, and moved the stage. A gate
        that trusts its arguments is a gate over the caller's own values.
        """

        _require_a_real_snapshot(snapshot)
        _require_real_observations(observations)
        self._require_this_sitting(session_id)
        # And the snapshot this workflow pinned, once it has one. `start` has
        # not pinned anything yet and is the one stage where this is silent;
        # every later stage asks it at its entrance too, and asking it here is
        # what makes reaching this function reaching the substitution check
        # rather than reaching past it.
        if self._pinned is not None:
            self._require_the_same_snapshot(snapshot)

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
        #
        # **And it is a `bool`.** Round 8 pinned the snapshot, the
        # observations and the sitting inside this function precisely because
        # `commit` is not the only way in (`media_binding_holds` was already
        # pinned here, from the commit that gave D8 gate 1 its own name,
        # before round 7 — R13 doctrine review: this comment misattributed it
        # to round 8 alongside the other three) — and left `confirmed`
        # checked in `commit` alone. A review called this
        # method directly with `confirmed="declined"`, which is truthy, took
        # the **full-D8** clearance because `confirmed is not None`, and
        # reached `COMMITTED` with a forged candidate and no
        # `OPERATOR_CONFIRMATION` refusal anywhere. `"declined"` is this
        # module's own worked example, in `_require_an_actual_bool`'s
        # docstring, of the bug that function exists to remove.
        if confirmed is not None:
            _require_an_actual_bool("confirmed", confirmed)
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

    def _require_an_unfenced_medium(self) -> None:
        """The last read before a stage moves, as a **refusal**.

        `_sealed_assign` refuses to spend a clearance over a medium fenced
        since the gates read it, and it refuses with an `AttributeError` — a
        seal's answer, outside the `RecoveryRefused` vocabulary a caller
        writes `except` for. The fence is raised by device monitoring rather
        than by this module, so a legitimate stage move can meet it: the
        window is small and it is not empty, and a caller meeting it would
        have crashed instead of being refused.

        The same shape as the `_require_stage` re-check before the commit's
        stage move, added when an interruption from inside `attempt()` raised
        the seal's `AttributeError` at a caller writing `except
        RecoveryRefused`. What escapes this module is a refusal; the seal's
        rule stays as the structural backstop for a direct `_sealed_assign`.
        """

        if self._quarantine.is_fenced:
            self._refuse_gate(RecoveryGate.MEDIUM_FENCED)

    def _refuse_gate(self, gate: RecoveryGate) -> None:
        """Refuse a gate — in this module's vocabulary, whatever the stage.

        `attempt()` is caller code called mid-gate, and a review interrupted
        the workflow from inside it. Round seven noticed that and re-checked
        the stage in `commit`, **after** `_require_the_gates` had returned —
        so the one row it drove (an operator who confirms, over an unfenced
        medium) reached that re-check, and every other row reached this
        function first: an operator who stops mid-prompt and then declines, or
        stops and has the medium pulled, hit `_sealed_assign`'s terminal rule
        and got an `AttributeError`. That is outside `RecoveryRefused` and
        outside `Refused`, so the single `except` this package promises did not
        catch it, and the unhandled traceback rendered `commit`'s own frame —
        the acquisition object, the sitting and the descriptor included.

        A guard that fixes one row of the input space is a guard over one row.
        This is the same fix at the place every row passes through.
        """

        if self._stage in TERMINAL_STAGES:
            self._refuse(
                Refusal.WORKFLOW_ALREADY_FINISHED,
                "this workflow has ended; a further attempt is a new workflow "
                "that runs every gate again",
            )
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
        quarantine. What it removes is the accidental reach — the three fields
        that legitimately move are named, and a terminal workflow moves none
        of them.
        """

        with self._lock:
            if name not in _MOVES_DURING_A_RECOVERY:
                raise AttributeError(
                    "only the stage, the snapshot's pinned fields and the "
                    "candidate move; the quarantine, the binding and the sitting "
                    "cannot be replaced"
                )
            # **`_refuse`, not a raised `AttributeError` — round eighteen, the
            # same move round ten made for the fence check below.** Round
            # seventeen closed a genuine two-thread race here (`commit`'s
            # candidate-write racing an `interrupt()`) by re-asking the stage
            # immediately before the final write, and a round-eighteen review
            # proved that shape can never fully close: `_require_stage` and the
            # write it guards are two separate statements, so the race just
            # narrows one call-frame at a time and a second thread can always
            # land in whatever gap is left, for `commit`'s candidate write, for
            # `start`'s and `open_trial`'s stage writes, and for `interrupt`
            # racing a second call to itself. Every one of those writes passes
            # through here, and this is the last statement before any of them
            # lands — so the fix is not another re-check upstream, it is this
            # check answering in this module's own vocabulary.
            #
            # **This alone still was not enough — a round-nineteen review
            # found two genuinely concurrent, legitimate `commit()` calls
            # (no `interrupt()` needed) both passing every check before
            # either wrote anything, because nothing serialised the *whole*
            # read-then-write sequence, only each individual write.** That
            # produced a real double commit — two `RECOVERY_COMPLETED`
            # entries, and a legitimately returned candidate `holds()`
            # denied — not merely the wrong exception type. `self._lock`
            # (`__init__`, above) is the actual close: `start`/`open_trial`/
            # `interrupt`/`_sealed_assign` hold it for their whole body, and
            # `commit` for all of its body except one call (see the comment
            # above the call into `_require_the_gates`, round twenty), so
            # two calls on the same workflow can never be inside the parts
            # that read-then-write at once. This check stays as the
            # backstop for a caller who reaches `_sealed_assign` directly —
            # `_sealed_assign` takes this same `self._lock` itself, so that
            # reach does not bypass the lock, only the business-logic
            # checks (`_require_stage` and the rest) the public methods run
            # first — the same reach this method has never claimed a
            # capability boundary against, only "the accidental reach". (A
            # round-twenty doctrine review caught an earlier draft of this
            # comment saying "bypassing the lock"; `docs/snapshot-and-
            # recovery.md` had the identical error, also corrected.)
            # A caller who correctly wrote `except RecoveryRefused:`
            # used to crash on whichever race it lost, through either
            # route; now it is refused, the same `WORKFLOW_ALREADY_FINISHED`
            # `interrupt` and `_require_stage` already answer for the
            # identical fact reached without a race. Nothing here grants
            # anything either way: the write this call would have made
            # still never happens, and `holds()` still asks the stage as
            # well as the object.
            if self._stage in TERMINAL_STAGES:
                self._refuse(
                    Refusal.WORKFLOW_ALREADY_FINISHED,
                    "this workflow has ended; a further attempt is a new workflow "
                    "that runs every gate again",
                )
            # **The same gap, a sixth time, and the sharpest yet.** Every other
            # write this method accepts pins the value's exact type before
            # trusting it in a comparison; a `_stage` write never did, and every
            # check below it — the edge table, `_REACHED_WITHOUT_GATES`, the
            # `is RecoveryStage.COMMITTED` branch that decides which clearance is
            # demanded — reads `value` before its type is known. A round-sixteen
            # review built a stand-in answering `==`/`in`/`.value` like
            # `RecoveryStage.COMMITTED` but failing `is` it, and slid through the
            # *permissive* clearance branch below (the one `open_trial`'s own
            # transition already satisfies) without ever asking D8's gates. The
            # `Quarantine` was never touched and no candidate was minted — `holds`
            # and `candidate_applies_to` still ask `is`, which this could not
            # spoof — but `flow.stage` then answered `== COMMITTED` for any
            # caller who wrote the ordinary comparison instead of this module's
            # own insisted-on `is`, while the audit stayed at
            # `RECOVERY_TRIAL_OPENED` forever and the workflow was permanently
            # stuck. Pinned here, the same as every other value this method
            # accepts.
            if name == "_stage" and type(value) is not RecoveryStage:
                raise AttributeError("a stage must be a RecoveryStage exactly")
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
                # **And the fence, once more, at the moment the clearance is
                # spent.** A clearance is issued when the gates pass and says
                # nothing about *when*: a review took one, fenced the medium, and
                # then moved the stage, arriving at `TRIAL_OPEN` and at
                # `COMMITTED` over a medium that was fenced at every instant after
                # the read. This is the last instant before the stage moves.
                #
                # The fence and not the volume quarantine, because only one of
                # them can change here. `quarantine_volume()` is one-way and the
                # gates refuse unless it is already on, so it cannot be off by the
                # time a clearance is spent, and the quarantine itself cannot be
                # swapped — this method refuses that two rules above. A branch
                # nothing can drive is not a check, and this module says so about
                # `_require_this_sitting`.
                if self._quarantine.is_fenced:
                    # **`_refuse_gate`, not a raised `AttributeError`.** A
                    # round-ten review found the gap this closes: `commit` asks
                    # `_require_an_unfenced_medium()`, mints the candidate, and
                    # only then moves the stage — and the fence can still be
                    # raised in that window, by a device this method does not
                    # control. This branch used to answer with a bare
                    # `AttributeError`, the seal's usual vocabulary for a
                    # *structural* violation; reached from the legitimate path
                    # through `start`/`open_trial`/`commit` rather than from a
                    # direct malicious call, that is the wrong vocabulary — a
                    # caller who correctly wrote `except RecoveryRefused:`
                    # crashed. "The medium is fenced" is the same *business*
                    # fact every other gate expresses through `RecoveryRefused`,
                    # so it is expressed that way here too, from any caller.
                    # `_refuse_gate` calls back into this method for `_stage` →
                    # `REFUSED`, a value in `_REACHED_WITHOUT_GATES`, which does
                    # not re-enter this branch — no `try`/`except` needed, and
                    # none is added: this module raises exceptions, it does not
                    # catch them.
                    self._refuse_gate(RecoveryGate.MEDIUM_FENCED)
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
            # **The pin's own type, not only when it may be written.** The
            # `_candidate` branch below checks both *when* a write is legal and
            # *what* the value says; this branch, above, only ever checked the
            # former. A round-fifteen review wrote a `_pinned` that was not a
            # `SnapshotDescriptor` at all through this same bound-method reach,
            # and the workflow accepted it silently — the crash then landed
            # several calls later, inside `_fields_of`, as a bare
            # `AttributeError` from ordinary attribute lookup rather than a
            # refusal at the point of the bad write. `_require_a_real_snapshot`
            # is the same check every legitimate entrance (`start`, `open_
            # trial`, `commit`) already runs on its own `snapshot` argument
            # before this method is ever reached; reused here rather than
            # reimplemented, so the pin cannot be written as anything that
            # check would have refused at the door.
            if name in _PINNED_AT_THE_START:
                _require_a_real_snapshot(value)
            if name == "_candidate" and self._stage is not RecoveryStage.TRIAL_OPEN:
                raise AttributeError(
                    "a candidate is minted by a commit and by nothing else"
                )
            # **A candidate is answerable to the pin, not just to the clearance
            # and the stage.** The three checks above establish *when* a
            # candidate may be written; none of them establish *what* it may
            # say. A round-fourteen review reached `_require_the_gates` and
            # `_sealed_assign` directly — the same bound-method reach `commit`
            # itself has, and the reach this module has never claimed a
            # capability boundary against, only "the accidental reach" — and
            # used it to write a `RecoveryCandidate` naming a schema version
            # `_pinned` never judged, in one case with `_pinned` never even set
            # (`start` skipped entirely): a workflow reached `COMMITTED`,
            # `holds()` true, `candidate_applies_to` true, over a candidate
            # `commit`'s own honest mint — reading `_pinned`, never the argument
            # — would never have produced. Checked here, on the one write this
            # class actually performs, rather than trusted to `commit`'s own
            # good behaviour: a candidate's `schema_version` must be the pin's.
            #
            # Not the fingerprint: `RecoveryCandidate._fingerprint` is set once,
            # in `__init__`, and read by nothing anywhere in this module or
            # this package — not even here. Comparing it would be this class's
            # first read of a field the whole design keeps deliberately
            # write-only, and nothing downstream of a candidate ever asks for
            # it back to decide anything; `schema_version` is the field a
            # caller can act on, and it is the field pinned.
            if name == "_candidate":
                if self._pinned is None:
                    raise AttributeError(
                        "a candidate is minted from the snapshot a workflow "
                        "pinned at start; there is no pin to mint one from"
                    )
                # **The same gap, a fourth time.** `RecoveryCandidate` is the
                # one class in this module whose constructor validates nothing
                # — deliberately, since its *published* surface is checked by
                # identity (`holds`/`candidate_applies_to`), never by reading a
                # field, and its own docstring says so: "Anyone can build a
                # `RecoveryCandidate(99, …)` and it will answer `99`." This
                # check, added at round fourteen, is a second reader that does
                # trust the field — and a round-fifteen review built a genuine
                # `RecoveryCandidate`, through its own public constructor, with
                # an `int` subclass `schema_version` whose `__ne__` always
                # answered `False`, and this `!=` accepted it. Pinned here, the
                # same as `binding`'s and `quarantine`'s fields two rounds
                # running: the operand this check is about to compare is typed
                # before it is compared, not after. `_require_an_exact_int`
                # raises `TypeError`, not this method's own `AttributeError` —
                # deliberately reused as-is rather than reimplemented, so a
                # value's *type* is refused in the one vocabulary every other
                # type pin in this file uses, and only the *state* checks below
                # stay in `_sealed_assign`'s own.
                _require_an_exact_int("candidate.schema_version", value.schema_version)
                if value.schema_version != self._pinned.schema_version:
                    raise AttributeError(
                        "a candidate names the schema version the pin was "
                        "judged at, not one supplied separately"
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

    __slots__ = ("_audit", "_sealed")

    def __init__(self) -> None:
        object.__setattr__(self, "_sealed", False)
        self._audit: list[SnapshotAuditEntry] = []
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("a MigrationLedger is sealed after construction")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """The seal's other door. `__setattr__` alone left it open.

        Every seal in this package gates on `getattr(self, "_sealed", False)`,
        and `_sealed` is an ordinary slot: `del x._sealed` removes it with
        plain syntax, no dunder call and nothing for a static scan to see, and
        every later assignment is then an ordinary one. A review deleted it and
        wrote a stage, a candidate, a quarantine and a sitting onto a workflow
        by assignment — reaching `COMMITTED` with a forged candidate and an
        **empty audit**, past the moving-fields allowlist, the stage graph and
        the clearance interlock at once. A defence is not deeper than its floor.

        `azazel_boot.media.DeviceIdentity` already refused this; the idiom was
        in the codebase and in one class of twelve.
        """

        raise AttributeError("a MigrationLedger is sealed after construction")

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
        #
        # **And the order, not only the set.** Set equality was the passing
        # half's whole question, so a rebound order that asked all ten in a
        # permuted order passed it — and the refusing half asked something
        # that could not fail: `refused_by` is set from the check the loop
        # stopped on, so it *is* the last of `evaluated` for every verdict
        # this module mints, and no other verdict reaches here. A guard that
        # cannot fail for its own reason is not a guard.
        #
        # What holds instead is one sentence for both halves: what was asked
        # is the enum's own order, from the start, for as far as it got. A
        # pass got all the way; a refusal stopped at the check it names.
        asked = verdict.evaluated
        # **`_EVERY_CHECK`, not a fresh `tuple(PreflightCheck)`.** The
        # difference is not cosmetic: `PreflightCheck._member_names_` accepts
        # reassignment, and `tuple(PreflightCheck)` then returns whatever is
        # left — so a live re-derivation is exactly as rebindable as
        # `PREFLIGHT_ORDER`, one step further away. `_EVERY_CHECK` is a plain
        # tuple captured once, at import, and no rebind of the enum after that
        # moment can shorten, reorder or extend it: the length comparison
        # below is checked against a value the shortening cannot reach, which
        # is what closes the question rather than moving it.
        canonical = _EVERY_CHECK
        prefix: list[PreflightCheck] = []
        for check in canonical:
            if len(prefix) < len(asked):
                prefix.append(check)
        in_order = tuple(prefix) == asked
        if verdict.may_migrate and not (in_order and len(asked) == len(canonical)):
            raise RecoveryRefused(
                Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK,
                "a passing verdict is one that was asked every check, in the "
                "order they are asked in; a shorter one answers a question "
                "nobody finished",
            )
        if not verdict.may_migrate:
            stopped_at = None
            for check in asked:
                stopped_at = check
            if not in_order or stopped_at is not verdict.refused_by:
                raise RecoveryRefused(
                    Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK,
                    "a refusal is the checks that ran, in order, ending at the "
                    "one it names; a classification the run never reached is "
                    "not one",
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
        #
        # **Unconditional.** The first fix read `verdict._judged is not None
        # and ... is not quarantine`, so a verdict that judged no medium was
        # spendable against every medium — and the `None` the shortcut existed
        # for is now unreachable, because `_mint` requires one. A guard that
        # its own attacker's value switches off is not a guard.
        if not _a_medium_was_judged(verdict):
            raise RecoveryRefused(
                Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT,
                "a verdict this module minted judged a medium; one that "
                "judged none was put on the list rather than produced",
            )
        if not _medium_was_judged(verdict, quarantine):
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
        # **Whether this is one of ours, first.** `_require_the_medium_now`
        # asks the module's verdict→medium index about the value it was
        # handed, and answering "no medium was judged" for something that is
        # not a verdict at all classifies it `MEDIUM_MOVED_SINCE_THE_PREFLIGHT`
        # — an operator told the medium moved, about a call that never had a
        # preflight. `may_migrate` orders these two the other way round for
        # this reason; this path did not.
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
        self._require_the_medium_now(verdict, quarantine)
        # Asked here as well, after the verdict is known to be one of ours. It
        # was enforced on the **permission** path and not on the **recording**
        # path, so a verdict `may_migrate` had refused for asking one check was
        # still accepted as the record of a write.
        self._require_every_gate_was_asked(verdict)
        # **The values the preflight judged**, not the values the descriptor
        # answers now. The descriptor is sealed and its fields are pinned to
        # exactly `int` and exactly `str`, and neither stops
        # `object.__setattr__` from rewriting one between the preflight and
        # this call — the same in-place mutation `_require_the_same_snapshot`
        # exists for, on the path that has no workflow to pin anything. A
        # review rewrote the fingerprint after a passing preflight and recorded
        # a second write for one judged snapshot, because the key was derived
        # from the mutated object both times.
        judged = _JUDGED_FIELDS.get(verdict)
        if judged is None or judged != _fields_of(snapshot):
            raise RecoveryRefused(
                Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW,
                "the snapshot presented now is not the one this verdict's "
                "preflight judged; a substituted snapshot is refused, not "
                "recorded",
            )
        # **One rule, and it is the one that can fail.** There were three:
        # this verdict, in a `WeakSet`; this ledger's own list of values; and
        # the module-wide record. A review proved the first two unreachable —
        # a replayed verdict carries the same medium and the same judged
        # values, so the module-wide record answers first, every time — and
        # the middle one was worse than dead. It was keyed on the values
        # alone, with no medium: inside one ledger, a *second medium's* first
        # write was refused as "a second write that did not happen", which is
        # the failure the module-wide key was given a medium to fix. Two
        # spare guards that could not fire, in front of one that could, one of
        # which refused a legitimate caller when it did.
        #
        # **One call, not a check and a write.** It used to be
        # `_a_write_is_recorded(...)` then, on its own line, `_remember_a_
        # write(...)` — a genuine TOCTOU a round-eighteen review drove with
        # two real threads: both reached the check before either reached the
        # write, both saw "not yet recorded", and both recorded — two
        # `SNAPSHOT_WRITTEN` entries for the one preflight this verdict
        # authorised. `_remember_a_write_if_new` is the same rule as one
        # call, under one lock, so there is no gap between the check and the
        # write for a second thread to land in.
        if not _remember_a_write_if_new(quarantine, judged):
            _raise_already_spent()

        self._audit.append(
            SnapshotAuditEntry(
                event=SnapshotAuditEvent.SNAPSHOT_WRITTEN,
                schema_version=snapshot.schema_version,
                fingerprint=snapshot.fingerprint,
            )
        )
