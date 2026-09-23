"""A recovery produces a candidate, and the volume stays quarantined.

Azazel-Boot#42, [ADR-0010](../../docs/adr/0010-persistence-key-and-migration.md)
D6, D7 and D8.

**No storage act has happened.** No snapshot has been written, no migration
run, no trial interrupted, no restore attempted, on any device. Every value
here is a report a caller would have made, and the real key acquisition and
real LUKS unlock do not exist either — so a recovery cannot complete outside
this file in any case.

The property that shapes the whole module, and most of this file, is an
**absence**: nothing here lifts a quarantine. A recovery that succeeded hands
back a `RecoveryCandidate`, which is not a volume, and the `Quarantine` that
judged the medium refuses exactly as much afterwards as before.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import gc
import inspect
import os
import pickle
import subprocess
import sys
import textwrap
import threading
import weakref as _weakref
from collections import Counter
from pathlib import Path

import pytest
from conftest import mac_reader
from test_persistence import MEDIA_ARGS, MEDIUM, SESSION, layout, session, unlock_arguments

from azazel_boot.commissioning import SessionBinding, host_fingerprint
from azazel_boot.dirty_write import (
    MediumContinuity,
    ReceiptState,
    Verification,
    WriteObservation,
)
from azazel_boot.inventory import InterfaceObservation, collect_interfaces
from azazel_boot.persistence import OrdinaryAct, PersistenceRefused, PersistenceState
from azazel_boot.quarantine import Device, DeviceClass, Quarantine
from azazel_boot.session_mode import AttemptOutcome, PassphraseChannel
from azazel_boot.snapshot import (
    KNOWN_CONTAINER_VERSIONS,
    PREFLIGHT_ORDER,
    SUPPORTED_SCHEMA_VERSIONS,
    TERMINAL_STAGES,
    CapacityReport,
    MigrationLedger,
    PreflightCheck,
    PreflightVerdict,
    RecoveryCandidate,
    RecoveryGate,
    RecoveryRefused,
    RecoveryStage,
    RecoveryWorkflow,
    Refusal,
    SnapshotAuditEntry,
    SnapshotAuditEvent,
    SnapshotDescriptor,
    SnapshotIntegrity,
    _fields_of,
    candidate_applies_to,
    preflight,
    schema_is_compatible,
    verdict_was_minted_here,
)

MODULE = Path(__file__).resolve().parents[2] / "src" / "azazel_boot" / "snapshot.py"
TREE = ast.parse(MODULE.read_text(encoding="utf-8"))

#: The two module-side indexes a quarantine may be **put into**, as opposed to
#: read from. Written out rather than derived, because this is an allowlist and
#: a derived one would grow itself: the point is that adding a third place a
#: quarantine travels to is an edit to this file. `test_the_module_indexes_are
#: _what_this_file_says_they_are` asserts both names exist and hold what the
#: rule assumes, so a rename leaves a red test rather than a dead allowance.
_MODULE_INDEXES = frozenset({"_JUDGED_BY", "_SNAPSHOTS_RECORDED"})

TWO_NIC_MACS = {"enp3s0": "a0:b1:c2:d3:e4:f5", "enx001122334455": "00:11:22:33:44:55"}

#: Opaque, and never given to anything that renders. Present so a test can
#: assert its absence.
FINGERPRINT = "snapshot-fingerprint-0001"

#: Something that is not a `PassphraseChannel`. `None` will not do: the double
#: below treats `None` as "use the default", which is how a wrong-channel case
#: silently became a right-channel one.
NOT_A_CHANNEL = "not-a-passphrase-channel"
OLD_FINGERPRINT = "snapshot-fingerprint-0000"


@pytest.fixture
def observations(sysfs_two_nics):
    return collect_interfaces(sysfs_two_nics, permanent_mac_reader=mac_reader(TWO_NIC_MACS))


@pytest.fixture
def elsewhere(sysfs_single_nic):
    return collect_interfaces(
        sysfs_single_nic, permanent_mac_reader=mac_reader({"wlp2s0": "12:34:56:78:9a:bc"})
    )


def descriptor(**overrides) -> SnapshotDescriptor:
    fields = {
        "container_version": 1,
        "schema_version": 1,
        "integrity": SnapshotIntegrity.VERIFIED,
        "fingerprint": FINGERPRINT,
    }
    fields.update(overrides)
    return SnapshotDescriptor(**fields)


def _half_built(cls, **arguments):
    """An instance whose `__init__` raised before finishing.

    `__new__` always runs before `__init__`, so the instance and its exact
    `type()` exist the moment the constructor call is made — `__init__`
    raising partway through leaves an object of the right class with none
    of its ordinary `__slots__` set, which is exactly the shape a
    round-22/23 security review found several dunder methods unprepared
    for. `RecoveryWorkflow` is the one exception: round 24 made `_sealed`
    the very first slot its `__init__` sets, before any validation runs,
    so a half-built `RecoveryWorkflow` from this helper already carries
    that one slot — deliberately, so the half-built instance refuses
    ordinary writes rather than accepting them. Walking the raised
    exception's own traceback for the `__init__` frame reaches that live
    half-built `self` directly, the same object a debugger evaluating an
    expression at a breakpoint would reach.
    """

    try:
        cls(**arguments)
    except TypeError as exc:
        tb = exc.__traceback__
        while tb is not None:
            if tb.tb_frame.f_code.co_name == "__init__":
                return tb.tb_frame.f_locals["self"]
            tb = tb.tb_next
        raise AssertionError("no __init__ frame found in traceback") from exc
    raise AssertionError("construction unexpectedly succeeded")


def capacity(required: int = 100, available: int = 1000) -> CapacityReport:
    return CapacityReport(required=required, available=available)


class Opens:
    """An acquisition that reports one enum value, like every other one."""

    def __init__(self, outcome: AttemptOutcome = AttemptOutcome.OPENED, channel=None):
        self._outcome = outcome
        self._channel = PassphraseChannel.LOCAL_HIDDEN_PROMPT if channel is None else channel
        self.secret = "never-handed-over-0001"
        self.attempts = 0

    def __repr__(self) -> str:
        """Leaks deliberately — a double with the default `repr` renders an
        address and makes an absence assertion pass against any implementation."""

        return f"Opens(secret={self.secret!r})"

    @property
    def channel(self):
        return self._channel

    def attempt(self) -> AttemptOutcome:
        self.attempts += 1
        return self._outcome


def _a_quarantine_that_never_saw_the_medium() -> Quarantine:
    """Volume-quarantined, so `NOTHING_TO_RECOVER` passes, and blind.

    `medium_is_bound()` answers `False`. A review committed a whole recovery
    over exactly this object, because the gate named for the target asked the
    host binding instead.
    """

    rule = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
    rule.quarantine_volume()
    return rule


def a_migration(**overrides):
    """One medium, one snapshot, and the verdict its own preflight minted.

    A verdict now names the quarantine its preflight judged, so a ledger call
    that builds a *fresh* `a_quarantine()` is presenting a different medium —
    which is the finding this helper exists to stop the suite from re-creating
    by accident.
    """

    rule = overrides.pop("quarantine", None) or a_quarantine(quarantined=False)
    snapshot = overrides.pop("snapshot", None) or descriptor()
    arguments = {
        "capacity": capacity(),
        "current_schema": 1,
        "target_schema": 2,
        "binding_holds": True,
        "generation_holds": True,
        "image_digest_holds": True,
    }
    arguments.update(overrides)
    return rule, snapshot, preflight(rule, snapshot=snapshot, **arguments)


def a_quarantine(*, fenced: bool = False, quarantined: bool = True) -> Quarantine:
    rule = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
    rule.observe(MEDIUM)
    rule.observe(Device(identity="host-nvme-SN-1", device_class=DeviceClass.HOST_STORAGE))
    if quarantined:
        rule.quarantine_volume()
    if fenced:
        rule.fence()
    return rule


def workflow(observations, *, quarantine=None) -> RecoveryWorkflow:
    return RecoveryWorkflow(
        quarantine if quarantine is not None else a_quarantine(),
        SessionBinding(host_fingerprint=host_fingerprint(observations), session_id=SESSION),
        session_id=SESSION,
    )


def run_to_commit(flow, observations, *, snapshot=None, acquisition=None):
    snap = snapshot if snapshot is not None else descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    return flow.commit(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        acquisition=acquisition if acquisition is not None else Opens(),
        confirmed=True,
    )


# --------------------------------------------------------------------------
# The rule everything is built around: the quarantine does not move
# --------------------------------------------------------------------------


def test_a_completed_recovery_leaves_the_volume_quarantined(observations) -> None:
    """The whole point, driven end to end.

    A recovery that passed every gate hands back a candidate. The medium is
    exactly as quarantined afterwards as before: every ordinary act still
    refuses, the fence is untouched, and no capability rose.
    """

    # Not quarantined yet: the torn write below is what quarantines it, which
    # is the state a recovery is *for*.
    quarantine = a_quarantine(quarantined=False)
    live = session(observations, quarantine=quarantine)
    live.report_write(
        WriteObservation(
            receipt=ReceiptState.MISSING,
            continuity=MediumContinuity.PRESENT_THROUGHOUT,
            verification=Verification.VERIFIED,
        ),
        observations,
    )
    assert live.volume_is_quarantined

    candidate = run_to_commit(workflow(observations, quarantine=quarantine), observations)

    assert isinstance(candidate, RecoveryCandidate)
    assert quarantine.volume_is_quarantined
    assert live.volume_is_quarantined
    assert live.status().state is PersistenceState.QUARANTINED
    for act in OrdinaryAct:
        with pytest.raises(PersistenceRefused) as refused:
            live.require_ordinary(act, observations)
        assert refused.value.refusal.value == "volume_quarantined"


def test_an_interrupted_recovery_leaves_the_volume_quarantined(observations) -> None:
    """The doctrine names three outcomes for a recovery workflow — success,
    failure and interruption — and drives the full ordinary-act refusal loop
    through a real session only for success (above). This drives it after an
    interruption: `flow.interrupt()` ends the workflow with no candidate at
    all, and the quarantine that judged the medium is exactly as unmoved as
    if the workflow had never run.
    """

    quarantine = a_quarantine()
    live = session(observations, quarantine=quarantine)
    assert live.volume_is_quarantined

    flow = workflow(observations, quarantine=quarantine)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    flow.interrupt(session_id=SESSION)
    assert flow.stage is RecoveryStage.INTERRUPTED

    assert quarantine.volume_is_quarantined
    assert live.volume_is_quarantined
    assert live.status().state is PersistenceState.QUARANTINED
    for act in OrdinaryAct:
        with pytest.raises(PersistenceRefused) as refused:
            live.require_ordinary(act, observations)
        assert refused.value.refusal.value == "volume_quarantined"


def test_a_gate_refused_recovery_leaves_the_volume_quarantined(observations) -> None:
    """The third of the doctrine's three outcomes: a recovery refused at a
    gate before `start` even opens a trial. The workflow never advances past
    `REFUSED`, and the quarantine is exactly as unmoved as after a success or
    an interruption.

    Uses the blind quarantine (`_a_quarantine_that_never_saw_the_medium`)
    rather than a fenced one: a fenced *quarantine* also fences the
    `PersistenceSession` wrapping it (`_is_fenced` is `self._fenced or
    self._quarantine.is_fenced`), which changes `require_ordinary`'s refusal
    to `SESSION_FENCED` before it ever reaches the `volume_quarantined`
    check this test means to drive. `MEDIUM_NOT_RECOGNISED` refuses the gate
    without touching the fence, keeping the two vocabularies apart.
    """

    quarantine = _a_quarantine_that_never_saw_the_medium()
    flow = workflow(observations, quarantine=quarantine)
    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.MEDIUM_NOT_RECOGNISED
    assert flow.stage is RecoveryStage.REFUSED

    live = session(observations, quarantine=quarantine)
    assert quarantine.volume_is_quarantined
    assert live.volume_is_quarantined
    assert live.status().state is PersistenceState.QUARANTINED
    for act in OrdinaryAct:
        with pytest.raises(PersistenceRefused) as refused_ordinary:
            live.require_ordinary(act, observations)
        assert refused_ordinary.value.refusal.value == "volume_quarantined"


def test_a_candidate_is_not_a_volume_and_grants_nothing(observations) -> None:
    """It says which schema version a restore would reach — not that one
    happened — and it cannot do anything with it."""

    candidate = run_to_commit(workflow(observations), observations)

    assert candidate.authority == ()
    assert candidate.schema_version == 1
    surface = {name for name in dir(candidate) if not name.startswith("_")}
    assert surface == {"authority", "schema_version"}

    # Assigned to a **slot** and to a new name, not to `schema_version`.
    # `schema_version` is a property without a setter, so Python refuses it
    # whatever `__setattr__` does — a mutation replacing `__setattr__` with
    # `object.__setattr__` survived the whole suite against the first version
    # of this assertion. That is the incidental-refusal pattern this repository
    # has now hit three times: crediting the class for a refusal it did not make.
    assert RecoveryCandidate.__setattr__ is not object.__setattr__
    for name, value in (("_schema_version", 2), ("_fingerprint", "other"), ("extra", 1)):
        with pytest.raises(AttributeError, match="fixed when it is minted"):
            setattr(candidate, name, value)
    assert candidate.schema_version == 1

    assert RecoveryCandidate.__reduce__ is not object.__reduce__
    with pytest.raises(TypeError, match="not serialisable"):
        pickle.dumps(candidate)
    with pytest.raises(TypeError, match="not serialisable"):
        copy.deepcopy(candidate)


def test_nothing_in_this_module_can_lift_a_quarantine_or_a_fence() -> None:
    """Structural, because the prose saying so is not what makes it true.

    An exact allowlist of every public name the module exports, not a denylist
    of spellings — `tests/unit/test_dirty_write.py` learned that the hard way,
    where a seven-word substring list let a `lift()` through.
    """

    import azazel_boot.snapshot as module

    # **Every** public name in the module, with no `__module__` filter. The
    # first version filtered on `__module__ == module.__name__`, so any public
    # name bound to a value defined elsewhere was invisible — a review added
    # `unquarantine_the_volume = binding_applies` at module level and the
    # "exact allowlist" stayed green while that name was importable.
    exported = {name for name in vars(module) if not name.startswith("_")}
    assert exported == {
        # imported for a signature or a check, and named here so that a new
        # import is a deliberate edit to this literal
        "SessionBinding",
        "binding_applies",
        "InterfaceObservation",
        "Quarantine",
        "AttemptOutcome",
        "KeyAcquisition",
        "PassphraseChannel",
        "annotations",
        # A stdlib module, not a symbol from one — `import threading`, not
        # `from threading import Lock`, so the module itself is what `vars()`
        # sees. Added round eighteen: `_WRITE_LOCK` is a `threading.Lock`,
        # the fix for a real TOCTOU in `_remember_a_write_if_new`. A public
        # name is a public name whether it names this module's own value or
        # a module it imported.
        "threading",
        # A second stdlib module, added round 31: `_require_an_opaque_value`
        # rejects Unicode control/format categories via
        # `unicodedata.category`, the fix for a fingerprint that could
        # carry raw terminal escape sequences (ANSI/OSC) unchanged through
        # to the one place this module deliberately leaves it unredacted
        # (`SnapshotAuditEntry.fingerprint`, "the object destined for a
        # log"). Same reasoning as `threading` above: a public name is a
        # public name whether it names this module's own value or a
        # module it imported.
        "unicodedata",
        "Enum",
        "KNOWN_CONTAINER_VERSIONS",
        "PREFLIGHT_ORDER",
        "SUPPORTED_SCHEMA_VERSIONS",
        "TERMINAL_STAGES",
        "CapacityReport",
        "MigrationLedger",
        "PreflightCheck",
        "PreflightVerdict",
        "RecoveryCandidate",
        "RecoveryGate",
        "RecoveryRefused",
        "RecoveryStage",
        "RecoveryWorkflow",
        "Refusal",
        # Imported so that `RecoveryRefused` is one of the refusals
        # `azazel_boot.refusals` says it is the base of. That docstring said
        # "one base class for every refusal these modules raise" while six of
        # the nine did not derive from it, so a caller writing the single
        # `except Refused` the sentence promises let this module's refusal
        # escape as an unhandled traceback — locals and all.
        "Refused",
        "SnapshotAuditEntry",
        "SnapshotAuditEvent",
        "SnapshotDescriptor",
        "SnapshotIntegrity",
        "preflight",
        "schema_is_compatible",
        "verdict_was_minted_here",
        "candidate_applies_to",
    }

    # And no method on the two classes that act, under any spelling.
    for owner in (RecoveryWorkflow, MigrationLedger):
        methods = {name for name in dir(owner) if not name.startswith("_")}
        for never in (
            "unquarantine",
            "clear",
            "lift",
            "restore",
            "reopen",
            "release",
            "trust",
            "permit",
            "enable",
            "mount",
            "fsck",
            "repair",
            "export",
            "download",
            "upload",
        ):
            assert not any(never in name for name in methods), f"{owner.__name__}.{never}"


def test_this_module_never_calls_anything_that_would_change_a_quarantine() -> None:
    """The indirect route: not a method here, but a call to one elsewhere.

    `Quarantine` has no un-quarantine call to make, which is the real defence.
    This asserts the second half — that nothing here reaches for `fence`,
    `approve_export` or an attribute assignment onto the quarantine's flags.
    """

    attributes = {node.attr for node in ast.walk(TREE) if isinstance(node, ast.Attribute)}
    assert not attributes & {
        "fence",
        "approve_export",
        "withdraw_export",
        "observe",
        "_fenced",
        "_volume_quarantined",
        "quarantine_volume",
    }

    # **An allowlist of what may be touched on the quarantine at all**, rather
    # than a denylist of names. The flags were the whole of the denylist, and
    # `Quarantine` also holds two mutable containers: a re-review put
    # `self._quarantine._audit.clear()` and `_dispositions.clear()` into
    # `interrupt()`, erasing the audit trail and flipping `medium_is_bound()`
    # with the flags never moving and the whole suite green.
    #
    # A denylist of container names would have been the same mistake one layer
    # down. This module reads exactly **four** things from the quarantine, so
    # that is what it is held to — two when this was written, and the sentence
    # went on saying two for two rounds after `medium_is_bound` and
    # `session_id` were added. (`_audit` as a bare name is *this* object's own
    # slot, which is why the check is on the receiver rather than the name.)
    # **A quarantine may appear only as the receiver of those four reads**, or
    # in one of the travels named below. The first version matched
    # `self._quarantine.<attr>` as a shape, so aliasing it to a local first —
    # `q = self._quarantine; q._audit.clear()` — made the receiver a plain
    # `Name` that the comprehension never looked at. A re-review emptied the
    # audit and the dispositions that way, with the flags never moving and the
    # whole suite green.
    #
    # Checking the *use* rather than the shape closes the alias, the argument,
    # the tuple unpack and everything else at once: the object goes nowhere
    # this list does not name, so there is nothing to alias.
    # **Every quarantine, not only `self._quarantine`.** The rule used to key on
    # `ast.Attribute` nodes named `_quarantine`, and `MigrationLedger`'s three
    # methods take the quarantine as a **plain parameter** — so none of them was
    # covered. A review wrote
    # `quarantine._dispositions[snapshot.fingerprint] = quarantine._dispositions.get(
    #     quarantine.boot_medium_identity)` into `note_snapshot_written` and
    # promoted a host NVMe to `BOOT_MEDIUM`, making it writable-mountable and
    # fsck-able, with the whole suite green. The parameter is a `Name`; the rule
    # now covers both spellings.
    holders: list[ast.expr] = []
    for node in ast.walk(TREE):
        if isinstance(node, ast.Attribute) and node.attr == "_quarantine":
            if isinstance(node.ctx, ast.Load):
                holders.append(node)
        elif isinstance(node, ast.Name) and node.id == "quarantine":
            if isinstance(node.ctx, ast.Load):
                holders.append(node)

    for node in holders:
        reader = [
            outer
            for outer in ast.walk(TREE)
            if isinstance(outer, ast.Attribute) and outer.value is node
        ]
        if not reader:
            # Handed on to one of this module's own `_require_*` helpers, which
            # are themselves covered by this walk. Anything else is an escape.
            # The four ways a quarantine may travel without being read: into
            # one of this module's own checks, into the gate evaluator (which
            # this same walk covers), into `type(...)` for the exact-type pin,
            # and into the workflow's one slot.
            #
            # And three more, added with the two module-side indexes that
            # replaced a `_judged` slot on the verdict: the slot handed the
            # live `Quarantine` to every verdict holder, so the association
            # moved off the object — and an association has to hold the object
            # to be one. Each is a named function whose whole body is the one
            # index operation, so the travel is a line on this list rather
            # than a shape this walk happens not to look at.
            #
            # `_remember_a_write` and `_a_write_is_recorded` were two of the
            # four; a round-eighteen review merged them into one atomic
            # `_remember_a_write_if_new` (the two-call shape was the TOCTOU
            # gap a real second thread landed in), so this list now names
            # three functions where it named four.
            passed_to = [
                outer
                for outer in ast.walk(TREE)
                if isinstance(outer, ast.Call)
                and isinstance(outer.func, ast.Name)
                and outer.func.id
                in {
                    "_require_a_real_quarantine",
                    "_gate_fails",
                    "type",
                    "_mint",
                    "_remember_the_medium",
                    "_medium_was_judged",
                    "_remember_a_write_if_new",
                }
                and any(argument is node for argument in outer.args)
            ]
            method_calls = [
                outer
                for outer in ast.walk(TREE)
                if isinstance(outer, ast.Call)
                and isinstance(outer.func, ast.Attribute)
                and outer.func.attr == "_require_the_medium_now"
                and any(argument is node for argument in outer.args)
            ]
            assigned_to_the_slot = [
                outer
                for outer in ast.walk(TREE)
                if isinstance(outer, ast.Assign)
                and outer.value is node
                and all(
                    isinstance(target, ast.Attribute) and target.attr == "_quarantine"
                    for target in outer.targets
                )
            ]
            # **The same slot, the sealed-construction shape.** Round 24's
            # security review moved `RecoveryWorkflow.__init__`'s field
            # writes past the seal (`object.__setattr__(self, "_quarantine",
            # quarantine)`, not `self._quarantine = quarantine` — see that
            # class's own comment for why), which is the identical travel
            # `assigned_to_the_slot` above already permits, spelled as a call
            # instead of a plain assignment.
            sealed_assigned_to_the_slot = [
                outer
                for outer in ast.walk(TREE)
                if isinstance(outer, ast.Call)
                and isinstance(outer.func, ast.Attribute)
                and isinstance(outer.func.value, ast.Name)
                and outer.func.value.id == "object"
                and outer.func.attr == "__setattr__"
                and len(outer.args) == 3
                and isinstance(outer.args[1], ast.Constant)
                and outer.args[1].value == "_quarantine"
                and outer.args[2] is node
            ]
            # And compared by identity, which reads nothing off it: the ledger
            # asks whether the quarantine it was handed **is** the one the
            # verdict's preflight judged.
            compared = [
                outer
                for outer in ast.walk(TREE)
                if isinstance(outer, ast.Compare)
                and (
                    outer.left is node
                    or any(operand is node for operand in outer.comparators)
                )
            ]
            # And into the two indexes themselves, in the three shapes an
            # index takes: the value of a subscript store, the key of one, and
            # an element of a tuple appended to the list. The receiver is
            # pinned **by name** to the two module globals, so `anything.get(
            # quarantine)` and `whatever.append((quarantine, ...))` are not on
            # this list — the point of the rule is that a quarantine goes into
            # this module's own bookkeeping and nowhere else.
            indexed = [
                outer
                for outer in ast.walk(TREE)
                if isinstance(outer, ast.Assign)
                and outer.value is node
                and all(
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in _MODULE_INDEXES
                    for target in outer.targets
                )
            ]
            indexed += [
                outer
                for outer in ast.walk(TREE)
                if isinstance(outer, ast.Subscript)
                and isinstance(outer.value, ast.Name)
                and outer.value.id in _MODULE_INDEXES
                and outer.slice is node
            ]
            indexed += [
                outer
                for outer in ast.walk(TREE)
                if isinstance(outer, ast.Call)
                and isinstance(outer.func, ast.Attribute)
                and isinstance(outer.func.value, ast.Name)
                and outer.func.value.id in _MODULE_INDEXES
                and any(
                    argument is node
                    or (
                        isinstance(argument, ast.Tuple)
                        and any(element is node for element in argument.elts)
                    )
                    for argument in outer.args
                )
            ]
            assert (
                passed_to
                or method_calls
                or assigned_to_the_slot
                or sealed_assigned_to_the_slot
                or compared
                or indexed
            ), "a quarantine is used other than as a receiver of its four reads"
            continue
        # Four reads, all questions. `medium_is_bound` and `session_id` were
        # added deliberately: D8 gate 1 is about the **target**, and the
        # workflow used to ask the host binding in its name — a review
        # committed a recovery over a quarantine that had never observed any
        # device, and over two different media in turn. Both are answers the
        # quarantine computes, so no device identity enters this module.
        assert reader[0].attr in {
            "is_fenced",
            "volume_is_quarantined",
            "medium_is_bound",
            "session_id",
        }, reader[0].attr

    assigned = {
        target.attr
        for node in ast.walk(TREE)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Attribute)
    }
    assert not assigned & {"_fenced", "_volume_quarantined"}

    # **`object.__setattr__` on anything but `self`.** This rule was written
    # once and never landed — the edit script that carried it aborted on a
    # later assertion before writing, and the re-review found the guard absent.
    # A string handed to `object.__setattr__` is neither an `ast.Attribute` nor
    # an `ast.Assign` target, so nothing above sees it, and `Quarantine` uses
    # `__slots__`, so it writes straight past that class's own seal.
    # The one exemption is `_mint`, which stamps a `PreflightVerdict` it
    # constructed on the line above — an object that cannot be anyone else's.
    # It is named per function, not allowed as a general shape, so a second
    # place doing this has to be added here deliberately.
    # **Positional, not by name.** The exemption used to be `{"self"}` plus
    # `"verdict"` inside `_mint`, which meant any helper whose first parameter
    # was *spelled* `self` inherited it, whatever was passed in. A re-review
    # added `def _settle(self, key, value)` at module level and wrote the
    # quarantine's flags through it.
    #
    # The rule is now: the target must be **that function's own first
    # parameter**, and the function must be one of the four named here. Both
    # `FunctionDef` and `AsyncFunctionDef`, because `async def` is a different
    # node and the first version walked neither it nor a module-level lambda.
    permitted_functions = {
        "_mint",
        "__init__",
        "__setattr__",
        "_sealed_assign",
        # Issues the gate clearance onto `self` when every gate has just
        # passed. Naming the moving fields and the legal stage edges was not
        # enough: `trial_open -> committed` is a legal edge and D8's key
        # acquisition and operator confirmation live inside `commit`, so a
        # review took that edge and minted an accepted candidate with no
        # acquisition and no operator, on an audit identical to a real commit.
        "_require_the_gates",
    }
    seen: set[int] = set()
    for function in ast.walk(TREE):
        if not isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        own = function.args.args[0].arg if function.args.args else None

        # A name this function constructed itself, from a class defined in
        # this module, on a line above. `_mint` stamps a `PreflightVerdict` it
        # just built; that object cannot be anyone else's, and requiring the
        # construction to be *in the same function* is what makes it safe —
        # unlike the parameter-name exemption this replaces, which any helper
        # could inherit by spelling its first parameter `self`.
        built_here = {
            target.id
            for statement in ast.walk(function)
            if isinstance(statement, ast.Assign)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Name)
            and statement.value.func.id in {"PreflightVerdict", "RecoveryCandidate"}
            for target in statement.targets
            if isinstance(target, ast.Name)
        }

        for node in ast.walk(function):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr not in {"__setattr__", "__delattr__"}:
                continue
            seen.add(id(node))
            assert function.name in permitted_functions, function.name
            assert node.args, "a bare __setattr__ call"
            first = node.args[0]
            assert isinstance(first, ast.Name) and first.id in ({own} | built_here) - {None}, (
                f"__setattr__ in {function.name} targets neither its own first "
                f"parameter nor an object it constructed"
            )

    # And a flat pass, so nothing can sit outside a function — a module-level
    # lambda is inside no `FunctionDef` at all.
    for node in ast.walk(TREE):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr in {"__setattr__", "__delattr__"}:
            assert id(node) in seen, "a __setattr__ call outside any function"
    for node in ast.walk(TREE):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"setattr", "delattr"}

    # And the flag names as **string constants**, which is the form they take
    # when they are written this way. Nothing here has a legitimate reason to
    # name them at all.
    literals = {
        node.value
        for node in ast.walk(TREE)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert not literals & {"_fenced", "_volume_quarantined", "_dispositions", "_approval"}

    # `is_fenced` and `volume_is_quarantined` are *read*, which is the point.
    assert {"is_fenced", "volume_is_quarantined"} <= attributes


# --------------------------------------------------------------------------
# Preflight (D7): read-only, refuses on the first failure, keeps the old schema
# --------------------------------------------------------------------------


def test_there_is_no_migration_without_a_snapshot(observations) -> None:
    """D7, asserted as an absence as well as a refusal.

    There is no flag, no acceptance and no emergency state — so there is no
    parameter an operator could consent with, because what they would be
    consenting to is the loss of the only path back.
    """

    verdict = preflight(
        a_quarantine(quarantined=False),
        snapshot=None,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict.refused_by is PreflightCheck.SNAPSHOT_ABSENT
    assert verdict.may_migrate is False

    parameters = set(inspect.signature(preflight).parameters)
    for never in ("force", "accept", "override", "without_snapshot", "degraded", "emergency"):
        assert not any(never in name for name in parameters), never


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"snapshot": None}, PreflightCheck.SNAPSHOT_ABSENT),
        (
            {"snapshot": descriptor(container_version=99)},
            PreflightCheck.SNAPSHOT_CONTAINER_UNKNOWN,
        ),
        (
            {"snapshot": descriptor(integrity=SnapshotIntegrity.FAILED)},
            PreflightCheck.SNAPSHOT_INTEGRITY,
        ),
        (
            {"snapshot": descriptor(integrity=SnapshotIntegrity.INDETERMINATE)},
            PreflightCheck.SNAPSHOT_INTEGRITY,
        ),
        ({"capacity": capacity(required=1000, available=999)}, PreflightCheck.REQUIRED_SPACE),
        ({"current_schema": 2, "target_schema": 1}, PreflightCheck.SCHEMA_COMPATIBILITY),
        ({"current_schema": 1, "target_schema": 1}, PreflightCheck.SCHEMA_COMPATIBILITY),
        ({"current_schema": 1, "target_schema": 99}, PreflightCheck.SCHEMA_COMPATIBILITY),
        ({"binding_holds": False}, PreflightCheck.BINDING),
        ({"generation_holds": False}, PreflightCheck.GENERATION),
        ({"image_digest_holds": False}, PreflightCheck.IMAGE_DIGEST),
    ],
)
def test_each_failing_check_refuses_with_its_own_classification(overrides, expected) -> None:
    """D7: an operator learns **which** check refused, and nothing behind it."""

    arguments = {
        "snapshot": descriptor(),
        "capacity": capacity(),
        "current_schema": 1,
        "target_schema": 2,
        "binding_holds": True,
        "generation_holds": True,
        "image_digest_holds": True,
    }
    arguments.update(overrides)
    verdict = preflight(a_quarantine(quarantined=False), **arguments)
    assert verdict.refused_by is expected


def test_a_fenced_medium_refuses_preflight_before_anything_else() -> None:
    """D9: a version upgrade is not a way round the fence.

    Asked first, with every other input simultaneously wrong, so the ordering
    is pinned rather than inferred from a case where only one thing failed.
    """

    verdict = preflight(
        a_quarantine(fenced=True, quarantined=False),
        snapshot=None,
        capacity=capacity(required=10**9, available=0),
        current_schema=2,
        target_schema=1,
        binding_holds=False,
        generation_holds=False,
        image_digest_holds=False,
    )
    assert verdict.refused_by is PreflightCheck.MEDIUM_FENCED


def test_the_snapshot_is_established_before_capacity_is_even_asked() -> None:
    """Order matters: the load-bearing check goes before the cheap one."""

    verdict = preflight(
        a_quarantine(quarantined=False),
        snapshot=None,
        capacity=capacity(required=10**9, available=0),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict.refused_by is PreflightCheck.SNAPSHOT_ABSENT


def test_a_refused_migration_keeps_the_old_schema_usable(observations) -> None:
    """D7's safe outcome, driven rather than asserted about.

    The old schema still unlocks afterwards. A refusal that left the volume
    unusable would be a degraded outcome dressed as a safe one.
    """

    judged_medium = a_quarantine(quarantined=False)

    ledger = MigrationLedger()
    verdict = preflight(
        judged_medium,
        snapshot=None,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert ledger.may_migrate(verdict, quarantine=judged_medium) is False

    live = session(observations)
    status = live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
    assert status.state is PersistenceState.OPEN


def test_a_schema_downgrade_and_a_no_op_are_both_refused() -> None:
    assert schema_is_compatible(current=1, target=2) is True
    assert schema_is_compatible(current=2, target=1) is False
    assert schema_is_compatible(current=1, target=1) is False
    assert schema_is_compatible(current=1, target=99) is False
    assert schema_is_compatible(current=99, target=1) is False
    assert SUPPORTED_SCHEMA_VERSIONS == (1, 2)
    assert KNOWN_CONTAINER_VERSIONS == (1,)


def test_schema_is_compatible_pins_both_operands_on_its_own() -> None:
    """R28 (security review): checked here, not only by `preflight()`.

    `schema_is_compatible` is public and independently importable, and its
    body compared `current`/`target` with `in`/`>` — the caller-controlled-
    operand shape this file guards against everywhere else. Every path
    through this file already went through `preflight()`'s own
    `_require_an_exact_int` first, so this was never reachable today, but a
    future caller that imports this function directly would have walked
    straight past a hostile `__eq__`/`__gt__` that always answers True.
    """

    class _Agreeable:
        def __eq__(self, other: object) -> bool:
            return True

        def __hash__(self) -> int:
            return hash(1)

        def __gt__(self, other: object) -> bool:
            return True

        def __lt__(self, other: object) -> bool:
            return True

    for bad in (True, False, "1", 1.0, None, _Agreeable()):
        with pytest.raises(TypeError, match="current"):
            schema_is_compatible(current=bad, target=1)
        with pytest.raises(TypeError, match="target"):
            schema_is_compatible(current=1, target=bad)


def test_preflight_is_read_only_by_construction() -> None:
    """It has no port to write through, and nothing to write with.

    A "preflight is read-only" claim enforced by reviewing the body is a claim
    that lasts until the body changes. This asserts the *shape*: the function
    takes reports and a quarantine it only reads, and the module imports
    nothing that could write.
    """

    parameters = inspect.signature(preflight).parameters
    for never in ("writer", "port", "store", "device", "path", "file", "handle", "fd"):
        assert not any(never in name for name in parameters), never

    imported: set[str] = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0] or ".")
    # **By name, not only by root.** The set below is module roots, and a
    # review re-exported `pathlib.Path` through a sibling — `from .inventory
    # import Path` has root `inventory`, already allowed — then wrote to the
    # host filesystem at import time with every guard in this file green. So
    # the names are listed too, and the assertion is equality.
    named: set[str] = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.ImportFrom):
            named.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            named.update(alias.name for alias in node.names)
    assert named == {
        "annotations",
        # Added deliberately, round eighteen: `_WRITE_LOCK` is a
        # `threading.Lock`, closing a real TOCTOU `_remember_a_write_if_new`
        # needs a lock and not a re-check to fix — a genuine race in the
        # *state itself*, not merely in which exception type escapes it.
        "threading",
        # Added deliberately, round 31: `_require_an_opaque_value` asks
        # `unicodedata.category` to refuse Unicode control/format
        # characters — the fix for a fingerprint that could carry raw
        # terminal escape sequences through to the one place this module
        # deliberately leaves it unredacted.
        "unicodedata",
        "Enum",
        "WeakKeyDictionary",
        "WeakSet",
        "SessionBinding",
        "binding_applies",
        "InterfaceObservation",
        "Quarantine",
        "Refused",
        "AttemptOutcome",
        "KeyAcquisition",
        "PassphraseChannel",
        # `_WeakIdentityIndex` holds a weak reference purely to verify
        # identity on lookup and to notice when the object it names dies —
        # the callback `ref()` itself takes is what makes that possible.
        "ref",
    }, f"unexpected imported names: {sorted(named)}"

    assert imported == {
        "__future__",
        "threading",
        "unicodedata",
        "enum",
        # Added deliberately: `_MINTED_HERE` is a `WeakSet` now, because a
        # sentinel stamped onto a verdict is a sentinel a caller can read off
        # one. Imported privately, so it is not a name this module exports.
        "weakref",
        "commissioning",
        "inventory",
        "quarantine",
        "refusals",
        "session_mode",
    }


# --------------------------------------------------------------------------
# Recovery (D8): operator-started, one-way, gates in order, re-checked
# --------------------------------------------------------------------------


def test_no_recovery_starts_by_itself(observations) -> None:
    """D8: automatic restore means writing when the state is least understood.

    `started_by_operator` is a required keyword with no default. A default of
    `True` would make the automatic start the easiest thing to write; a default
    of `False` would make it a flag somebody flips. There is also no `retry`,
    no `resume` and no `auto` anywhere on the surface.
    """

    flow = workflow(observations)
    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=False,
        )
    assert refused.value.refusal is Refusal.RECOVERY_NOT_STARTED_BY_AN_OPERATOR

    parameter = inspect.signature(RecoveryWorkflow.start).parameters["started_by_operator"]
    assert parameter.default is inspect.Parameter.empty
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY

    methods = {name for name in dir(RecoveryWorkflow) if not name.startswith("_")}
    for never in ("retry", "resume", "auto", "background", "schedule", "again"):
        assert not any(never in name for name in methods), never
    assert not any("automatic" in stage.value for stage in RecoveryStage)


@pytest.mark.parametrize(
    "skip",
    [
        lambda flow, snap, obs: flow.open_trial(
            snap, obs, media_binding_holds=True, session_id=SESSION
        ),
        lambda flow, snap, obs: flow.commit(
            snap,
            obs,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        ),
    ],
)
def test_no_stage_can_be_skipped(skip, observations) -> None:
    flow = workflow(observations)
    assert flow.stage is RecoveryStage.NOT_STARTED
    with pytest.raises(RecoveryRefused) as refused:
        skip(flow, descriptor(), observations)
    assert refused.value.refusal is Refusal.STAGE_SKIPPED


def test_the_stages_advance_one_at_a_time_and_end(observations) -> None:
    flow = workflow(observations)
    snap = descriptor()

    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    assert flow.stage is RecoveryStage.PREFLIGHT_PASSED
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    assert flow.stage is RecoveryStage.TRIAL_OPEN
    flow.commit(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        acquisition=Opens(),
        confirmed=True,
    )
    assert flow.stage is RecoveryStage.COMMITTED
    assert flow.stage in TERMINAL_STAGES


def test_a_second_commit_is_refused(observations) -> None:
    """A committed workflow is finished. A further attempt is a new workflow."""

    flow = workflow(observations)
    run_to_commit(flow, observations)

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        )
    assert refused.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED
    assert flow.stage is RecoveryStage.COMMITTED


def test_an_interruption_is_terminal_and_restores_nothing(observations) -> None:
    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    flow.interrupt(session_id=SESSION)
    assert flow.stage is RecoveryStage.INTERRUPTED

    for attempt in (
        lambda: flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION),
        lambda: flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        ),
        lambda: flow.interrupt(session_id=SESSION),
    ):
        with pytest.raises(RecoveryRefused) as refused:
            attempt()
        assert refused.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED


@pytest.mark.parametrize(
    ("build", "expected"),
    [
        (lambda: a_quarantine(fenced=True), RecoveryGate.MEDIUM_FENCED),
        (lambda: a_quarantine(quarantined=False), RecoveryGate.NOTHING_TO_RECOVER),
    ],
)
def test_the_two_gates_before_the_four(build, expected, observations) -> None:
    """A fenced medium, and a volume nobody quarantined.

    The second is not pedantry: running this over a healthy volume would be a
    restore of live data from a snapshot — the write D8 refuses to make
    automatically, made deliberately over something that was fine.
    """

    flow = workflow(observations, quarantine=build())
    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is expected
    assert flow.stage is RecoveryStage.REFUSED


def test_a_binding_from_another_machine_refuses_before_a_key_is_asked_for(
    observations, elsewhere
) -> None:
    """The gates in order: the acquisition is never even invoked."""

    flow = workflow(observations)
    acquisition = Opens()
    flow.start(
        descriptor(),
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    flow.open_trial(descriptor(), observations, media_binding_holds=True, session_id=SESSION)

    with pytest.raises(RecoveryRefused):
        flow.commit(
            descriptor(),
            elsewhere,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=acquisition,
            confirmed=True,
        )
    assert acquisition.attempts == 0
    # `HOST_BINDING`, which is what `binding_applies` answers. It carried D8
    # gate 1's name until a review committed a recovery over a quarantine that
    # had never observed a device: the host was right, and nothing had asked
    # what medium was being recovered.
    assert flow.audit()[-1].gate is RecoveryGate.HOST_BINDING


@pytest.mark.parametrize(
    # Factories, not instances: a parametrize list is built once at collection,
    # so shared objects carry state between runs of the same test.
    "build_acquisition",
    [
        lambda: Opens(AttemptOutcome.REJECTED),
        lambda: Opens(AttemptOutcome.NO_KEY_MATERIAL),
        lambda: Opens(AttemptOutcome.NO_LOCAL_INPUT_CHANNEL),
        lambda: Opens(AttemptOutcome.INTERRUPTED),
        lambda: Opens(channel=NOT_A_CHANNEL),
    ],
)
def test_key_acquisition_refuses_before_integrity_is_judged(
    build_acquisition, observations
) -> None:
    acquisition = build_acquisition()
    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    with pytest.raises(RecoveryRefused):
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=acquisition,
            confirmed=True,
        )
    assert flow.audit()[-1].gate is RecoveryGate.KEY_ACQUISITION


def test_a_confirmation_that_was_not_given_refuses_last(observations) -> None:
    """And a confirmation that *was* given grants nothing by itself: the
    volume is still quarantined afterwards, which the first test drives."""

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    with pytest.raises(RecoveryRefused):
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=False,
        )
    assert flow.audit()[-1].gate is RecoveryGate.OPERATOR_CONFIRMATION


def test_a_snapshot_swapped_under_the_workflow_is_refused(observations) -> None:
    """An older snapshot substituted between the start and the trial.

    The workflow holds what it started on and compares. Re-presenting a
    different descriptor — an older fingerprint, a lower schema version, a
    weakened integrity verdict — is refused rather than used.
    """

    flow = workflow(observations)
    flow.start(
        descriptor(),
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )

    with pytest.raises(RecoveryRefused) as refused:
        flow.open_trial(
            descriptor(fingerprint=OLD_FINGERPRINT),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
        )
    assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW

    # **Terminal and audited.** It used to raise and leave no trace, so a
    # caller could present a substituted snapshot, be refused, and simply retry
    # with the original — with nothing recording that a swap was attempted. The
    # earlier version of this test asserted the stage was still
    # `PREFLIGHT_PASSED`, i.e. it pinned exactly that.
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.audit()[-1].event is SnapshotAuditEvent.RECOVERY_SNAPSHOT_SUBSTITUTED
    with pytest.raises(RecoveryRefused) as retried:
        flow.open_trial(descriptor(), observations, media_binding_holds=True, session_id=SESSION)
    assert retried.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED

    # And each shape of substitution, on its own fresh workflow.
    for swapped in (
        descriptor(schema_version=2),
        descriptor(integrity=SnapshotIntegrity.INDETERMINATE),
        descriptor(container_version=99),
    ):
        fresh = workflow(observations)
        fresh.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
        with pytest.raises(RecoveryRefused) as refused:
            fresh.open_trial(swapped, observations, media_binding_holds=True, session_id=SESSION)
        assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW
        assert fresh.stage is RecoveryStage.REFUSED

    # L17: the comparison is by **value**, and the prose no longer implies
    # otherwise. An equal-but-distinct descriptor is the same report.
    twin = workflow(observations)
    twin.start(
        descriptor(),
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    equal_but_distinct = descriptor()
    assert equal_but_distinct is not twin._pinned
    twin.open_trial(equal_but_distinct, observations, media_binding_holds=True, session_id=SESSION)
    assert twin.stage is RecoveryStage.TRIAL_OPEN

    # And the swap is refused at **commit** too, not only at the trial.
    with pytest.raises(RecoveryRefused) as at_commit:
        twin.commit(
            descriptor(fingerprint=OLD_FINGERPRINT),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        )
    assert at_commit.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW


def test_the_gates_are_rechecked_before_the_commit_not_only_at_the_start(
    observations,
) -> None:
    """A medium can be pulled while an operator reads a confirmation screen."""

    quarantine = a_quarantine()
    flow = workflow(observations, quarantine=quarantine)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    quarantine.fence()

    with pytest.raises(RecoveryRefused):
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        )
    assert flow.audit()[-1].gate is RecoveryGate.MEDIUM_FENCED
    assert flow.stage is RecoveryStage.REFUSED


def test_a_workflow_rebuilt_over_the_same_medium_starts_at_the_beginning(
    observations,
) -> None:
    """Rebuilding gets a fresh workflow, not a resumed one — and the medium is
    still quarantined, so the new workflow faces every gate again."""

    quarantine = a_quarantine()
    first = workflow(observations, quarantine=quarantine)
    run_to_commit(first, observations)

    second = workflow(observations, quarantine=quarantine)
    assert second.stage is RecoveryStage.NOT_STARTED
    assert second.audit() == ()
    assert quarantine.volume_is_quarantined

    with pytest.raises(RecoveryRefused) as refused:
        second.open_trial(descriptor(), observations, media_binding_holds=True, session_id=SESSION)
    assert refused.value.refusal is Refusal.STAGE_SKIPPED


# --------------------------------------------------------------------------
# What may be rendered, and what the audit may hold
# --------------------------------------------------------------------------


def test_no_audit_entry_can_carry_contents_a_figure_or_an_identity() -> None:
    """Checked by field name, because a field is how the rest arrives."""

    # Not a dataclass, for the same reason `SnapshotDescriptor` is not one —
    # `dataclasses.fields()` was the route `asdict()` used to hand the
    # fingerprint back regardless of the two raising hooks.
    names = {name.lstrip("_") for name in SnapshotAuditEntry.__slots__}
    assert names == {"event", "check", "gate", "schema_version", "fingerprint"}

    # The loop below cannot fail while the exact set above holds. It is kept
    # because it says *why* those five and no others — a reader adding a sixth
    # edits the set above and then has to answer this list. It is documentation
    # with an assertion's syntax, and is labelled as such rather than counted
    # as a second check.
    for bad in (
        "content",
        "contents",
        "payload",
        "data",
        "bytes",
        "block",
        "record",
        "offset",
        "size",
        "length",
        "capacity",
        "free",
        "space",
        "required",
        "available",
        "count",
        "time",
        "timestamp",
        "device",
        "identity",
        "serial",
        "path",
        "key",
        "passphrase",
        "operator",
        "detail",
        "message",
        "reason",
        "error",
    ):
        assert not any(bad in name for name in names), bad


def test_the_audit_vocabulary_is_exactly_nine_classifications() -> None:
    assert {event.value for event in SnapshotAuditEvent} == {
        "migration_refused",
        "snapshot_written",
        "recovery_started",
        "recovery_trial_opened",
        "recovery_completed",
        "recovery_refused",
        "recovery_interrupted",
        "recovery_snapshot_substituted",
        "recovery_foreign_sitting",
    }


def test_a_refused_migration_records_the_check_and_no_figure() -> None:
    """The capacity numbers describe the operator's medium. They stay there."""

    judged_medium = a_quarantine(quarantined=False)

    ledger = MigrationLedger()
    verdict = preflight(
        judged_medium,
        snapshot=descriptor(),
        capacity=capacity(required=987654321, available=123456789),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict.refused_by is PreflightCheck.REQUIRED_SPACE
    assert ledger.may_migrate(verdict, quarantine=judged_medium) is False

    rendered = repr(ledger.audit()) + str(ledger.audit())
    assert "987654321" not in rendered
    assert "123456789" not in rendered
    assert ledger.audit() == (
        SnapshotAuditEntry(
            event=SnapshotAuditEvent.MIGRATION_REFUSED, check=PreflightCheck.REQUIRED_SPACE
        ),
    )


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"snapshot": None}, PreflightCheck.SNAPSHOT_ABSENT),
        (
            {"snapshot": descriptor(container_version=99)},
            PreflightCheck.SNAPSHOT_CONTAINER_UNKNOWN,
        ),
        (
            {"snapshot": descriptor(integrity=SnapshotIntegrity.FAILED)},
            PreflightCheck.SNAPSHOT_INTEGRITY,
        ),
        ({"capacity": capacity(required=1000, available=999)}, PreflightCheck.REQUIRED_SPACE),
        ({"current_schema": 2, "target_schema": 1}, PreflightCheck.SCHEMA_COMPATIBILITY),
        ({"binding_holds": False}, PreflightCheck.BINDING),
        ({"generation_holds": False}, PreflightCheck.GENERATION),
        ({"image_digest_holds": False}, PreflightCheck.IMAGE_DIGEST),
    ],
)
def test_may_migrates_audited_check_matches_the_verdicts_refused_by_for_every_check(
    overrides, expected
) -> None:
    """R15 (test-suite review): `may_migrate`'s `check=verdict.refused_by`
    passthrough was end-to-end proven for exactly one of the eight
    `PreflightCheck` members it can actually carry through this path.

    `test_each_failing_check_refuses_with_its_own_classification` proves
    `preflight()` itself produces the right `refused_by`, for all ten
    members, but never calls `may_migrate` or reads the ledger's audit.
    `test_a_refused_migration_records_the_check_and_no_figure` is the only
    test that does, and it only ever drives `REQUIRED_SPACE`. A narrow
    mutant that mislabels one specific, untested check (e.g. records
    `BINDING` whenever the real reason was `GENERATION`) survived the whole
    suite undetected — an operator refused for one reason would be told a
    different one.

    `MEDIUM_FENCED`/`VOLUME_QUARANTINED` are not parametrized here: fencing
    and volume-quarantining are both one-way, so a verdict whose preflight
    refused on either is a verdict over a medium that is *still* fenced or
    unquarantined by the time `may_migrate` is called — `_require_the_
    medium_now`, asked first, always refuses those two before this
    passthrough is ever reached (driven separately, elsewhere in this
    file, via its own `RecoveryRefused`).
    """

    judged_medium = a_quarantine(quarantined=False)
    ledger = MigrationLedger()
    arguments = {
        "snapshot": descriptor(),
        "capacity": capacity(),
        "current_schema": 1,
        "target_schema": 2,
        "binding_holds": True,
        "generation_holds": True,
        "image_digest_holds": True,
    }
    arguments.update(overrides)
    verdict = preflight(judged_medium, **arguments)
    assert verdict.refused_by is expected

    assert ledger.may_migrate(verdict, quarantine=judged_medium) is False
    assert ledger.audit()[-1].check is expected


def test_nothing_rendered_carries_the_fingerprint_a_secret_or_an_identity(
    observations,
) -> None:
    """Repr, refusal, traceback — and the acquisition leaks its secret on purpose.

    A double with the default `object.__repr__` renders an address, which makes
    an absence assertion pass against any implementation at all. `Opens` was
    given a leaking `__repr__` for that reason.
    """

    import traceback

    quarantine = a_quarantine()
    flow = workflow(observations, quarantine=quarantine)
    snap = descriptor()
    acquisition = Opens()
    candidate = run_to_commit(flow, observations, snapshot=snap, acquisition=acquisition)

    # The **verdict** is on this list because it was not: it holds the
    # descriptor it judged, its `__repr__` was never called anywhere in the
    # process, and a repr that rendered `self._snapshot.fingerprint` left the
    # whole suite green. Every other object here had a redaction test.
    judged = preflight(
        a_quarantine(quarantined=False),
        snapshot=snap,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    refused_verdict = preflight(
        a_quarantine(fenced=True),
        snapshot=snap,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    rendered = " ".join(
        [
            repr(flow),
            repr(candidate),
            repr(snap),
            repr(capacity()),
            repr(MigrationLedger()),
            repr(judged),
            repr(refused_verdict),
            repr(flow.audit()),
        ]
    )
    assert FINGERPRINT not in rendered
    assert acquisition.secret not in rendered
    assert MEDIUM.identity not in rendered
    assert host_fingerprint(observations) not in rendered
    assert SESSION not in rendered

    refused = workflow(observations, quarantine=a_quarantine(fenced=True))
    with pytest.raises(RecoveryRefused) as error:
        refused.start(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )

    message = str(error.value) + error.value.detail
    for value in (
        FINGERPRINT,
        acquisition.secret,
        MEDIUM.identity,
        SESSION,
        host_fingerprint(observations),
    ):
        assert value not in message
    assert not any(character.isdigit() for character in message)

    summary = traceback.TracebackException.from_exception(error.value, capture_locals=True)
    module_frames = [frame for frame in summary.stack if frame.filename == str(MODULE)]
    raising = module_frames[-1]
    assert raising.name == "_raise_gate_refused"
    assert set(raising.locals or {}) == set()


def test_the_capacity_report_never_renders_its_figures() -> None:
    """It is the operator's medium, described. `repr` reaches every traceback."""

    rendered = repr(capacity(required=424242, available=848484))
    assert "424242" not in rendered
    assert "848484" not in rendered
    assert not any(character.isdigit() for character in rendered)


def test_the_snapshot_descriptor_redacts_its_fingerprint() -> None:
    assert FINGERPRINT not in repr(descriptor())
    assert "<redacted>" in repr(descriptor())
    # The versions stay: they are this build's own vocabulary, not the
    # operator's hardware, and ADR-0010 names the schema version as permitted.
    assert "schema_version=1" in repr(descriptor())


def test_a_descriptor_of_the_wrong_shape_cannot_be_built() -> None:
    """An annotation is not a check — the lesson `dirty_write` paid for."""

    for overrides in (
        {"integrity": "verified"},
        {"container_version": "1"},
        {"schema_version": 0},
        {"schema_version": True},
        {"fingerprint": ""},
        {"fingerprint": "   "},
        {"fingerprint": 1234},
    ):
        with pytest.raises(TypeError):
            descriptor(**overrides)

    for overrides in ({"required": -1}, {"available": "1000"}, {"required": True}):
        with pytest.raises(TypeError):
            CapacityReport(**{"required": 1, "available": 1, **overrides})


# --------------------------------------------------------------------------
# Nothing leaves the partition
# --------------------------------------------------------------------------


def test_this_module_cannot_reach_a_host_a_network_a_vm_or_a_second_partition() -> None:
    """An allowlist, plus the names that make a call unnecessary.

    A denylist of module names is one `__import__` wide — a review proved that
    against two of this repository's guards by assembling module names from
    fragments and reading `__builtins__` with no import statement at all.

    **And a denylist of *names* is one name wide.** Round four proved that too:
    `locals` was not on the list below, at module level `locals()` *is* the
    module dict, CPython puts `__builtins__` in it, and `.get("op" + "en")`
    reaches it with no import, no subscript, no `getattr` and no `except`. The
    string constants were never examined, so the spelling could be assembled.
    `preflight` wrote to the disk and ran a subprocess with the suite green.

    So the first rule below is not a denylist. Every free name — every name
    this module reads without binding it — is listed, and the assertion is
    **equality**. A builtin that is not one of these nineteen is not reachable
    by any spelling, because reaching it needs a name, and the name is absent.
    The count moves as the module grows — it was fourteen, then fifteen,
    then seventeen (R14 doctrine review: this sentence stopped being
    updated at seventeen while the set itself kept growing; it is nineteen
    now) — and what holds is the equality, not the number.
    `locals`, `breakpoint`, `globals`, `vars`, `open`, `__import__`, `eval` and
    whatever the next round finds are all refused by the same line, which is
    the difference between a list of what is forbidden and a list of what is
    permitted. Everything after it is a second line, kept because it is cheap.

    What this still does **not** establish is that the module performs no I/O:
    a static scan refuses the shapes it knows.
    `test_this_module_performs_no_io_when_it_actually_runs` is the capability
    check, and it is the one that covers what this module *calls*.
    """

    bound: set[str] = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            bound.add(node.name)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            spec = node.args
            for argument in (
                *spec.posonlyargs,
                *spec.args,
                *spec.kwonlyargs,
                spec.vararg,
                spec.kwarg,
            ):
                if argument is not None:
                    bound.add(argument.arg)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            bound.add(node.id)
        if isinstance(node, ast.alias):
            bound.add((node.asname or node.name).split(".")[0])
        if isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)

    free = {
        node.id
        for node in ast.walk(TREE)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    } - bound
    assert free == {
        "AttributeError",
        "NotImplemented",
        "TypeError",
        "bool",
        "dict",  # and only as `_WeakIdentityIndex`'s own private store
        "frozenset",
        "getattr",  # and only in the seal's one shape, pinned below
        "hash",  # and only in the two value types' own `__hash__`
        "id",  # and only as `_WeakIdentityIndex`'s opaque integer key
        "int",
        "isinstance",
        "len",
        "list",
        "object",
        "property",
        "str",
        "super",
        "tuple",
        "type",
    }, f"unexpected free names: {sorted(free)}"

    reachable: set[str] = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Name):
            reachable.add(node.id)
        elif isinstance(node, ast.Attribute):
            reachable.add(node.attr)
    assert not reachable & {
        "__builtins__",
        "globals",
        "locals",
        "vars",
        "breakpoint",
        "mro",
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "input",
        "setattr",
        "delattr",
        # The introspection chain that reaches `open` with **no import at
        # all**. A review walked `().__class__.__base__.__subclasses__()` to a
        # class whose `__globals__["__builtins__"]` yielded `open`, wrote a
        # file to the host disk, and the whole suite stayed green — through a
        # scan whose own documentation boasted about defeating the `__import__`
        # hole a previous review had found.
        "__subclasses__",
        "__globals__",
        "__base__",
        "__bases__",
        "__mro__",
        "__class__",
        "__getattribute__",
        # F-4: the route the previous widening did not contain. A re-review
        # raised and caught an exception inside `audit()`, walked
        # `caught.__traceback__.tb_frame.f_builtins["open"]`, assembled the
        # path from one-character fragments so the string scan never saw it,
        # and wrote to the host filesystem with the whole suite green.
        "__traceback__",
        "tb_frame",
        "tb_next",
        "f_globals",
        "f_builtins",
        "f_locals",
        "f_back",
        "gi_frame",
        "cr_frame",
        "ag_frame",
        "__code__",
        "__func__",
        "__self__",
        "__dict__",
        "__init_subclass__",
        "__class_getitem__",
        "__reduce_ex__",
        "__loader__",
        "__spec__",
    }
    assert not [
        node
        for node in ast.walk(TREE)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Subscript)
    ]

    # **No dunder is called through an attribute, except `object.__setattr__`
    # in the four functions below.** The `__setattr__`-call rule inspects only
    # calls whose `func.attr` is `__setattr__`, so a review wrote a class whose
    # `__init__` does `object.__setattr__(self, name, False)` — permitted,
    # since `__init__` is on the list and `self` is its own first parameter —
    # and then called it as `_Tally.__init__(quarantine, "_volume" + "_quar…")`.
    # The call site's `func.attr` is `__init__`, so nothing looked at it, and
    # the assembled name slipped the literal scan. `preflight` lifted the
    # volume quarantine and the whole suite stayed green.
    def _is_a_bare_super_init(node: ast.Call) -> bool:
        """`super().__init__(...)`, the one shape an exception needs."""

        receiver = node.func.value
        return (
            node.func.attr == "__init__"
            and isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Name)
            and receiver.func.id == "super"
            and not receiver.args
            and not receiver.keywords
        )

    assert not [
        node
        for node in ast.walk(TREE)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr.startswith("__")
        and node.func.attr.endswith("__")
        and node.func.attr != "__setattr__"
        and not _is_a_bare_super_init(node)
    ]

    # **And no dunder is read at all except to call it.** Both dunder rules —
    # this one and the `object.__setattr__` rule in
    # `test_this_module_never_calls_anything_that_would_change_a_quarantine` —
    # matched on `ast.Call` whose `func` is an `ast.Attribute`. A module-level
    # `_write = object.__setattr__` is an `ast.Attribute` **Load**, not a call,
    # and `_write(rule, name, value)` is a call whose `func` is an `ast.Name`:
    # neither rule looks at either node, no new free name appears, and a review
    # cleared the volume quarantine through it with the suite green. So a
    # dunder attribute may only be the callee of a call.
    called = {
        id(node.func)
        for node in ast.walk(TREE)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not [
        node
        for node in ast.walk(TREE)
        if isinstance(node, ast.Attribute)
        and node.attr.startswith("__")
        and node.attr.endswith("__")
        and id(node) not in called
    ]

    # **No subscript load outside an annotation.** Refusing only
    # `Subscript`-as-callee was sidestepped by binding the callable to a name
    # first — `writer = builtins["open"]`, then `writer(...)`. This module
    # indexes nothing at runtime, so the honest rule is that it indexes
    # nothing; `tuple[()]` and `list[SnapshotAuditEntry]` in annotations are
    # subscripts too, and are excluded by position rather than by name.
    annotated: set[int] = set()
    for node in ast.walk(TREE):
        for holder in (
            getattr(node, "annotation", None),
            getattr(node, "returns", None),
        ):
            if holder is not None:
                annotated.update(id(inner) for inner in ast.walk(holder))
    assert annotated, "the module is expected to carry annotations"

    assert not [
        node
        for node in ast.walk(TREE)
        if isinstance(node, ast.Subscript)
        and isinstance(node.ctx, ast.Load)
        and id(node) not in annotated
    ]

    # And no `try`/`except`, which is how a frame is obtained without calling
    # anything: raise, catch, walk the traceback. Nothing here handles an
    # exception — it raises them.
    assert not [node for node in ast.walk(TREE) if isinstance(node, ast.ExceptHandler)]

    # `getattr` had a blanket exemption, and that exemption *was* the hole
    # above: `getattr` is how the chain is walked once the names are strings.
    # It is allowed only in the seal's one shape.
    for node in ast.walk(TREE):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id != "getattr":
            continue
        assert len(node.args) == 3, "getattr is permitted only as the seal's read"
        assert isinstance(node.args[0], ast.Name) and node.args[0].id == "self"
        # Six shapes, all reads of this object's own state with a default:
        # the seal, and one canary field per class whose `__repr__` must
        # survive a half-built instance. `__init__` validates before it
        # assigns in each of these classes, and the traceback machinery
        # calls `repr` on the half-built object — a clean `TypeError` became
        # an `AttributeError` raised from inside the redacting repr. Each
        # canary is a field its own `__init__` always sets once validation
        # has passed, before the constructor can raise again, and each repr
        # reads nothing else without going through the same canary check
        # first — so its absence still means "not safely readable" even
        # where it is not literally the first field written.
        # `SnapshotDescriptor` and `SnapshotAuditEntry`'s canaries (round 22)
        # were deliberately chosen to be their first-assigned field, so
        # there absence also means none of the others were assigned either.
        # `RecoveryWorkflow`'s pre-existing `_stage` canary is not first —
        # `_sealed`, `_quarantine`, `_binding` and `_session_id` are all
        # written before it — but `RecoveryWorkflow.__repr__` reads only
        # `_stage` and nothing built after it, so the same "absent means
        # unbuilt, for what this repr touches" reasoning still holds for it
        # alone (round 23 doctrine review: an earlier version of this
        # comment claimed `_stage` was also "the first field", which is
        # false and was corrected here without changing the runtime code).
        # `PreflightVerdict`'s `_refused_by` (round 25) is a fifth: before
        # round 24 gave `__init__` its first validation, this class could
        # never raise mid-construction and needed no guard at all; the
        # validation itself opened the same half-built window its siblings
        # already had, closed here the same way — except the sentinel is
        # not `None`, because `None` is `_refused_by`'s own legitimate
        # "passed" value and would be indistinguishable from "unbuilt".
        # `RecoveryCandidate`'s `_schema_version` (round 26) is a sixth,
        # added pre-emptively rather than in response to a live crash:
        # `__init__` still cannot raise today (deliberately unvalidated, by
        # this class's own design), so no caller can reach a half-built one
        # through the public constructor — but a round-26 security review
        # flagged that every OTHER class whose repr reads instance state and
        # is capable of raising mid-construction already carries this guard
        # (`CapacityReport` can also raise mid-construction, but its own
        # repr is a fixed string reading nothing off `self`, so it correctly
        # carries none — round 27 doctrine review, narrowing a version of
        # this sentence that omitted that qualifier), and closing this one
        # now costs nothing and does not touch the deliberately permissive
        # constructor at all. Same reason as `_refused_by`: the sentinel is
        # not `None`, because this constructor accepts `None` as a
        # legitimate `schema_version`.
        assert isinstance(node.args[1], ast.Constant)
        assert node.args[1].value in {
            "_sealed",
            "_stage",
            "_container_version",
            "_event",
            "_refused_by",
            "_schema_version",
        }, node.args[1].value

    # Over **code**, with every docstring excluded — which is the opposite of
    # what `test_dirty_write.py`'s erasure scan does, deliberately. The two
    # scans ask different questions. "Does this module claim the volume was
    # erased?" is about a *claim*, and a claim lives in a docstring, so that
    # scan reads them. "Can this module reach a host disk?" is about *code*,
    # and `RecoveryCandidate`'s docstring saying it cannot be mounted is not a
    # mount — reading it as one is the self-contradiction both files have hit.
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(TREE)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    assert docstrings, "the module is expected to carry docstrings"

    code: list[str] = []
    for node in ast.walk(TREE):
        if isinstance(node, ast.Name):
            code.append(node.id)
        elif isinstance(node, ast.Attribute):
            code.append(node.attr)
        elif isinstance(node, ast.ClassDef | ast.FunctionDef):
            code.append(node.name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings:
                code.append(node.value)

    joined = " ".join(code)
    for never in (
        "/dev",
        "/tmp",
        "/mnt",
        "host_disk",
        "host_storage",
        "staging",
        "tempfile",
        "second_partition",
        "partition_two",
        "usb_write",
        "download",
        "upload",
        "socket",
        "http",
        "url",
        "mount",
        "fsck",
    ):
        assert never not in joined, f"snapshot names {never!r} in code"


def test_no_fourth_partition_is_created_expected_or_accepted() -> None:
    """D6 keeps ADR-0008 D4.1's three-partition layout unrevised.

    Asserted here as an absence, and `check_layout` still refuses a fourth —
    driven rather than asserted about, because "the other module still does it"
    is the kind of claim that stops being true quietly.
    """

    from azazel_boot.persistence import (
        PARTITION_ROLES,
        MediumLayout,
        Partition,
        check_layout,
    )
    from azazel_boot.persistence import (
        PersistenceRefused as LayoutRefused,
    )

    assert PARTITION_ROLES == ("esp", "boot_root", "persistence")

    with pytest.raises(LayoutRefused):
        check_layout(
            MediumLayout(
                partition_table="gpt",
                partitions=(
                    Partition(role="esp", filesystem="vfat"),
                    Partition(role="boot_root", filesystem="squashfs", read_only=True),
                    Partition(role="persistence", filesystem="ext4", mappings=("dm-crypt",)),
                    Partition(role="snapshot", filesystem="ext4"),
                ),
            )
        )


def test_the_verdict_and_the_candidate_are_capabilities_never_authorities(
    observations,
) -> None:
    verdict = preflight(
        a_quarantine(quarantined=False),
        snapshot=descriptor(),
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict.may_migrate is True
    assert verdict.authority == ()
    assert run_to_commit(workflow(observations), observations).authority == ()
    assert PreflightVerdict(PreflightCheck.BINDING).authority == ()


def test_a_preflight_verdicts_refused_by_is_pinned_to_the_enum_or_none() -> None:
    """R24 (security review, medium): `refused_by` took anything at all.

    `preflight` only ever passes `None` or a genuine `PreflightCheck`
    member, but the public constructor validated nothing, and `__repr__`
    reads `self._refused_by.value` unconditionally whenever it is not
    `None`. `PreflightVerdict("nonsense")` used to build cleanly and then
    crash `repr()` with a bare `AttributeError`; worse, an object whose own
    `.value` returns caller-chosen text rendered that text verbatim — the
    same disclosure class `_require_an_exact_str`/`_require_an_opaque_value`
    exist elsewhere in this file to refuse.
    """

    class _Leaky:
        value = "capacity_available=17179869184 medium=usb-SN-AA11BB22"

    for refused_by in ("nonsense", 1, _Leaky()):
        with pytest.raises(TypeError):
            PreflightVerdict(refused_by)

    # `None` and a genuine member still build, unaffected.
    assert PreflightVerdict(None).refused_by is None
    assert PreflightVerdict(PreflightCheck.BINDING).refused_by is PreflightCheck.BINDING


def test_a_preflight_verdicts_repr_survives_an_instance_that_was_never_built() -> None:
    """R25 (security review): round 24's own validation fix opened this gap.

    Before round 24, `PreflightVerdict.__init__` never validated anything
    and so could never raise partway through — a half-built instance was
    structurally impossible, and `__repr__` never needed a guard. Round
    24's fix (rejecting a non-`PreflightCheck` `refused_by`) made a
    half-built instance reachable for the first time, in the same file that
    already treats this exact shape as worth fixing for
    `SnapshotDescriptor`/`SnapshotAuditEntry`/`RecoveryWorkflow` — closed
    here the same way, via `traceback.TracebackException(...,
    capture_locals=True)`, the ordinary shape of `pytest --showlocals` and
    most crash reporters.
    """

    import traceback

    with pytest.raises(TypeError) as raised:
        PreflightVerdict("nonsense")
    rendered = "".join(
        traceback.TracebackException.from_exception(raised.value, capture_locals=True).format()
    )
    assert "PreflightVerdict(unbuilt)" in rendered


def test_a_recovery_candidates_repr_does_not_render_a_hostile_schema_version() -> None:
    """R24 (security review, medium): `__repr__` interpolated whatever it
    was handed.

    `RecoveryCandidate.__init__` takes `schema_version` with no validation
    at all, by design — the class docstring's own point is that anyone can
    build `RecoveryCandidate(99, …)` and it will answer `99`. `__repr__`'s
    f-string calls `format()`/`str()` on that value regardless, so an
    object whose own `__format__` returns caller-chosen text rendered
    verbatim through the one place this class exists to keep opaque.
    """

    class _Leaky:
        def __format__(self, spec: str) -> str:
            return "DEVICE_SERIAL=usb-SN-AA11BB22 host=/dev/nvme0n1p3"

    hostile = RecoveryCandidate(_Leaky(), FINGERPRINT)
    rendered = repr(hostile)
    assert "usb-SN-AA11BB22" not in rendered
    assert "/dev/nvme0n1p3" not in rendered
    assert "<non-int>" in rendered

    # A genuine int still renders normally.
    assert "schema_version=1" in repr(RecoveryCandidate(1, FINGERPRINT))


def test_a_recovery_candidates_repr_survives_an_instance_that_was_never_built() -> None:
    """R26 (security review, latent): the same guard, added pre-emptively.

    `RecoveryCandidate.__init__` cannot raise today — it validates nothing,
    by design — so no caller can reach a half-built instance through the
    public constructor, and this is not a live crash the way the sibling
    classes' repr fixes were. `object.__new__` is the only way to build one,
    the same technique this module's own `_WeakIdentityIndex` and sealed
    classes' `__delattr__` docstrings describe as "the same reach a
    debugger or `pickle.__reduce_ex__` would have" — worth guarding now
    rather than waiting for a future round that adds validation here to
    reopen the crash, the way round 24's `PreflightVerdict` fix did (found
    and closed the very next round, round 25).
    """

    half = object.__new__(RecoveryCandidate)
    assert repr(half) == "RecoveryCandidate(unbuilt)"


# --------------------------------------------------------------------------
# The behavioural half of the central claim, which the static guards missed
# --------------------------------------------------------------------------


def _flags(quarantine) -> tuple:
    """The flags **and the containers** — F-3's finding.

    Erasing `_audit` and `_dispositions` moved neither flag, so a check on the
    two booleans alone was satisfied while the quarantine's record was wiped
    and `medium_is_bound()` flipped.
    """

    return (
        quarantine.is_fenced,
        quarantine.volume_is_quarantined,
        quarantine.audit(),
        quarantine.disposition(MEDIUM),
    )


def test_no_public_method_ever_turns_either_flag_off(observations, elsewhere) -> None:
    """Every method, every refusal path, before and after.

    The static guards were the only defence, and a review walked past both with
    two lines in `interrupt()` — the one method whose effect on the quarantine
    no test observed. `grep is_fenced` over this file used to return only the
    AST scan; the single behavioural check covered the *commit* path alone.

    So this drives every public method of `RecoveryWorkflow` and
    `MigrationLedger`, on the success path and on refusals, and asserts neither
    flag ever goes from True to False.
    """

    def drive(build):
        quarantine = a_quarantine(fenced=True)
        flow = workflow(observations, quarantine=quarantine)
        before = _flags(quarantine)
        try:
            build(flow, quarantine)
        except (RecoveryRefused, AssertionError, TypeError):
            pass
        assert _flags(quarantine) == before, "a flag was turned off"

    # **Derived, not written out.** The list below was hand-written, so it was
    # stale the moment a method was added: a re-review added an `abandon()`
    # that cleared both flags through a module-private helper and the whole
    # suite stayed green. This asserts first that the driven set *is* the
    # public surface, so a new method fails here until it is driven.
    driven = {
        "start",
        "open_trial",
        "commit",
        "interrupt",
        "audit",
        "stage",
        "holds",
    }
    assert driven == {
        name for name, _ in inspect.getmembers(RecoveryWorkflow) if not name.startswith("_")
    }, "a public method of RecoveryWorkflow is not driven below"
    assert {"audit", "may_migrate", "note_snapshot_written"} == {
        name for name, _ in inspect.getmembers(MigrationLedger) if not name.startswith("_")
    }, "a public method of MigrationLedger is not driven below"

    snap = descriptor()
    for build in (
        lambda flow, q: flow.start(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        ),
        lambda flow, q: flow.start(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=False,
        ),
        lambda flow, q: flow.open_trial(
            snap, observations, media_binding_holds=True, session_id=SESSION
        ),
        lambda flow, q: flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        ),
        lambda flow, q: flow.interrupt(session_id=SESSION),
        lambda flow, q: flow.audit(),
        lambda flow, q: flow.stage,
        lambda flow, q: flow.holds(RecoveryCandidate(1, FINGERPRINT)),
    ):
        drive(build)

    # And the whole successful path, on an unfenced but quarantined medium.
    quarantine = a_quarantine()
    flow = workflow(observations, quarantine=quarantine)
    before = _flags(quarantine)
    run_to_commit(flow, observations)
    flow_after = _flags(quarantine)
    assert flow_after == before

    # **Every gate's refusal path**, not only the fenced one. `_refuse_gate`
    # was driven with `MEDIUM_FENCED` alone, so a re-review gated the clear on
    # `OPERATOR_CONFIRMATION` — an operator declining the confirmation
    # un-fenced and un-quarantined the volume, fully green.
    # **Derived, not written out.** This list was hand-written, and it went
    # stale the moment D8 gate 1 was split: `TARGET_BINDING` and
    # `MEDIUM_NOT_RECOGNISED` were never driven here, and a payload on either
    # refusal branch cleared both flags with the whole suite green — which is
    # the same failure the paragraph above records, one gate along. The set of
    # gates these cases actually reach is collected and asserted against
    # `RecoveryGate` itself, so a new gate cannot be added without a case.
    reached: set[RecoveryGate] = set()
    for gate_case in (
        lambda: (a_quarantine(fenced=True), "start", {}),
        lambda: (a_quarantine(quarantined=False), "start", {}),
        lambda: (_a_quarantine_that_never_saw_the_medium(), "start", {}),
        lambda: (a_quarantine(), "commit", {"elsewhere": True}),
        lambda: (a_quarantine(), "start", {"no_media_binding": True}),
        lambda: (a_quarantine(), "commit", {"no_media_binding": True}),
        lambda: (a_quarantine(), "commit", {"bad_channel": True}),
        lambda: (a_quarantine(), "commit", {"confirmed": False}),
        lambda: (a_quarantine(), "start", {"bad_snapshot": True}),
        lambda: (a_quarantine(), "open_trial", {"swap": True}),
        lambda: (a_quarantine(), "start", {"other_sitting": True}),
        lambda: (a_quarantine(), "start", {"not_operator": True}),
    ):
        quarantine, where, options = gate_case()
        binds = not options.get("no_media_binding")
        before = (_flags(quarantine), quarantine.audit(), len(quarantine.audit()))
        flow = workflow(observations, quarantine=quarantine)
        good = descriptor()
        try:
            if where != "start":
                flow.start(
                    good,
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                    started_by_operator=True,
                )
            if where == "commit":
                flow.open_trial(good, observations, media_binding_holds=True, session_id=SESSION)
                flow.commit(
                    good,
                    elsewhere if options.get("elsewhere") else observations,
                    media_binding_holds=binds,
                    session_id=SESSION,
                    acquisition=Opens(channel=NOT_A_CHANNEL)
                    if options.get("bad_channel")
                    else Opens(),
                    confirmed=options.get("confirmed", True),
                )
            elif where == "open_trial":
                flow.open_trial(
                    descriptor(fingerprint=OLD_FINGERPRINT),
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                )
            else:
                flow.start(
                    descriptor(integrity=SnapshotIntegrity.FAILED)
                    if options.get("bad_snapshot")
                    else good,
                    observations,
                    media_binding_holds=binds,
                    session_id="another" if options.get("other_sitting") else SESSION,
                    started_by_operator=not options.get("not_operator"),
                )
        except RecoveryRefused:
            pass
        after = (_flags(quarantine), quarantine.audit(), len(quarantine.audit()))
        assert after == before, f"{where} {options} changed the quarantine"
        reached.update(
            entry.gate for entry in flow.audit() if entry.gate is not None
        )

    assert reached == set(RecoveryGate), (
        "every gate's refusal must be driven across a quarantine comparison; "
        f"never reached: {sorted(gate.value for gate in set(RecoveryGate) - reached)}"
    )

    # Every `MigrationLedger` method, and `preflight` itself.
    ledger = MigrationLedger()
    verdict = preflight(
        quarantine,
        snapshot=snap,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    unchanged = _flags(quarantine)
    for act in (
        lambda: ledger.may_migrate(verdict, quarantine=a_quarantine(quarantined=False)),
        lambda: ledger.note_snapshot_written(
            verdict,
            snap,
            quarantine=a_quarantine(quarantined=False),
        ),
        lambda: ledger.audit(),
    ):
        try:
            act()
        except RecoveryRefused:
            pass
        assert _flags(quarantine) == unchanged


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"snapshot": None}, PreflightCheck.SNAPSHOT_ABSENT),
        ({"capacity": capacity(required=10**9, available=0)}, PreflightCheck.REQUIRED_SPACE),
        ({"binding_holds": False}, PreflightCheck.BINDING),
        ({}, None),
    ],
)
def test_preflight_changes_nothing_it_was_handed(overrides, expected, observations) -> None:
    """Read-only, **observed** rather than inferred from the signature.

    `test_preflight_is_read_only_by_construction` checks parameter names and
    the import allowlist; neither watches behaviour. A review made `preflight`
    fence the quarantine it was handed, immediately after reading `is_fenced`,
    and the suite stayed green.
    """

    quarantine = a_quarantine(quarantined=False)
    arguments = {
        "snapshot": descriptor(),
        "capacity": capacity(),
        "current_schema": 1,
        "target_schema": 2,
        "binding_holds": True,
        "generation_holds": True,
        "image_digest_holds": True,
    }
    arguments.update(overrides)

    before = (_flags(quarantine), quarantine.audit())
    verdict = preflight(quarantine, **arguments)
    assert verdict.refused_by is expected
    assert (_flags(quarantine), quarantine.audit()) == before


def test_a_migration_is_refused_over_a_quarantined_volume() -> None:
    """The recovery path treated it as load-bearing; this one did not ask.

    ADR-0010 D4 stops the **whole volume** on a suspected torn write, and a
    schema migration is a large write to exactly that volume. Every preflight
    test used an unquarantined medium, so nothing noticed.
    """

    verdict = preflight(
        a_quarantine(),
        snapshot=descriptor(),
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict.refused_by is PreflightCheck.VOLUME_QUARANTINED
    assert verdict.may_migrate is False


# --------------------------------------------------------------------------
# The gates, each contested against every later one also failing
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("gate", "build"),
    [
        (
            RecoveryGate.MEDIUM_FENCED,
            lambda: {
                "quarantine": a_quarantine(fenced=True),
                "bad_acquisition": True,
                "confirmed": False,
                "elsewhere": True,
            },
        ),
        (
            RecoveryGate.NOTHING_TO_RECOVER,
            lambda: {
                "quarantine": a_quarantine(quarantined=False),
                "bad_acquisition": True,
                "confirmed": False,
                "elsewhere": True,
            },
        ),
        # D8 gate 1, the **target**: a quarantine that never saw the medium.
        # This used to be the host binding wearing gate 1's name, so a recovery
        # committed over a quarantine that had observed no device at all.
        (
            RecoveryGate.MEDIUM_NOT_RECOGNISED,
            lambda: {
                "quarantine": _a_quarantine_that_never_saw_the_medium(),
                "elsewhere": True,
                "bad_acquisition": True,
                "confirmed": False,
            },
        ),
        (
            RecoveryGate.HOST_BINDING,
            lambda: {"elsewhere": True, "bad_acquisition": True, "confirmed": False},
        ),
        (
            RecoveryGate.KEY_ACQUISITION,
            lambda: {"bad_acquisition": True, "confirmed": False},
        ),
        # `INTEGRITY_VERIFICATION` is contested in
        # `test_the_integrity_gate_is_reached_and_refuses`, at `start`: a
        # snapshot the workflow did not start on is caught by the substitution
        # check first, so it cannot be introduced at `commit` at all.
        (RecoveryGate.OPERATOR_CONFIRMATION, lambda: {"confirmed": False}),
    ],
)
def test_each_gate_refuses_with_every_later_gate_also_failing(
    gate, build, observations, elsewhere
) -> None:
    """D8's order, pinned. Two reorderings used to ship green.

    Moving the integrity block above key acquisition, and moving the
    confirmation check to the top of `commit()`, both left the suite green —
    the second one meaning a fenced machine on the wrong host with a
    substituted snapshot would report `OPERATOR_CONFIRMATION` as the reason.

    `RecoveryGate.INTEGRITY_VERIFICATION` appeared in no assertion at all:
    deleting both integrity checks from `_require_the_gates` was green too.
    """

    options = build()
    quarantine = options.get("quarantine") or a_quarantine()
    flow = workflow(observations, quarantine=quarantine)

    # A workflow is started and brought to the trial on a good snapshot, then
    # the failing conditions are introduced at the commit — which is where all
    # four of D8's gates run.
    good = descriptor()
    # Three of the four gates that precede D8's own four are refused at
    # `start` already, so a workflow over one of them never reaches the
    # trial. `HOST_BINDING`, the fourth, can be refused at `start` too — it
    # is left out of this tuple on purpose, so this drive's row for it
    # reaches `commit` instead and exercises the re-check path there.
    #
    # (R18 doctrine review: this used to say "`TARGET_BINDING` joined them
    # when it stopped being the host binding under gate 1's name" — true when
    # written, stale since: `TARGET_BINDING` was renamed to
    # `MEDIUM_NOT_RECOGNISED`, already reflected in the tuple below, and the
    # name `TARGET_BINDING` was then reused for the unrelated D8 gate 1 media
    # binding check `RecoveryGate`'s own class docstring names. Corrected to
    # describe what this tuple and the row below it actually do.)
    refused_at_start = (
        RecoveryGate.MEDIUM_FENCED,
        RecoveryGate.NOTHING_TO_RECOVER,
        RecoveryGate.MEDIUM_NOT_RECOGNISED,
    )
    if gate not in refused_at_start:
        flow.start(
            good,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
        flow.open_trial(good, observations, media_binding_holds=True, session_id=SESSION)

    snapshot_now = good

    acquisition = Opens(channel=NOT_A_CHANNEL) if options.get("bad_acquisition") else Opens()
    inventory = elsewhere if options.get("elsewhere") else observations

    if gate in refused_at_start:
        with pytest.raises(RecoveryRefused) as refused:
            flow.start(
                good,
                inventory,
                media_binding_holds=True,
                session_id=SESSION,
                started_by_operator=True,
            )
    else:
        with pytest.raises(RecoveryRefused) as refused:
            flow.commit(
                snapshot_now,
                inventory,
                media_binding_holds=True,
                session_id=SESSION,
                acquisition=acquisition,
                confirmed=options.get("confirmed", True),
            )

    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is gate


@pytest.mark.parametrize(
    "broken",
    [
        {"integrity": SnapshotIntegrity.FAILED},
        {"integrity": SnapshotIntegrity.INDETERMINATE},
        {"container_version": 99},
    ],
)
def test_the_integrity_gate_is_reached_and_refuses(broken, observations) -> None:
    """The gate that no test drove. Deleting it entirely was green.

    Presented at `start`, where the substitution check cannot fire first —
    the earlier test passed these at `open_trial`, where
    `_require_the_same_snapshot` caught them and the assertion named
    `SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW`. That is weak-test pattern (c): a
    `RecoveryRefused` raised by a different rule entirely.
    """

    flow = workflow(observations)
    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            descriptor(**broken),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.INTEGRITY_VERIFICATION
    assert flow.stage is RecoveryStage.REFUSED


def test_the_gates_are_rechecked_before_the_trial_too(observations) -> None:
    """Deleting the recheck from `open_trial` used to be green.

    Only the commit-side recheck was tested, while the documentation said
    "before the trial opens and again before the commit".
    """

    quarantine = a_quarantine()
    flow = workflow(observations, quarantine=quarantine)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )

    quarantine.fence()

    with pytest.raises(RecoveryRefused):
        flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    assert flow.audit()[-1].gate is RecoveryGate.MEDIUM_FENCED
    assert flow.stage is RecoveryStage.REFUSED


# --------------------------------------------------------------------------
# The forgeable verdict, the uncheckable candidate, and the dead sitting
# --------------------------------------------------------------------------


def test_a_hand_built_verdict_does_not_authorise_a_migration() -> None:
    """H5: the "rebuild the object a legitimate caller holds" attack, again.

    `PreflightVerdict` was a public frozen dataclass and `MigrationLedger`
    read `may_migrate` and nothing else, so `PreflightVerdict(None)` authorised
    a migration over a snapshot whose integrity had **failed**, with no
    preflight ever having run.
    """

    judged_medium = a_quarantine(quarantined=False)

    ledger = MigrationLedger()
    forged = PreflightVerdict(None)

    assert verdict_was_minted_here(forged) is False
    with pytest.raises(RecoveryRefused) as refused:
        ledger.may_migrate(forged, quarantine=judged_medium)
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT
    # **The first check's own detail, not the fallback's.** `_require_the_
    # medium_now` — asked one line below — carries its own, independent
    # "verdict this module minted judged a medium" refusal, over the SAME
    # `Refusal` member. A verdict that answers `False` to the first check and
    # would have answered `True` to the second is the only input that tells
    # them apart; `test_the_mintedness_check_is_not_saved_by_the_medium_check`
    # drives exactly that split.
    assert "a value that merely has the right shape" in refused.value.detail

    with pytest.raises(RecoveryRefused) as refused:
        ledger.note_snapshot_written(
            forged,
            descriptor(),
            quarantine=judged_medium,
        )
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT
    assert ledger.audit() == ()

    minted = preflight(
        judged_medium,
        snapshot=descriptor(),
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict_was_minted_here(minted) is True
    assert ledger.may_migrate(minted, quarantine=judged_medium) is True


def test_a_snapshot_is_recorded_as_written_only_after_the_caller_acted() -> None:
    """M12: `record` asserted the write at permission time.

    In a repository whose every document says no snapshot has been written,
    the audit's only positive classification was a claim about an act that had
    not occurred and might never occur.
    """

    judged_medium = a_quarantine(quarantined=False)

    ledger = MigrationLedger()
    judged = descriptor()
    minted = preflight(
        judged_medium,
        snapshot=judged,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )

    assert ledger.may_migrate(minted, quarantine=judged_medium) is True
    assert ledger.audit() == ()  # permission granted; nothing written yet

    ledger.note_snapshot_written(minted, judged, quarantine=judged_medium)
    assert ledger.audit()[-1].event is SnapshotAuditEvent.SNAPSHOT_WRITTEN

    # **The verdict names the snapshot it judged.** It used to name none, so
    # this method could only re-check that *some* passing verdict existed: a
    # re-review recorded `SNAPSHOT_WRITTEN` against a snapshot whose integrity
    # was `FAILED`, on a verdict minted for a different, verified one. Both
    # objects were real and the verdict legitimately minted; nothing tied them.
    other = descriptor(integrity=SnapshotIntegrity.FAILED, schema_version=2)
    with pytest.raises(RecoveryRefused) as refused:
        ledger.note_snapshot_written(minted, other, quarantine=judged_medium)
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT

    # An equal-but-distinct descriptor is not the one that was judged either:
    # the tie is identity, because the point is *which* snapshot the preflight
    # actually looked at.
    #
    # On a **fresh** verdict, and asserting **which** rule answered. This used
    # to reuse `minted`, which three lines above had already been spent — so
    # with the identity tie weakened to `!=` the spent-verdict rule answered
    # instead, still a `RecoveryRefused`, still green. The incidental-refusal
    # antipattern this repository has now hit five times, in the one test whose
    # comment says the tie is identity.
    unspent = preflight(
        judged_medium,
        snapshot=judged,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    twin = descriptor()
    assert twin == judged and twin is not judged
    with pytest.raises(RecoveryRefused) as tie:
        ledger.note_snapshot_written(unspent, twin, quarantine=judged_medium)
    assert tie.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT

    # And both methods exist, which the class docstring used to claim while
    # shipping neither.
    assert {name for name in dir(ledger) if not name.startswith("_")} == {
        "audit",
        "may_migrate",
        "note_snapshot_written",
    }


def test_a_candidate_from_elsewhere_is_not_this_workflows_answer(observations) -> None:
    """M6: the class claimed "checked by identity" and shipped no checker.

    A constructed candidate answered every question exactly as a minted one
    did, and a subclass overrode `authority` with nothing type-checking it.
    """

    flow = workflow(observations)
    candidate = run_to_commit(flow, observations)

    assert flow.holds(candidate)
    assert candidate_applies_to(flow, candidate)

    forged = RecoveryCandidate(candidate.schema_version, FINGERPRINT)
    assert forged.schema_version == candidate.schema_version
    assert not flow.holds(forged)
    assert not candidate_applies_to(flow, forged)

    class Subclassed(RecoveryCandidate):
        @property
        def authority(self):
            return ("everything",)

    assert Subclassed(1, FINGERPRINT).authority == ("everything",)

    # **The subclass is forced into the workflow's own slot**, past the seal,
    # so that `holds()` answers True by identity and the type check is the only
    # thing left refusing. Asserting it on a *separately constructed* subclass
    # proved nothing: that object is not the one the workflow minted, so
    # `holds()` excluded it and `type(...) is` never decided anything —
    # mutating it to `isinstance` survived the whole suite.
    #
    # Reaching past the seal is exactly what `azazel_boot.quarantine` says
    # cannot be prevented in Python. The point here is that the *second* line
    # of defence holds when the first is walked round.
    #
    # **On a workflow that committed**, because `holds` asks the stage too: a
    # hostile candidate planted on a fresh workflow is refused for being on a
    # workflow that never committed, and the type check — the thing this half
    # of the test exists for — would never decide anything. That is this
    # file's own recurring antipattern, in a `holds` rather than a `match=`.
    hostile = Subclassed(1, FINGERPRINT)
    planted = workflow(observations)
    run_to_commit(planted, observations, snapshot=descriptor(fingerprint="snapshot-planted"))
    object.__setattr__(planted, "_candidate", hostile)

    assert planted.holds(hostile)  # identity says yes
    assert not candidate_applies_to(planted, hostile)  # the type says no
    assert hostile.authority == ("everything",)

    # An uncommitted workflow holds nothing — including `None`, which is what
    # it holds. `PersistenceSession.holds` was found in exactly this trap.
    fresh = workflow(observations)
    assert not fresh.holds(None)
    assert not candidate_applies_to(fresh, None)

    # And nothing else either, however it got there. `commit` writes the
    # candidate and then moves the stage, and the fence going up between those
    # two writes left a workflow at `TRIAL_OPEN` answering `True` for a
    # candidate no commit finished.
    uncommitted = workflow(observations)
    object.__setattr__(uncommitted, "_candidate", RecoveryCandidate(1, FINGERPRINT))
    assert uncommitted._candidate is not None
    assert not uncommitted.holds(uncommitted._candidate)
    assert not candidate_applies_to(uncommitted, uncommitted._candidate)
    assert not fresh.holds(candidate)

    # Another workflow's candidate is not this one's.
    other = workflow(observations)
    assert not other.holds(candidate)


def test_a_workflow_reached_at_committed_with_no_candidate_holds_nothing(observations) -> None:
    """R12 (test-suite review): `holds()`'s own docstring names the reason
    for `self._candidate is not None`, and no test ever drove the state it
    names — `_stage is COMMITTED` with `_candidate` still `None`.

    The prior "uncommitted" case above (`object.__setattr__`-planting a
    candidate on a workflow whose stage never moved) drives the other half:
    a candidate present without `COMMITTED`. It is not the same state, and
    a mutant dropping `self._candidate is not None` survives it — nothing
    in that case reaches `_stage is COMMITTED` at all, so the mutant and the
    real code agree there too.

    This reaches `COMMITTED` directly through `_sealed_assign`, the same
    bound-method reach `commit()` itself uses, but stops one line short of
    `commit()`'s own candidate mint — `_require_the_gates` issues a real
    clearance (D8's full run, `acquisition` and `confirmed` both supplied),
    so the stage-edge and clearance checks inside `_sealed_assign` pass
    exactly as they would from inside `commit()`; only the mint is skipped.
    """

    snap = descriptor()
    flow = workflow(observations)
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    flow._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=Opens(),
        confirmed=True,
    )
    flow._sealed_assign("_stage", RecoveryStage.COMMITTED)

    assert flow.stage is RecoveryStage.COMMITTED
    assert flow._candidate is None
    assert not flow.holds(None)
    assert not flow.holds(RecoveryCandidate(1, FINGERPRINT))


def test_a_workflow_refuses_a_stage_asked_for_another_sitting(observations) -> None:
    """M13: `_session_id` was assigned once and read nowhere.

    `__setattr__` claimed "the quarantine, the binding and the sitting cannot
    be replaced", while the sitting was not used at all — so a review committed
    a workflow built for one sitting by passing another's id to every stage.
    """

    flow = workflow(observations)
    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id="another-sitting",
            started_by_operator=True,
        )
    assert refused.value.refusal is Refusal.NOT_THIS_SITTING
    # Terminal and audited, on the module's own principle that a swap is an
    # event rather than a typo. It used to raise and leave `NOT_STARTED` with
    # an empty audit, so a foreign sitting could probe a live workflow as often
    # as it liked and nothing recorded that it had.
    assert flow.stage is RecoveryStage.REFUSED
    assert [entry.event for entry in flow.audit()] == [SnapshotAuditEvent.RECOVERY_FOREIGN_SITTING]


def test_the_no_payload_events_carry_no_payload_field_either(observations) -> None:
    """R16 (test-suite review): four `_record` call sites deliberately pass
    neither `schema_version` nor `fingerprint` — nothing asserted they stay
    that way.

    `RECOVERY_REFUSED` (via `_refuse_gate`), `RECOVERY_TRIAL_OPENED`,
    `RECOVERY_INTERRUPTED` and `RECOVERY_FOREIGN_SITTING` are the module's
    four "classification, and nothing behind it" events. A mutation adding
    `schema_version=self._pinned.schema_version,
    fingerprint=self._pinned.fingerprint` to any one of the four calls
    survived the entire suite undetected — for `RECOVERY_FOREIGN_SITTING`
    the sharper version leaks `self._session_id`, the raw sitting
    identifier, not even the caller's own opaque fingerprint. A fifth
    "no-payload" event, `RECOVERY_SNAPSHOT_SUBSTITUTED`, already has this
    coverage via the generic `schema_version==99` sweep elsewhere in this
    file; these four did not.

    R18 (test-suite review): `schema_version`/`fingerprint` are not this
    entry's whole payload. `check` and `gate` were asked nowhere in this
    test either — a mutation adding `check=PreflightCheck.REQUIRED_SPACE` to
    any of the four calls, or `gate=RecoveryGate.MEDIUM_FENCED` to the ones
    that do not already carry a legitimate gate, survived undetected too.
    Extended to ask all four fields of every "classification, and nothing
    behind it" event, `RECOVERY_SNAPSHOT_SUBSTITUTED` included, rather than
    trusting the class name to say what it does not check.
    """

    # RECOVERY_FOREIGN_SITTING
    foreign = workflow(observations)
    with pytest.raises(RecoveryRefused):
        foreign.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id="another-sitting",
            started_by_operator=True,
        )
    entry = foreign.audit()[-1]
    assert entry.event is SnapshotAuditEvent.RECOVERY_FOREIGN_SITTING
    assert entry.schema_version is None
    assert entry.fingerprint is None
    assert entry.check is None
    assert entry.gate is None

    # RECOVERY_REFUSED, via any gate failure — `gate` is this event's own
    # legitimate payload, so only `check` and the schema fields are asked.
    refused_flow = workflow(observations)
    with pytest.raises(RecoveryRefused):
        refused_flow.start(
            descriptor(),
            observations,
            media_binding_holds=False,
            session_id=SESSION,
            started_by_operator=True,
        )
    entry = refused_flow.audit()[-1]
    assert entry.event is SnapshotAuditEvent.RECOVERY_REFUSED
    assert entry.schema_version is None
    assert entry.fingerprint is None
    assert entry.check is None
    assert entry.gate is not None

    # RECOVERY_TRIAL_OPENED
    snap = descriptor()
    trial_flow = workflow(observations)
    trial_flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    trial_flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    entry = trial_flow.audit()[-1]
    assert entry.event is SnapshotAuditEvent.RECOVERY_TRIAL_OPENED
    assert entry.schema_version is None
    assert entry.fingerprint is None
    assert entry.check is None
    assert entry.gate is None

    # RECOVERY_INTERRUPTED
    interrupted_flow = workflow(observations)
    interrupted_flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    interrupted_flow.interrupt(session_id=SESSION)
    entry = interrupted_flow.audit()[-1]
    assert entry.event is SnapshotAuditEvent.RECOVERY_INTERRUPTED
    assert entry.schema_version is None
    assert entry.fingerprint is None
    assert entry.check is None
    assert entry.gate is None

    # RECOVERY_SNAPSHOT_SUBSTITUTED — the fifth "no-payload" event. Elsewhere
    # in this file it is driven through a generic `schema_version==99` sweep
    # that only ever checks the entry does not carry *that* schema version;
    # this drives it directly and asks all four fields.
    substituted_flow = workflow(observations)
    substituted_flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    with pytest.raises(RecoveryRefused):
        substituted_flow.open_trial(
            descriptor(schema_version=2),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
        )
    entry = substituted_flow.audit()[-1]
    assert entry.event is SnapshotAuditEvent.RECOVERY_SNAPSHOT_SUBSTITUTED
    assert entry.schema_version is None
    assert entry.fingerprint is None
    assert entry.check is None
    assert entry.gate is None


def test_the_payload_carrying_events_carry_only_their_own_payload(observations) -> None:
    """R17 (test-suite review): round 16 pinned the *no*-payload events'
    fields to `None`; nothing pinned the *payload*-carrying events' own
    field to be the whole of what they carry.

    `RECOVERY_STARTED`, `RECOVERY_COMPLETED` and `SNAPSHOT_WRITTEN` are
    supposed to carry `schema_version`/`fingerprint` and nothing else —
    `check`/`gate` are `_refuse_gate`'s and D7's own vocabulary, not
    theirs. A mutation adding `gate=RecoveryGate.MEDIUM_FENCED` (or
    `check=...`) to any of the three `_record`/`SnapshotAuditEntry(...)`
    call sites survived the whole suite undetected, and the same shape
    survived a fourth site: `_require_the_medium_now`'s `MIGRATION_REFUSED`
    entry (the "medium moved since the preflight" path) carries `check=`
    by design, but nothing pinned `gate`/`schema_version`/`fingerprint`
    there to stay `None`. `may_migrate`'s own `MIGRATION_REFUSED` entry
    already had this coverage (`test_a_refused_migration_records_the_
    check_and_no_figure`'s exact-tuple equality); these four did not.
    """

    # RECOVERY_STARTED
    started_flow = workflow(observations)
    snap = descriptor()
    started_flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    entry = started_flow.audit()[-1]
    assert entry.event is SnapshotAuditEvent.RECOVERY_STARTED
    assert entry.check is None
    assert entry.gate is None

    # RECOVERY_COMPLETED
    committed_flow = workflow(observations)
    committed_flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    committed_flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    committed_flow.commit(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        acquisition=Opens(),
        confirmed=True,
    )
    entry = committed_flow.audit()[-1]
    assert entry.event is SnapshotAuditEvent.RECOVERY_COMPLETED
    assert entry.check is None
    assert entry.gate is None

    # SNAPSHOT_WRITTEN
    judged_medium, written_snapshot, verdict = a_migration()
    ledger = MigrationLedger()
    assert ledger.may_migrate(verdict, quarantine=judged_medium) is True
    ledger.note_snapshot_written(verdict, written_snapshot, quarantine=judged_medium)
    entry = ledger.audit()[-1]
    assert entry.event is SnapshotAuditEvent.SNAPSHOT_WRITTEN
    assert entry.check is None
    assert entry.gate is None

    # MIGRATION_REFUSED, via `_require_the_medium_now`'s medium-moved path
    moved_medium = a_quarantine(quarantined=False)
    moved_snapshot = descriptor()
    moved_verdict = preflight(
        moved_medium,
        snapshot=moved_snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    moved_ledger = MigrationLedger()
    moved_medium.quarantine_volume()
    with pytest.raises(RecoveryRefused):
        moved_ledger.may_migrate(moved_verdict, quarantine=moved_medium)
    entry = moved_ledger.audit()[-1]
    assert entry.event is SnapshotAuditEvent.MIGRATION_REFUSED
    assert entry.check is PreflightCheck.VOLUME_QUARANTINED
    assert entry.gate is None
    assert entry.schema_version is None
    assert entry.fingerprint is None


def test_the_audit_repr_does_not_render_the_fingerprint(observations) -> None:
    """M9: the descriptor redacted it and the audit entry rendered it.

    The audit is the object destined for an operator-facing log, and the
    absence test rendered five reprs — deliberately not this one.
    """

    flow = workflow(observations)
    run_to_commit(flow, observations)

    rendered = repr(flow.audit()) + str(flow.audit())
    assert FINGERPRINT not in rendered
    assert "<redacted>" in rendered
    assert flow.audit()[-1].fingerprint == FINGERPRINT  # still carried, not rendered


@pytest.mark.parametrize("name", ["binding_holds", "generation_holds", "image_digest_holds"])
def test_a_truthy_object_is_not_a_check(name) -> None:
    """L18: annotated `bool`, unchecked — the lesson applied to the descriptor
    and not to `preflight`."""

    arguments = {
        "snapshot": descriptor(),
        "capacity": capacity(),
        "current_schema": 1,
        "target_schema": 2,
        "binding_holds": True,
        "generation_holds": True,
        "image_digest_holds": True,
    }
    arguments[name] = "yes"
    with pytest.raises(TypeError):
        preflight(a_quarantine(quarantined=False), **arguments)


def test_the_key_and_integrity_gates_cannot_be_contested_against_each_other(
    observations,
) -> None:
    """D8 orders key acquisition before integrity. That pair is **not testable**,
    and saying so is better than a test that looks like it proves it.

    At `commit` the snapshot is pinned to the one the workflow started on, so a
    failed-integrity snapshot cannot be presented there at all — the
    substitution check fires first. At `start` there is no acquisition, because
    that is where an operator has not yet been asked to type. So no input makes
    both gates fail at the same moment.

    A re-review found the helper written to contest this pair was **defined and
    never called**, and that moving the integrity block above the acquisition
    block left the suite green. The helper is deleted rather than wired up,
    because wiring it up would not have worked either; what is pinned instead
    is the fact that makes it untestable.
    """

    flow = workflow(observations)
    good = descriptor()
    flow.start(
        good, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(good, observations, media_binding_holds=True, session_id=SESSION)

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            descriptor(integrity=SnapshotIntegrity.FAILED),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(channel=NOT_A_CHANNEL),
            confirmed=False,
        )
    # Not GATE_REFUSED: the substitution rule answers first, which is what
    # makes the integrity gate unreachable-with-a-bad-snapshot at commit.
    assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW

    # The integrity gate at commit is therefore a re-check that cannot fail
    # given the pinning, not an ordered gate. Deleting it is still caught, at
    # `start`, by `test_the_integrity_gate_is_reached_and_refuses`.


def test_the_workflow_and_the_ledger_are_sealed(observations) -> None:
    """Both seals were entirely untested; turning either off was green.

    The docstrings claim the quarantine, the binding and the sitting cannot be
    replaced. Nothing attempted it, so the claim could have been tidied away
    without a red test — the same gap the candidate's seal had.
    """

    flow = workflow(observations)
    for name in ("_quarantine", "_binding", "_session_id", "_stage", "_pinned", "_candidate"):
        with pytest.raises(AttributeError, match="sealed after construction"):
            setattr(flow, name, None)

    ledger = MigrationLedger()
    with pytest.raises(AttributeError, match="sealed after construction"):
        ledger._audit = []

    # `_sealed_assign` used to be an unconditional `object.__setattr__` that
    # any caller could reach, and this test recorded that as a stated limit. A
    # review then used it: `NOT_STARTED` and `TRIAL_OPEN` are both non-terminal
    # and both `_stage` and `_pinned` were on the moves-during-a-recovery list,
    # so a jump straight between them minted a candidate whose entire audit was
    # `['recovery_completed']` — no start, no operator, no trial. So the stage
    # travels its own graph, and the two pinned fields move only at the start.
    with pytest.raises(AttributeError, match="travels its own graph"):
        flow._sealed_assign("_stage", RecoveryStage.TRIAL_OPEN)
    assert flow.stage is RecoveryStage.NOT_STARTED

    flow.start(
        descriptor(),
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    with pytest.raises(AttributeError, match="pinned when it starts"):
        flow._sealed_assign("_pinned", descriptor(schema_version=2))
    # The **full** message. "minted by a commit" is a prefix of two different
    # rules — the clearance one and the stage one — so the short `match=` was
    # satisfied by whichever fired first, which is this repository's own
    # incidental-refusal antipattern in the assertion written to close it.
    with pytest.raises(AttributeError, match="minted by a commit whose gates passed"):
        flow._sealed_assign("_candidate", RecoveryCandidate(2, FINGERPRINT))
    assert flow.stage is RecoveryStage.PREFLIGHT_PASSED
    assert flow.holds(RecoveryCandidate(2, FINGERPRINT)) is False

    # The limit that remains, stated rather than implied: `object.__setattr__`
    # reaches every one of these directly. `azazel_boot.quarantine` says the
    # same of its own seal — careless-caller defence, not a capability
    # boundary. What is gone is the reach of an ordinary method call.
    object.__setattr__(flow, "_stage", RecoveryStage.TRIAL_OPEN)
    assert flow.stage is RecoveryStage.TRIAL_OPEN


def test_a_verdict_subclass_carrying_a_stolen_token_is_refused() -> None:
    """F-11: `type(verdict) is PreflightVerdict` had no test behind it.

    It is semantically load-bearing — the same "a check nobody tests" shape the
    candidate's type check was found in one round earlier.
    """

    minted = preflight(
        a_quarantine(quarantined=False),
        snapshot=descriptor(),
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict_was_minted_here(minted)

    class Subclassed(PreflightVerdict):
        pass

    # Registered as if minted — which is what an importer of this module can
    # do, and what the module says about its own limit. The type check is what
    # refuses it, and it is the one being driven here.
    stolen = Subclassed(None)
    module_registry = sys.modules["azazel_boot.snapshot"]._MINTED_HERE
    module_registry.add(stolen)
    assert stolen in module_registry
    assert stolen.may_migrate is True
    assert verdict_was_minted_here(stolen) is False
    with pytest.raises(RecoveryRefused) as refused:
        MigrationLedger().may_migrate(stolen, quarantine=a_quarantine(quarantined=False))
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT


def test_the_token_cannot_be_read_off_a_verdict_and_reused() -> None:
    """F-6: it could, including off a **refused** one.

    Round two removed the `token` **parameter**, and round four pointed out
    that this test then asserted the parameter was gone and stopped — it never
    read a token off a verdict and never reused one, while the read path was
    untouched: `_token` on every returned verdict, refusals included, **was**
    the live sentinel.

    So the assertion is now an absence, which is the only kind that holds:
    there is nothing on a verdict that says it was minted. Not a guarded
    attribute — no attribute.
    """

    judged_medium = a_quarantine(quarantined=False)

    refused = preflight(
        judged_medium,
        snapshot=descriptor(integrity=SnapshotIntegrity.FAILED),
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert refused.refused_by is PreflightCheck.SNAPSHOT_INTEGRITY

    assert "token" not in inspect.signature(PreflightVerdict).parameters
    assert "_token" not in PreflightVerdict.__slots__
    for verdict in (refused, PreflightVerdict(None)):
        assert not [name for name in dir(verdict) if "token" in name.lower()]
        for name in PreflightVerdict.__slots__:
            if name == "__weakref__":
                continue
            held = object.__getattribute__(verdict, name)
            # A check, the checks asked, the descriptor judged, or the
            # quarantine judged — all things the caller already had. What is
            # absent is anything that *says the verdict was minted*: there is
            # no token to copy onto another one.
            assert held is None or isinstance(
                held, PreflightCheck | tuple | SnapshotDescriptor | Quarantine
            ), name

    rebuilt = PreflightVerdict(None)
    assert rebuilt.may_migrate is True
    assert verdict_was_minted_here(rebuilt) is False

    ledger = MigrationLedger()
    with pytest.raises(RecoveryRefused) as error:
        ledger.may_migrate(rebuilt, quarantine=judged_medium)
    assert error.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT
    assert ledger.audit() == ()


def test_the_key_acquisition_refusal_traceback_holds_what_it_was_handed(
    observations,
) -> None:
    """F-13: the existing traceback assertion ran only on the fenced-`start`
    path, where `acquisition` is `None` — so it read as coverage it did not have.

    This pins the **acknowledged** outcome on the path that actually holds a
    secret: the raising frame holds nothing, and the frames above hold what
    they were handed, because a frame cannot forget its own argument.
    """

    import traceback

    flow = workflow(observations)
    snap = descriptor()
    acquisition = Opens(channel=NOT_A_CHANNEL)
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=acquisition,
            confirmed=True,
        )

    summary = traceback.TracebackException.from_exception(refused.value, capture_locals=True)
    frames = [frame for frame in summary.stack if frame.filename == str(MODULE)]
    by_name = {frame.name: frame for frame in frames}

    assert set(by_name["_raise_gate_refused"].locals or {}) == set()
    assert set(by_name["_refuse_gate"].locals or {}) == {"gate", "self"}

    # And what is *not* claimed: `commit` holds the acquisition it was handed,
    # so a double whose `__repr__` leaks renders its secret from that frame.
    held = " ".join((by_name["commit"].locals or {}).values())
    assert acquisition.secret in held
    assert SESSION in held

    # The message carries neither.
    assert acquisition.secret not in str(refused.value)
    assert SESSION not in str(refused.value)


def test_a_stand_in_for_the_quarantine_is_refused(observations) -> None:
    """F-9: the load-bearing input was the one input nothing checked.

    A re-review passed an object with two class attributes — `is_fenced =
    False`, `volume_is_quarantined = True` — and both gates that precede D8's
    four were satisfied by them. `RecoveryWorkflow.__init__` checked nothing at
    all, so a `session_id` of `1234` and a binding of `"not a SessionBinding"`
    were equally accepted.
    """

    class NotAQuarantine:
        is_fenced = False
        volume_is_quarantined = True

    with pytest.raises(TypeError, match="must be a Quarantine"):
        preflight(
            NotAQuarantine(),
            snapshot=descriptor(),
            capacity=capacity(),
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        )

    binding = SessionBinding(host_fingerprint=host_fingerprint(observations), session_id=SESSION)
    with pytest.raises(TypeError, match="must be a Quarantine"):
        RecoveryWorkflow(NotAQuarantine(), binding, session_id=SESSION)
    with pytest.raises(TypeError, match="must be a SessionBinding"):
        RecoveryWorkflow(a_quarantine(), "not a SessionBinding", session_id=SESSION)
    for bad_sitting in (1234, "", "   ", None):
        with pytest.raises(TypeError, match="session_id"):
            RecoveryWorkflow(a_quarantine(), binding, session_id=bad_sitting)


def test_a_bindings_own_fields_are_pinned_not_only_its_container_type(observations) -> None:
    """R13 (security review): `type(binding) is not SessionBinding` checks
    the container; nothing checked what was *inside* it.

    `SessionBinding` is a public `@dataclass` with no field validation of
    its own, and `binding_applies` (`commissioning.py`) decides
    `RecoveryGate.HOST_BINDING` with `binding.host_fingerprint == observed
    and binding.session_id == session_id` — the caller's own operand on the
    left of `==`, the exact shape `_require_an_exact_str`'s own docstring
    names for the `session_id` *parameter* ("a `str` subclass whose
    `__ne__` answers `False` decided ... for the caller"). Nothing pinned
    the same hazard for `binding`'s own two fields: a genuine
    `SessionBinding`, built through its own public constructor with an
    `__eq__`-hostile `str` subclass as `host_fingerprint`, passed the gate
    for a host the real fingerprint never matched and committed a full
    recovery — `docs/snapshot-and-recovery.md`'s "a binding from another
    machine refuses with the acquisition never invoked" did not hold.
    """

    class AlwaysEqual(str):
        def __eq__(self, other: object) -> bool:
            return True

        def __ne__(self, other: object) -> bool:
            return False

        def __hash__(self) -> int:
            return 0

    real_fingerprint = host_fingerprint(observations)
    for forged, expected_pattern in (
        (
            SessionBinding(host_fingerprint=AlwaysEqual("not the real host"), session_id=SESSION),
            r"binding\.host_fingerprint",
        ),
        (
            SessionBinding(host_fingerprint=real_fingerprint, session_id=AlwaysEqual(SESSION)),
            r"binding\.session_id",
        ),
    ):
        # R14 (test-suite review): `match="binding\\."` alone does not say
        # *which* field's check fired — a label-swap bug (the two
        # `_require_an_exact_str` calls' name strings exchanged, values
        # left correct) survived undetected, since both messages still
        # contained "binding.". Matching the exact expected field name
        # closes that.
        with pytest.raises(TypeError, match=expected_pattern):
            RecoveryWorkflow(a_quarantine(), forged, session_id=SESSION)


def test_a_quarantines_own_session_id_is_pinned_not_only_the_container_type() -> None:
    """R14 (security review): the same gap round 13 closed for `binding`,
    one field over, on the quarantine itself.

    `_require_a_real_quarantine` pins `type(quarantine) is Quarantine`, the
    container, and `_require_the_gates` decides `MEDIUM_NOT_RECOGNISED` with
    `self._quarantine.session_id != self._session_id` — the quarantine's own
    field on the *left* of `!=`, asked first. `Quarantine.__init__`
    (`azazel_boot.quarantine`, tracked separately as issue #51, out of this
    file's ownership) performs no validation of its own on `session_id`, so
    a genuine `Quarantine`, built only through its public constructor, can
    hold a `str` subclass whose `__ne__` always answers `False`. Reached
    `COMMITTED` and minted a real `RecoveryCandidate` for a quarantine whose
    honest `session_id` was a different sitting entirely — the exact pairing
    the comment above `MEDIUM_NOT_RECOGNISED`'s check says it exists to
    refuse (`QUARANTINE_FROM_ANOTHER_SESSION`'s sibling check here).
    """

    class LyingStr(str):
        def __eq__(self, other: object) -> bool:
            return True

        def __ne__(self, other: object) -> bool:
            return False

        def __hash__(self) -> int:
            return str.__hash__(self)

    lying = Quarantine(
        session_id=LyingStr("session-elsewhere"), boot_medium_identity=MEDIUM.identity
    )
    lying.observe(MEDIUM)
    lying.observe(Device(identity="host-nvme-SN-1", device_class=DeviceClass.HOST_STORAGE))
    lying.quarantine_volume()

    binding = SessionBinding(host_fingerprint="irrelevant-to-this-check", session_id=SESSION)
    with pytest.raises(TypeError, match="quarantine\\.session_id"):
        RecoveryWorkflow(lying, binding, session_id=SESSION)


def test_an_attempted_automatic_start_is_terminal_and_audited(observations) -> None:
    """F-12: it used to take the silent refusal and leave no trace.

    Three refused automatic starts left `stage=NOT_STARTED, audit=()`, and a
    real start then succeeded — nothing recording that D8's central
    prohibition had been exercised. That is the same reasoning which made a
    snapshot substitution terminal and audited: a start nothing started is an
    event, not a typo.
    """

    flow = workflow(observations)
    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=False,
        )
    assert refused.value.refusal is Refusal.RECOVERY_NOT_STARTED_BY_AN_OPERATOR
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.audit() == (SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_REFUSED),)

    # And terminal: a real start afterwards is refused, so the attempt cannot
    # be washed away by simply trying again properly.
    with pytest.raises(RecoveryRefused) as again:
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
    assert again.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED


# --------------------------------------------------------------------------
# The third review's findings, each as the reproduction that found it
# --------------------------------------------------------------------------


@pytest.mark.parametrize("truthy", ["no", "declined", 1, [0], object()])
def test_the_two_operator_flags_must_be_actual_bools(truthy, observations) -> None:
    """F-2: they took any truthy object, and they are D8's operator gates.

    `preflight` checked its three flags with the comment "a truthy object is
    not a check" while the two that carry the whole operator-started doctrine
    were not checked at all. A review reached `COMMITTED` and minted a
    candidate with `started_by_operator="no"` and `confirmed="declined"` — the
    hostile reading, and the point: any non-empty string, any non-zero int, any
    object without `__bool__` did this.
    """

    flow = workflow(observations)
    with pytest.raises(TypeError, match="started_by_operator"):
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=truthy,
        )
    assert flow.stage is RecoveryStage.NOT_STARTED

    good = workflow(observations)
    snap = descriptor()
    good.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    good.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    with pytest.raises(TypeError, match="confirmed"):
        good.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=truthy,
        )
    assert good.stage is RecoveryStage.TRIAL_OPEN


def test_a_quarantine_subclass_that_lies_about_its_state_is_refused(observations) -> None:
    """F-4: `isinstance` was the fix for a stand-in, and a subclass wore the class.

    Overriding `is_fenced` and `volume_is_quarantined` as properties let a
    genuinely **fenced** medium run the whole workflow to a minted candidate.
    `Quarantine.is_fenced.fget(q)` answered True the entire time.

    `PreflightVerdict` and `RecoveryCandidate` were already checked with
    `type(...) is`; the quarantine is the input the two gates before D8's four
    read, so it gets the same.
    """

    class Lying(Quarantine):
        @property
        def is_fenced(self) -> bool:
            return False

        @property
        def volume_is_quarantined(self) -> bool:
            return True

    lying = Lying(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
    lying.observe(MEDIUM)
    lying.fence()
    assert Quarantine.is_fenced.fget(lying) is True  # it really is fenced
    assert lying.is_fenced is False  # and it says otherwise

    binding = SessionBinding(host_fingerprint=host_fingerprint(observations), session_id=SESSION)
    with pytest.raises(TypeError, match="exactly"):
        RecoveryWorkflow(lying, binding, session_id=SESSION)
    with pytest.raises(TypeError, match="exactly"):
        preflight(
            lying,
            snapshot=descriptor(),
            capacity=capacity(),
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        )


def test_a_snapshot_stand_in_is_refused_by_the_type_before_its_eq_is_asked(
    observations,
) -> None:
    """F-3: the workflow accepted any object and compared with `!=`.

    A stand-in with three class attributes satisfied both integrity gates, and
    an `__eq__` returning `True` decided the substitution check for itself. The
    type check is what refuses it; the field-by-field comparison behind it is
    the second line, and cannot be reached by a hostile `__eq__` once the type
    is pinned. Why that second line is required anyway, and pinned, is
    `test_the_snapshot_pin_compares_every_field_the_descriptor_has`.
    """

    class Substitute:
        container_version = 1
        schema_version = 99
        integrity = SnapshotIntegrity.VERIFIED
        fingerprint = "attacker"

        def __eq__(self, other) -> bool:
            return True

        def __ne__(self, other) -> bool:
            return False

        def __hash__(self) -> int:
            return 0

    flow = workflow(observations)
    real = descriptor()
    flow.start(
        real, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )

    for stage in (
        lambda item: flow.open_trial(
            item, observations, media_binding_holds=True, session_id=SESSION
        ),
        lambda item: flow.commit(
            item,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        ),
    ):
        with pytest.raises(TypeError, match="exactly"):
            stage(Substitute())
    assert flow.stage is RecoveryStage.PREFLIGHT_PASSED

    with pytest.raises(TypeError, match="exactly"):
        RecoveryWorkflow(
            a_quarantine(),
            SessionBinding(host_fingerprint=host_fingerprint(observations), session_id=SESSION),
            session_id=SESSION,
        ).start(
            Substitute(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )


@pytest.mark.parametrize("name", ["current_schema", "target_schema"])
@pytest.mark.parametrize("bad", [True, False, "1", 1.0, None])
def test_a_schema_version_must_be_an_int_that_is_not_a_bool(name, bad) -> None:
    """F-5: they were annotated and unchecked.

    An object whose `__eq__` and `__gt__` always answer True produced a
    **legitimately minted** passing verdict for a step in no supported set, and
    `schema_is_compatible(current=True, target=2)` was True — a `bool` passing
    as version 1, the exact case `SnapshotDescriptor.__post_init__` goes out of
    its way to refuse.
    """

    arguments = {
        "snapshot": descriptor(),
        "capacity": capacity(),
        "current_schema": 1,
        "target_schema": 2,
        "binding_holds": True,
        "generation_holds": True,
        "image_digest_holds": True,
    }
    arguments[name] = bad
    with pytest.raises(TypeError, match=name):
        preflight(a_quarantine(quarantined=False), **arguments)


@pytest.mark.parametrize(
    "bad",
    [
        {"schema_version": "capacity_available=123456789 medium=usb-SN-0007"},
        {"schema_version": True},
        {"schema_version": 1.0},
        {"fingerprint": 1234},
        {"event": "recovery_started"},
        {"check": "required_space"},
        {"gate": "medium_fenced"},
    ],
)
def test_an_audit_entry_refuses_anything_it_would_render_verbatim(bad) -> None:
    """F-6: the repr rendered whatever it was handed.

    Reached through a snapshot stand-in whose `schema_version` was a string
    carrying **a capacity figure and a medium identity** — the two things
    ADR-0010 D10 names specifically — into the object this module's own
    docstring calls "the object destined for a log". Fixing the reachability is
    the snapshot type check; this removes the class of it.
    """

    fields = {"event": SnapshotAuditEvent.RECOVERY_STARTED}
    fields.update(bad)
    with pytest.raises(TypeError):
        SnapshotAuditEntry(**fields)


@pytest.mark.parametrize("stage", ["start", "open_trial", "commit"])
def test_every_stage_refuses_a_foreign_sitting(stage, observations) -> None:
    """F-8: the check was tested on `start` only.

    Deleting it from `open_trial` and from `commit` each left the suite green,
    while the docstring said a review had committed a workflow built for one
    sitting by passing another's id **to every stage**.
    """

    flow = workflow(observations)
    snap = descriptor()
    if stage != "start":
        flow.start(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
    if stage == "commit":
        flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    call = {
        "start": lambda: flow.start(
            snap,
            observations,
            media_binding_holds=True,
            session_id="elsewhere",
            started_by_operator=True,
        ),
        "open_trial": lambda: flow.open_trial(
            snap, observations, media_binding_holds=True, session_id="elsewhere"
        ),
        "commit": lambda: flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id="elsewhere",
            acquisition=Opens(),
            confirmed=True,
        ),
    }[stage]

    with pytest.raises(RecoveryRefused) as refused:
        call()
    assert refused.value.refusal is Refusal.NOT_THIS_SITTING
    # **And the stage and the record**, for all three. Asserting only the
    # refusal enum let a review narrow the rule to `NOT_STARTED`: four foreign
    # probes against a live `TRIAL_OPEN` workflow then left no record and no
    # terminal stage, which is verbatim what the module says this rule exists
    # to notice.
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.audit()[-1].event is SnapshotAuditEvent.RECOVERY_FOREIGN_SITTING


def test_the_snapshot_pin_compares_every_field_the_descriptor_has() -> None:
    """F-3b: the substitution check may not delegate, and must be total.

    Two requirements, and the second is why the first is not merely style.

    *Not delegated*: the check compares field by field so that no `__eq__` or
    `__ne__` on the presented object can answer it. The type pin in
    `_require_a_real_snapshot` makes a hostile one unreachable today; this is
    the second line, for the day somebody weakens the first.

    *Total*: a hand-written conjunction is exactly as good as the fields it
    names. Add a fifth field to `SnapshotDescriptor` and a comparison nobody
    updated would pass two descriptors that differ in it — a substitution, not
    noticed. So the names the check reads are derived from its own source and
    asserted equal to the dataclass's fields.

    The two forms agree on every pair of real descriptors today, asserted
    below: what is pinned here is what a later edit can break, not a difference
    that exists now.
    """

    from azazel_boot import snapshot as module

    source = inspect.getsource(module._fields_of)
    tree = ast.parse(textwrap.dedent(source))
    compared = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "snapshot"
    }
    # `SnapshotDescriptor` is not a dataclass — `dataclasses.fields()` was the
    # route `dataclasses.asdict()` used to hand the fingerprint back through,
    # so the class stopped being one. `__slots__`, with the leading
    # underscore each field is stored under stripped, is its declaration now.
    declared = {name.lstrip("_") for name in SnapshotDescriptor.__slots__}
    assert compared == declared, (
        "the substitution check must compare every field of SnapshotDescriptor; "
        f"missing {sorted(declared - compared)}, unknown {sorted(compared - declared)}"
    )

    # And, for the pairs that can actually reach it, the two forms agree.
    made = [
        SnapshotDescriptor(1, version, integrity, fingerprint)
        for version in (1, 2)
        for integrity in SnapshotIntegrity
        for fingerprint in ("one", "two")
    ]
    for left in made:
        for right in made:
            field_by_field = all(
                getattr(left, name) == getattr(right, name) for name in sorted(declared)
            )
            assert (left == right) is field_by_field


# --------------------------------------------------------------------------
# The fourth review's findings on the commit gates, each as its reproduction
# --------------------------------------------------------------------------


def test_a_commit_without_a_key_acquisition_is_refused(observations) -> None:
    """R4-1: `acquisition=None` skipped D8's second gate and left no trace.

    `_require_the_gates` takes an optional acquisition because `start` and
    `open_trial` have none, and `commit` forwarded whatever it was handed into
    an `if acquisition is not None:`. A commit with `None` produced an audit
    **byte-identical** to a legitimate one, so nothing downstream could tell a
    recovery that unlocked the volume from one where nobody was ever prompted.

    Worse than the hostile cases around it: a caller reaches this by writing
    `acquisition=maybe_an_acquisition`, not by trying.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    with pytest.raises(TypeError, match="requires a key acquisition"):
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=None,
            confirmed=True,
        )
    assert flow.stage is RecoveryStage.TRIAL_OPEN
    assert flow.holds(RecoveryCandidate(1, FINGERPRINT)) is False

    # And the honest failing acquisition, for the contrast the finding rests on.
    refused_flow = workflow(observations)
    refused_flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    refused_flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    with pytest.raises(RecoveryRefused) as refused:
        refused_flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(AttemptOutcome.REJECTED),
            confirmed=True,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert refused_flow.stage is RecoveryStage.REFUSED


def test_a_sitting_id_cannot_answer_its_own_check(observations) -> None:
    """R4-2: round three's fix compared values the caller supplied.

    `_require_this_sitting` had the caller's operand on the **left** of a
    `!=`, so a `str` subclass whose `__ne__` answers `False` decided it. The
    binding's session half fell to the same object: there the caller's value is
    on the right, and Python gives a subclass reflected priority.

    So the type is pinned before the comparison, which is what makes the
    comparison a comparison.
    """

    class AnySitting(str):
        def __eq__(self, other) -> bool:
            return True

        def __ne__(self, other) -> bool:
            return False

        def __hash__(self) -> int:
            return 0

    lying = AnySitting("some-other-sitting-entirely")
    assert (lying != SESSION) is False  # it really does lie

    flow = workflow(observations)
    with pytest.raises(TypeError, match="session_id must be a str exactly"):
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=lying,
            started_by_operator=True,
        )
    assert flow.stage is RecoveryStage.NOT_STARTED

    with pytest.raises(TypeError, match="session_id must be a str exactly"):
        RecoveryWorkflow(
            a_quarantine(),
            SessionBinding(host_fingerprint=host_fingerprint(observations), session_id=SESSION),
            session_id=lying,
        )


@pytest.mark.parametrize("field_name", ["container_version", "schema_version"])
def test_a_descriptor_built_from_a_lying_int_is_refused(field_name) -> None:
    """R4-3: the substitution check compared fields that answered for it.

    `__post_init__` took `isinstance(..., int)`, so a review built a **genuine**
    `SnapshotDescriptor` through the public constructor — no
    `object.__setattr__` — whose `container_version` really was 7 and whose
    comparisons said whatever it liked. It passed the substitution check and
    the container-version half of the integrity gate, and committed on a
    container format in no known set.
    """

    class Answers(int):
        def __eq__(self, other) -> bool:
            return True

        def __ne__(self, other) -> bool:
            return False

        def __hash__(self) -> int:
            return 0

    arguments = {
        "container_version": 1,
        "schema_version": 1,
        "integrity": SnapshotIntegrity.VERIFIED,
        "fingerprint": FINGERPRINT,
    }
    arguments[field_name] = Answers(7)
    with pytest.raises(TypeError, match=field_name):
        SnapshotDescriptor(**arguments)

    with pytest.raises(TypeError, match="fingerprint"):
        SnapshotDescriptor(1, 1, SnapshotIntegrity.VERIFIED, type("S", (str,), {})("x"))


def test_the_medium_is_read_again_after_the_passphrase_prompt(observations) -> None:
    """R4-4: the last fence read was on the wrong side of the only wait.

    `attempt()` is the operator typing a passphrase — the one step in this
    workflow that blocks on a human — and the fence is raised by device
    monitoring when the medium is pulled. The gates read the flags above it and
    never again, so a medium pulled *during the prompt* committed.

    The class docstring already said a gate checked once is a gate checked at a
    moment that has passed. This is that moment, driven: the acquisition itself
    pulls the medium, which is what a pull during a prompt looks like from
    inside the function.
    """

    quarantine = a_quarantine()

    class PulledDuringThePrompt(Opens):
        def attempt(self):
            quarantine.fence()
            return super().attempt()

    flow = workflow(observations, quarantine=quarantine)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    assert quarantine.is_fenced is False

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=PulledDuringThePrompt(),
            confirmed=True,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert quarantine.is_fenced is True
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.holds(RecoveryCandidate(1, FINGERPRINT)) is False
    assert [entry.gate for entry in flow.audit() if entry.gate is not None] == [
        RecoveryGate.MEDIUM_FENCED
    ]


def test_mutating_the_held_descriptor_between_the_stages_is_a_substitution(
    observations,
) -> None:
    """R4-5: `held = self._snapshot` compared the object with itself.

    The workflow held the very object the caller passed to `start` and passed
    again to `commit`, so the four field comparisons were an aliasing
    tautology. A review mutated the frozen descriptor in place between the
    stages and committed on a different schema version and fingerprint — and
    the audit recorded two different fingerprints across one workflow with no
    `RECOVERY_SNAPSHOT_SUBSTITUTED` between them, because the check could not
    fire against a value it had never stored.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )

    object.__setattr__(snap, "_schema_version", 2)
    object.__setattr__(snap, "_fingerprint", "snapshot-fingerprint-0000")

    with pytest.raises(RecoveryRefused) as refused:
        flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW
    assert flow.stage is RecoveryStage.REFUSED
    assert SnapshotAuditEvent.RECOVERY_SNAPSHOT_SUBSTITUTED in [
        entry.event for entry in flow.audit()
    ]


def test_the_seal_writes_only_the_three_fields_a_recovery_moves(observations) -> None:
    """R4-6: `_sealed_assign` was a general unsealing method on every instance.

    `__setattr__` refuses ordinary assignment with the words "the quarantine,
    the binding and the sitting cannot be replaced", and the class handed out a
    bound method that replaced any of them. A review used it to resume after
    `interrupt`, to swap the quarantine for an unfenced one, and to jump from
    `NOT_STARTED` straight to `TRIAL_OPEN` and mint a candidate whose entire
    audit was `['recovery_completed']`.

    This is **not** claimed as a capability boundary — `object.__setattr__` is
    not defensible in Python and this module says so about the quarantine. What
    it removes is the accidental reach: the three fields that legitimately
    move are named, and a terminal workflow moves none of them.

    Three, not four. `_snapshot` held the caller's own descriptor, was written
    twice and read nowhere, and was what a review moved the commit's mint onto
    to commit a substituted snapshot with the suite green. The slot is gone, so
    the rows below name `_pinned` — naming a field that no longer exists would
    make these `raises` blocks pass on the field-list rule instead of the rule
    each one names, which is this file's own recurring antipattern.
    """

    flow = workflow(observations)
    for name, value in (
        ("_quarantine", a_quarantine(quarantined=False)),
        ("_binding", None),
        ("_session_id", "another-sitting"),
        ("_sealed", False),
        ("_audit", []),
    ):
        with pytest.raises(AttributeError, match="cannot be replaced"):
            flow._sealed_assign(name, value)

    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.interrupt(session_id=SESSION)
    assert flow.stage is RecoveryStage.INTERRUPTED
    # R18 (security review): this used to be a bare `AttributeError` — the
    # seal's structural vocabulary — for a fact every other terminal-stage
    # check in this module expresses through `RecoveryRefused`. Aligned here
    # too, the same move round ten made for the fence check: see
    # `_sealed_assign`'s own comment.
    for name, value in (
        ("_stage", RecoveryStage.TRIAL_OPEN),
        ("_pinned", descriptor(schema_version=2)),
        ("_candidate", RecoveryCandidate(2, FINGERPRINT)),
    ):
        with pytest.raises(RecoveryRefused) as refused:
            flow._sealed_assign(name, value)
        assert refused.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED
    assert flow.stage is RecoveryStage.INTERRUPTED
    assert flow.holds(RecoveryCandidate(2, FINGERPRINT)) is False


def test_an_audit_entry_refuses_an_int_that_renders_as_a_capacity() -> None:
    """R4-7: `isinstance` admitted an `int` subclass, and the repr formats it.

    The entry's own `__post_init__` exists to stop a `schema_version` carrying
    `"capacity_available=… medium=usb-SN-…"` into the object this module calls
    "destined for a log" — ADR-0010 D10 names those two payloads specifically.
    An `int` subclass whose `__format__` renders that string went through the
    check written to refuse it, on an otherwise entirely legitimate commit.
    """

    class Renders(int):
        def __str__(self) -> str:
            return "capacity_available=17402 medium=usb-SN-BOOT-0001"

        def __format__(self, spec) -> str:
            return self.__str__()

    with pytest.raises(TypeError, match="schema_version must be an int exactly"):
        SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_STARTED, schema_version=Renders(1))
    with pytest.raises(TypeError, match="fingerprint must be a str exactly"):
        SnapshotAuditEntry(
            event=SnapshotAuditEvent.RECOVERY_STARTED,
            fingerprint=type("F", (str,), {})("x"),
        )


def test_an_interruption_belongs_to_its_sitting_like_every_other_stage(
    observations,
) -> None:
    """R4, low: `interrupt` was the one stage method exempt from the sitting.

    Any holder of the object, from any sitting, could end the workflow. It
    fails closed, so the exemption only ever bought a denial — and a denial is
    still an outcome somebody else chose, on a workflow that was mid-flight.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )

    with pytest.raises(RecoveryRefused) as refused:
        flow.interrupt(session_id="another-sitting")
    assert refused.value.refusal is Refusal.NOT_THIS_SITTING

    with pytest.raises(TypeError, match="session_id must be a str exactly"):
        flow.interrupt(session_id=type("S", (str,), {})(SESSION))


@pytest.mark.parametrize("stage", ["start", "open_trial", "commit"])
def test_every_stage_refuses_observations_that_are_not_observations(stage, observations) -> None:
    """R4, low: the one input to the gates that nothing pinned.

    `binding_applies` re-derives the host fingerprint from these rather than
    re-comparing a field it was handed, so a stand-in does not forge a host.
    But every other input to the gates is pinned, and this was the missing
    member of the set: a commit ran on a tuple of two-attribute stand-ins with
    no `InterfaceObservation` involved anywhere.
    """

    class NotAnObservation:
        interface_key = "en-0001"
        is_commissionable = True

    stand_ins = (NotAnObservation(), NotAnObservation())
    flow = workflow(observations)
    snap = descriptor()
    if stage != "start":
        flow.start(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
    if stage == "commit":
        flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    call = {
        "start": lambda items: flow.start(
            snap, items, media_binding_holds=True, session_id=SESSION, started_by_operator=True
        ),
        "open_trial": lambda items: flow.open_trial(
            snap, items, media_binding_holds=True, session_id=SESSION
        ),
        "commit": lambda items: flow.commit(
            snap,
            items,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        ),
    }[stage]

    with pytest.raises(TypeError, match="InterfaceObservation"):
        call(stand_ins)
    with pytest.raises(TypeError, match="tuple"):
        call(list(observations))


# --------------------------------------------------------------------------
# The guard that does not pin what it feeds
# --------------------------------------------------------------------------


QUARANTINE_SETATTR = Quarantine.__setattr__
QUARANTINE_DELATTR = Quarantine.__delattr__
#: Every name on the class, by identity. Comparing three dunders was not
#: enough: a review rebound `Quarantine.volume_is_quarantined` to a property
#: that answered `False` for chosen instances. No slot moved, the three
#: identities held, the seal still refused an ordinary assignment — and the
#: medium was out of quarantine for every caller in the process, including
#: ones this module was never handed.
QUARANTINE_CLASS = {name: value for name, value in vars(Quarantine).items()}


def _swallow(call, *args, **keywords):
    """Drive it and keep going. A refusal is the ordinary outcome here.

    **`TypeError` is not caught**, and that is the whole of the lesson. It was,
    and when `media_binding_holds` became a required keyword the four calls
    below stopped passing it: every one died with "missing 1 required
    keyword-only argument" *before entering the method*, and this swallowed it.
    The guard whose docstring calls itself "the claim" then executed **one of
    twenty-eight lines** of `_require_the_gates` and reached `COMMITTED` zero
    times, across every row of its product, for as long as the split lasted.

    A guard that swallows `TypeError` cannot tell "the module refused" from "I
    called it wrong". The module's own type refusals are `TypeError` too, so
    where one is expected it is asked for by name.
    """

    try:
        return call(*args, **keywords)
    except (RecoveryRefused, AttributeError):
        return None


#: The `AttributeError` rules the seal has, by a distinctive fragment of each
#: message. Used to *count* which of them a drive actually reached — a probe
#: that lands on a different rule from the one it was written for is the
#: incidental-refusal antipattern expressed as a drive rather than a `match=`.
#: **Disambiguated**, not merely distinct. `"cannot be replaced"` used to
#: stand for both `RecoveryWorkflow.__setattr__`'s seal message and
#: `_sealed_assign`'s not-in-`_MOVES_DURING_A_RECOVERY` message — both
#: `AttributeError`, both ending in the same six words — so `reached["cannot
#: be replaced"] > 0` could not say which of the two had actually answered.
#: Each fragment here is a prefix unique to one message.
#:
#: One more `AttributeError` rule exists in `_sealed_assign` — "a candidate
#: is minted by a commit and by nothing else" — and is **not** listed:
#: reaching it needs a real clearance already spent, which the probes below
#: build fresh workflows to avoid rather than arrange. It is driven directly,
#: with its own assertion, by
#: `test_the_clearance_is_issued_by_the_gates_and_by_nothing_shorter`
#: (`match="minted by a commit and by nothing else"`); this drive's job is
#: the input space around the calls it does make, not every shape the seal
#: can raise.
#:
#: The fence-since-the-clearance check used to be a second such rule and is
#: not one any more: round 10 found that a caller reaching it through the
#: legitimate path — `commit`, not a direct `_sealed_assign` call — met a
#: bare `AttributeError` for a fact every other gate expresses through
#: `RecoveryRefused`, so it now calls `_refuse_gate` instead and no longer
#: raises `AttributeError` at all. `test_a_clearance_is_spent_over_the_
#: medium_the_gates_read` and the R10 fence-landing-mid-commit test drive it
#: through `RecoveryRefused`, not through this fragment list.
#:
#: The terminal-stage rule (`"has ended"`) was a third and is gone the same
#: way, for the same reason, at round 18: a genuine second thread could reach
#: it through the legitimate path — racing `commit`/`start`/`open_trial`/
#: `interrupt` against another ordinary call — and met the identical bare
#: `AttributeError`. It answers `RecoveryRefused(WORKFLOW_ALREADY_FINISHED)`
#: now, so it is driven through that, not through this fragment list either.
_SEAL_RULES = (
    "a RecoveryWorkflow is sealed after construction",
    "only the stage, the snapshot's pinned fields",
    "travels its own graph",
    "reached by passing the gates",
    "a candidate is minted by a commit whose gates passed",
    "pinned when it starts",
)


def _a_workflow_at(stage, rule, binding, snap, observations):
    """A **fresh** workflow brought as far as `stage`, for one refusal probe.

    A refusal probe needs a workflow in the state its rule lives in. Running
    them all against the workflow the drive had just committed meant every one
    of them met the terminal rule instead, which is the same refusal for the
    right reason and the wrong one.

    The start and the trial may themselves refuse — a fenced medium, a failed
    integrity, an operator who did not start it — so this returns whatever it
    got there, and the caller counts which rule actually answered.
    """

    flow = RecoveryWorkflow(rule, binding, session_id=SESSION)
    if stage is RecoveryStage.NOT_STARTED:
        return flow
    _swallow(
        flow.start,
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    if stage is RecoveryStage.PREFLIGHT_PASSED:
        return flow
    _swallow(flow.open_trial, snap, observations, media_binding_holds=True, session_id=SESSION)
    return flow


def _rule_reached(call, *args, **keywords):
    """Drive it and report **which rule** answered, or `None` for no refusal.

    `_swallow` returns `None` for a refusal and `None` for a success, which is
    all a "did the quarantine move?" guard needs — and it is why that guard
    could run twenty-four refusal probes of which every single one was
    answered `workflow_already_finished` by a workflow the drive had already
    made terminal, with nobody noticing for three rounds. What a probe was
    written to reach and what it reached are different facts, and this is the
    second one.

    `TypeError` is not caught here either, for the reason it is not there.
    """

    try:
        call(*args, **keywords)
    except RecoveryRefused as refused:
        return refused.refusal
    except AttributeError as refused:
        for fragment in _SEAL_RULES:
            if fragment in str(refused):
                return fragment
        return f"unrecognised AttributeError: {refused}"
    return None


def _whole_quarantine_state(rule: Quarantine) -> dict[str, object]:
    """Every slot, not the two flags.

    `_flags` read `is_fenced`, `volume_is_quarantined`, `audit()` and one
    disposition, and a review wrote to `_dispositions` for every *other*
    device, deleted `_sealed`, and rebound `Quarantine.__setattr__` — each time
    with that comparison satisfied, because it asked about four things out of
    eight and nothing about the class.
    """

    state: dict[str, object] = {}
    for name in Quarantine.__slots__:
        # `__weakref__` is not a field: it is CPython's own list of weak
        # references to this object, and it is **not writable**, by plain
        # assignment or by `object.__setattr__` — asserted below rather than
        # assumed, because excluding a slot from this comparison is exactly the
        # move that made the earlier `_flags` version worthless. It changes
        # from `None` the moment anything takes a weak reference, which
        # `azazel_boot.snapshot` now does to remember something *about* a
        # medium without holding one, and a weak reference grants nothing: you
        # need the object to make one.
        if name == "__weakref__":
            continue
        try:
            state[name] = copy.deepcopy(object.__getattribute__(rule, name))
        except AttributeError:
            state[name] = "<deleted>"
    return state


def _the_weakref_slot_is_not_a_field(rule: Quarantine) -> bool:
    """Why `_whole_quarantine_state` may skip it.

    A slot excluded from the state comparison is a slot an attacker may use,
    unless it cannot hold anything an attacker chose. This one cannot: CPython
    makes `__weakref__` read-only on both paths.
    """

    for write in (setattr, object.__setattr__):
        try:
            write(rule, "__weakref__", "planted")
        except AttributeError:
            continue
        return False
    return True


def _quarantine_defences_intact(rule: Quarantine) -> tuple[object, ...]:
    """The seal as a *behaviour*, and the class as an identity.

    `del quarantine._sealed` leaves every slot value a before/after comparison
    would look at untouched and makes `q._volume_quarantined = False` succeed
    from any caller one line later. Rebinding `Quarantine.__setattr__` does the
    same for every `Quarantine` in the process, including ones this module was
    never handed. Neither shows up in a state diff, so neither is checked by
    one.
    """

    refused = False
    try:
        rule._volume_quarantined = False
    except AttributeError:
        refused = True
    unchanged = {name: value for name, value in vars(Quarantine).items()}

    # Identity against a snapshot taken when *this* file was imported is not
    # enough on its own: a rebind performed while `azazel_boot.snapshot` was
    # importing is already in that snapshot. So the class's own code is asked
    # where it comes from — every function and every property on `Quarantine`
    # must be defined in `azazel_boot.quarantine` — and a control instance is
    # asked the question, so an answer that changed is an answer that is wrong.
    home = []
    for value in unchanged.values():
        owner = value.fget if isinstance(value, property) else value
        module = getattr(owner, "__module__", "azazel_boot.quarantine")
        home.append(module == "azazel_boot.quarantine")

    control = Quarantine(session_id="control", boot_medium_identity=MEDIUM.identity)
    control.observe(MEDIUM)
    control.quarantine_volume()

    return (
        Quarantine.__setattr__ is QUARANTINE_SETATTR,
        Quarantine.__delattr__ is QUARANTINE_DELATTR,
        refused,
        set(unchanged) == set(QUARANTINE_CLASS),
        all(unchanged[name] is QUARANTINE_CLASS[name] for name in QUARANTINE_CLASS),
        all(home),
        control.volume_is_quarantined is True and control.is_fenced is False,
    )


def test_no_input_to_this_module_changes_anything_about_the_quarantine(
    observations,
) -> None:
    """The behavioural guard, over the input space rather than one row of it.

    Round four's decisive finding was not a new AST shape. It was that the
    guard which *did* hold — the one driving every public method and comparing
    the flags before and after — drove them with one fixed descriptor. A
    payload reading `if snapshot.schema_version > 1: clear the flags` passed
    the entire suite: a schema-1 recovery behaved perfectly, and a schema-2
    recovery, which is exactly the ADR-0010 D7/D8 migration case this module
    exists for, returned a candidate and turned both flags off.

    A guard that enumerates the call surface and fixes the inputs is a guard
    over one row of the input space. So this varies the inputs the module
    branches on — both schema versions, every container version it might see,
    every integrity verdict, both flag states, both operator flags and every
    acquisition outcome — and compares the **whole** of the quarantine's state,
    plus the defences that do not appear in a state diff at all.

    Three static guards in this file remain, and are worth what they are worth.
    This one is the claim.
    """

    from itertools import product

    binding = SessionBinding(host_fingerprint=host_fingerprint(observations), session_id=SESSION)
    drives = 0
    committed = 0
    recorded = 0
    #: Which rule each refusal probe actually reached, counted rather than
    #: assumed. `None` is "no refusal", which several probes legitimately are.
    reached: Counter = Counter()
    for (
        schema_version,
        container_version,
        integrity,
        fenced,
        quarantined,
        by_operator,
        confirmed,
        outcome,
        room,
        reports_hold,
        media_binding,
    ) in product(
        (1, 2, 3),
        (1, 2),
        tuple(SnapshotIntegrity),
        (False, True),
        (True, False),
        (True, False),
        (True, False),
        tuple(AttemptOutcome),
        (True, False),
        (True, False),
        # D8 gate 1's report. `media_binding_holds=False` reached a refusal
        # branch no test watched the quarantine across, and a payload there
        # cleared both flags with the suite green.
        (True, False),
    ):
        rule = a_quarantine(fenced=fenced, quarantined=quarantined)
        before = _whole_quarantine_state(rule)
        snap = SnapshotDescriptor(
            container_version=container_version,
            schema_version=schema_version,
            integrity=integrity,
            fingerprint=f"snapshot-fingerprint-{schema_version}{container_version}",
        )

        # The arguments this guard used to hold fixed. Round four's lesson was
        # not a new AST shape — it was that a guard which enumerates the call
        # surface and pins its inputs is a guard over one row of the input
        # space, so a payload gated on `schema_version > 1` walked past it.
        # These are the rest of the rows: with and without room, with and
        # without a snapshot, and with the three caller-supplied reports
        # holding and not holding.
        for snapshot_argument in (snap, None):
            _swallow(
                preflight,
                rule,
                snapshot=snapshot_argument,
                capacity=capacity() if room else capacity(required=1000, available=1),
                current_schema=1 if reports_hold else 2,
                target_schema=schema_version,
                binding_holds=reports_hold,
                generation_holds=reports_hold,
                image_digest_holds=reports_hold,
            )

        # A verdict a ledger can legitimately hold, so the spend rules and the
        # completeness rule are reached rather than merely present. Over
        # **`rule`**, because a verdict is spent against the medium its own
        # preflight judged: minted over a fresh quarantine, every ledger call
        # below was refused by that pin before reaching anything it was
        # written for.
        for_the_ledger = preflight(
            rule,
            snapshot=snap,
            capacity=capacity(),
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        )

        # And twice over one medium, because "a second workflow over the same
        # quarantine" is an input dimension too: a payload firing only on the
        # second would see a guard that always builds the first.
        for _sitting in (1, 2):
            flow = RecoveryWorkflow(rule, binding, session_id=SESSION)
            _swallow(
                flow.start,
                snap,
                observations,
                media_binding_holds=True,
                session_id=SESSION,
                started_by_operator=by_operator,
            )
            _swallow(
                flow.open_trial,
                snap,
                observations,
                media_binding_holds=True,
                session_id=SESSION,
            )
            committed += (
                _swallow(
                    flow.commit,
                    snap,
                    observations,
                    media_binding_holds=media_binding,
                    session_id=SESSION,
                    acquisition=Opens(outcome),
                    confirmed=confirmed,
                )
                is not None
            )
            _swallow(
                flow.commit,
                snap,
                observations,
                media_binding_holds=media_binding,
                session_id=SESSION,
                acquisition=Opens(outcome),
                confirmed=confirmed,
            )
            _swallow(flow.audit)
            _swallow(flow.holds, RecoveryCandidate(schema_version, "x"))
            _swallow(repr, flow)
            _swallow(candidate_applies_to, flow, RecoveryCandidate(schema_version, "x"))

            # **The refusal branches, each on a workflow that can still reach
            # it.** A review measured which lines of the module this drive
            # executes and found eleven that neither behavioural guard
            # reached — among them every refusal in `_sealed_assign`, the
            # foreign-sitting rule, the substitution rule, the stage-skip rule
            # and the whole of `MigrationLedger`. A payload on an unexecuted
            # line is judged by the static guards alone, which is how three
            # rounds were lost.
            #
            # The probes were then added **to `flow`**, after the commit above
            # had already made it terminal — so every one of them was answered
            # `workflow_already_finished`, not one reached the rule it names,
            # and the eleven lines stayed unexecuted while the comment said
            # otherwise. A review planted a flag-write on the foreign-sitting
            # branch and left both behavioural guards green. Each probe now
            # gets a workflow in the state its rule lives in, and `reached`
            # counts which rule actually answered: a probe that lands on a
            # different rule from the one it was written for is the
            # incidental-refusal antipattern in the shape of a drive.
            reached[
                _rule_reached(
                    _a_workflow_at(
                        RecoveryStage.NOT_STARTED, rule, binding, snap, observations
                    ).start,
                    snap,
                    observations,
                    media_binding_holds=True,
                    session_id="another-sitting",
                    started_by_operator=by_operator,
                )
            ] += 1
            reached[
                _rule_reached(
                    _a_workflow_at(
                        RecoveryStage.PREFLIGHT_PASSED, rule, binding, snap, observations
                    ).open_trial,
                    descriptor(schema_version=1 if schema_version != 1 else 2),
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                )
            ] += 1
            reached[
                _rule_reached(
                    _a_workflow_at(
                        RecoveryStage.NOT_STARTED, rule, binding, snap, observations
                    ).commit,
                    snap,
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                    acquisition=Opens(outcome),
                    confirmed=confirmed,
                )
            ] += 1
            # The seal's rules, each over a workflow at the stage the rule is
            # about. `("_stage", 0)` used to stand in for the edge graph and
            # died inside the *condition* on `0.value`, one line before the
            # rule — swallowed as an `AttributeError` like any refusal.
            for stage, name, value in (
                (RecoveryStage.NOT_STARTED, "_quarantine", rule),
                (RecoveryStage.NOT_STARTED, "_stage", RecoveryStage.COMMITTED),
                (RecoveryStage.NOT_STARTED, "_stage", RecoveryStage.PREFLIGHT_PASSED),
                (RecoveryStage.PREFLIGHT_PASSED, "_pinned", snap),
                (RecoveryStage.TRIAL_OPEN, "_candidate", RecoveryCandidate(schema_version, "x")),
            ):
                reached[
                    _rule_reached(
                        _a_workflow_at(stage, rule, binding, snap, observations)._sealed_assign,
                        name,
                        value,
                    )
                ] += 1
            reached[
                _rule_reached(flow._sealed_assign, "_stage", RecoveryStage.TRIAL_OPEN)
            ] += 1
            # **Plain assignment**, not `_sealed_assign`. Every probe above
            # calls the seal's one writer directly, so `__setattr__`'s own
            # message — the one a caller actually meets writing `flow.x = y`
            # — was never reached by this drive at all; it only looked
            # reached because its message shared a six-word suffix with
            # `_sealed_assign`'s, before the two were disambiguated.
            reached[_rule_reached(setattr, flow, "_quarantine", rule)] += 1

            # The ledger, over **this** medium. `for_the_ledger` used to be
            # minted over a freshly built quarantine, so the judged-medium pin
            # refused every call before any spend rule ran: the `for _twice`
            # loop that exists to exercise them recorded nothing, ever.
            ledger = MigrationLedger()
            reached[
                _rule_reached(ledger.may_migrate, PreflightVerdict(None), quarantine=rule)
            ] += 1
            for _twice in (1, 2):
                reached[
                    _rule_reached(
                        ledger.note_snapshot_written,
                        PreflightVerdict(None),
                        snap,
                        quarantine=rule,
                    )
                ] += 1
                _swallow(ledger.may_migrate, for_the_ledger, quarantine=rule)
                reached[
                    _rule_reached(
                        ledger.note_snapshot_written, for_the_ledger, snap, quarantine=rule
                    )
                ] += 1
            recorded += len(ledger.audit())
            _swallow(ledger.audit)
            _swallow(repr, ledger)

            reached[_rule_reached(flow.interrupt, session_id="another-sitting")] += 1
            _swallow(
                _a_workflow_at(
                    RecoveryStage.PREFLIGHT_PASSED, rule, binding, snap, observations
                ).interrupt,
                session_id=SESSION,
            )
            _swallow(flow.interrupt, session_id=SESSION)

        drives += 1
        assert _whole_quarantine_state(rule) == before, (
            f"the quarantine moved on schema={schema_version} "
            f"container={container_version} integrity={integrity.value} "
            f"room={room} reports_hold={reports_hold}"
        )
        assert _quarantine_defences_intact(rule) == (True,) * 7
        # The one slot `_whole_quarantine_state` skips, asked rather than
        # assumed: a slot excluded from a state comparison is a slot an
        # attacker may use, unless it cannot hold anything an attacker chose.
        assert _the_weakref_slot_is_not_a_field(rule) is True

    assert drives == 3 * 2 * 3 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * len(AttemptOutcome)
    # **And it reached the thing it guards.** The drive was silently dead on
    # the workflow for as long as `_swallow` caught `TypeError`, so the count
    # is asserted rather than assumed: a guard that never commits says nothing
    # about what a commit does to the quarantine.
    assert committed > 0, "the drive never reached a commit"
    # **And it reached the refusal branches it was written for.** Every one of
    # these was answered `workflow_already_finished` for three rounds, by a
    # workflow the drive had already finished, while the comment above said
    # the eleven unexecuted lines were now executed.
    assert recorded > 0, "the drive never recorded a write"
    for rule_reached in (
        Refusal.NOT_THIS_SITTING,
        Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW,
        Refusal.STAGE_SKIPPED,
        Refusal.WORKFLOW_ALREADY_FINISHED,
        Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT,
        Refusal.VERDICT_ALREADY_SPENT,
        *_SEAL_RULES,
    ):
        assert reached[rule_reached] > 0, rule_reached
    assert not [key for key in reached if isinstance(key, str) and key not in _SEAL_RULES]


def test_this_module_performs_no_io_when_it_actually_runs() -> None:
    """The capability check. The three static guards above are not one.

    A static scan refuses the shapes it has been taught. Round four taught it
    two more — `locals()` at module level *is* the module dict, and CPython
    puts `__builtins__` in it — and the honest reading of three rounds is that
    a per-file AST spelling check cannot establish "this module performs no
    I/O". It also cannot say anything at all about `azazel_boot.quarantine`,
    whose `is_fenced` this module reads on every call: a review put the same
    escape there and the whole suite stayed green.

    So this asks the runtime instead. The workflow is driven end to end under
    `sys.addaudithook`, which cannot be removed once installed, and the hook
    records **every** audited event: `open`, `exec`, `compile`, `import`,
    `socket.*`, `subprocess.*`, `os.*`. The assertion is that the list is
    empty — not that no forbidden name appears, but that no operation
    happened, whatever it was spelled. What this module calls is covered too,
    because the hook is on the interpreter rather than on a file.

    The limit, stated: this covers the paths this drive reaches. It is a
    capability check over an executed path, not a proof about unexecuted ones.
    """

    script = textwrap.dedent(
        """
        import sys

        # **The hook goes on before the module is imported.** It used to be
        # installed after the imports at the top of this script, so everything
        # `azazel_boot.snapshot` did at *import* time was invisible: a review
        # re-exported `pathlib.Path` through a sibling and wrote to the host
        # filesystem from module scope, with this test green. Import reads
        # source files, so a read is expected here; a **write**, a socket, a
        # subprocess or an `exec` is not.
        at_import = []
        sys.addaudithook(lambda event, arguments: at_import.append((event, arguments)))

        from azazel_boot.commissioning import SessionBinding, host_fingerprint
        from azazel_boot.inventory import InterfaceObservation
        from azazel_boot.quarantine import Device, DeviceClass, Quarantine
        from azazel_boot.session_mode import AttemptOutcome, PassphraseChannel
        from azazel_boot.snapshot import (
            CapacityReport,
            MigrationLedger,
            PreflightVerdict,
            RecoveryCandidate,
            RecoveryRefused,
            RecoveryStage,
            RecoveryWorkflow,
            SnapshotDescriptor,
            SnapshotIntegrity,
            candidate_applies_to,
            preflight,
            schema_is_compatible,
            verdict_was_minted_here,
        )

        SESSION = "session-0001"
        MEDIUM = Device(identity="usb-SN-0001", device_class=DeviceClass.BOOT_MEDIUM)
        observations = (
            InterfaceObservation(interface_key="en-0001", permanent_mac="02:00:00:00:00:01"),
            InterfaceObservation(interface_key="en-0002", permanent_mac="02:00:00:00:00:02"),
        )

        class Opens:
            channel = PassphraseChannel.LOCAL_HIDDEN_PROMPT

            def attempt(self):
                return AttemptOutcome.OPENED

        def build(*, quarantined=True, fenced=False):
            rule = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
            rule.observe(MEDIUM)
            rule.observe(Device(identity="host-nvme-SN-1", device_class=DeviceClass.HOST_STORAGE))
            if quarantined:
                rule.quarantine_volume()
            if fenced:
                rule.fence()
            return rule

        # An **allowlist**, of what the interpreter's own import machinery
        # does: read a file, compile it, exec it, and the bookkeeping around
        # that. Bytecode writing is off (`PYTHONDONTWRITEBYTECODE`), so no
        # write-mode `open` and no `os.rename` belong here either. Anything
        # else — a write, a socket, a subprocess — is the module acting, and
        # is what this refuses. If a future interpreter adds an event, this
        # goes red and is widened deliberately, which is the point of a list
        # of what is permitted rather than a list of what is not.
        MACHINERY = {
            "compile",
            "exec",
            "import",
            "marshal.dumps",
            "marshal.loads",
            "object.__getattr__",
            "object.__setattr__",
            "os.listdir",
            "sys._getframe",
            "sys._getframemodulename",
            "builtins.id",
        }
        forbidden_at_import = [
            (event, arguments)
            for event, arguments in at_import
            if event not in MACHINERY
            and not (event == "open" and (arguments[1] or "r") in ("r", "rb"))
        ]

        binding = SessionBinding(
            host_fingerprint=host_fingerprint(observations), session_id=SESSION
        )
        snapshots = [
            SnapshotDescriptor(1, version, integrity, f"fingerprint-{version}")
            for version in (1, 2)
            for integrity in SnapshotIntegrity
        ]
        # **All four flag states.** A `fenced = build(); fenced.fence()` used
        # to sit here and was never handed to anything, so `is_fenced` answered
        # `False` on every read under the hook and `volume_is_quarantined`
        # answered `True` on every read. A review put the escape back on each
        # of the two unreached branches — in `azazel_boot.quarantine`, which
        # this module reads on every gate — and the suite stayed green both
        # times, writing a boot-medium identity to the host disk during the
        # run. A dead variable is not coverage.
        prepared = [
            (build(quarantined=quarantined, fenced=fenced), snapshot)
            for snapshot in snapshots
            for quarantined in (True, False)
            for fenced in (False, True)
        ]

        reached = []

        def probe(call, *args, **keywords):
            # Drive a refusal probe and record **which rule** answered.
            try:
                call(*args, **keywords)
            except RecoveryRefused as refused:
                reached.append(refused.refusal.value)
            except AttributeError as refused:
                reached.append(str(refused))

        def at(stage, rule, snapshot):
            # A fresh workflow as far as `stage`, for one refusal probe.
            flow = RecoveryWorkflow(rule, binding, session_id=SESSION)
            if stage == "not_started":
                return flow
            try:
                flow.start(
                    snapshot,
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                    started_by_operator=True,
                )
                if stage == "preflight_passed":
                    return flow
                flow.open_trial(
                    snapshot, observations, media_binding_holds=True, session_id=SESSION
                )
            except RecoveryRefused:
                pass
            return flow

        seen = []
        sys.addaudithook(lambda event, arguments: seen.append(event))

        for index, (rule, snapshot) in enumerate(prepared):
            # **Varied, not fixed.** These arguments were all held at their
            # passing values, so any branch gated on them never ran under the
            # hook — and a review put a host-disk write on the binding branch,
            # which other tests in this file *do* take, without a hook. The
            # guard's fixed arguments were a published list of where to hide.
            holds = index % 2 == 0
            for offered in (snapshot, None):
                preflight(
                    rule,
                    snapshot=offered,
                    capacity=CapacityReport(required=100, available=1000)
                    if holds
                    else CapacityReport(required=1000, available=1),
                    current_schema=1 if holds else 2,
                    target_schema=snapshot.schema_version,
                    binding_holds=holds,
                    generation_holds=holds,
                    image_digest_holds=holds,
                )
            verdict = preflight(
                rule,
                snapshot=snapshot,
                capacity=CapacityReport(required=100, available=1000),
                current_schema=1,
                target_schema=snapshot.schema_version,
                binding_holds=True,
                generation_holds=True,
                image_digest_holds=True,
            )
            verdict_was_minted_here(verdict)
            schema_is_compatible(current=1, target=snapshot.schema_version)
            ledger = MigrationLedger()
            try:
                ledger.may_migrate(verdict, quarantine=rule)
                ledger.note_snapshot_written(verdict, snapshot, quarantine=rule)
            except Exception:
                pass
            repr(verdict)
            repr(snapshot)

            flow = RecoveryWorkflow(rule, binding, session_id=SESSION)
            for act in (
                lambda: flow.start(
                    snapshot,
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                    started_by_operator=True,
                ),
                lambda: flow.open_trial(
                    snapshot,
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                ),
                lambda: flow.commit(
                    snapshot,
                    observations,
                    media_binding_holds=True, session_id=SESSION,
                    acquisition=Opens(),
                    confirmed=True,
                ),
                lambda: repr(flow.audit()),
                lambda: candidate_applies_to(flow, flow._candidate),
            ):
                try:
                    act()
                except (RecoveryRefused, AttributeError, TypeError):
                    # A refusal is the point. **`NameError` is not caught**: two
                    # probes here named `PreflightVerdict`, which the script did
                    # not import, and `except Exception` swallowed both — so
                    # they never ran and nothing said so.
                    pass

            # **The refusal branches, each on a workflow that can reach it.**
            # These used to run on `flow`, after the three stages above had
            # already made it terminal, so every one of them was answered
            # `workflow_already_finished` and the eleven lines a review found
            # unexecuted stayed unexecuted — under the guard whose whole job
            # is to run the module for real. `reached` is printed back and
            # asserted, so a probe that lands on a different rule from the one
            # it was written for is a red test rather than a green one.
            probe(
                at("not_started", rule, snapshot).start,
                snapshot,
                observations,
                media_binding_holds=True,
                session_id="elsewhere",
                started_by_operator=True,
            )
            probe(
                at("preflight_passed", rule, snapshot).open_trial,
                SnapshotDescriptor(1, 2, SnapshotIntegrity.VERIFIED, "other"),
                observations,
                media_binding_holds=True,
                session_id=SESSION,
            )
            probe(
                at("not_started", rule, snapshot).commit,
                snapshot,
                observations,
                media_binding_holds=True,
                session_id=SESSION,
                acquisition=Opens(),
                confirmed=True,
            )
            # `("_stage", 0)` stood in for the edge graph and died inside the
            # *condition*, on `0.value`, one line before the rule — and was
            # swallowed as an `AttributeError` like any refusal.
            for stage, name, value in (
                ("not_started", "_quarantine", rule),
                ("not_started", "_stage", RecoveryStage.COMMITTED),
                ("not_started", "_stage", RecoveryStage.PREFLIGHT_PASSED),
                ("preflight_passed", "_pinned", snapshot),
                ("trial_open", "_candidate", RecoveryCandidate(2, "other")),
            ):
                probe(at(stage, rule, snapshot)._sealed_assign, name, value)
            probe(flow._sealed_assign, "_stage", RecoveryStage.TRIAL_OPEN)
            # Plain assignment, so `__setattr__`'s own message is reached
            # here too, not only `_sealed_assign`'s.
            probe(setattr, flow, "_quarantine", rule)

            probe(ledger.may_migrate, PreflightVerdict(None), quarantine=rule)
            probe(
                ledger.note_snapshot_written,
                PreflightVerdict(None),
                snapshot,
                quarantine=rule,
            )
            probe(ledger.note_snapshot_written, verdict, snapshot, quarantine=rule)
            probe(ledger.note_snapshot_written, verdict, snapshot, quarantine=rule)
            probe(flow.interrupt, session_id="elsewhere")
            probe(at("preflight_passed", rule, snapshot).interrupt, session_id=SESSION)
            probe(flow.interrupt, session_id=SESSION)

        print(
            repr(
                [
                    sorted(set(seen)),
                    [event for event, _ in forbidden_at_import],
                    sorted(set(reached)),
                ]
            )
        )
        """
    )

    finished = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=MODULE.parents[2],
        env={
            **os.environ,
            "PYTHONPATH": str(MODULE.parents[2] / "src"),
            # So the import machinery writes no bytecode: a `.pyc` write is an
            # `os.rename` and a write-mode `open`, and neither is this module.
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        timeout=120,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr
    while_running, at_import, reached = ast.literal_eval(finished.stdout.strip())
    # `builtins.id` is the one audited runtime operation this module now
    # performs, from `_WeakIdentityIndex`'s own lookup: `id(obj)` returns an
    # opaque integer with no path back to the object, unlike every other
    # audited event this hook would catch (`open`, `socket.*`,
    # `subprocess.*`, `os.*`), and PEP 578 audits it purely because it can be
    # used *alongside* other introspection to correlate objects — not
    # because it touches a device, a network or a process on its own.
    # Anything else audited is still refused outright.
    runtime_allowed = {"builtins.id"}
    unexpected_while_running = [event for event in while_running if event not in runtime_allowed]
    assert unexpected_while_running == [], (
        f"the decision path performed audited operations: {unexpected_while_running}"
    )
    assert at_import == [], f"the module performed audited operations while importing: {at_import}"

    # **And the drive reached the refusal branches it claims to.** Every probe
    # in the script used to run against a workflow the drive had already
    # finished, so all of them were answered `workflow_already_finished` and
    # the lines they name never ran under the hook — a payload on any of them
    # was judged by the static guards alone. This is a capability check over an
    # executed path, so which path it executed is part of the assertion.
    for rule in (
        Refusal.NOT_THIS_SITTING.value,
        Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW.value,
        Refusal.STAGE_SKIPPED.value,
        Refusal.WORKFLOW_ALREADY_FINISHED.value,
        Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT.value,
        Refusal.VERDICT_ALREADY_SPENT.value,
        *_SEAL_RULES,
    ):
        assert [answer for answer in reached if rule in answer], rule


# --------------------------------------------------------------------------
# The fourth review's findings on the gates and the verdict
# --------------------------------------------------------------------------


def _preflight_failing_from(position: int, **overrides):
    """Every gate from `position` onwards failing at once.

    The earliest one is the answer the contract promises, and a reordering is
    exactly what changes that answer without changing which inputs pass.
    """

    knobs = {
        "fenced": position <= 1,
        "quarantined": position <= 2,
        "absent": position <= 3,
        "container": position <= 4,
        "integrity": position <= 5,
        "space": position <= 6,
        "schema": position <= 7,
        "binding": position <= 8,
        "generation": position <= 9,
        "digest": position <= 10,
    }
    knobs.update(overrides)
    snapshot = (
        None
        if knobs["absent"]
        else descriptor(
            container_version=2 if knobs["container"] else 1,
            integrity=(
                SnapshotIntegrity.FAILED if knobs["integrity"] else SnapshotIntegrity.VERIFIED
            ),
        )
    )
    return preflight(
        a_quarantine(fenced=knobs["fenced"], quarantined=knobs["quarantined"]),
        snapshot=snapshot,
        capacity=capacity(required=1000, available=1) if knobs["space"] else capacity(),
        current_schema=1,
        target_schema=99 if knobs["schema"] else 2,
        binding_holds=not knobs["binding"],
        generation_holds=not knobs["generation"],
        image_digest_holds=not knobs["digest"],
    )


@pytest.mark.parametrize("position", range(1, 11))
def test_the_earliest_failing_gate_is_the_one_an_operator_is_told(position) -> None:
    """R4: the ten-gate order was held up by prose, and a review permuted it.

    Eight of nine adjacent swaps and six of seven demotions-to-last kept the
    whole suite green. No bad input passed — `preflight` short-circuits, so a
    permutation cannot change the *set* that passes — but the classification
    changed, and the classification is what ADR-0010 D7 promises. The worst
    case: an operator whose medium had been **pulled** was told
    `volume_quarantined`, a state a recovery exists for, instead of
    `medium_fenced`.

    The suite had two ordering assertions for a ten-element ordered contract,
    and one of them never contested its own neighbour. So every gate is now
    driven against **all** of its successors failing at once.
    """

    verdict = _preflight_failing_from(position)
    expected = PREFLIGHT_ORDER[position - 1]
    assert verdict.refused_by is expected
    assert verdict.evaluated == PREFLIGHT_ORDER[:position]


def test_a_passing_verdict_names_every_check_it_was_asked() -> None:
    """R4: "not evaluated" and "passed" were the same answer.

    A verdict was `refused_by is None` and nothing else, so one from a
    `preflight` that ran three gates was indistinguishable from one that ran
    all ten — by repr, by `refused_by`, by `may_migrate`, by the whole public
    surface. That is the structural reason the order could be permuted with the
    suite green: the gate set lived in test parametrisation, and neither the
    ledger nor the audit could notice a gate that had stopped running.

    Completeness, in the sense `Azazel-Knowledge`'s scorer means it: what
    passed is named as well as what refused.
    """

    passing = preflight(
        a_quarantine(quarantined=False),
        snapshot=descriptor(),
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert passing.may_migrate is True
    assert passing.evaluated == PREFLIGHT_ORDER
    assert set(PREFLIGHT_ORDER) == set(PreflightCheck)
    assert len(PREFLIGHT_ORDER) == len(PreflightCheck)


def test_a_verdict_is_fixed_when_it_is_minted() -> None:
    """R4: the two defences the whole claim rests on had no test at all.

    `__setattr__` and `__reduce__` could both be deleted with the suite green,
    and with `__setattr__` gone two plain assignments —
    `verdict._refused_by = None` — turned a genuine refusal over a
    failed-integrity snapshot into a passing verdict that
    `verdict_was_minted_here` **correctly** accepts, because it really was
    minted. No `object.__setattr__`, no private import, no forgery.

    `tests/unit/test_snapshot.py` already asserted exactly this on
    `RecoveryCandidate`, with a comment naming the incidental-refusal pattern
    this repository has now hit four times. It was never mirrored onto the
    object that gates the migration.
    """

    assert PreflightVerdict.__setattr__ is not object.__setattr__
    assert PreflightVerdict.__reduce__ is not object.__reduce__

    verdict = preflight(
        a_quarantine(quarantined=False),
        snapshot=descriptor(integrity=SnapshotIntegrity.FAILED),
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict.refused_by is PreflightCheck.SNAPSHOT_INTEGRITY

    for name in ("_refused_by", "_snapshot", "_evaluated", "refused_by"):
        with pytest.raises(AttributeError, match="fixed when it is minted"):
            setattr(verdict, name, None)
    with pytest.raises(TypeError, match="not serialisable"):
        pickle.dumps(verdict)
    with pytest.raises(TypeError, match="not serialisable"):
        copy.deepcopy(verdict)
    with pytest.raises(TypeError, match="not serialisable"):
        copy.copy(verdict)
    assert verdict.may_migrate is False
    assert verdict.refused_by is PreflightCheck.SNAPSHOT_INTEGRITY


def test_the_write_record_asks_whether_the_verdict_was_minted() -> None:
    """R4: the clause had no test that could fail for its own reason.

    `test_a_hand_built_verdict_does_not_authorise_a_migration` looks like it
    covers this, and does not: a hand-built verdict's `_snapshot` is always
    `None`, so the identity tie answers first and the mint check is never the
    reason. Deleting the mint check left the suite green while a verdict that
    was never minted recorded `SNAPSHOT_WRITTEN` against a failed-integrity
    snapshot.

    So: a verdict of the exact type, never minted, whose `_snapshot` **is** the
    one presented. Then only the mint check can refuse it.
    """

    snapshot = descriptor(integrity=SnapshotIntegrity.FAILED)
    never_minted = PreflightVerdict(None)
    object.__setattr__(never_minted, "_snapshot", snapshot)

    assert type(never_minted) is PreflightVerdict
    assert never_minted.may_migrate is True
    assert never_minted._snapshot is snapshot
    assert verdict_was_minted_here(never_minted) is False

    ledger = MigrationLedger()
    with pytest.raises(RecoveryRefused) as refused:
        ledger.note_snapshot_written(
            never_minted,
            snapshot,
            quarantine=a_quarantine(quarantined=False),
        )
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT
    assert ledger.audit() == ()


def test_two_real_threads_preflighting_the_same_medium_both_stay_judged() -> None:
    """R19 (security/doctrine review, finding 2): `_remember_the_medium`'s
    own unlocked check-then-record, the sibling of `note_snapshot_written`'s.

    `preflight()` is documented as "free, read-only and unlimited" — an
    explicit invitation to call it as often and as concurrently as a caller
    likes. Two real threads doing exactly that over the *same* `Quarantine`,
    the first time it is judged, could each see `_JUDGED_BY.get(quarantine)
    is None`, each build their own fresh `_WeakSet`, and each write it — the
    second write silently discarding the first thread's set, and the
    verdict it held, from `_JUDGED_BY`. `_MINTED_HERE` still answers for the
    dropped verdict (a different index, unaffected), so
    `verdict_was_minted_here` stays `True` for it, but `_medium_was_judged`
    then answers `False` for a verdict that genuinely did judge exactly this
    medium — and `may_migrate`/`note_snapshot_written` refuse it with
    `MEDIUM_MOVED_SINCE_THE_PREFLIGHT`, a classification that is simply
    false. Fails closed (a legitimate migration is wrongly refused, never
    wrongly permitted), but still a real misclassification, fixed the same
    way `_SNAPSHOTS_RECORDED`'s check-then-record was: one lock,
    `_JUDGED_LOCK`.

    `_WeakIdentityIndex.get` (a class method — instances hold no writable
    slot of their own to monkeypatch, `__slots__ = ("__weakref__",)`) is
    patched to pause **each** thread's first call through it until both
    have arrived, then release together — so both observe `None` and both
    proceed to write, deterministically, rather than leaving it to chance
    whether the GIL ever switches between two threads inside a lookup this
    short.
    """

    import azazel_boot.snapshot as module

    quarantine = a_quarantine(quarantined=False)
    snap = descriptor()

    arrived = {"a": threading.Event(), "b": threading.Event()}
    release = threading.Event()
    label_of = threading.local()
    original_get = module._WeakIdentityIndex.get

    def racy_get(self, obj: object) -> object | None:
        result = original_get(self, obj)
        label = getattr(label_of, "label", None)
        if label is not None and not arrived[label].is_set():
            arrived[label].set()
            release.wait(timeout=30)
        return result

    module._WeakIdentityIndex.get = racy_get
    outcomes: dict[str, dict[str, object]] = {}

    def do_preflight(label: str) -> None:
        label_of.label = label
        outcomes[label] = {}
        verdict = preflight(
            quarantine,
            snapshot=snap,
            capacity=capacity(),
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        )
        outcomes[label]["verdict"] = verdict

    # **Not a hard assertion on `arrived["b"]`, and this is deliberate** —
    # see the identical note and its full reasoning in
    # `test_two_real_threads_recording_the_same_write_record_it_once`.
    # `_remember_the_medium` holds `_JUDGED_LOCK` across this exact same
    # `racy_get` pause, so under the correct, locked implementation "b"
    # cannot reach this checkpoint while "a" is paused there, full stop —
    # a round-29 investigation found this test was passing only by
    # consistently winning a coin-flip race between two independent
    # ~30-second timers (confirmed: every isolated run still took the
    # full ~30s despite "passing"), the identical latent flaw its sibling
    # test lost consistently. "b" gets a short, generous grace period to
    # reach the checkpoint on its own (all the mutated/lock-removed code
    # under test needs, since nothing blocks it there in that case), and
    # `release` fires unconditionally afterward so a correctly-locked "a"
    # is never held hostage waiting for a "b" that cannot arrive.
    try:
        a_thread = threading.Thread(target=do_preflight, args=("a",))
        a_thread.start()
        assert arrived["a"].wait(timeout=30)
        b_thread = threading.Thread(target=do_preflight, args=("b",))
        b_thread.start()
        arrived["b"].wait(timeout=2)
        release.set()
        a_thread.join(timeout=30)
        b_thread.join(timeout=30)
    finally:
        module._WeakIdentityIndex.get = original_get

    verdict_a = outcomes["a"]["verdict"]
    verdict_b = outcomes["b"]["verdict"]
    assert verdict_was_minted_here(verdict_a)
    assert verdict_was_minted_here(verdict_b)
    # The actual claim: **both** verdicts judged this medium, not just
    # whichever one's write survived the race.
    assert module._medium_was_judged(verdict_a, quarantine)
    assert module._medium_was_judged(verdict_b, quarantine)

    for verdict in (verdict_a, verdict_b):
        ledger = MigrationLedger()
        assert ledger.may_migrate(verdict, quarantine=quarantine) is True


def test_the_judged_lock_never_releases_between_the_read_and_the_record() -> None:
    """R30 (test-suite review): the sibling gap, for `_JUDGED_LOCK`. R31
    (doctrine review): round 30's first attempt did not reach far enough
    here either — see the full account in `test_the_write_lock_never_
    releases_between_the_read_and_the_record`, which this mirrors exactly.

    Same finding as that test, for the sibling lock: the two-thread race
    test above proves a full removal of `_JUDGED_LOCK` is caught, but a
    narrower mutant that releases it right after `_JUDGED_BY.get(quarantine)`
    and lets `_JUDGED_BY[quarantine] = judged` / `judged.add(verdict)` run
    unprotected reopens the identical race one or two statements later, and
    the race test's own thread "b" stays blocked on the (still-present,
    just narrower) lock for its whole grace period, never interleaving with
    "a"'s now-unprotected tail. Round 30's original version hooked
    `_WeakIdentityIndex.__setitem__` as its "write" checkpoint — which
    fires at `_JUDGED_BY[quarantine] = judged`, *before* `judged.add(verdict)`
    — so it never observed whether the verdict was actually recorded into
    the set, only whether the (still-empty) set had been registered. Asked
    directly instead, the same way its sibling now is: patch
    `_CountingRLock.release` — called exactly once, synchronously, at the
    moment `_JUDGED_LOCK`'s `with` block exits — and check, before
    forwarding to the real release, whether this quarantine's judged-set
    already has a member. A fresh quarantine (never preflighted before
    this call) makes the check exact: nothing else in this process could
    have populated it first.
    """

    import azazel_boot.snapshot as module

    quarantine = a_quarantine(quarantined=False)
    snap = descriptor()

    counting_lock = _CountingRLock()
    original_lock = module._JUDGED_LOCK
    original_release = counting_lock.release
    original_get = module._WeakIdentityIndex.get
    write_landed_by_first_release: list[bool] = []

    def checking_release() -> None:
        if not write_landed_by_first_release:
            judged = original_get(module._JUDGED_BY, quarantine)
            write_landed_by_first_release.append(judged is not None and len(judged) >= 1)
        original_release()

    counting_lock.release = checking_release
    module._JUDGED_LOCK = counting_lock
    try:
        preflight(
            quarantine,
            snapshot=snap,
            capacity=capacity(),
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        )
    finally:
        module._JUDGED_LOCK = original_lock

    # The actual claim: by the moment `_JUDGED_LOCK` is first released, the
    # verdict this call minted has already been recorded against this
    # medium — not merely that the medium's index entry exists (round 30's
    # gap), the set membership itself.
    assert write_landed_by_first_release == [True]
    assert counting_lock.full_release_count == 1


def test_one_preflight_records_one_write_in_any_ledger() -> None:
    """R4: nothing marked a verdict spent.

    One `preflight` over one snapshot produced four `SNAPSHOT_WRITTEN`
    classifications across two ledgers. For an audit whose only positive
    classification is "a snapshot was written", n records for one judged write
    is a false count — and the second ledger is not a second write, which is
    why the spent-ness is kept module-side rather than per-ledger.
    """

    judged_medium = a_quarantine(quarantined=False)

    snapshot = descriptor(fingerprint="snapshot-fingerprint-any-ledger")
    verdict = preflight(
        judged_medium,
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    first, second = MigrationLedger(), MigrationLedger()
    first.note_snapshot_written(verdict, snapshot, quarantine=judged_medium)
    assert len(first.audit()) == 1

    for ledger in (first, second):
        with pytest.raises(RecoveryRefused) as refused:
            ledger.note_snapshot_written(
                verdict,
                snapshot,
                quarantine=judged_medium,
            )
        assert refused.value.refusal is Refusal.VERDICT_ALREADY_SPENT
    assert len(first.audit()) == 1
    assert second.audit() == ()


def test_two_real_threads_recording_the_same_write_record_it_once() -> None:
    """R18 (security review, finding 1): a genuine TOCTOU, not a race in
    which exception type escapes.

    `note_snapshot_written` used to call two separate module functions,
    `_a_write_is_recorded` then `_remember_a_write`, with nothing between
    them but ordinary statements. Two real threads racing this call for the
    same verdict, the same medium and the same judged snapshot both reached
    the check before either reached the write, both saw "not yet recorded",
    and both recorded — two `SNAPSHOT_WRITTEN` entries for one preflight
    authorization, contradicting this method's own "once".

    R20 (test-suite review): a `threading.Barrier` synchronizing only the
    top of `do_record` — before `MigrationLedger()` construction and before
    `note_snapshot_written`'s several preceding checks
    (`verdict_was_minted_here`, `_require_the_medium_now`,
    `_require_every_gate_was_asked`, `_JUDGED_FIELDS.get`) — does not
    reliably synchronize the two threads at the actual check-then-record
    line inside `_remember_a_write_if_new`: by the time either thread gets
    there, ordinary scheduling has desynchronized them enough that the
    protective lock's absence is never observed. Measured: 0/50 failures
    against `_WRITE_LOCK` fully removed. Redesigned the same way
    `test_two_real_threads_preflighting_the_same_medium_both_stay_judged`
    already forces its own rendezvous: `_WeakIdentityIndex.get` (a class
    method — instances hold no writable slot to monkeypatch,
    `__slots__ = ("__weakref__",)`) is patched to pause **each** thread's
    first call through it *for `_SNAPSHOTS_RECORDED` specifically* — gated
    on `self is module._SNAPSHOTS_RECORDED`, not the bare fact of being
    called, because `note_snapshot_written` reaches `_JUDGED_BY.get(...)`
    first, via `_require_the_medium_now`, and pausing on that unrelated
    lookup instead misses the actual vulnerable line just as reliably as
    the `Barrier` did. Both threads pause at the right call and are
    released together, deterministically.
    """

    import azazel_boot.snapshot as module

    judged_medium = a_quarantine(quarantined=False)
    snapshot = descriptor(fingerprint="snapshot-fingerprint-race")
    verdict = preflight(
        judged_medium,
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )

    arrived = {"a": threading.Event(), "b": threading.Event()}
    release = threading.Event()
    label_of = threading.local()
    original_get = module._WeakIdentityIndex.get

    def racy_get(self, obj: object) -> object | None:
        result = original_get(self, obj)
        label = getattr(label_of, "label", None)
        if label is not None and self is module._SNAPSHOTS_RECORDED and not arrived[label].is_set():
            arrived[label].set()
            release.wait(timeout=30)
        return result

    module._WeakIdentityIndex.get = racy_get
    outcomes: dict[str, dict[str, object]] = {}

    def do_record(label: str) -> None:
        label_of.label = label
        outcomes[label] = {}
        ledger = MigrationLedger()
        try:
            ledger.note_snapshot_written(verdict, snapshot, quarantine=judged_medium)
            outcomes[label]["kind"] = "recorded"
            outcomes[label]["ledger"] = ledger
        except RecoveryRefused as refused:
            outcomes[label]["kind"] = "refused"
            outcomes[label]["refusal"] = refused.refusal

    # **Not a hard assertion on `arrived["b"]`, and this is deliberate.**
    # `_remember_a_write_if_new` holds `_WRITE_LOCK` for the entire span
    # `racy_get`'s pause sits inside, so under the *correct*, locked
    # implementation thread "b" cannot reach this checkpoint at all while
    # "a" is paused there — it blocks acquiring the same lock "a" already
    # holds, full stop, no amount of waiting changes that. A round-29
    # follow-up investigation found the previous `assert
    # arrived["b"].wait(timeout=30)` here made this test structurally
    # racy against its *own* correct-code path: "a" only ever gives up
    # its pause via its own internal 30s timeout (nothing else can reach
    # `release.set()`), and whether "b" then reaches `arrived["b"]`
    # before *this* thread's independent 30s deadline expires came down
    # to which of two ~30-second timers, started microseconds apart,
    # fired first — a coin flip that this environment was found to lose
    # consistently (3/3 isolated runs), not occasional background-load
    # flakiness. `b` is given a short, generous grace period to reach the
    # checkpoint on its own — which is all the *mutated* (lock-removed)
    # code being probed for needs, since nothing blocks it there in that
    # case — and `release` is set unconditionally afterward either way,
    # so a correctly-locked "a" is never held hostage waiting for a "b"
    # that cannot arrive. Correctness is verified below by the outcome
    # (exactly one recorded, one refused), not by whether the rendezvous
    # itself completed.
    try:
        a_thread = threading.Thread(target=do_record, args=("a",))
        a_thread.start()
        assert arrived["a"].wait(timeout=30)
        b_thread = threading.Thread(target=do_record, args=("b",))
        b_thread.start()
        arrived["b"].wait(timeout=2)
        release.set()
        a_thread.join(timeout=30)
        b_thread.join(timeout=30)
    finally:
        module._WeakIdentityIndex.get = original_get

    kinds = sorted(outcome["kind"] for outcome in outcomes.values())
    assert kinds == ["recorded", "refused"], outcomes
    refused = next(outcome for outcome in outcomes.values() if outcome["kind"] == "refused")
    assert refused["refusal"] is Refusal.VERDICT_ALREADY_SPENT
    recorded = next(outcome for outcome in outcomes.values() if outcome["kind"] == "recorded")
    assert len(recorded["ledger"].audit()) == 1


def test_the_write_lock_never_releases_between_the_read_and_the_record() -> None:
    """R30 (test-suite review): a coverage gap the two-thread race test
    above could not see. R31 (doctrine review): round 30's own first
    attempt at closing it did not actually reach far enough.

    `test_two_real_threads_recording_the_same_write_record_it_once` proves
    a full removal of `_WRITE_LOCK` is caught — but a *narrower* mutant,
    one that keeps `_WRITE_LOCK` around only the `.get()` read and
    releases it before the `if written is None: ...`/`.append(...)` write
    that follows, reopens the identical TOCTOU one statement later and
    passed that race test 10/10 times: thread "b" stays blocked acquiring
    the (still-present, just narrower) lock for the whole grace period and
    never gets a chance to interleave with "a"'s now-unprotected tail, so
    the outcome-based assertion never sees the difference — exactly the
    class of gap `test_commits_candidate_and_stage_writes_share_one_
    uninterrupted_lock_hold` already closed once for `RecoveryWorkflow._lock`
    (round 21), never extended to this module-level lock.

    Round 30's first version of this test hooked `_WeakIdentityIndex.
    __setitem__` as its "write" checkpoint — but `__setitem__` only fires
    on this medium's *first-ever* write, at `_SNAPSHOTS_RECORDED[quarantine]
    = written`, which happens *before* `written.append(fields)` — the
    actual mutation this lock exists to protect. A round-31 doctrine
    review pointed out that checkpoint therefore never observed the append
    at all, and a hand-built mutant that left exactly that line unprotected
    (identical in shape to the one above) passed the "fixed" test
    undetected. `list.append` cannot be patched per-instance the way
    `_WeakIdentityIndex`'s methods can (`list` accepts no such override),
    so this asks a different, more direct question instead: patch
    `_CountingRLock.release` itself — called exactly once, synchronously,
    at the moment (and only the moment) `_WRITE_LOCK`'s `with` block exits
    — and check, *before* forwarding to the real release, whether
    `_SNAPSHOTS_RECORDED` already reflects the completed write. Under the
    correct implementation the append has already happened by the time
    release is even called, because both are inside the same unbroken
    hold; under either shape of narrowed-lock mutant, release fires before
    the append ever runs, and the check catches it looking at the state
    directly rather than counting releases around a proxy event.
    """

    import azazel_boot.snapshot as module

    quarantine = a_quarantine(quarantined=False)
    snapshot = descriptor(fingerprint="snapshot-fingerprint-structural")
    verdict = preflight(
        quarantine,
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    fields = _fields_of(snapshot)

    counting_lock = _CountingRLock()
    original_lock = module._WRITE_LOCK
    original_release = counting_lock.release
    original_get = module._WeakIdentityIndex.get
    write_landed_by_first_release: list[bool] = []

    def checking_release() -> None:
        if not write_landed_by_first_release:
            written = original_get(module._SNAPSHOTS_RECORDED, quarantine)
            write_landed_by_first_release.append(
                written is not None and fields in written
            )
        original_release()

    counting_lock.release = checking_release
    module._WRITE_LOCK = counting_lock
    try:
        ledger = MigrationLedger()
        ledger.note_snapshot_written(verdict, snapshot, quarantine=quarantine)
    finally:
        module._WRITE_LOCK = original_lock

    # The actual claim: by the moment `_WRITE_LOCK` is first released, the
    # write this call was making has already landed — not merely that the
    # medium's index entry exists (round 30's gap), the recorded fields
    # themselves.
    assert write_landed_by_first_release == [True]
    assert counting_lock.full_release_count == 1


def test_the_write_record_asks_whether_the_verdict_passed() -> None:
    """R4: the `may_migrate` clause had nothing that could fail for its reason.

    Deleting it left the suite green, because a refusal mints with
    `_snapshot=None` and the identity tie answered first — so the clause is
    unreachable through `preflight` today, and is the kind a later tidy-up
    removes as dead. What it guards against is `_mint` one day carrying the
    snapshot on refusals too, at which point a *refused* verdict would name the
    snapshot it refused and the tie would no longer answer.

    So it is driven against exactly that shape: a genuinely minted **refusal**
    that names the presented snapshot. Only this clause can refuse it.
    """

    judged_medium = a_quarantine(quarantined=False)

    snapshot = descriptor(integrity=SnapshotIntegrity.FAILED)
    refused_verdict = preflight(
        judged_medium,
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    object.__setattr__(refused_verdict, "_snapshot", snapshot)

    assert verdict_was_minted_here(refused_verdict) is True
    assert refused_verdict._snapshot is snapshot
    assert refused_verdict.may_migrate is False

    ledger = MigrationLedger()
    with pytest.raises(RecoveryRefused) as refused:
        ledger.note_snapshot_written(
            refused_verdict,
            snapshot,
            quarantine=judged_medium,
        )
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT
    assert ledger.audit() == ()


# --------------------------------------------------------------------------
# The fifth review: the seam between this module and the rest of the package
# --------------------------------------------------------------------------


def test_a_recovery_refuses_a_medium_the_quarantine_never_saw(observations) -> None:
    """R5: D8 gate 1 is about the **target**, and it asked about the host.

    `RecoveryGate.TARGET_BINDING` called `commissioning.binding_applies`, which
    compares a host fingerprint and a sitting. A review committed a whole
    recovery over a quarantine that had **never observed any device**, and over
    two different media identities in turn, because nothing in the workflow
    ever asked what it was recovering. The audit said `recovery_completed` with
    a schema version and a fingerprint, for a volume the module could not name.

    The quarantine is asked through its own question — `medium_is_bound()`,
    which is also `False` after a fence — so no device identity crosses into
    this module to ask it.
    """

    blind = _a_quarantine_that_never_saw_the_medium()
    assert blind.medium_is_bound() is False
    assert blind.volume_is_quarantined is True

    flow = workflow(observations, quarantine=blind)
    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.MEDIUM_NOT_RECOGNISED
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.holds(RecoveryCandidate(1, FINGERPRINT)) is False


def test_a_recovery_refuses_a_quarantine_from_another_sitting(observations) -> None:
    """R5: the module type-checked all three and compared none of them.

    `PersistenceSession` refuses the identical pairing with
    `QUARANTINE_FROM_ANOTHER_SESSION`; this workflow committed. Combined with
    the gate above it meant neither the medium nor the sitting the quarantine
    belongs to constrained a recovery.
    """

    elsewhere = Quarantine(session_id="another-sitting", boot_medium_identity=MEDIUM.identity)
    elsewhere.observe(MEDIUM)
    elsewhere.quarantine_volume()
    assert elsewhere.medium_is_bound() is True

    flow = workflow(observations, quarantine=elsewhere)
    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.MEDIUM_NOT_RECOGNISED


def test_a_verdict_is_not_a_permission_that_outlives_what_it_judged() -> None:
    """R5: the fence is `PREFLIGHT_ORDER[0]`, and only at the time of check.

    A verdict has no session, no medium, no boot and no clock. A review minted
    one over a healthy volume, then fenced the medium **and** quarantined the
    volume, and the ledger still answered `may_migrate` and recorded a write —
    a durable, transferable bearer token for a large write to a volume since
    judged torn, which is what ADR-0010 D9 refuses under the name of an
    upgrade. `RecoveryWorkflow` re-reads its gates three times for this reason;
    the migration path re-read nothing.
    """

    medium = a_quarantine(quarantined=False)
    snapshot = descriptor()
    verdict = preflight(
        medium,
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    ledger = MigrationLedger()
    assert ledger.may_migrate(verdict, quarantine=medium) is True

    medium.quarantine_volume()
    for act in (
        lambda: ledger.may_migrate(verdict, quarantine=medium),
        lambda: ledger.note_snapshot_written(verdict, snapshot, quarantine=medium),
    ):
        with pytest.raises(RecoveryRefused) as refused:
            act()
        assert refused.value.refusal is Refusal.MEDIUM_MOVED_SINCE_THE_PREFLIGHT
    assert [entry.check for entry in ledger.audit()] == [
        PreflightCheck.VOLUME_QUARANTINED,
        PreflightCheck.VOLUME_QUARANTINED,
    ]

    medium.fence()
    with pytest.raises(RecoveryRefused):
        ledger.may_migrate(verdict, quarantine=medium)
    assert ledger.audit()[-1].check is PreflightCheck.MEDIUM_FENCED
    assert not [
        entry for entry in ledger.audit() if entry.event is not SnapshotAuditEvent.MIGRATION_REFUSED
    ]


def test_the_repr_survives_an_instance_that_was_never_built(observations) -> None:
    """R5: the redaction defeated the tool it exists to serve.

    `__init__` validates before it assigns, so a `TypeError` from one of its
    checks leaves an object with no `_stage`. The traceback machinery, asked
    for captured locals — which is what `pytest --showlocals` and ordinary
    crash reporters do — called the redacting `__repr__` and died inside it
    with an `AttributeError`. A clean, message-only refusal became a crash in
    the code written to keep refusals clean.
    """

    import traceback

    binding = SessionBinding(host_fingerprint=host_fingerprint(observations), session_id=SESSION)
    for arguments in (
        {"quarantine": object(), "binding": binding, "session_id": SESSION},
        {"quarantine": a_quarantine(), "binding": object(), "session_id": SESSION},
        {"quarantine": a_quarantine(), "binding": binding, "session_id": b"bytes"},
    ):
        with pytest.raises(TypeError) as raised:
            RecoveryWorkflow(
                arguments["quarantine"],
                arguments["binding"],
                session_id=arguments["session_id"],
            )
        rendered = "".join(
            traceback.TracebackException.from_exception(raised.value, capture_locals=True).format()
        )
        assert "RecoveryWorkflow(stage=unbuilt)" in rendered
        assert FINGERPRINT not in rendered
        assert MEDIUM.identity not in rendered


def test_a_half_built_recovery_workflow_is_sealed_and_refuses_every_write(observations) -> None:
    """R24 (security review, critical): a half-built workflow used to be
    writable.

    `__init__` used to set `_sealed = False` only *after* its validation —
    `_require_a_real_quarantine`, the binding field pins, the `session_id`
    checks — had already run, so a `TypeError` from any of those left an
    object with no `_sealed` slot at all. `__setattr__` gates on
    `getattr(self, "_sealed", False)`, which defaults to `False` — "not
    sealed, writes permitted" — when the slot was never set. Anyone holding
    that half-built `self` (reached the same way `_half_built` reaches one)
    could then write `_stage`, `_candidate` and `_quarantine` by ordinary
    assignment, and `candidate_applies_to`/`holds` — which check
    `type(flow) is RecoveryWorkflow` and read `_stage`/`_candidate` straight
    off the instance — had nothing to tell a forged-by-write workflow from
    a genuinely minted one. `_sealed` is now the very first thing `__init__`
    sets, before any validation runs, so every write below now meets the
    same sealed refusal a fully-built workflow already gives.

    Every name in `RecoveryWorkflow.__slots__` is driven, not just three of
    them — `__setattr__` checks only the seal, never the field or the
    value, so one placeholder value works for all ten. A round-25
    test-suite review pointed out an earlier version of this test drove
    only four names, which happened to be masked by the seal-first
    architecture (any other field left unconverted to `object.__setattr__`
    inside `__init__` fails *every* construction, loudly, long before this
    test's own narrower check could matter) but was not itself a proof
    covering the remaining six.
    """

    assert set(RecoveryWorkflow.__slots__) == {
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
    }

    binding = SessionBinding(host_fingerprint=host_fingerprint(observations), session_id=SESSION)
    placeholder = object()
    for arguments in (
        {"quarantine": object(), "binding": binding, "session_id": SESSION},
        {"quarantine": a_quarantine(), "binding": object(), "session_id": SESSION},
        {"quarantine": a_quarantine(), "binding": binding, "session_id": b"bytes"},
    ):
        half = _half_built(RecoveryWorkflow, **arguments)
        for name in RecoveryWorkflow.__slots__:
            with pytest.raises(AttributeError, match="sealed"):
                setattr(half, name, placeholder)
            with pytest.raises(AttributeError, match="sealed"):
                delattr(half, name)


def test_a_snapshot_descriptors_repr_survives_an_instance_that_was_never_built() -> None:
    """R22 (security review): the same crash, for a sibling class.

    `SnapshotDescriptor.__init__` validates every field before assigning any
    of them — a related but not identical shape to `RecoveryWorkflow.__init__`
    (round 24 made that class seal itself *before* validating, rather than
    after) — and its `__repr__` read `self.container_version`/
    `self.schema_version`/`self.integrity` unconditionally, so the same
    `capture_locals=True` traceback rendering that `RecoveryWorkflow`'s test
    above drives died the same way here, one validation failure away.
    """

    import traceback

    # None of these pass `FINGERPRINT` itself: the constructor's own
    # `fingerprint` parameter becomes a local of the raising `__init__`
    # frame regardless of which check actually fails, and `capture_locals`
    # renders every frame's locals — a property of the traceback machinery
    # this fix cannot and does not change. What this test drives is the
    # `__repr__` fallback specifically, so the fingerprint used here is an
    # unrelated placeholder, not the value the suite treats as "the secret
    # under test" elsewhere.
    placeholder_fingerprint = "unrelated-placeholder-fingerprint"
    for arguments in (
        {
            "container_version": 0,
            "schema_version": 1,
            "integrity": SnapshotIntegrity.VERIFIED,
            "fingerprint": placeholder_fingerprint,
        },
        {
            "container_version": 1,
            "schema_version": 1,
            "integrity": "not-a-member",
            "fingerprint": placeholder_fingerprint,
        },
        {
            "container_version": 1,
            "schema_version": 1,
            "integrity": SnapshotIntegrity.VERIFIED,
            "fingerprint": "",
        },
    ):
        with pytest.raises(TypeError) as raised:
            SnapshotDescriptor(**arguments)
        rendered = "".join(
            traceback.TracebackException.from_exception(raised.value, capture_locals=True).format()
        )
        assert "SnapshotDescriptor(unbuilt)" in rendered
        assert FINGERPRINT not in rendered
        assert MEDIUM.identity not in rendered


def test_a_snapshot_audit_entrys_repr_survives_an_instance_that_was_never_built() -> None:
    """R22 (security review): the same crash, for the object this module's
    own docstring calls "the object destined for a log"."""

    import traceback

    for arguments in (
        {"event": "not-a-member"},
        {"event": SnapshotAuditEvent.RECOVERY_COMPLETED, "check": "not-a-member"},
        {
            "event": SnapshotAuditEvent.RECOVERY_COMPLETED,
            "fingerprint": "bad fingerprint with spaces",
        },
    ):
        with pytest.raises(TypeError) as raised:
            SnapshotAuditEntry(**arguments)
        rendered = "".join(
            traceback.TracebackException.from_exception(raised.value, capture_locals=True).format()
        )
        assert "SnapshotAuditEntry(unbuilt)" in rendered
        assert FINGERPRINT not in rendered
        assert MEDIUM.identity not in rendered


def test_a_half_built_snapshot_descriptor_is_never_equal_and_refuses_to_hash() -> None:
    """R23 (security review): the repr fix's own regression test, one level
    deeper. `__eq__`/`__hash__` read `_fields_of(self)` unconditionally and
    crashed with a second `AttributeError` the same way `__repr__` did
    before round 22 — not reachable through `pytest --showlocals` (that
    machinery only ever calls `repr()` on frame locals, never `==`/
    `hash()`), but reachable by any caller that already holds a reference to
    the half-built instance, such as a debugger evaluating an expression at
    a breakpoint, or identity-set dedup over caught construction failures.
    A half-built instance carries no value, so it is never equal to
    anything — including another half-built instance, including itself —
    and hashing it is a deliberate `TypeError`, not a crash.
    """

    half = _half_built(
        SnapshotDescriptor,
        container_version=1,
        schema_version=1,
        integrity=SnapshotIntegrity.VERIFIED,
        fingerprint="bad fingerprint with spaces",
    )
    built = descriptor()

    assert (half == built) is False
    assert (built == half) is False
    assert (half == half) is False
    with pytest.raises(TypeError, match="half-built SnapshotDescriptor is not hashable"):
        hash(half)


def test_a_half_built_snapshot_audit_entry_is_never_equal_and_refuses_to_hash() -> None:
    """R23 (security review): the same gap, for the object this module's own
    docstring calls "the object destined for a log"."""

    half = _half_built(
        SnapshotAuditEntry,
        event=SnapshotAuditEvent.RECOVERY_COMPLETED,
        fingerprint="bad fingerprint with spaces",
    )
    built = SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_COMPLETED)

    assert (half == built) is False
    assert (built == half) is False
    assert (half == half) is False
    with pytest.raises(TypeError, match="half-built SnapshotAuditEntry is not hashable"):
        hash(half)


def test_a_snapshot_mutated_during_the_prompt_is_a_substitution(observations) -> None:
    """R5: the flags were re-read after the prompt and the pin was not.

    `attempt()` is caller-supplied code and the one step the module documents
    as blocking on a human. The two quarantine flags learned to be re-read
    after it; the snapshot pin did not, and the commit then read the
    descriptor's fields **twice more** on the far side of that wait. A review
    mutated the frozen descriptor from inside the acquisition and reached
    `COMMITTED`: `candidate_applies_to` answered `True`, and the audit's
    `recovery_completed` named a schema version and a fingerprint no gate had
    judged, with no `RECOVERY_SNAPSHOT_SUBSTITUTED` anywhere.

    This is the substitution the whole design exists to notice, through the
    one window the fix for the flags left open.
    """

    snap = descriptor()

    class MutatesDuringThePrompt(Opens):
        def attempt(self):
            object.__setattr__(snap, "_schema_version", 99)
            object.__setattr__(snap, "_fingerprint", "a-completely-different-snapshot")
            return super().attempt()

    flow = workflow(observations)
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=MutatesDuringThePrompt(),
            confirmed=True,
        )
    assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW
    assert flow.stage is RecoveryStage.REFUSED
    assert SnapshotAuditEvent.RECOVERY_SNAPSHOT_SUBSTITUTED in [
        entry.event for entry in flow.audit()
    ]
    assert not [entry for entry in flow.audit() if entry.schema_version == 99]


def test_the_candidate_names_the_snapshot_that_was_judged(observations) -> None:
    """R5, the other half: minting read the argument, not what was judged.

    Even with the pin re-checked, reading the caller's object again at the
    moment of minting is reading something the caller still holds. The values
    come from `_pinned` — a descriptor built at `start` from the fields as they
    were then, which the caller never had a reference to.
    """

    snap = descriptor()
    flow = workflow(observations)
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    held = flow._pinned
    assert held is not snap
    assert _fields_of(held) == _fields_of(snap)

    candidate = flow.commit(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        acquisition=Opens(),
        confirmed=True,
    )
    assert candidate.schema_version == 1
    assert flow.audit()[-1].fingerprint == FINGERPRINT
    assert flow.audit()[-1].schema_version == 1


def test_reading_pinned_rather_than_the_argument_at_the_mint_is_what_this_test_drives(
    monkeypatch, observations
) -> None:
    """R11 (test-suite review): the comment at the mint says reading
    `_pinned` rather than `snapshot` is what closed the mid-prompt mutation
    bug — nothing drove the one window that distinguishes the two.

    `test_a_snapshot_mutated_during_the_prompt_is_a_substitution` mutates
    `snap` from inside `attempt()`, which lands *before* `commit`'s second
    `_require_the_same_snapshot(snapshot)` check — so it is caught as
    `SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW` and never reaches the mint at all.
    That test proves the re-check exists; it cannot prove which object the
    mint itself reads, because a mutation it drives never survives to that
    line. Monkeypatching `RecoveryCandidate.__init__` does not reach it
    either: Python evaluates `judged.schema_version, judged.fingerprint`
    before `__init__` runs, so the constructor only ever sees an
    already-resolved value.

    The one place left is the narrow window *after* the second same-snapshot
    check and *before* the mint — `_require_an_unfenced_medium()`, the last
    synchronous call in between, re-checks the fence and nothing about the
    snapshot. Hooking it to mutate the live `snap` object right there is the
    same shape a review used mid-`attempt()`, aimed at the one instant that
    shape cannot otherwise reach. If the mint read `snapshot` instead of
    `self._pinned`, the candidate and the audit would show the mutated
    values; `_pinned` was built as its own copy back at `start()` and cannot.
    """

    snap = descriptor()
    flow = workflow(observations)
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    original_gate = RecoveryWorkflow._require_an_unfenced_medium

    def mutate_after_the_last_gate(self):
        original_gate(self)
        object.__setattr__(snap, "_schema_version", 99)
        object.__setattr__(snap, "_fingerprint", "mutated-after-the-last-gate")

    monkeypatch.setattr(
        RecoveryWorkflow, "_require_an_unfenced_medium", mutate_after_the_last_gate
    )

    candidate = flow.commit(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        acquisition=Opens(),
        confirmed=True,
    )

    assert candidate.schema_version == 1
    assert flow.audit()[-1].schema_version == 1
    assert flow.audit()[-1].fingerprint == FINGERPRINT
    assert not [entry for entry in flow.audit() if entry.schema_version == 99]


def test_a_preflight_is_free_so_spending_is_keyed_on_the_snapshot() -> None:
    """R5: the write-once defence was one `preflight()` call wide.

    `preflight` is read-only, unlimited and free, so four calls over one
    snapshot mint four distinct spendable verdicts — and one ledger recorded
    four `SNAPSHOT_WRITTEN` classifications for one write, which is the false
    count the WeakSet was added to remove. Spent-ness belongs to the snapshot.
    """

    healthy = a_quarantine(quarantined=False)
    snapshot = descriptor(fingerprint="snapshot-fingerprint-keyed-on-value")
    ledger = MigrationLedger()

    def judged():
        return preflight(
            healthy,
            snapshot=snapshot,
            capacity=capacity(),
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        )

    ledger.note_snapshot_written(judged(), snapshot, quarantine=healthy)
    for _ in range(3):
        with pytest.raises(RecoveryRefused) as refused:
            ledger.note_snapshot_written(judged(), snapshot, quarantine=healthy)
        assert refused.value.refusal is Refusal.VERDICT_ALREADY_SPENT
    assert len(ledger.audit()) == 1

    # A *different* snapshot, judged separately, is a different write.
    other = descriptor(schema_version=2, fingerprint="snapshot-fingerprint-0002")
    second = preflight(
        healthy,
        snapshot=other,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    ledger.note_snapshot_written(second, other, quarantine=healthy)
    assert len(ledger.audit()) == 2


def test_a_passing_verdict_that_skipped_a_check_is_refused() -> None:
    """R5: `evaluated` reported honestly and nothing asked it back.

    `PREFLIGHT_ORDER` is a module global the loop trusts, so rebinding it
    produced a **legitimately minted** passing verdict, asked one check, over a
    medium that was fenced, quarantined and failing its binding — and the
    ledger accepted it. Completeness that nobody consumes is a note, not a
    check.
    """

    judged_medium = a_quarantine(quarantined=False)

    verdict = preflight(
        judged_medium,
        snapshot=descriptor(),
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict.evaluated == PREFLIGHT_ORDER

    shortened = PREFLIGHT_ORDER[:1]
    object.__setattr__(verdict, "_evaluated", shortened)
    assert verdict.may_migrate is True
    assert verdict_was_minted_here(verdict) is True

    ledger = MigrationLedger()
    # **Both paths.** It was enforced on the permission path and not on the
    # recording one, so a verdict `may_migrate` had just refused was still
    # accepted as the record of a write.
    for act in (
        lambda: ledger.may_migrate(verdict, quarantine=judged_medium),
        lambda: ledger.note_snapshot_written(
            verdict, verdict._snapshot, quarantine=judged_medium
        ),
    ):
        with pytest.raises(RecoveryRefused) as refused:
            act()
        assert refused.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK
    assert ledger.audit() == ()


# --------------------------------------------------------------------------
# The fifth review, on the suite itself: checks with no test behind them
# --------------------------------------------------------------------------


def test_a_snapshot_subclass_is_refused_like_every_other_stand_in(observations) -> None:
    """R5: the one `type(...) is` in this module with no subclass test.

    The quarantine, the verdict and the candidate each have a test that drives
    a genuine **subclass**; the snapshot had only a stand-in that was not one.
    Weakening its check to `isinstance` therefore survived the whole suite —
    and with it the entire round-four attack returns, because a subclass can
    simply decline validation and carry fields that answer comparisons for
    themselves.

    `SnapshotDescriptor` used to be a dataclass whose auto-generated
    `__init__` called a separately overridable `__post_init__` hook, and
    declining that hook declined every check in it. It is a hand-written
    `__init__` now — the same edit that stopped `dataclasses.asdict` handing
    the fingerprint back — so the hook a subclass could skip no longer
    exists; validation is the constructor itself. A subclass can still skip
    it, the only way any subclass can skip any base method: by overriding
    `__init__` outright. That is the shape driven below, and it is the shape
    the type pin at the point of use — not the constructor — exists for.
    """

    class Sneaky(SnapshotDescriptor):
        def __init__(self, container_version, schema_version, integrity, fingerprint) -> None:
            object.__setattr__(self, "_container_version", container_version)
            object.__setattr__(self, "_schema_version", schema_version)
            object.__setattr__(self, "_integrity", integrity)
            object.__setattr__(self, "_fingerprint", fingerprint)

    class Lies(int):
        def __eq__(self, other) -> bool:
            return True

        def __ne__(self, other) -> bool:
            return False

        def __hash__(self) -> int:
            return 0

    sneaky = Sneaky(Lies(99), 1, SnapshotIntegrity.VERIFIED, FINGERPRINT)
    assert int(sneaky.container_version) == 99
    assert 99 not in KNOWN_CONTAINER_VERSIONS

    flow = workflow(observations)
    for act in (
        lambda: flow.start(
            sneaky,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        ),
        lambda: preflight(
            a_quarantine(quarantined=False),
            snapshot=sneaky,
            capacity=capacity(),
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        ),
        lambda: MigrationLedger().note_snapshot_written(
            PreflightVerdict(None), sneaky, quarantine=a_quarantine(quarantined=False)
        ),
    ):
        with pytest.raises(TypeError, match="exactly"):
            act()
    assert flow.stage is RecoveryStage.NOT_STARTED


def test_a_workflow_with_nothing_pinned_commits_nothing(observations) -> None:
    """R5: `pinned is not None` was the last guard, and had no test.

    Forcing the stage to `TRIAL_OPEN` while `_pinned` is still `None` is the
    round-four outcome `_sealed_assign` was hardened against — a candidate
    whose entire audit is `['recovery_completed']`. `_sealed_assign` refuses
    the jump now, so the reach is `object.__setattr__`, which this module
    concedes it cannot defend against. That makes this half of the comparison
    the thing that is left, and it is driven here rather than assumed.
    """

    flow = workflow(observations)
    object.__setattr__(flow, "_stage", RecoveryStage.TRIAL_OPEN)
    assert flow._pinned is None

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            descriptor(schema_version=2),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        )
    assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.holds(RecoveryCandidate(2, FINGERPRINT)) is False


def test_a_workflow_and_a_ledger_do_not_fork(observations) -> None:
    """R5: two of the four `__reduce__` defences had no test at all.

    Deleting `RecoveryWorkflow.__reduce__` survived the whole suite, and
    `copy.copy` then forked a one-way workflow into two live ones that each
    minted a candidate from one trial — the same "n records for one act" false
    count the ledger's spend rules exist to prevent, on the workflow side.
    `MigrationLedger.__reduce__` was untested the same way, and a deep copy
    carried its audit into a second ledger.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    ledger = MigrationLedger()
    for subject in (flow, ledger):
        assert type(subject).__reduce__ is not object.__reduce__
        for act in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError, match="not serialisable"):
                act(subject)
    assert flow.stage is RecoveryStage.TRIAL_OPEN


@pytest.mark.parametrize(
    "overrides",
    [
        {"capacity": type("C", (), {"required": 1, "available": 10**18})()},
        {"capacity": None},
        {"snapshot": type("S", (), {"container_version": 1, "schema_version": 1})()},
    ],
)
def test_preflights_own_inputs_are_pinned_too(overrides) -> None:
    """R5: `capacity` and `snapshot` were the two `preflight` inputs with none.

    Every other one has a dedicated test. Removing either check survived the
    whole suite, and a capacity stand-in claiming `10**18` bytes needed of `1`
    free produced a **passing** verdict — the space gate satisfied by two class
    attributes.
    """

    arguments = {
        "snapshot": descriptor(),
        "capacity": capacity(),
        "current_schema": 1,
        "target_schema": 2,
        "binding_holds": True,
        "generation_holds": True,
        "image_digest_holds": True,
    }
    arguments.update(overrides)
    with pytest.raises(TypeError, match="exactly"):
        preflight(a_quarantine(quarantined=False), **arguments)


def test_a_schema_two_recovery_hands_back_a_schema_two_candidate(observations) -> None:
    """R5: every commit in the suite ran on `descriptor()`, i.e. schema 1.

    So the candidate's only substantive payload was never checked against a
    value that differs from the default: hard-coding `RecoveryCandidate(1, …)`
    survived the whole suite, and a schema-2 recovery — the ADR-0010 D7/D8
    migration case this module exists for — handed back a candidate naming the
    wrong schema, with the audit naming it too.
    """

    snap = descriptor(schema_version=2, fingerprint="snapshot-fingerprint-0002")
    flow = workflow(observations)
    candidate = run_to_commit(flow, observations, snapshot=snap)

    assert candidate.schema_version == 2
    assert candidate_applies_to(flow, candidate) is True
    assert flow.audit()[-1].schema_version == 2
    assert flow.audit()[-1].fingerprint == "snapshot-fingerprint-0002"
    # And the start event names it too: it used to carry neither, so "which
    # snapshot did this workflow begin on" was unanswerable from the record.
    assert flow.audit()[0].event is SnapshotAuditEvent.RECOVERY_STARTED
    assert flow.audit()[0].schema_version == 2
    assert flow.audit()[0].fingerprint == "snapshot-fingerprint-0002"


@pytest.mark.parametrize("current", [0, -1, 99])
def test_a_schema_this_build_does_not_know_migrates_nowhere(current) -> None:
    """R5: the `current` membership half was satisfied by the other clause.

    `test_a_schema_downgrade_and_a_no_op_are_both_refused` drives `current=99`,
    above the supported range, where `target > current` answers first. Below it
    nothing did: `schema_is_compatible(current=0, target=1)` answered `True`,
    so a migration **from a schema this build does not know** was permitted.
    """

    assert current not in SUPPORTED_SCHEMA_VERSIONS
    assert schema_is_compatible(current=current, target=1) is False
    verdict = preflight(
        a_quarantine(quarantined=False),
        snapshot=descriptor(),
        capacity=capacity(),
        current_schema=current,
        target_schema=1,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict.may_migrate is False
    assert verdict.refused_by is PreflightCheck.SCHEMA_COMPATIBILITY


def test_the_media_binding_is_reported_and_asked_at_every_stage(observations) -> None:
    """ADR-0010 D8 gate 1, as the ADR names it.

    `RecoveryGate.TARGET_BINDING` used to be `commissioning.binding_applies` —
    the **host** binding — and D8 gate 1 is ADR-0008 D4.1.1's key-protected
    **media** binding. The caller re-derives that (`media_binding_applies` over
    a `MediaClaim` under a `BindingKey`, in `azazel_boot.persistence`) and
    reports the answer here, in the same shape `preflight` takes its three
    reports. The key does not come here: a decision module that holds key
    material is a decision module the secret arrives at.

    Asked at **every** stage, because a medium can be swapped while an operator
    reads a screen — the same reason the fence is re-read three times.
    """

    snap = descriptor()
    for stage in ("start", "open_trial", "commit"):
        flow = workflow(observations)
        if stage != "start":
            flow.start(
                snap,
                observations,
                media_binding_holds=True,
                session_id=SESSION,
                started_by_operator=True,
            )
        if stage == "commit":
            flow.open_trial(
                snap, observations, media_binding_holds=True, session_id=SESSION
            )

        def call(holds, *, on=flow, at=stage):
            if at == "start":
                return on.start(
                    snap,
                    observations,
                    media_binding_holds=holds,
                    session_id=SESSION,
                    started_by_operator=True,
                )
            if at == "open_trial":
                return on.open_trial(
                    snap, observations, media_binding_holds=holds, session_id=SESSION
                )
            return on.commit(
                snap,
                observations,
                media_binding_holds=holds,
                session_id=SESSION,
                acquisition=Opens(),
                confirmed=True,
            )

        # A truthy object is not a check, here as everywhere else.
        with pytest.raises(TypeError, match="media_binding_holds"):
            call("yes")

        with pytest.raises(RecoveryRefused) as refused:
            call(False)
        assert refused.value.refusal is Refusal.GATE_REFUSED
        assert flow.audit()[-1].gate is RecoveryGate.TARGET_BINDING
        assert flow.stage is RecoveryStage.REFUSED
        assert flow.holds(RecoveryCandidate(1, FINGERPRINT)) is False


def test_no_function_here_takes_the_live_data_and_the_snapshot_together() -> None:
    """ADR-0010 D6, asserted on the signatures — which nothing did.

    The module docstring and `docs/snapshot-and-recovery.md` both said "a test
    asserts that on the signatures rather than on the bodies", and a review
    found there was no such test. D6 requires that a snapshot's integrity is
    judged **on the snapshot alone**: a snapshot that can only be judged by the
    thing it would restore is not a snapshot.

    So: no callable here takes a parameter naming live data, and no callable
    takes two snapshot-shaped parameters at once.
    """

    from azazel_boot import snapshot as module

    live = ("live", "current_data", "volume_data", "original", "source_bytes", "actual")
    for name, value in inspect.getmembers(module):
        if not (inspect.isfunction(value) or inspect.isclass(value)):
            continue
        if getattr(value, "__module__", None) != module.__name__:
            continue
        callables = (
            [(name, value)]
            if inspect.isfunction(value)
            else [
                (f"{name}.{attribute}", member)
                for attribute, member in inspect.getmembers(value, inspect.isfunction)
                if member.__module__ == module.__name__
            ]
        )
        for label, call in callables:
            parameters = inspect.signature(call).parameters
            assert not [
                word for word in live for key in parameters if word in key.lower()
            ], label
            snapshots = [
                key
                for key, parameter in parameters.items()
                if "snapshot" in key.lower()
                and "written" not in key.lower()
                and parameter.kind is not parameter.VAR_KEYWORD
            ]
            assert len(snapshots) <= 1, f"{label} takes {snapshots}"


def test_one_write_is_one_record_however_many_ledgers_and_verdicts(observations) -> None:
    """R6: the round-five fix was exactly one verdict-object wide.

The verdict-keyed `WeakSet` and the per-ledger list of values both
    answered per object, so a fresh `preflight` per ledger satisfied both —
    four ledgers, four verdicts, one judged snapshot, four `SNAPSHOT_WRITTEN`
    records. The module's own sentence is "n records for one write is a false
    count", and the docstring claimed the spent-ness was "kept module-side
    rather than per-ledger".

    So the **medium and the snapshot's values** are what is recorded, module
    side. Both of the other two were later proved unable to fire in front of
    it and removed; this test is what says the remaining one carries them.
    """

    healthy = a_quarantine(quarantined=False)
    snapshot = descriptor(fingerprint="snapshot-fingerprint-once")

    def judged():
        return preflight(
            healthy,
            snapshot=snapshot,
            capacity=capacity(),
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        )

    ledgers = [MigrationLedger() for _ in range(4)]
    ledgers[0].note_snapshot_written(judged(), snapshot, quarantine=healthy)
    for ledger in ledgers[1:]:
        with pytest.raises(RecoveryRefused) as refused:
            ledger.note_snapshot_written(judged(), snapshot, quarantine=healthy)
        assert refused.value.refusal is Refusal.VERDICT_ALREADY_SPENT
        assert ledger.audit() == ()
    assert sum(len(ledger.audit()) for ledger in ledgers) == 1


def test_a_stage_the_gates_lead_to_is_reached_by_passing_them(observations) -> None:
    """R6: `trial_open -> committed` is a legal edge, and D8 gates 2 and 4 are
    not in the graph at all.

    Round five closed the `NOT_STARTED -> TRIAL_OPEN` jump by naming the legal
    edges. A review then took the *legal* edge instead: from a genuine
    `TRIAL_OPEN` — real start, real trial, real audit — `_sealed_assign` minted
    an accepted candidate for schema 99 with no `KeyAcquisition` ever
    constructed and no operator ever asked, and the forged audit was
    **byte-identical** to a legitimate commit. A better disguise than the one
    that was fixed.

    So the stages the gates lead to are reached by passing them: the clearance
    is issued by `_require_the_gates` and spent by the one transition that may
    follow. `REFUSED` and `INTERRUPTED` need none, being what a refusal and an
    interruption reach.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    assert flow.stage is RecoveryStage.TRIAL_OPEN

    with pytest.raises(AttributeError, match="minted by a commit whose gates passed"):
        flow._sealed_assign("_candidate", RecoveryCandidate(99, FINGERPRINT))
    with pytest.raises(AttributeError, match="reached by passing the gates"):
        flow._sealed_assign("_stage", RecoveryStage.COMMITTED)
    assert flow.stage is RecoveryStage.TRIAL_OPEN
    assert flow.holds(RecoveryCandidate(99, FINGERPRINT)) is False

    # An interruption needs no clearance, being what an interruption reaches.
    flow.interrupt(session_id=SESSION)
    assert flow.stage is RecoveryStage.INTERRUPTED

    # And the clearance is spent, not held: a second commit on a workflow that
    # passed its gates once cannot reuse the first one's.
    fresh = workflow(observations)
    candidate = run_to_commit(fresh, observations)
    assert candidate_applies_to(fresh, candidate) is True
    assert fresh._cleared is None


def test_no_rendering_path_hands_back_what_the_repr_redacts(observations) -> None:
    """R6: the discipline was `__repr__`-shaped and so was the test suite.

    A review rendered every object this module produces through
    `dataclasses.asdict`, `astuple`, `vars()`, `__getstate__` and
    `pickle.dumps` — none of which a `__repr__` touches — and got the
    fingerprint, both capacity figures, the host fingerprint and the sitting id
    back in plain text. The suite asserted against `repr()` alone; the phrase
    `asdict` did not appear in it once.

    `CapacityReport` stopped being a dataclass, because the claim about its
    figures was a claim about a **boundary** and a `__repr__` is a rendering.
    Everything refuses `__getstate__`, `copy` and `pickle`.

    `SnapshotDescriptor` and `SnapshotAuditEntry` remain dataclasses, so
    `dataclasses.asdict`, `astuple` and `vars()` still answer field by field —
    **deliberately**, and the messages on their refusals were corrected to say
    "is not serialisable" rather than "does not hand back its fields", which
    was false of exactly those three paths. The fingerprint is this design's
    opaque answer to "which snapshot" and ADR-0010 permits that
    classification in an audit; the figures are neither, which is why only one
    of the three classes stopped being a dataclass.
    """

    canary_fingerprint = "CANARY-FINGERPRINT-AAAA"
    canary_required, canary_available = 111222333, 444555666

    room = CapacityReport(required=canary_required, available=canary_available)
    assert room.has_room_for_the_snapshot() is True
    assert repr(room) == "CapacityReport(<redacted>)"
    assert not dataclasses.is_dataclass(room)
    for reach in (
        lambda: dataclasses.asdict(room),
        lambda: dataclasses.astuple(room),
        lambda: vars(room),
        lambda: room.__getstate__(),
        lambda: pickle.dumps(room),
        lambda: copy.deepcopy(room),
        lambda: setattr(room, "_required", 0),
    ):
        with pytest.raises((TypeError, AttributeError)):
            reach()
    assert "111222333" not in repr(room) and "444555666" not in repr(room)

    snap = descriptor(fingerprint=canary_fingerprint)
    flow = workflow(observations)
    candidate = run_to_commit(flow, observations, snapshot=snap)
    entry = flow.audit()[-1]
    verdict = preflight(
        a_quarantine(quarantined=False),
        snapshot=snap,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )

    for subject in (snap, entry, candidate, verdict, flow, MigrationLedger()):
        for reach in (
            lambda item=subject: item.__getstate__(),
            lambda item=subject: pickle.dumps(item),
            lambda item=subject: copy.deepcopy(item),
            lambda item=subject: copy.copy(item),
        ):
            with pytest.raises(TypeError):
                reach()
        assert canary_fingerprint not in repr(subject)

    # And the one rendering that is allowed to name a snapshot still redacts.
    assert "<redacted>" in repr(snap)
    assert entry.fingerprint == canary_fingerprint  # the documented answer
    assert canary_fingerprint not in repr(entry)


# --------------------------------------------------------------------------
# Checks whose refusal enum was asserted and whose *effect* was not
# --------------------------------------------------------------------------


def test_a_fence_alone_ends_a_verdict_even_with_the_volume_healthy() -> None:
    """R6: the ledger's `or` was only ever driven with both flags on.

    `test_a_verdict_is_not_a_permission_that_outlives_what_it_judged`
    quarantines the volume first and fences afterwards, so
    `volume_is_quarantined` answered for the fence every time and deleting the
    fence half left the suite green. ADR-0010 D9 is specifically about the
    fence: a version upgrade is not a way round it, and a verdict minted before
    a removal is a bearer token for a large write after one.
    """

    medium = a_quarantine(quarantined=False)
    snapshot = descriptor()
    verdict = preflight(
        medium,
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    ledger = MigrationLedger()
    assert ledger.may_migrate(verdict, quarantine=medium) is True

    medium.fence()
    assert medium.is_fenced is True
    assert medium.volume_is_quarantined is False  # the fence alone

    for act in (
        lambda: ledger.may_migrate(verdict, quarantine=medium),
        lambda: ledger.note_snapshot_written(verdict, snapshot, quarantine=medium),
    ):
        with pytest.raises(RecoveryRefused) as refused:
            act()
        assert refused.value.refusal is Refusal.MEDIUM_MOVED_SINCE_THE_PREFLIGHT
    assert ledger.audit()[-1].check is PreflightCheck.MEDIUM_FENCED
    assert not [
        entry for entry in ledger.audit() if entry.event is SnapshotAuditEvent.SNAPSHOT_WRITTEN
    ]


def test_the_ledger_pins_the_quarantine_it_is_handed() -> None:
    """R6: the only quarantine check on the migration path had no test.

    A two-attribute stand-in (`is_fenced = False`, `volume_is_quarantined =
    False`) satisfied it while the real medium was fenced and quarantined —
    round three's stand-in attack, unguarded on the ledger side.
    """

    class StandIn:
        is_fenced = False
        volume_is_quarantined = False

    snapshot = descriptor()
    verdict = preflight(
        a_quarantine(quarantined=False),
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    ledger = MigrationLedger()
    for act in (
        lambda: ledger.may_migrate(verdict, quarantine=StandIn()),
        lambda: ledger.note_snapshot_written(verdict, snapshot, quarantine=StandIn()),
    ):
        with pytest.raises(TypeError, match="exactly"):
            act()
    assert ledger.audit() == ()


def test_a_volume_that_stops_being_quarantined_during_the_prompt_refuses(
    observations,
) -> None:
    """R6: the post-prompt re-read had two halves and one of them was dead.

    `test_the_medium_is_read_again_after_the_passphrase_prompt` pulls the
    *fence* during the prompt and never un-quarantines the volume, so the
    second half — "there is still something to recover" — was uncovered by the
    whole suite. Deleting it let a recovery commit over a volume that stopped
    being quarantined inside `attempt()`: a restore over live data, which is
    the write D8 refuses to make.
    """

    quarantine = a_quarantine()

    class HealedDuringThePrompt(Opens):
        def attempt(self):
            object.__setattr__(quarantine, "_volume_quarantined", False)
            return super().attempt()

    flow = workflow(observations, quarantine=quarantine)
    snap = descriptor()
    flow.start(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=HealedDuringThePrompt(),
            confirmed=True,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.NOTHING_TO_RECOVER
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.holds(RecoveryCandidate(1, FINGERPRINT)) is False


def test_the_operator_is_prompted_once_and_never_over_a_forbidden_channel(
    observations,
) -> None:
    """R6: the refusal enum was asserted and the *prompt* was not.

    Hoisting `attempt()` above the channel check left the suite green: the
    module asked a human for a passphrase over a channel ADR-0010 D2 forbids
    and *then* refused. Calling `attempt()` twice was green too — and in a real
    acquisition each call spends a retry from D2's budget.

    `test_a_binding_from_another_machine_refuses_before_a_key_is_asked_for`
    does assert `attempts == 0`, but only for the host-binding gate, which sits
    above the whole acquisition block.
    """

    forbidden = Opens(channel=NOT_A_CHANNEL)
    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    with pytest.raises(RecoveryRefused):
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=forbidden,
            confirmed=True,
        )
    assert forbidden.attempts == 0, "a forbidden channel is refused before it is used"

    once = Opens()
    good = workflow(observations)
    run_to_commit(good, observations, acquisition=once)
    assert once.attempts == 1, "the operator types once"


def test_a_stage_is_asked_for_before_the_operator_flag_is_read(observations) -> None:
    """R6: `start`'s guard order had no test, and it crosses two rules.

    Moving the operator check to the top left the suite green, and a foreign
    caller could then terminate somebody else's live workflow — with
    `RECOVERY_NOT_STARTED_BY_AN_OPERATOR` as the classification and no
    `RECOVERY_FOREIGN_SITTING` recorded. `test_every_stage_refuses_a_foreign_
    sitting[start]` passes `started_by_operator=True`, so the crossing case was
    never driven.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    assert flow.stage is RecoveryStage.PREFLIGHT_PASSED

    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            snap,
            observations,
            media_binding_holds=True,
            session_id="somebody-elses-sitting",
            started_by_operator=False,
        )
    assert refused.value.refusal is Refusal.STAGE_SKIPPED
    assert flow.stage is RecoveryStage.PREFLIGHT_PASSED
    assert [entry.event for entry in flow.audit()] == [
        SnapshotAuditEvent.RECOVERY_STARTED
    ]


@pytest.mark.parametrize(
    "near_miss",
    [
        SESSION.upper(),
        SESSION.capitalize(),
        f" {SESSION}",
        f"{SESSION} ",
        f"{SESSION}\n",
        f"\t{SESSION}\t",
    ],
)
def test_a_sitting_that_merely_resembles_this_one_is_not_this_one(
    near_miss, observations
) -> None:
    """R6: every foreign-sitting test used an obviously different string.

    So a comparison that folded case, or stripped whitespace, was green — and
    accepted a sitting id that is not this workflow's. An identifier is
    compared, not interpreted.
    """

    assert near_miss != SESSION
    flow = workflow(observations)
    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=near_miss,
            started_by_operator=True,
        )
    assert refused.value.refusal is Refusal.NOT_THIS_SITTING
    assert flow.audit()[-1].event is SnapshotAuditEvent.RECOVERY_FOREIGN_SITTING


@pytest.mark.parametrize(
    ("was", "asked"),
    [
        (RecoveryStage.NOT_STARTED, RecoveryStage.COMMITTED),
        (RecoveryStage.NOT_STARTED, RecoveryStage.TRIAL_OPEN),
        (RecoveryStage.PREFLIGHT_PASSED, RecoveryStage.COMMITTED),
        (RecoveryStage.TRIAL_OPEN, RecoveryStage.PREFLIGHT_PASSED),
        (RecoveryStage.PREFLIGHT_PASSED, RecoveryStage.NOT_STARTED),
    ],
)
def test_every_edge_the_stage_may_not_travel(was, asked, observations) -> None:
    """R6: one forbidden edge was driven and the graph had four more.

    Adding `not_started -> committed` to `_STAGE_EDGES` left the suite green,
    and a workflow then reported `COMMITTED` with an **empty audit** — the
    shape the graph exists to refuse — through a bound method on every
    instance.
    """

    flow = workflow(observations)
    snap = descriptor()
    if was is not RecoveryStage.NOT_STARTED:
        flow.start(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
    if was is RecoveryStage.TRIAL_OPEN:
        flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    assert flow.stage is was

    # `match=` on **the graph's own message**, not on any refusal. Asserting
    # "either message" was this repository's own incidental-refusal antipattern
    # committed in the test written to close it: with the edge added to
    # `_STAGE_EDGES`, the gate-clearance rule answered instead and the loose
    # assertion stayed green. Every edge below is one the graph refuses.
    with pytest.raises(AttributeError, match="travels its own graph"):
        flow._sealed_assign("_stage", asked)
    assert flow.stage is was


def test_every_stage_this_module_reaches_is_recorded(observations) -> None:
    """R6: three classifications existed in the enum and nothing produced them.

    `test_the_audit_vocabulary_is_exactly_nine_classifications` checks the
    enum's members; it does not check that anything writes them. Deleting the
    `RECOVERY_INTERRUPTED` record, writing `RECOVERY_REFUSED` in its place, and
    deleting the `RECOVERY_TRIAL_OPENED` record all left the suite green.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    flow.interrupt(session_id=SESSION)
    assert [entry.event for entry in flow.audit()] == [
        SnapshotAuditEvent.RECOVERY_STARTED,
        SnapshotAuditEvent.RECOVERY_TRIAL_OPENED,
        SnapshotAuditEvent.RECOVERY_INTERRUPTED,
    ]

    committed = workflow(observations)
    run_to_commit(committed, observations)
    assert [entry.event for entry in committed.audit()] == [
        SnapshotAuditEvent.RECOVERY_STARTED,
        SnapshotAuditEvent.RECOVERY_TRIAL_OPENED,
        SnapshotAuditEvent.RECOVERY_COMPLETED,
    ]


def test_a_refusal_entry_names_the_check_or_the_gate_it_refused_on() -> None:
    """R6: the redacting repr's two classification fields were unasserted.

    The repr is the operator-facing rendering, and a refusal that does not say
    *what* refused is an entry with nothing in it. Observability, not a leak —
    but the absence test renders a committed workflow's audit, which carries no
    gate and no check, so both lines were uncovered suite-wide.
    """

    gate_entry = SnapshotAuditEntry(
        event=SnapshotAuditEvent.RECOVERY_REFUSED, gate=RecoveryGate.MEDIUM_FENCED
    )
    check_entry = SnapshotAuditEntry(
        event=SnapshotAuditEvent.MIGRATION_REFUSED, check=PreflightCheck.REQUIRED_SPACE
    )
    assert "gate=medium_fenced" in repr(gate_entry)
    assert "check=required_space" in repr(check_entry)
    assert "fingerprint" not in repr(gate_entry)


def test_a_medium_with_exactly_enough_room_is_not_refused() -> None:
    """R6: the boundary `available == required` appeared nowhere.

    So `<` could become `<=` unnoticed. Fail-closed, and still wrong: a
    migration that fits exactly is a migration that fits.
    """

    assert CapacityReport(required=100, available=100).has_room_for_the_snapshot()
    assert not CapacityReport(required=101, available=100).has_room_for_the_snapshot()
    verdict = preflight(
        a_quarantine(quarantined=False),
        snapshot=descriptor(),
        capacity=capacity(required=100, available=100),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict.may_migrate is True


# --------------------------------------------------------------------------
# The seventh review
# --------------------------------------------------------------------------


def test_a_verdict_is_spent_against_the_medium_its_preflight_judged() -> None:
    """R7: the ledger re-read whatever quarantine the call handed it.

    The doc said it re-reads "as the workflow's gates do", and the workflow
    binds its quarantine at construction and checks the sitting. The ledger had
    no equivalent, so a verdict minted over one medium in one sitting was spent
    against a different medium in a different sitting that had never been
    preflighted at all.
    """

    judged_medium, snapshot, verdict = a_migration()
    elsewhere = Quarantine(
        session_id="another-sitting", boot_medium_identity="usb-SN-SOMEONE-ELSE"
    )
    elsewhere.observe(Device(identity="usb-SN-SOMEONE-ELSE", device_class=DeviceClass.BOOT_MEDIUM))

    ledger = MigrationLedger()
    for act in (
        lambda: ledger.may_migrate(verdict, quarantine=elsewhere),
        lambda: ledger.note_snapshot_written(verdict, snapshot, quarantine=elsewhere),
    ):
        with pytest.raises(RecoveryRefused) as refused:
            act()
        assert refused.value.refusal is Refusal.MEDIUM_MOVED_SINCE_THE_PREFLIGHT
    assert ledger.audit() == ()
    assert ledger.may_migrate(verdict, quarantine=judged_medium) is True


def test_a_verdict_is_spent_against_the_medium_that_judged_it_not_any_judged_medium() -> None:
    """R11 (test-suite review): `_medium_was_judged`'s identity half —
    `judged is not None and verdict in judged` — was untested in isolation.

    Every prior "wrong medium" test presents a medium with **no** preflight
    history at all, so `_JUDGED_BY.get(elsewhere) is None` either way —
    mutating the check to `judged is not None` alone (dropping `and verdict
    in judged`) agrees with the real one on every case any test drives, and
    the whole suite stays green. That mutant accepts exactly the durable
    bearer-token attack ADR-0010 D9 exists to refuse: a verdict minted for
    one medium, spent against a second medium that merely *has some*
    preflight history of its own.

    `elsewhere` gets its own, unrelated preflight here — so it genuinely is
    judged, and `judged is not None` is true — without ever judging
    `verdict`. Only `verdict in judged` tells the two apart.
    """

    judged_medium, _snapshot, verdict = a_migration()
    elsewhere = a_quarantine(quarantined=False)
    preflight(
        elsewhere,
        snapshot=descriptor(fingerprint="an-unrelated-fingerprint"),
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )

    ledger = MigrationLedger()
    with pytest.raises(RecoveryRefused) as refused:
        ledger.may_migrate(verdict, quarantine=elsewhere)
    assert refused.value.refusal is Refusal.MEDIUM_MOVED_SINCE_THE_PREFLIGHT
    assert ledger.audit() == ()
    assert ledger.may_migrate(verdict, quarantine=judged_medium) is True


def test_a_refusal_names_the_check_the_run_actually_stopped_at() -> None:
    """R7: the completeness rule ran on the passing half only.

    So a rebound `PREFLIGHT_ORDER` produced a **refusal** whose classification
    was a check the run never reached — and that classification is the whole of
    what an operator is told and what the ledger records, permanently.
    """

    judged_medium, snapshot, _ = a_migration(
        snapshot=descriptor(integrity=SnapshotIntegrity.FAILED)
    )
    honest = preflight(
        judged_medium,
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert honest.refused_by is PreflightCheck.SNAPSHOT_INTEGRITY
    assert honest.evaluated[len(honest.evaluated) - 1] is PreflightCheck.SNAPSHOT_INTEGRITY

    object.__setattr__(honest, "_evaluated", (PreflightCheck.BINDING,))
    ledger = MigrationLedger()
    with pytest.raises(RecoveryRefused) as refused:
        ledger.may_migrate(honest, quarantine=judged_medium)
    assert refused.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK
    assert ledger.audit() == ()


def test_a_preflight_refusal_is_a_bool_and_an_audit_entry_not_a_raised_refusal() -> None:
    """R14 (test-suite/doctrine review): `Refusal.MIGRATION_REFUSED_BY_
    PREFLIGHT` was removed — no code path in this module ever raised it.

    `may_migrate` communicates a preflight's own refusal as `False` plus a
    `SnapshotAuditEvent.MIGRATION_REFUSED` entry, never as a raised
    `RecoveryRefused`; raising is reserved for structural/adversarial
    misuse (a forged verdict, a rebound enum, a moved medium). A `Refusal`
    member matching no raise anywhere is a classification claim resting on
    nothing — this asserts the absence directly, so a member re-added
    without a corresponding raise turns this red rather than leaving
    nothing to notice.
    """

    assert not hasattr(Refusal, "MIGRATION_REFUSED_BY_PREFLIGHT")

    judged_medium, snapshot, _ = a_migration(
        snapshot=descriptor(integrity=SnapshotIntegrity.FAILED)
    )
    refused_by_preflight = preflight(
        judged_medium,
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    ledger = MigrationLedger()
    assert ledger.may_migrate(refused_by_preflight, quarantine=judged_medium) is False
    assert ledger.audit() == (
        SnapshotAuditEntry(
            event=SnapshotAuditEvent.MIGRATION_REFUSED,
            check=PreflightCheck.SNAPSHOT_INTEGRITY,
        ),
    )


def test_a_forged_refusal_reason_alone_is_still_caught_with_evaluated_honest() -> None:
    """R12 (test-suite review): the refusal half's own identity check —
    `stopped_at is not verdict.refused_by`, alongside `not in_order` — was
    never isolated from `in_order`.

    `test_a_refusal_names_the_check_the_run_actually_stopped_at` above forges
    `_evaluated` down to one check, which makes `in_order` false on its own
    (a one-element prefix doesn't match `canonical[:1]` once `refused_by`
    disagrees) — so `not in_order` alone already raises, and `stopped_at is
    not verdict.refused_by` never gets to be the deciding clause. A mutant
    dropping it (leaving only `if not in_order:`) survives the whole suite.

    This isolates it: `_evaluated` stays a genuine, honestly in-order prefix
    — the real one a real preflight produced, ending at `SNAPSHOT_INTEGRITY`
    — and only `_refused_by` is forged, to a check the run never reached.
    `in_order` is still true (the prefix is real and in order); only the
    identity check tells the ledger the *reason* doesn't match where the run
    actually stopped. Without it, `may_migrate` returns `False` silently and
    the ledger's own permanent audit records the wrong check as the reason a
    migration was refused — the exact misclassification this module's
    completeness rule exists to prevent.
    """

    judged_medium, snapshot, _ = a_migration(
        snapshot=descriptor(integrity=SnapshotIntegrity.FAILED)
    )
    honest = preflight(
        judged_medium,
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert honest.refused_by is PreflightCheck.SNAPSHOT_INTEGRITY

    object.__setattr__(honest, "_refused_by", PreflightCheck.GENERATION)
    ledger = MigrationLedger()
    with pytest.raises(RecoveryRefused) as refused:
        ledger.may_migrate(honest, quarantine=judged_medium)
    assert refused.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK
    assert ledger.audit() == ()


def test_the_gates_cannot_be_reached_without_all_of_them(observations) -> None:
    """R7: the clearance's issuer sat at the reach it was built to blunt.

    `_require_the_gates` is a bound method on every instance, exactly like
    `_sealed_assign`, and its `acquisition` defaulted to `None` — so a review
    called it directly, got a clearance without D8's gate 2 or gate 4, moved
    the stage, and minted an accepted candidate for schema 99 on an audit
    byte-identical to a legitimate commit.

    Both are required arguments now, and both are asked before the clearance,
    so reaching this method is passing all of D8. The residual limit is the one
    this module states everywhere: `object.__setattr__` reaches everything, and
    a determined caller can name `_GATES_JUST_PASSED`.

    **Both, and each of them.** This drove the two extremes — neither supplied,
    and both supplied — and neither of the two **mixed** rows, which is where
    the rule actually lives: `asked_all_of_d8` is a conjunction, and a review
    deleted either half of it with the suite green, then reached `COMMITTED`
    with an accepted candidate having asked D8's gate 4 (or gate 2) never. A
    test that drives a conjunction at its two extremes has driven neither
    conjunct.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    with pytest.raises(TypeError, match="acquisition"):
        flow._require_the_gates(
            snap, observations, session_id=SESSION, media_binding_holds=True
        )
    # **Each on its own**, not only both omitted together. Omitting neither
    # parameter's message says anything about whether the *other* one is
    # also required — a call missing both raises CPython's own "missing 2
    # required keyword-only arguments: 'acquisition' and 'confirmed'", which
    # matches `"acquisition"` whether or not `confirmed` has a default at
    # all. A review gave `confirmed` a default of `None` and this call above
    # still passed.
    with pytest.raises(TypeError, match="missing 1 required keyword-only argument: 'confirmed'"):
        flow._require_the_gates(
            snap,
            observations,
            session_id=SESSION,
            media_binding_holds=True,
            acquisition=None,
        )
    with pytest.raises(
        TypeError, match="missing 1 required keyword-only argument: 'acquisition'"
    ):
        flow._require_the_gates(
            snap,
            observations,
            session_id=SESSION,
            media_binding_holds=True,
            confirmed=None,
        )
    # `acquisition=None` is honest for `start` and `open_trial`, so the
    # clearance it issues says so: it cannot reach `COMMITTED`.
    flow._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=None,
        confirmed=None,
    )
    with pytest.raises(AttributeError, match="reached by passing the gates"):
        flow._sealed_assign("_stage", RecoveryStage.COMMITTED)
    with pytest.raises(AttributeError, match="gates passed"):
        flow._sealed_assign("_candidate", RecoveryCandidate(99, FINGERPRINT))
    assert flow.stage is RecoveryStage.TRIAL_OPEN

    # The two mixed rows. Each passes every gate it is asked and issues the
    # clearance of a stage that has **not** asked all of D8, so neither
    # reaches `COMMITTED` and neither mints a candidate.
    for acquisition, confirmed in ((Opens(), None), (None, True)):
        mixed = workflow(observations)
        mixed.start(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
        mixed.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
        mixed._require_the_gates(
            snap,
            observations,
            session_id=SESSION,
            media_binding_holds=True,
            acquisition=acquisition,
            confirmed=confirmed,
        )
        with pytest.raises(AttributeError, match="reached by passing the gates"):
            mixed._sealed_assign("_stage", RecoveryStage.COMMITTED)
        with pytest.raises(AttributeError, match="a candidate is minted by a commit whose"):
            mixed._sealed_assign("_candidate", RecoveryCandidate(99, FINGERPRINT))
        assert mixed.stage is RecoveryStage.TRIAL_OPEN
        assert mixed.holds(RecoveryCandidate(99, FINGERPRINT)) is False

    with pytest.raises(RecoveryRefused) as refused:
        flow._require_the_gates(
            snap,
            observations,
            session_id=SESSION,
            media_binding_holds=True,
            acquisition=Opens(),
            confirmed=False,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.OPERATOR_CONFIRMATION


def test_the_pin_is_typed_when_it_is_written_not_only_when(observations) -> None:
    """R15 (test-suite review): `_sealed_assign`'s `_pinned` write checked
    *when* (only from `NOT_STARTED`), never *what*.

    Unlike the `_candidate` branch a few lines below — which checks both
    when a write is legal and what the value says — the `_pinned` branch
    only ever checked the former. A `_pinned` written as something other
    than a `SnapshotDescriptor`, through the same bound-method reach
    `start` itself has, was accepted silently; the crash then landed
    several calls later, inside `_fields_of`, as a bare `AttributeError`
    from ordinary attribute lookup — the exact "caller who wrote `except
    RecoveryRefused:` crashed" shape this module refuses everywhere else.
    `_require_a_real_snapshot` is reused here, the same check every
    legitimate entrance already runs on its own argument.
    """

    class BogusPin:
        pass

    flow = workflow(observations)
    with pytest.raises(TypeError, match="SnapshotDescriptor"):
        flow._sealed_assign("_pinned", BogusPin())
    assert flow._pinned is None
    assert flow.stage is RecoveryStage.NOT_STARTED


def test_a_stage_written_through_the_seal_is_typed_before_it_is_compared(
    observations,
) -> None:
    """R16 (security review): the same gap, a sixth time, and the
    sharpest yet — a `_stage` write was never typed before the edge table,
    `_REACHED_WITHOUT_GATES` and the `is RecoveryStage.COMMITTED` clearance
    check all read it.

    A stand-in answering `==`/`in`/`.value` like `RecoveryStage.COMMITTED`
    but failing `is` it slides through the *permissive* clearance branch —
    the one `open_trial` alone already satisfies — without D8's gates ever
    being asked. Nothing this bypasses lets a caller reach an accepted
    `RecoveryCandidate` (`holds`/`candidate_applies_to` ask `is`, which a
    stand-in cannot spoof) and the `Quarantine` is never touched, but
    `flow.stage` then answers `== RecoveryStage.COMMITTED` for any caller
    who wrote the ordinary comparison instead of this module's own
    insisted-on `is`, while the audit stays at `RECOVERY_TRIAL_OPENED`
    forever and the workflow is stuck — every later call meets
    `WORKFLOW_ALREADY_FINISHED`.
    """

    class FakeCommitted:
        value = "committed"

        def __eq__(self, other: object) -> bool:
            return other is RecoveryStage.COMMITTED or getattr(other, "value", None) == "committed"

        def __ne__(self, other: object) -> bool:
            return not self.__eq__(other)

        def __hash__(self) -> int:
            return hash(RecoveryStage.COMMITTED)

    snap = descriptor()
    flow = workflow(observations)
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    flow._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=None,
        confirmed=None,
    )

    fake = FakeCommitted()
    with pytest.raises(AttributeError, match="a stage must be a RecoveryStage exactly"):
        flow._sealed_assign("_stage", fake)
    assert flow.stage is RecoveryStage.TRIAL_OPEN
    assert flow.stage is not fake


def test_a_candidate_cannot_be_minted_without_a_pin_via_the_bound_methods_directly(
    observations,
) -> None:
    """R14 (test-suite review): reaching `_require_the_gates`/`_sealed_assign`
    directly — the reach `commit` itself has, and the one this module has
    never claimed a capability boundary against, only "the accidental
    reach" — could write a `_candidate` and reach `COMMITTED` **without
    `start` ever having been called**, `_pinned` still `None`.

    `commit`'s own mint reads `self._pinned.schema_version`, so this state
    was never reachable through the public surface; nothing stopped it
    through the bound methods a caller driving the state machine directly
    already reaches for other reasons (`test_the_gates_cannot_be_reached_
    without_all_of_them`, above, is exactly that reach). The result: a
    workflow `COMMITTED`, `holds()` true, `candidate_applies_to` true, and
    `flow.audit() == ()` — no `RECOVERY_COMPLETED` entry, because only
    `commit` writes one, and this path skips `commit` too.
    """

    flow = workflow(observations)
    snap = descriptor()

    flow._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=None,
        confirmed=None,
    )
    flow._sealed_assign("_stage", RecoveryStage.PREFLIGHT_PASSED)
    flow._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=None,
        confirmed=None,
    )
    flow._sealed_assign("_stage", RecoveryStage.TRIAL_OPEN)
    flow._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=Opens(),
        confirmed=True,
    )

    assert flow._pinned is None
    forged = RecoveryCandidate(999, "not-derived-from-any-pin")
    with pytest.raises(AttributeError, match="there is no pin to mint one from"):
        flow._sealed_assign("_candidate", forged)
    assert flow.stage is RecoveryStage.TRIAL_OPEN
    assert flow.holds(forged) is False


def test_a_candidate_names_the_pins_schema_version_not_a_separate_one(observations) -> None:
    """R14 (test-suite review): the other half — `_pinned` is set, by a real
    `start`/`open_trial`, but nothing checked that a candidate written
    through `_sealed_assign` directly agrees with it.

    A candidate naming schema 999 minted over a pin that judged schema 1 is
    exactly the "which schema version a restore would reach" claim
    `RecoveryCandidate`'s own docstring makes, made false — reachable
    without `object.__setattr__` anywhere, through the same bound-method
    surface `commit` itself uses to mint the real one.
    """

    snap = descriptor()
    flow = workflow(observations)
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    flow._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=Opens(),
        confirmed=True,
    )

    assert flow._pinned.schema_version == 1
    mismatched = RecoveryCandidate(999, "totally-unrelated-fingerprint")
    with pytest.raises(AttributeError, match="names the schema version the pin was judged at"):
        flow._sealed_assign("_candidate", mismatched)
    assert flow.stage is RecoveryStage.TRIAL_OPEN
    assert flow.holds(mismatched) is False

    # R21 (security review): every case above is wildly off from the pin
    # (999 against 1). A range/tolerance check standing in for the exact
    # `!=` this line uses — accepting, say, `pinned ± 1` — would pass every
    # existing case here undetected. Isolated the same way R11 isolated
    # each forbidden character elsewhere in this file: the pin's immediate
    # neighbour, refused on its own.
    off_by_one = RecoveryCandidate(2, "one-more-than-the-pin")
    with pytest.raises(AttributeError, match="names the schema version the pin was judged at"):
        flow._sealed_assign("_candidate", off_by_one)
    assert flow.holds(off_by_one) is False

    # And the pin's own schema version is still accepted — the check is
    # about agreement, not about refusing every direct write.
    matching = RecoveryCandidate(1, "any-fingerprint-the-pin-does-not-constrain")
    flow._sealed_assign("_candidate", matching)
    assert flow._candidate is matching


def test_the_candidates_schema_version_is_typed_before_it_is_compared_to_the_pin(
    observations,
) -> None:
    """R15 (security review): the same gap, a fourth time — the check
    above compares `value.schema_version != self._pinned.schema_version`
    without ever pinning `value.schema_version`'s type first.

    `RecoveryCandidate` is the one class in this module with a fully
    unchecked constructor — deliberate, since its published surface
    (`holds`/`candidate_applies_to`) is checked by identity, never by
    reading a field. Round fourteen's fix made `_sealed_assign` a second
    reader that *does* trust the field, and a genuine `RecoveryCandidate`,
    built through its own public constructor with an `int` subclass
    `schema_version` whose `__ne__` always answers `False`, defeated the
    very check built to close the round-fourteen attack. Pinned the same
    way `binding`'s and `quarantine`'s fields were, two rounds running.
    """

    class LyingInt(int):
        def __eq__(self, other: object) -> bool:
            return True

        def __ne__(self, other: object) -> bool:
            return False

        def __hash__(self) -> int:
            return int.__hash__(self)

    snap = descriptor()
    flow = workflow(observations)
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    flow._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=Opens(),
        confirmed=True,
    )

    assert flow._pinned.schema_version == 1
    forged = RecoveryCandidate(LyingInt(999), "not-derived-from-any-pin")
    with pytest.raises(TypeError, match="candidate\\.schema_version"):
        flow._sealed_assign("_candidate", forged)
    assert flow.stage is RecoveryStage.TRIAL_OPEN
    assert flow.holds(forged) is False


def test_one_write_is_one_record_even_after_the_snapshot_is_dropped() -> None:
    """R7: "Once" was decided by the garbage collector.

    `_SNAPSHOTS_RECORDED` was a `WeakSet` of descriptors, so dropping the last
    reference evaporated the entry and an equal descriptor recorded again —
    five times, through the public API alone. And the key said nothing about
    whose medium it was, so one sitting's entry refused an unrelated later
    sitting's own write.
    """

    import gc

    judged_medium, snapshot, verdict = a_migration(
        snapshot=descriptor(fingerprint="snapshot-fingerprint-dropped")
    )
    MigrationLedger().note_snapshot_written(verdict, snapshot, quarantine=judged_medium)

    del snapshot, verdict
    gc.collect()

    again = descriptor(fingerprint="snapshot-fingerprint-dropped")
    with pytest.raises(RecoveryRefused) as refused:
        MigrationLedger().note_snapshot_written(
            preflight(
                judged_medium,
                snapshot=again,
                capacity=capacity(),
                current_schema=1,
                target_schema=2,
                binding_holds=True,
                generation_holds=True,
                image_digest_holds=True,
            ),
            again,
            quarantine=judged_medium,
        )
    assert refused.value.refusal is Refusal.VERDICT_ALREADY_SPENT

    # And a **different sitting** is a different question, so its own write is
    # its own: one sitting's residue does not decide another's audit.
    other = Quarantine(session_id="a-later-sitting", boot_medium_identity=MEDIUM.identity)
    other.observe(MEDIUM)
    theirs = descriptor(fingerprint="snapshot-fingerprint-dropped")
    ledger = MigrationLedger()
    ledger.note_snapshot_written(
        preflight(
            other,
            snapshot=theirs,
            capacity=capacity(),
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        ),
        theirs,
        quarantine=other,
    )
    assert len(ledger.audit()) == 1


def test_an_acquisition_that_ends_the_workflow_is_refused_in_this_vocabulary(
    observations,
) -> None:
    """R7: `attempt()` is caller code called mid-gate.

    A review interrupted the workflow from inside it and the stage move then
    raised `AttributeError` from the seal — outside this module's refusal
    vocabulary, so a caller writing `except RecoveryRefused` got a crash.
    Fail-closed either way; `WORKFLOW_ALREADY_FINISHED` exists for the case.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    class EndsTheWorkflow(Opens):
        def attempt(self):
            flow.interrupt(session_id=SESSION)
            return super().attempt()

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=EndsTheWorkflow(),
            confirmed=True,
        )
    assert refused.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED
    assert flow.stage is RecoveryStage.INTERRUPTED
    assert flow.holds(RecoveryCandidate(1, FINGERPRINT)) is False


def test_the_capacity_refusal_holds_no_measurement() -> None:
    """R7: the figures rendered in the constructor's own traceback.

    A caller whose free-space probe returned `None` got a `TypeError` whose
    captured-locals traceback carried the **other**, real figure — on an
    ordinary path, in the constructor of the class whose docstring says these
    numbers never render. The refusal is raised from a frame holding two
    booleans now.
    """

    import traceback

    for arguments in (
        {"required": 424242, "available": None},
        {"required": "x", "available": 919191},
    ):
        with pytest.raises(TypeError) as raised:
            CapacityReport(**arguments)
        # **The refusing frame.** `CapacityReport.__init__` holds what it was
        # handed — a frame cannot forget its own argument, which this design
        # states as a limit rather than claiming away — so the assertion is
        # about the frame the `TypeError` is raised from, which used to hold
        # both figures and now holds two booleans.
        summary = traceback.TracebackException.from_exception(
            raised.value, capture_locals=True
        )
        by_name = {frame.name: frame for frame in summary.stack}
        assert "_require_two_measurements" in by_name
        rendered = repr(by_name["_require_two_measurements"].locals)
        assert "424242" not in rendered, rendered
        assert "919191" not in rendered, rendered
        assert set(by_name["_require_two_measurements"].locals or {}) == {
            "required_is_a_count",
            "available_is_a_count",
        }


def test_a_workflow_stand_in_does_not_make_a_candidate_apply(observations) -> None:
    """R7: `candidate_applies_to` pinned one operand and its docstring two.

    "A constructed one, a subclassed one and one from another workflow are all
    answered `False`" is unconditional, and an object with a `holds` that
    returns `True` answered `True` for a candidate nobody minted.
    """

    class NotAWorkflow:
        def holds(self, candidate) -> bool:
            return True

    assert candidate_applies_to(NotAWorkflow(), RecoveryCandidate(99, FINGERPRINT)) is False

    real = workflow(observations)
    candidate = run_to_commit(real, observations)
    assert candidate_applies_to(real, candidate) is True


# --------------------------------------------------------------------------
# The seventh review's mutation pass: checks whose own layer nothing drove
# --------------------------------------------------------------------------


def test_a_rebound_order_does_not_make_a_short_verdict_complete(observations) -> None:
    """R7: the attack the completeness rule names was never driven.

    Its comment says it compares against `PreflightCheck` "not against
    `PREFLIGHT_ORDER`… comparing with the same global is tautologically true
    while the rebind is live" — and the test written for it set `_evaluated`
    directly instead of rebinding the global, so the tautological version
    survived. This drives the rebind.
    """

    from azazel_boot import snapshot as module

    # A **healthy** medium, so the ledger's own re-read passes and the only
    # rule left to answer is the completeness one. Driving this on a fenced
    # medium would be the incidental-refusal antipattern: the medium check
    # answers first and the assertion learns nothing.
    healthy = a_quarantine(quarantined=False)
    original = module.PREFLIGHT_ORDER
    try:
        object.__setattr__(module, "PREFLIGHT_ORDER", (PreflightCheck.IMAGE_DIGEST,))
        verdict = preflight(
            healthy,
            snapshot=descriptor(integrity=SnapshotIntegrity.FAILED),
            capacity=capacity(required=1000, available=1),
            current_schema=1,
            target_schema=99,
            binding_holds=False,
            generation_holds=False,
            image_digest_holds=True,
        )
        assert verdict.may_migrate is True  # it really was minted, and it really passes
        assert len(verdict.evaluated) == 1
        with pytest.raises(RecoveryRefused) as refused:
            MigrationLedger().may_migrate(verdict, quarantine=healthy)
        assert refused.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK
    finally:
        object.__setattr__(module, "PREFLIGHT_ORDER", original)


def test_a_verdict_that_skipped_exactly_one_check_is_refused(observations) -> None:
    """R16 (test-suite review): the completeness comparison's own boundary
    (`len(asked) == len(canonical)`) was only ever driven at length 1 or at
    the full length 10 — never at 9 of 10, the one length an off-by-one
    slip (`>=` for `==`, or `len(canonical) - 1`) would let through
    silently.

    `PREFLIGHT_ORDER` is rebound to the real first nine checks, in the real
    order — `PREFLIGHT_ORDER[:-1]`, dropping only `IMAGE_DIGEST` — so the
    verdict this mints is genuinely, legitimately passing every check it
    was asked; `evaluated` is a real nine-element prefix of the canonical
    ten, honestly in order. Only its length is short. A mutant loosening
    the length comparison by exactly one accepts this; the real check
    refuses it.
    """

    from azazel_boot import snapshot as module

    healthy = a_quarantine(quarantined=False)
    original = module.PREFLIGHT_ORDER
    try:
        object.__setattr__(module, "PREFLIGHT_ORDER", original[:-1])
        assert len(module.PREFLIGHT_ORDER) == 9
        verdict = preflight(
            healthy,
            snapshot=descriptor(),
            capacity=capacity(),
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        )
        assert verdict.may_migrate is True
        assert len(verdict.evaluated) == 9
        assert verdict.evaluated == original[:-1]

        with pytest.raises(RecoveryRefused) as refused:
            MigrationLedger().may_migrate(verdict, quarantine=healthy)
        assert refused.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK
    finally:
        object.__setattr__(module, "PREFLIGHT_ORDER", original)


def test_the_clearance_is_issued_by_the_gates_and_by_nothing_shorter(
    observations,
) -> None:
    """R7: the interlock has five moving parts and two were pinned.

    A review added `PREFLIGHT_PASSED` to the stages that need no clearance and
    reached `TRIAL_OPEN` over a **fenced** medium with no gate asked; forged a
    clearance from the string `"gates_just_passed"` once the sentinel was a
    nameable value; and combined those with the candidate's stage rule to reach
    `COMMITTED` with no trial, no acquisition and no operator, schema 99,
    `candidate_applies_to` answering True.
    """

    from azazel_boot import snapshot as module

    # Nothing a caller can spell. The sentinel is a bare object, and the field
    # that holds it is not one a recovery moves.
    assert type(module._GATES_JUST_PASSED) is object
    assert type(module._PRE_TRIAL_GATES_PASSED) is object
    assert "_cleared" not in module._MOVES_DURING_A_RECOVERY
    assert set(module._REACHED_WITHOUT_GATES) == {
        RecoveryStage.REFUSED,
        RecoveryStage.INTERRUPTED,
    }

    # A fenced medium reaches no stage the gates lead to, at any stage.
    fenced = a_quarantine(fenced=True)
    flow = workflow(observations, quarantine=fenced)
    with pytest.raises(RecoveryRefused):
        flow.start(
            descriptor(),
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
    assert flow.stage is RecoveryStage.REFUSED
    assert flow._cleared is None

    # And the clearance is spent, not kept, so a second stage needs its own.
    clean = workflow(observations)
    snap = descriptor()
    clean.start(
        snap,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    assert clean._cleared is None
    with pytest.raises(AttributeError, match="reached by passing the gates"):
        clean._sealed_assign("_stage", RecoveryStage.TRIAL_OPEN)
    with pytest.raises(AttributeError, match="minted by a commit whose gates passed"):
        clean._sealed_assign("_candidate", RecoveryCandidate(99, FINGERPRINT))
    assert clean.stage is RecoveryStage.PREFLIGHT_PASSED

    # And with a clearance in hand but the wrong stage, the **stage** rule is
    # what refuses — the third leg of the triple, and the only line in the
    # module the whole suite did not execute.
    clean._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=Opens(),
        confirmed=True,
    )
    assert clean._cleared is not None
    with pytest.raises(AttributeError, match="minted by a commit and by nothing else"):
        clean._sealed_assign("_candidate", RecoveryCandidate(99, FINGERPRINT))
    assert clean.holds(RecoveryCandidate(99, FINGERPRINT)) is False


def test_a_capacity_subclass_does_not_answer_for_the_space_gate() -> None:
    """R7: the capacity pin was driven with a plain object, never a subclass.

    A `CapacityReport` subclass overriding `has_room_for_the_snapshot` produced
    a **passing** verdict with nothing free and an exabyte required — the space
    gate answered by the caller's own method.
    """

    class AlwaysRoom(CapacityReport):
        def has_room_for_the_snapshot(self) -> bool:
            return True

    lying = AlwaysRoom(required=10**18, available=0)
    assert lying.has_room_for_the_snapshot() is True
    with pytest.raises(TypeError, match="exactly"):
        preflight(
            a_quarantine(quarantined=False),
            snapshot=descriptor(),
            capacity=lying,
            current_schema=1,
            target_schema=2,
            binding_holds=True,
            generation_holds=True,
            image_digest_holds=True,
        )


def test_a_hand_built_verdict_has_asked_nothing() -> None:
    """R7: `_evaluated` starts empty, and that is load-bearing.

    The module concedes that `_MINTED_HERE.add(PreflightVerdict(None))`
    produces a verdict `verdict_was_minted_here` accepts — careless-caller
    defence, not a capability boundary. What stops that verdict authorising a
    migration is the completeness rule, and seeding `_evaluated` with every
    check in `__init__` defeated it with the whole suite green.
    """

    from azazel_boot import snapshot as module

    hand_built = PreflightVerdict(None)
    assert hand_built.evaluated == ()
    assert hand_built.may_migrate is True

    module._MINTED_HERE.add(hand_built)
    assert verdict_was_minted_here(hand_built) is True

    # **Two rules, in the order the ledger asks them.** A hand-built verdict
    # judged no medium, and `_mint` requires one, so the first thing it fails
    # is that — with the classification of a verdict nobody minted rather than
    # "the medium moved since the preflight", which would be a sentence about
    # a preflight that never ran.
    medium = a_quarantine(quarantined=False)
    with pytest.raises(RecoveryRefused) as refused:
        MigrationLedger().may_migrate(hand_built, quarantine=medium)
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT

    # And with that supplied too — an attacker holding the module holds the
    # index as well — the completeness rule is what is left, which is the rule
    # this test exists for.
    module._remember_the_medium(hand_built, medium)
    with pytest.raises(RecoveryRefused) as refused:
        MigrationLedger().may_migrate(hand_built, quarantine=medium)
    assert refused.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK


def test_a_candidate_that_merely_compares_equal_is_not_this_ones(observations) -> None:
    """R7: `holds` is public, and `==` could not be told from `is`.

    The existing test forges a candidate with identical field values, and
    `RecoveryCandidate` defines no `__eq__` — so `==` was already identity and
    the assertion could not distinguish the two. A stand-in whose `__eq__`
    answers `True` is what tells them apart.
    """

    flow = workflow(observations)
    candidate = run_to_commit(flow, observations)

    class SaysYes(RecoveryCandidate):
        def __eq__(self, other) -> bool:
            return True

        def __hash__(self) -> int:
            return 0

    agreeable = SaysYes(candidate.schema_version, FINGERPRINT)
    assert (agreeable == candidate) is True
    assert flow.holds(agreeable) is False
    assert candidate_applies_to(flow, agreeable) is False
    assert flow.holds(candidate) is True


def test_an_observation_subclass_is_not_an_observation(observations) -> None:
    """R7: the one `_require_*` helper whose exactness had no test.

    A `tuple` subclass of `InterfaceObservation` subclasses was accepted into
    `start` — every other helper's `type(...) is` had a driven subclass.
    """

    class Subclassed(InterfaceObservation):
        pass

    class ATuple(tuple):
        pass

    honest = observations[0]
    stand_in = Subclassed(
        interface_key=honest.interface_key, permanent_mac=honest.permanent_mac
    )
    flow = workflow(observations)
    for items in (
        ATuple(observations),
        (stand_in,) + tuple(observations[1:]),
    ):
        with pytest.raises(TypeError, match="exactly"):
            flow.start(
                descriptor(),
                items,
                media_binding_holds=True,
                session_id=SESSION,
                started_by_operator=True,
            )
    assert flow.stage is RecoveryStage.NOT_STARTED


def test_the_write_record_names_which_snapshot_was_written() -> None:
    """R7: the audit's only positive classification stopped saying which.

    Dropping `fingerprint=` from the `SNAPSHOT_WRITTEN` entry left the suite
    green, and "which snapshot was written" became unanswerable from the
    record — which is the one question the opaque fingerprint exists for.
    """

    judged_medium, snapshot, verdict = a_migration(
        snapshot=descriptor(fingerprint="snapshot-fingerprint-which-one")
    )
    ledger = MigrationLedger()
    ledger.note_snapshot_written(verdict, snapshot, quarantine=judged_medium)

    entry = ledger.audit()[-1]
    assert entry.event is SnapshotAuditEvent.SNAPSHOT_WRITTEN
    assert entry.fingerprint == "snapshot-fingerprint-which-one"
    assert entry.schema_version == snapshot.schema_version
    assert "snapshot-fingerprint-which-one" not in repr(entry)


# --------------------------------------------------------------------------
# Round eight: what the round-seven defences did not bound
# --------------------------------------------------------------------------


def _everything_a_holder_can_read(value: object) -> list[object]:
    """Every attribute a holder of this object can reach, one level deep."""

    reached: list[object] = []
    for name in dir(value):
        if name.startswith("__"):
            continue
        reached.append(getattr(value, name))
    for name in getattr(type(value), "__slots__", ()):
        if name != "__weakref__":
            reached.append(getattr(value, name, None))
    return reached


def test_no_verdict_hands_back_the_medium_its_preflight_judged() -> None:
    """R8 critical: `_judged` handed the live `Quarantine` to every holder.

    Round seven tied a verdict to the medium its preflight judged, so that a
    verdict could not be spent against a different one — and did it by putting
    the `Quarantine` **on the verdict**. `fence()`, `quarantine_volume()`, the
    sitting and the boot medium identity were then one attribute access from
    anyone a verdict was legitimately handed, on refusals as well as passes,
    through an object whose own docstring said there was nothing to read off
    it and a doc that said the object never escapes two expressions.

    The association is a fact about the verdict, not a field of it: it lives
    in `_JUDGED_BY`, which the verdict does not point at.
    """

    judged_medium, _, passing = a_migration(
        snapshot=descriptor(fingerprint="snapshot-fingerprint-not-readable")
    )
    refusing = preflight(
        judged_medium,
        snapshot=None,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert refusing.may_migrate is False

    assert "_judged" not in PreflightVerdict.__slots__
    for verdict in (passing, refusing):
        first = _everything_a_holder_can_read(verdict)
        assert not [value for value in first if isinstance(value, Quarantine)]
        assert not [value for value in first if value is judged_medium]
        for value in first:
            second = _everything_a_holder_can_read(value)
            assert not [inner for inner in second if isinstance(inner, Quarantine)]

    # And the tie it replaced still holds, which is the point of doing it this
    # way rather than by deletion.
    assert MigrationLedger().may_migrate(passing, quarantine=judged_medium) is True
    with pytest.raises(RecoveryRefused) as refused:
        MigrationLedger().may_migrate(passing, quarantine=a_quarantine(quarantined=False))
    assert refused.value.refusal is Refusal.MEDIUM_MOVED_SINCE_THE_PREFLIGHT


def test_no_parameter_that_holds_a_quarantine_is_spelled_anything_else() -> None:
    """R8 critical: the travel allowlist was one rename wide.

    `test_this_module_never_calls_anything_that_would_change_a_quarantine`
    holds every quarantine in the module to four reads, and it finds them by
    **spelling**: `self._quarantine`, or the bare name `quarantine`. `_mint`
    took one as `judged`, so the parameter that carried the live object into
    the verdict was outside the rule that exists to bound exactly that — and
    the rule read as though it covered the module.

    A spelling rule needs the spelling to be total. This is that: a parameter
    annotated `Quarantine` is named `quarantine`, everywhere, so the walk
    cannot be stepped around by naming one something else.
    """

    holders: list[tuple[str, str]] = []
    offenders: list[tuple[str, str]] = []
    for node in ast.walk(TREE):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        spec = node.args
        for argument in (
            *spec.posonlyargs,
            *spec.args,
            *spec.kwonlyargs,
            spec.vararg,
            spec.kwarg,
        ):
            if argument is None or argument.annotation is None:
                continue
            if "Quarantine" not in ast.unparse(argument.annotation):
                continue
            holders.append((node.name, argument.arg))
            if argument.arg != "quarantine":
                offenders.append((node.name, argument.arg))

    assert len(holders) >= 8, holders
    assert not offenders, offenders

    # **And the spelling of the type, too.** The rule matches the substring
    # `"Quarantine"` in the rendered annotation, so `_Q = Quarantine` at module
    # level and `def _note(medium: _Q, *rest: _Q, spare: _Q | None = None)`
    # sits outside it — a review harvested the sitting id and the boot medium
    # identity through exactly that, with the whole suite green, and the alias
    # itself was invisible to the public-name allowlist because that one
    # filters out every name beginning with an underscore. A guard keyed on a
    # spelling is one rename wide, and this was the rename.
    assert not [
        target.id
        for node in TREE.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name)
        for target in node.targets
        if isinstance(target, ast.Name)
    ], "this module binds no module-level alias of an imported name"

    # **And every parameter is annotated**, so an unannotated one cannot be a
    # `Quarantine` the rule above never examines. The rule reads annotations;
    # a parameter without one is a parameter it does not see.
    unannotated: list[tuple[str, str]] = []
    for node in ast.walk(TREE):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        spec = node.args
        for argument in (
            *spec.posonlyargs,
            *spec.args,
            *spec.kwonlyargs,
            spec.vararg,
            spec.kwarg,
        ):
            if argument is not None and argument.annotation is None and argument.arg != "self":
                unannotated.append((node.name, argument.arg))
    assert not unannotated, unannotated

    # And no `lambda`: `ast.Lambda` carries `args` and is never a `FunctionDef`,
    # so its parameters are outside every rule above. The module has none, and
    # the way to keep that true is to say so.
    assert not [node for node in ast.walk(TREE) if isinstance(node, ast.Lambda)]


def test_the_gates_check_their_own_inputs_when_they_are_reached_directly(
    observations,
) -> None:
    """R8 critical: the interlock bounded two of the gates' inputs, not the rest.

    Round seven made `acquisition` and `confirmed` required because a review
    called `_require_the_gates` directly — it is a bound method at the same
    reach as `_sealed_assign` — and obtained a clearance without D8's gates 2
    and 4. Every *other* input was still the caller's: the snapshot the
    integrity gate reads, the observations the host binding is derived from,
    and the sitting were checked in `start`, `open_trial` and `commit`, which
    is precisely the path the direct call does not take.
    """

    snapshot = descriptor()

    flow = workflow(observations)
    with pytest.raises(TypeError, match="must be a SnapshotDescriptor exactly"):
        flow._require_the_gates(
            _SnapshotStandIn(),
            observations,
            session_id=SESSION,
            media_binding_holds=True,
            acquisition=None,
            confirmed=None,
        )
    assert flow._cleared is None
    assert flow.stage is RecoveryStage.NOT_STARTED

    with pytest.raises(TypeError, match="observations must be a tuple exactly"):
        flow._require_the_gates(
            snapshot,
            list(observations),
            session_id=SESSION,
            media_binding_holds=True,
            acquisition=None,
            confirmed=None,
        )
    assert flow._cleared is None

    with pytest.raises(RecoveryRefused) as refused:
        flow._require_the_gates(
            snapshot,
            observations,
            session_id="s-somebody-else",
            media_binding_holds=True,
            acquisition=None,
            confirmed=None,
        )
    assert refused.value.refusal is Refusal.NOT_THIS_SITTING
    assert flow._cleared is None
    assert flow.stage is RecoveryStage.REFUSED

    # And the substitution check, which the direct call also walked past: a
    # workflow that has pinned a snapshot is asked about **that** one.
    started = workflow(observations)
    started.start(
        snapshot,
        observations,
        media_binding_holds=True,
        session_id=SESSION,
        started_by_operator=True,
    )
    with pytest.raises(RecoveryRefused) as refused:
        started._require_the_gates(
            descriptor(fingerprint="snapshot-fingerprint-substituted"),
            observations,
            session_id=SESSION,
            media_binding_holds=True,
            acquisition=Opens(),
            confirmed=True,
        )
    assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW
    assert started._cleared is None
    assert started.stage is RecoveryStage.REFUSED
    assert started.audit()[-1].event is SnapshotAuditEvent.RECOVERY_SNAPSHOT_SUBSTITUTED


class _SnapshotStandIn:
    """Three class attributes, which is all the gates used to read."""

    container_version = 1
    schema_version = 1
    integrity = SnapshotIntegrity.VERIFIED
    fingerprint = "snapshot-fingerprint-stand-in"


def test_a_clearance_is_spent_over_the_medium_the_gates_read(observations) -> None:
    """R8: a clearance said the gates passed, and nothing said *when*.

    The issue-and-spend interlock closed the route to a stage nobody passed
    the gates for. It said nothing about the interval between the two: a
    review passed the gates, fenced the medium, and then moved the stage,
    arriving at a stage reached over a medium that was fenced at every instant
    after the read.

    R10: this used to answer a bare `AttributeError`, outside
    `RecoveryRefused` — the seal's vocabulary for a *structural* violation,
    reached here instead through the one window `_require_an_unfenced_medium`
    cannot close (between its read, in `start`/`open_trial`/`commit`, and the
    stage write right after it). A caller who correctly wrote `except
    RecoveryRefused:` crashed. "The medium is fenced" is the same business
    fact every other gate expresses through `RecoveryRefused`, so this now
    does too — via `_refuse_gate`, terminally and audited, the same as a
    fence caught anywhere else.
    """

    flow = workflow(observations)
    flow._require_the_gates(
        descriptor(),
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=None,
        confirmed=None,
    )
    assert flow._cleared is not None

    flow._quarantine.fence()
    with pytest.raises(RecoveryRefused) as refused:
        flow._sealed_assign("_stage", RecoveryStage.PREFLIGHT_PASSED)
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.MEDIUM_FENCED

    # Terminal, and audited — a fence caught here is an event, the same as
    # everywhere else this module catches one, not a typo to retry past. A
    # further stage move, even to the one a genuine interruption reaches, is
    # refused as a terminal workflow, not honoured. R18 (security review):
    # `_sealed_assign`'s own terminal-stage guard now answers
    # `RecoveryRefused` too, so this is `RecoveryRefused` rather than the
    # bare `AttributeError` it used to be.
    assert flow.stage is RecoveryStage.REFUSED
    with pytest.raises(RecoveryRefused) as terminal:
        flow._sealed_assign("_stage", RecoveryStage.INTERRUPTED)
    assert terminal.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED
    assert flow.stage is RecoveryStage.REFUSED


def test_a_descriptor_rewritten_after_the_preflight_is_not_the_one_it_judged() -> None:
    """R8: the write record's key was derived from the object as it is now.

    `note_snapshot_written` re-derived the snapshot's four values at record
    time. The dataclass is frozen and its fields are pinned to exact types,
    and neither stops `object.__setattr__`: a review rewrote the fingerprint
    after a passing preflight, and the record was keyed on values no preflight
    had ever judged — so "once" counted it as a first write, and the audit's
    one positive classification named a snapshot nothing had looked at.
    """

    medium, snapshot, verdict = a_migration(
        snapshot=descriptor(fingerprint="snapshot-fingerprint-before")
    )
    ledger = MigrationLedger()
    object.__setattr__(snapshot, "_fingerprint", "snapshot-fingerprint-after")

    with pytest.raises(RecoveryRefused) as refused:
        ledger.note_snapshot_written(verdict, snapshot, quarantine=medium)
    assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW
    assert ledger.audit() == ()
    assert "snapshot-fingerprint-after" not in str(refused.value)


def test_two_media_in_one_sitting_each_record_their_own_write() -> None:
    """R8: the record's key was the **sitting**, and a sitting is not a medium.

    The key was `(session_id, the snapshot's four values)`, added to stop one
    sitting's entry from refusing an unrelated later sitting's write. A
    `PersistenceSession` has one sitting and can hold more than one
    quarantined medium, so two media in one boot collided: the second medium's
    genuine first write was refused as "a second write that did not happen" —
    the failure the key was introduced to fix, one level up.
    """

    snapshot = descriptor(fingerprint="snapshot-fingerprint-two-media")
    first_medium, _, first = a_migration(snapshot=snapshot)
    second_medium, _, second = a_migration(
        snapshot=snapshot, quarantine=a_quarantine(quarantined=False)
    )
    assert first_medium is not second_medium
    assert first_medium.session_id == second_medium.session_id

    # **One ledger**, deliberately. The per-ledger list of written values
    # carried no medium at all, so this pair collided inside a single ledger
    # even after the module-wide key was given one — and writing this test
    # with two ledgers would have stepped around the second bug while proving
    # the first. It is gone, and one ledger records both.
    ledger = MigrationLedger()
    ledger.note_snapshot_written(first, snapshot, quarantine=first_medium)
    ledger.note_snapshot_written(second, snapshot, quarantine=second_medium)
    assert [entry.event for entry in ledger.audit()] == [
        SnapshotAuditEvent.SNAPSHOT_WRITTEN,
        SnapshotAuditEvent.SNAPSHOT_WRITTEN,
    ]

    # And "once" still means once, **per medium**: a third verdict over the
    # first medium and the same values is the second record of one write.
    _, _, again = a_migration(snapshot=snapshot, quarantine=first_medium)
    with pytest.raises(RecoveryRefused) as refused:
        MigrationLedger().note_snapshot_written(again, snapshot, quarantine=first_medium)
    assert refused.value.refusal is Refusal.VERDICT_ALREADY_SPENT
    assert len(ledger.audit()) == 2


def test_the_second_record_refusal_is_raised_from_a_frame_holding_nothing() -> None:
    """R8: the refusal rendered the fingerprint and the sitting in plaintext.

    `_raise_gate_refused` exists because a captured-locals traceback renders
    the frame it was raised from. This refusal was raised from
    `note_snapshot_written`, whose locals at that moment held `written` and
    `recorded` — tuples of the descriptor's four values, which is exactly what
    `SnapshotDescriptor.__repr__` redacts.
    """

    snapshot = descriptor(fingerprint="snapshot-fingerprint-frame")
    medium, _, first = a_migration(snapshot=snapshot)
    MigrationLedger().note_snapshot_written(first, snapshot, quarantine=medium)

    _, _, again = a_migration(snapshot=snapshot, quarantine=medium)
    with pytest.raises(RecoveryRefused) as refused:
        MigrationLedger().note_snapshot_written(again, snapshot, quarantine=medium)
    assert refused.value.refusal is Refusal.VERDICT_ALREADY_SPENT

    deepest = refused.tb
    while deepest.tb_next is not None:
        deepest = deepest.tb_next
    assert deepest.tb_frame.f_code.co_name == "_raise_already_spent"
    assert deepest.tb_frame.f_locals == {}
    assert "snapshot-fingerprint-frame" not in repr(deepest.tb_frame.f_locals)
    assert SESSION not in repr(deepest.tb_frame.f_locals)


def test_a_permuted_order_does_not_produce_a_verdict_that_asked_every_check(
    monkeypatch,
) -> None:
    """R8: the completeness rule asked a **set**, and the naming rule was vacuous.

    Set equality was the passing half's whole question, so a rebound
    `PREFLIGHT_ORDER` that asked all ten in another order satisfied it — and
    the classification an operator is given is what the order decides. The
    refusing half asked whether the refusal named the last check evaluated,
    which `preflight` makes true by construction for every verdict it mints
    and no other verdict reaches the rule: a guard that cannot fail for its
    own reason is not a guard.
    """

    from azazel_boot import snapshot as module

    permuted = (
        PREFLIGHT_ORDER[1],
        PREFLIGHT_ORDER[0],
        *PREFLIGHT_ORDER[2:],
    )
    monkeypatch.setattr(module, "PREFLIGHT_ORDER", permuted)

    medium, snapshot, passing = a_migration(
        snapshot=descriptor(fingerprint="snapshot-fingerprint-permuted")
    )
    assert passing.may_migrate is True
    assert set(passing.evaluated) == set(PreflightCheck)
    with pytest.raises(RecoveryRefused) as refused:
        MigrationLedger().may_migrate(passing, quarantine=medium)
    assert refused.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK

    # And an order rebound to **ten copies of one check**, which is what a
    # length check and a set comparison each miss on their own: ten members,
    # one distinct value, `may_migrate` True over a medium whose fence,
    # quarantine, snapshot, space, schema and binding were never asked.
    monkeypatch.setattr(module, "PREFLIGHT_ORDER", (PreflightCheck.IMAGE_DIGEST,) * 10)
    repeated_medium, _, repeated = a_migration(
        snapshot=descriptor(fingerprint="snapshot-fingerprint-repeated")
    )
    assert repeated.may_migrate is True
    assert len(repeated.evaluated) == len(PreflightCheck)
    with pytest.raises(RecoveryRefused) as duplicated:
        MigrationLedger().may_migrate(repeated, quarantine=repeated_medium)
    assert duplicated.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK

    monkeypatch.setattr(module, "PREFLIGHT_ORDER", permuted)
    # And a refusal out of the same permuted order: it names a real check it
    # really stopped at, and the run that reached it is still not the order.
    other_medium = a_quarantine(quarantined=False)
    refusing = preflight(
        other_medium,
        snapshot=None,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert refusing.refused_by is PreflightCheck.SNAPSHOT_ABSENT
    assert refusing.evaluated[-1] is refusing.refused_by
    with pytest.raises(RecoveryRefused) as second:
        MigrationLedger().may_migrate(refusing, quarantine=other_medium)
    assert second.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK


def test_the_order_the_checks_are_asked_in_is_the_order_they_are_declared_in() -> None:
    """The ledger's completeness rule is asked against the enum, not the tuple.

    `PREFLIGHT_ORDER` is a module global and a rebindable one — that is the
    attack the rule exists for — so the question is put to `PreflightCheck`,
    which an assignment cannot shorten or permute. That only means anything
    while the two agree, and nothing in the source made them.
    """

    assert PREFLIGHT_ORDER == tuple(PreflightCheck)


def test_the_module_indexes_are_what_this_file_says_they_are() -> None:
    """`_MODULE_INDEXES` is an allowlist, and a stale name is a dead allowance.

    The quarantine-travel walk permits a quarantine to be put into the two
    indexes named there. Renaming one in the module would leave the allowance
    matching nothing — which fails open in the only direction that matters:
    quietly, with the suite green.
    """

    from azazel_boot import snapshot as module

    for name in _MODULE_INDEXES:
        assert hasattr(module, name), name
    # **Both are keyed by the medium**, which is what makes "nothing that
    # comes out of an index is a `Quarantine`" true. A review harvested the
    # sitting id and the boot medium identity out of this module through a
    # `for medium, written in …` over the record, which bound a live
    # `Quarantine` to a local — and the walk that bounds every quarantine here
    # finds them by the name they travel under.
    #
    # **`_WeakIdentityIndex`, not `WeakKeyDictionary`.** A `WeakKeyDictionary`
    # was tried, and `.keys()` on one dereferences every live weak key and
    # hands the real objects back — an ordinary public method, no possession
    # of the object required. A review called `list(_JUDGED_BY.keys())` and
    # read out every medium any preflight had judged, live, through the exact
    # container this module chose to avoid handing one back. The replacement
    # has no method that returns, iterates or otherwise exposes the object.
    assert type(module._SNAPSHOTS_RECORDED).__name__ == "_WeakIdentityIndex"
    assert type(module._JUDGED_BY).__name__ == "_WeakIdentityIndex"
    for index in (module._SNAPSHOTS_RECORDED, module._JUDGED_BY):
        assert not hasattr(index, "keys")
        assert not hasattr(index, "values")
        assert not hasattr(index, "items")
        assert not hasattr(index, "__iter__")


def test_a_value_that_is_not_a_verdict_is_refused_in_this_modules_vocabulary() -> None:
    """R8: the recording path asked the medium before asking what it held.

    `may_migrate` asks `verdict_was_minted_here` first and `note_snapshot_
    written` asked the medium first, so the two paths classified the same
    value differently — and the one that reads the verdict→medium index would
    have told an operator the medium had moved since a preflight that never
    ran.
    """

    medium = a_quarantine(quarantined=False)
    ledger = MigrationLedger()
    for value in (object(), None, PreflightVerdict(None)):
        with pytest.raises(RecoveryRefused) as refused:
            ledger.note_snapshot_written(value, descriptor(), quarantine=medium)
        assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT
    assert ledger.audit() == ()


def test_a_mint_without_a_medium_is_not_a_thing_that_can_be_minted() -> None:
    """The `None` the medium check's shortcut existed for is unreachable.

    `_mint` took the quarantine as a keyword defaulting to `None`, and
    `_require_the_medium_now` could therefore only ask "not a *different*
    one". Making it required is what makes that question unconditional.
    """

    from azazel_boot import snapshot as module

    with pytest.raises(TypeError, match="must be a Quarantine exactly"):
        module._mint(None, "not-a-quarantine")
    with pytest.raises(TypeError, match="must be a Quarantine exactly"):
        module._mint(None, None)


def test_the_gate_order_holds_where_two_gates_fail_at_once(observations, elsewhere) -> None:
    """R8: three of D8's adjacent pairs were contested by nothing.

    `test_each_gate_refuses_with_every_later_gate_also_failing` drives each
    gate failing with every **later** gate also failing, which is the right
    shape — and every one of its rows passes `media_binding_holds=True`, so
    the gate that reads it is contested against nothing, in either direction.
    A review moved target binding after key acquisition, host binding after
    target binding, and operator confirmation above integrity: all three ship
    green, and the classification is the whole of what ADR-0010 D7 promises an
    operator.

    Driven through `_require_the_gates` because two of the three cannot be
    reached any other way: a failed-integrity snapshot is refused at `start`,
    so it cannot be presented at a commit, and `confirmed` is not asked at a
    start. The module's own note that the key/integrity pair is uncontestable
    **at the commit** is unchanged and still true; this is the other reach.
    """

    def gates(**overrides):
        flow = workflow(observations)
        arguments = {
            "snapshot": descriptor(),
            "observations": observations,
            "media_binding_holds": True,
            "acquisition": Opens(),
            "confirmed": True,
        }
        arguments.update(overrides)
        with pytest.raises(RecoveryRefused) as refused:
            flow._require_the_gates(
                arguments["snapshot"],
                arguments["observations"],
                session_id=SESSION,
                media_binding_holds=arguments["media_binding_holds"],
                acquisition=arguments["acquisition"],
                confirmed=arguments["confirmed"],
            )
        assert refused.value.refusal is Refusal.GATE_REFUSED
        assert flow.stage is RecoveryStage.REFUSED
        return flow.audit()[-1].gate

    # D8 gate 1 before gate 2: which medium this is for, before unlocking it.
    assert (
        gates(media_binding_holds=False, acquisition=Opens(channel=NOT_A_CHANNEL))
        is RecoveryGate.TARGET_BINDING
    )
    # The host binding before gate 1: a machine that is not this one is not
    # told which of its media the recovery would have been for.
    assert (
        gates(observations=elsewhere, media_binding_holds=False)
        is RecoveryGate.HOST_BINDING
    )
    # D8 gate 3 before gate 4: an operator is not asked to confirm a restore
    # from a snapshot that did not verify, and a declined one is not what an
    # unverified snapshot is reported as.
    assert (
        gates(snapshot=descriptor(integrity=SnapshotIntegrity.FAILED), confirmed=False)
        is RecoveryGate.INTEGRITY_VERIFICATION
    )


def test_a_workflow_subclass_does_not_make_a_candidate_apply(observations) -> None:
    """R8: `candidate_applies_to` says "both operands", and pinned one.

    The candidate operand is driven against a subclass; the **flow** operand
    was driven only against a non-subclass stand-in, so `isinstance` in place
    of `type(...) is` shipped green — and a `RecoveryWorkflow` subclass whose
    `holds` answers `True` made a candidate nobody minted apply to a workflow
    nobody ran. `isinstance` is what the comment on that function says was
    removed from both sides.
    """

    class Liar(RecoveryWorkflow):
        def holds(self, candidate: RecoveryCandidate) -> bool:
            return True

    liar = Liar(
        a_quarantine(),
        SessionBinding(host_fingerprint=host_fingerprint(observations), session_id=SESSION),
        session_id=SESSION,
    )
    assert liar.holds(RecoveryCandidate(99, "not-minted-by-anyone")) is True
    assert candidate_applies_to(liar, RecoveryCandidate(99, "not-minted-by-anyone")) is False

    # And the real thing still answers, so this is not passing by refusing
    # everything.
    honest = workflow(observations)
    minted = run_to_commit(honest, observations)
    assert candidate_applies_to(honest, minted) is True


def test_a_capacity_report_refuses_a_bool_on_either_side() -> None:
    """R8: the exact-int pin was driven for `required` and not for `available`.

    `True` is an `int` that equals 1, so a caller's broken free-space probe
    returning a bool became "one byte free" rather than a refusal — and the
    asymmetry was purely in the test: the module refused it on one side and
    not the other, and nothing said so.
    """

    for arguments in (
        {"required": True, "available": 1000},
        {"required": 100, "available": True},
        {"required": False, "available": False},
    ):
        with pytest.raises(TypeError):
            CapacityReport(**arguments)

    assert CapacityReport(required=100, available=1000).has_room_for_the_snapshot() is True


def test_the_audit_entry_renders_the_payload_it_is_allowed_to_carry() -> None:
    """R8: every repr test in this file is an absence test.

    Dropping `schema_version` from `SnapshotAuditEntry.__repr__` is green,
    because nothing asserts the entry renders what it **is** for. An audit
    whose entries quietly stop saying which schema version a migration reached
    is still an audit that passes every "does not leak" test in the file.
    """

    entry = SnapshotAuditEntry(
        event=SnapshotAuditEvent.SNAPSHOT_WRITTEN,
        check=PreflightCheck.SCHEMA_COMPATIBILITY,
        gate=RecoveryGate.INTEGRITY_VERIFICATION,
        schema_version=2,
        fingerprint="snapshot-fingerprint-rendered",
    )
    rendered = repr(entry)
    assert "event=snapshot_written" in rendered
    assert "check=schema_compatibility" in rendered
    assert "gate=integrity_verification" in rendered
    assert "schema_version=2" in rendered
    assert "fingerprint=<redacted>" in rendered
    assert "snapshot-fingerprint-rendered" not in rendered


def test_a_fence_raised_between_the_gates_and_the_stage_is_a_refusal(observations) -> None:
    """The seal's rule is a backstop, not the answer a caller gets.

    `_sealed_assign` refuses to spend a clearance over a medium fenced since
    the gates read it, and it refuses with an `AttributeError`. The fence is
    raised by device monitoring rather than by any call in this module, so a
    legitimate stage move can meet that rule — and a caller writing `except
    RecoveryRefused`, which is the whole of this module's vocabulary, would
    have crashed instead of being refused. Round seven fixed the identical
    shape for an interruption from inside `attempt()`.

    **The window holds no caller code**, which is why the fence is raised here
    directly rather than from inside an acquisition: `attempt()` runs inside
    the gates, and the gates already re-read the fence after it. What is left
    is the interval between the gates returning and the stage moving, which
    only something outside this process can act in. So this drives the check
    the stage methods make, in the state that interval can be in.
    """

    rule = a_quarantine()
    flow = workflow(observations, quarantine=rule)
    snap = descriptor(fingerprint="snapshot-fingerprint-fenced-late")
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    acquisition = Opens()
    flow._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=acquisition,
        confirmed=True,
    )
    assert acquisition.attempts == 1
    rule.fence()

    with pytest.raises(RecoveryRefused) as refused:
        flow._require_an_unfenced_medium()
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.MEDIUM_FENCED
    assert flow.stage is RecoveryStage.REFUSED
    assert flow._candidate is None

    # And the volume is exactly as quarantined as it was.
    assert rule.volume_is_quarantined is True
    assert rule.is_fenced is True

    # Every stage method asks it, so none of them can move a stage over a
    # medium fenced since its gates read it. Derived from the source, because
    # a hand-written list of three goes stale on the day there is a fourth.
    for stage_method in ("start", "open_trial", "commit"):
        body = ast.unparse(
            [
                node
                for node in ast.walk(TREE)
                if isinstance(node, ast.FunctionDef) and node.name == stage_method
            ][0]
        )
        assert "_require_an_unfenced_medium()" in body, stage_method


def test_a_candidate_is_held_only_by_a_workflow_that_committed(observations) -> None:
    """R8 (self-review): `commit` writes the candidate, then moves the stage.

    Anything raising between those two writes — the fence going up is the one
    that can — left a workflow at `TRIAL_OPEN` holding a candidate that
    `holds` and `candidate_applies_to` both accepted, for a commit that never
    finished. A candidate is what a *completed* recovery produced.
    """

    flow = workflow(observations)
    snap = descriptor(fingerprint="snapshot-fingerprint-uncommitted")
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    # The clearance a full D8 run issues, so the candidate is legitimately
    # assignable — and the stage has not moved.
    flow._require_the_gates(
        snap,
        observations,
        session_id=SESSION,
        media_binding_holds=True,
        acquisition=Opens(),
        confirmed=True,
    )
    minted = RecoveryCandidate(snap.schema_version, snap.fingerprint)
    flow._sealed_assign("_candidate", minted)

    assert flow._candidate is minted
    assert flow.stage is RecoveryStage.TRIAL_OPEN
    assert flow.holds(minted) is False
    assert candidate_applies_to(flow, minted) is False


def _media_reachable_from(root: object, *, depth: int = 6) -> list[str]:
    """Every `Quarantine` reachable from `root`, with the path that found it.

    Deliberately not "every object": it walks the shapes module state actually
    takes — plain containers, the fields of objects this package defines, and
    the closures and defaults of its functions. A medium stashed somewhere this
    does not walk is a limit, and the limit is named rather than assumed away.

    **No class exemption any more.** R10 exempted `_WeakIdentityIndex` by
    name, because its `_by_id` dict — holding the live weak reference to a
    `Quarantine` — was that instance's own `__slots__` attribute, and walking
    it would have defeated the point of the object it was walking *for*. R11
    found that reasoning did not hold: `_by_id` was reachable through
    `gc.get_referents` on the index alone, no exemption asked. The fix moved
    the store off the instance entirely (`_INDEX_STORAGE`, a module global
    keyed by the index), so this walker no longer special-cases the class —
    it walks straight into `_INDEX_STORAGE` like any other `WeakKeyDictionary`
    global, and into the plain `dict` each index keeps there.

    What still stops it at a `Quarantine` is narrower and unexempted: each
    entry in that dict is `(weakref.ref, value)`, and a bare `weakref.ref` is
    not `dict`, `list`, `tuple`, `set`, a `WeakSet`/`WeakKeyDictionary`, a
    function or a value from `azazel_boot` — so the walk reaches it, cannot
    classify it, and stops without calling it. **Dereferencing it is
    `_WeakIdentityIndex.get`/`__contains__`'s own job**, gated by the identity
    check those methods run before handing anything back; nothing here
    special-cases the weak reference to avoid that job, it simply is not one
    of the shapes this walker knows how to open.
    """

    found: list[str] = []
    seen: set[int] = set()

    def walk(value: object, path: str, left: int) -> None:
        if left <= 0 or id(value) in seen:
            return
        seen.add(id(value))
        if isinstance(value, Quarantine):
            found.append(path)
            return
        if isinstance(value, dict | _weakref.WeakKeyDictionary):
            # `list(value.items())`, not `list(value.keys())` followed by a
            # second `value[key]` lookup: a `WeakKeyDictionary`'s key can die
            # between those two calls (R12 test-suite review — reproduced as
            # a genuine, GC-timing-dependent `KeyError`, not a mutation-
            # testing artefact), and `.items()` captures both atomically.
            for key, held in list(value.items()):
                walk(key, f"{path}.<key>", left - 1)
                walk(held, f"{path}[{type(key).__name__}]", left - 1)
            return
        if isinstance(value, list | tuple | set | frozenset | _weakref.WeakSet):
            for index, item in enumerate(list(value)):
                walk(item, f"{path}[{index}]", left - 1)
            return
        if inspect.isfunction(value):
            for cell in value.__closure__ or ():
                walk(cell.cell_contents, f"{path}.<closure>", left - 1)
            for default in value.__defaults__ or ():
                walk(default, f"{path}.<default>", left - 1)
            return
        if type(value).__module__.startswith("azazel_boot"):
            for name in getattr(type(value), "__slots__", ()):
                if name == "__weakref__":
                    continue
                walk(getattr(value, name, None), f"{path}.{name}", left - 1)
            for name, held in vars(value).items() if hasattr(value, "__dict__") else ():
                walk(held, f"{path}.{name}", left - 1)

    walk(root, "module", depth)
    return found


def test_no_module_level_state_in_this_module_holds_a_medium(observations) -> None:
    """R9: the travel walk finds a quarantine by the name it travels under.

    A review added a module-level list and appended `(quarantine, session_id,
    boot_medium_identity)` to it from inside this module's own index helpers,
    where a medium arrives as a **local** — a parameter of nothing and an
    annotation of nothing, so neither
    `test_this_module_never_calls_anything_that_would_change_a_quarantine` nor
    `test_no_parameter_that_holds_a_quarantine_is_spelled_anything_else` looked
    at it. The whole suite stayed green, and the live `Quarantine`, the sitting
    id and the boot medium identity were readable from `azazel_boot.snapshot`
    by anything in the process. The module's own bookkeeping was the leak.

    A spelling rule cannot see a local, so this asks the running module a
    different question: after a full drive, is a medium reachable from this
    module's globals at all? Round 10 found the previous answer here false:
    `_JUDGED_BY`/`_SNAPSHOTS_RECORDED` were `WeakKeyDictionary` instances, and
    this test's own exemption treated a weak key as the one permitted place —
    on the strength of the docstring claim that "a weak key hands nothing
    back, because reaching it needs the object already." `.keys()` on a
    `WeakKeyDictionary` needs no such thing: it dereferences every live weak
    key and hands the real objects back, an ordinary public method call. Both
    indexes are `_WeakIdentityIndex` now, keyed by `id()` rather than by the
    object, with no method that returns, iterates or otherwise exposes it —
    so this walk exempts nothing but that class's own private store.
    """

    from azazel_boot import snapshot as module

    rule = a_quarantine(quarantined=False)
    snapshot = descriptor(fingerprint="snapshot-fingerprint-reachability")
    verdict = preflight(
        rule,
        snapshot=snapshot,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    ledger = MigrationLedger()
    assert ledger.may_migrate(verdict, quarantine=rule) is True
    ledger.note_snapshot_written(verdict, snapshot, quarantine=rule)

    recovered = workflow(observations)
    run_to_commit(recovered, observations, snapshot=descriptor(fingerprint="snapshot-reach-2"))

    # The indexes really did record something over this drive, so the walk
    # below is over live bookkeeping rather than an empty structure that
    # would pass trivially.
    assert rule in module._JUDGED_BY, "the drive was expected to key an index by a medium"
    assert module._SNAPSHOTS_RECORDED.get(rule) is not None, (
        "the drive was expected to record a write"
    )

    escaped = _media_reachable_from(vars(module))
    assert not escaped, escaped

    # And the guard is not vacuous: a plain module-level container holding a
    # medium — the shape a review actually used — is still found.
    module._a_harvester_for_this_test = [rule]
    try:
        assert _media_reachable_from(vars(module))
    finally:
        del module._a_harvester_for_this_test

    # Nor does the class-name exemption cover more than the real class: the
    # walk only reaches objects whose module starts with `azazel_boot` at
    # all, so a same-named class from anywhere else is never walked into in
    # the first place, exempted or not — asserted here so that guard cannot
    # be quietly narrowed to admit one without this test noticing.
    assert module._WeakIdentityIndex.__module__ == "azazel_boot.snapshot"


def test_a_fingerprint_is_an_opaque_token_and_not_a_rendered_record() -> None:
    """R9: the audit's one caller-supplied string was type-pinned, not shaped.

    `SnapshotAuditEntry.fingerprint` is the object a log actually holds, and
    the confidentiality claim around it is about which **fields** the entry
    has. A review put a rendered record — a capacity figure, a device serial
    and a host path — through `_require_an_exact_str` and into an audit entry,
    where every other value is redacted.

    This narrows and does not guarantee: a caller who hides a serial inside an
    opaque-looking token still can, and the docstring says so. What it removes
    is the shape that turns one field into a log line.
    """

    for rejected in (
        "capacity_available=17179869184 medium=usb-SN-AA11BB22 host=/dev/nvme0n1p3",
        "/dev/nvme0n1p3",
        "snapshot fingerprint",
        "two\nlines",
        "a" * 129,
        # R11 (test-suite review): every case above combines "=" with a space
        # or a slash, so it was never asked in isolation — a mutant dropping
        # `"="` from the forbidden-character tuple survived undetected. One
        # rendered `key=value` field, with neither, isolates it.
        "generation=17",
    ):
        with pytest.raises(TypeError, match="opaque"):
            descriptor(fingerprint=rejected)

    # And an actually opaque one is accepted, so this is not refusing
    # everything.
    assert descriptor(fingerprint="b3c1d9e07f2a4856").fingerprint == "b3c1d9e07f2a4856"

    # R19 (test-suite review): the length check's own boundary was never
    # driven — only 129 (rejected) and a short opaque token (accepted), with
    # nothing at the boundary itself. A mutant tightening `> 128` to `>= 128`
    # survived the whole suite undetected. Isolated the same way R11 isolated
    # each forbidden character above: the true boundary value, accepted.
    assert descriptor(fingerprint="a" * 128).fingerprint == "a" * 128


def test_the_seals_other_door_is_shut_on_every_class_that_has_one() -> None:
    """R9: `del x._sealed` cost less than everything built on top of it.

    Every seal in this package gates on `getattr(self, "_sealed", False)`, and
    `_sealed` is an ordinary slot. A review deleted it with plain syntax — no
    dunder call, nothing for a static scan to see — and then wrote a stage, a
    candidate, a quarantine and a sitting onto a workflow **by assignment**,
    reaching `COMMITTED` with a forged candidate and an empty audit, past the
    moving-fields allowlist, the stage graph and the clearance interlock at
    once. The same `del` turned the volume quarantine off on a `Quarantine`
    and forged a `MigrationLedger`'s audit.

    Derived from the source rather than listed, because a thirteenth sealed
    class should inherit this on the day it is written.
    """

    import azazel_boot

    package = Path(azazel_boot.__file__).parent
    sealed: list[tuple[str, str]] = []
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            defined = {body.name for body in node.body if isinstance(body, ast.FunctionDef)}
            if "__setattr__" in defined:
                sealed.append((path.name, node.name, "__delattr__" in defined))

    assert len(sealed) >= 12, sealed
    assert not [(name, cls) for name, cls, has in sealed if not has]

    # And it refuses, rather than merely existing.
    rule = a_quarantine()
    flow = RecoveryWorkflow(
        rule,
        SessionBinding(host_fingerprint="0" * 64, session_id=SESSION),
        session_id=SESSION,
    )
    for target in (rule, flow, MigrationLedger()):
        with pytest.raises(AttributeError):
            del target._sealed
        assert object.__getattribute__(target, "_sealed") is True

    # The route the seal existed to stop, still stopped: the `del` refused, so
    # the plain assignment behind it never happens.
    with pytest.raises(AttributeError):
        flow._stage = RecoveryStage.COMMITTED
    assert flow.stage is RecoveryStage.NOT_STARTED
    assert rule.volume_is_quarantined is True


def test_confirmed_is_type_checked_inside_the_gates_directly(observations) -> None:
    """R9 F3: `confirmed` was the one gate input still the caller's alone.

    Round 8 pinned the snapshot, the observations, the sitting and
    `media_binding_holds` inside `_require_the_gates` because a review reaches
    it directly, at the same bound-method reach as `_sealed_assign`.
    `confirmed` was checked only in `commit`. `confirmed="declined"` is truthy,
    so `confirmed is not None` is `True`, the full-D8 clearance was issued, and
    a direct call reached `COMMITTED` with a forged candidate and no
    `OPERATOR_CONFIRMATION` refusal anywhere in the audit.
    """

    flow = workflow(observations)
    snap = descriptor(fingerprint="snapshot-fingerprint-confirmed-typecheck")
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    with pytest.raises(TypeError, match="confirmed"):
        flow._require_the_gates(
            snap,
            observations,
            session_id=SESSION,
            media_binding_holds=True,
            acquisition=Opens(),
            confirmed="declined",
        )
    assert flow._cleared is None
    assert flow.stage is RecoveryStage.TRIAL_OPEN

    # And the hostile value from the module's own worked example, driven all
    # the way: it never reaches COMMITTED, and nothing is minted.
    with pytest.raises(TypeError, match="confirmed"):
        flow._require_the_gates(
            snap,
            observations,
            session_id=SESSION,
            media_binding_holds=True,
            acquisition=Opens(),
            confirmed=[0],
        )
    with pytest.raises(AttributeError, match="reached by passing the gates"):
        flow._sealed_assign("_stage", RecoveryStage.COMMITTED)
    assert flow.stage is RecoveryStage.TRIAL_OPEN


def test_a_gate_refusal_on_an_already_finished_workflow_stays_in_vocabulary(
    observations,
) -> None:
    """R9 F5: round 7's re-check covered exactly the one row it drove.

    `attempt()` is caller code called mid-gate, and a review interrupts the
    workflow from inside it. `commit` re-checks the stage **after**
    `_require_the_gates` returns, so that re-check only ever sees a gate that
    passed. Any gate refusal reached from *inside* `_require_the_gates` after
    the workflow went terminal met `_sealed_assign`'s terminal rule instead,
    which raises `AttributeError` — outside `RecoveryRefused`, outside
    `Refused`, and outside the single `except` this package promises. Two rows
    reach it: an operator who stops mid-prompt and then declines, and one who
    stops and has the medium pulled.
    """

    class EndsTheWorkflow:
        """An acquisition whose `attempt()` interrupts its own workflow."""

        channel = PassphraseChannel.LOCAL_HIDDEN_PROMPT

        def __init__(self, flow: RecoveryWorkflow, *, then_fence: bool = False) -> None:
            self._flow = flow
            self._then_fence = then_fence

        def attempt(self) -> AttemptOutcome:
            self._flow.interrupt(session_id=SESSION)
            if self._then_fence:
                self._flow._quarantine.fence()
            return AttemptOutcome.OPENED

    # Row D: interrupted, then a declined confirmation reaches the gate that
    # used to raise `AttributeError` from inside a terminal-stage move.
    declined = workflow(observations)
    snap = descriptor(fingerprint="snapshot-fingerprint-interrupted-declined")
    declined.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    declined.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    with pytest.raises(RecoveryRefused) as refused:
        declined.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=EndsTheWorkflow(declined),
            confirmed=False,
        )
    assert refused.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED
    assert declined.stage is RecoveryStage.INTERRUPTED
    assert declined._candidate is None

    # Row E: interrupted, then fenced, then a commit that would have refused
    # `MEDIUM_FENCED` inside `_require_the_gates`'s post-prompt re-read.
    fenced = workflow(observations)
    snap2 = descriptor(fingerprint="snapshot-fingerprint-interrupted-fenced")
    fenced.start(
        snap2, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    fenced.open_trial(snap2, observations, media_binding_holds=True, session_id=SESSION)
    with pytest.raises(RecoveryRefused) as refused2:
        fenced.commit(
            snap2,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=EndsTheWorkflow(fenced, then_fence=True),
            confirmed=True,
        )
    assert refused2.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED
    assert fenced.stage is RecoveryStage.INTERRUPTED
    assert fenced._candidate is None
    assert fenced._quarantine.volume_is_quarantined is True


def test_a_real_second_thread_interrupting_between_the_two_final_writes_stays_in_vocabulary(
    observations,
) -> None:
    """R17 (security review): every re-check above this test's sibling
    covers a *single-threaded reentrancy* window — caller code, called back
    from inside `_require_the_gates` via `attempt()`. This is a different,
    narrower window that only a genuine second OS thread can reach: between
    `commit`'s two final writes, `_sealed_assign("_candidate", minted)` and
    `_sealed_assign("_stage", COMMITTED)`, nothing single-threaded runs at
    all — the gap exists only because the GIL can switch between two
    separate method calls, not because of any callback this module invokes.

    A real `threading.Thread` calling `interrupt()` in that exact gap moved
    `_stage` to `INTERRUPTED` (a legal edge needing no clearance), and the
    `commit` thread's own `_sealed_assign("_stage", COMMITTED)` then met
    `_sealed_assign`'s terminal-stage guard and raised a bare
    `AttributeError` — outside `RecoveryRefused`, the same "caller who
    wrote `except RecoveryRefused:` crashed" shape round 7's re-check
    closed for the single-threaded case, reopened here for the threaded
    one. Round seventeen closed it with a `_require_stage(TRIAL_OPEN)`
    re-check immediately before that final write.

    **R18 (test-suite review) proved the re-check itself was never enough**:
    it and the write it guards are two separate statements, so the identical
    race re-opens in the gap between *them* — reproduced directly against
    round seventeen's own fix. There is no re-check that closes a gap of
    this shape; round seventeen's re-check is gone, and `_sealed_assign`'s
    terminal-stage guard answered `RecoveryRefused` itself instead — but a
    round-nineteen review then drove two genuinely concurrent, entirely
    legitimate `commit()` calls (no `interrupt()` needed at all) and got a
    real double commit: both passed every check before either wrote,
    because nothing serialised the *whole* read-then-write sequence, only
    each individual `_sealed_assign` call. **`start`/`open_trial`/
    `interrupt` and `_sealed_assign` itself now each acquire
    `self._lock` (a per-instance `threading.RLock`) around their entire
    body, and `commit` around all of its body but one call** (round
    twenty released the lock across `_require_the_gates`, to avoid holding
    it across `attempt()`'s wait on a human — see that method's own
    comment; the write this test drives at is in the section still fully
    locked), so no second call on the same workflow — this method or a
    different one, `interrupt` racing in included — can proceed past the
    lock at all until the first one currently holding it has released it.
    This test still drives the same real race in the same real gap; what it
    now proves is that `interrupt()`, started while `commit()` is paused
    mid-body holding the lock, simply cannot proceed until `commit()`
    releases it — so the interleaving this test injects can no longer land
    inside this specific locked section at all, only after it, which is
    exactly the deterministic outcome asserted below.

    The `RecoveryCandidate` `commit` had already minted before the race
    lands is never returned either way (the exception fires before
    `return minted`), and `holds()` asks the stage as well as the object —
    doctrine holds regardless of which thread wins.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    candidate_written = threading.Event()
    let_commit_continue = threading.Event()
    original_sealed_assign = RecoveryWorkflow._sealed_assign

    def racy_sealed_assign(self: RecoveryWorkflow, name: str, value: object) -> None:
        original_sealed_assign(self, name, value)
        if name == "_candidate":
            candidate_written.set()
            let_commit_continue.wait(timeout=30)

    RecoveryWorkflow._sealed_assign = racy_sealed_assign
    commit_outcome: dict[str, object] = {}
    interrupt_outcome: dict[str, object] = {}
    try:

        def do_commit() -> None:
            try:
                candidate = flow.commit(
                    snap,
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                    acquisition=Opens(),
                    confirmed=True,
                )
                commit_outcome["kind"] = "returned"
                commit_outcome["candidate"] = candidate
            except RecoveryRefused as refused:
                commit_outcome["kind"] = "refused"
                commit_outcome["refusal"] = refused.refusal

        def do_interrupt() -> None:
            try:
                flow.interrupt(session_id=SESSION)
                interrupt_outcome["kind"] = "returned"
            except RecoveryRefused as refused:
                interrupt_outcome["kind"] = "refused"
                interrupt_outcome["refusal"] = refused.refusal

        committer = threading.Thread(target=do_commit)
        committer.start()
        assert candidate_written.wait(timeout=30)
        # `interrupt()` now blocks on `self._lock`, held by the paused
        # `commit()` — it cannot run at all until `commit()` releases the
        # pause and finishes. Joined only after the release, below.
        interrupter = threading.Thread(target=do_interrupt)
        interrupter.start()
        let_commit_continue.set()
        committer.join(timeout=30)
        interrupter.join(timeout=30)
    finally:
        RecoveryWorkflow._sealed_assign = original_sealed_assign

    # The lock makes this deterministic: `commit()` had already paused past
    # its point of no return before `interrupt()` could even try to run, so
    # `commit()` always wins now, cleanly, and `interrupt()` always meets an
    # already-`COMMITTED`, terminal workflow.
    assert commit_outcome["kind"] == "returned"
    assert flow.stage is RecoveryStage.COMMITTED
    assert flow.holds(commit_outcome["candidate"])
    assert interrupt_outcome["kind"] == "refused"
    assert interrupt_outcome["refusal"] is Refusal.WORKFLOW_ALREADY_FINISHED


class _CountingRLock:
    """Wraps a real `RLock`, counting every time its recursion depth drops
    back to zero — a genuine full release, not a nested one. Used to prove
    a *span* of code never lets go of the lock, which a race between two
    threads landing (or not landing) in a gap cannot prove on its own: a
    probabilistic race test can show a gap is exploitable when one exists,
    but "the lock was never fully released across this stretch" is a
    structural claim about the code's shape, checked more directly by
    asking the lock itself.
    """

    def __init__(self) -> None:
        self._real = threading.RLock()
        self._own = threading.Lock()
        self._depth = 0
        self.full_release_count = 0

    def acquire(self, *args, **kwargs):
        acquired = self._real.acquire(*args, **kwargs)
        if acquired:
            with self._own:
                self._depth += 1
        return acquired

    def release(self) -> None:
        self._real.release()
        with self._own:
            self._depth -= 1
            if self._depth == 0:
                self.full_release_count += 1

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc_info) -> None:
        self.release()


def test_commits_candidate_and_stage_writes_share_one_uninterrupted_lock_hold(
    observations,
) -> None:
    """R21 (test-suite review): a coverage gap in the double-commit tests
    themselves.

    `test_two_real_threads_committing_the_same_workflow_produce_one_
    candidate` proves two *concurrent* `commit()` calls cannot both
    succeed — but its checkpoints pause a thread from *inside* the
    patched `_sealed_assign` call, which means the paused thread still
    holds `self._lock` throughout the pause: the same protection the
    lock already gives, exercised again, never landing in a gap that
    would only exist if `commit()`'s second locked section — mint
    through the final `RECOVERY_COMPLETED` record, the one round 20's own
    comment calls "unbroken" — were ever split into two separate acquire/
    release cycles by a future change. A round-21 review built exactly
    that mutant (release the lock right after the `"_candidate"` write,
    reacquire right before the `"_stage"` write) and measured **0/200**
    detection from the existing race tests, plus a clean full-suite pass
    — a real, if narrow, regression this file had no test for.

    This asks the question directly instead of racing for it: replace
    `flow._lock` with a wrapper that counts genuine full releases (depth
    dropping to zero, not a nested `RLock` reentry), record that count
    immediately after the `"_candidate"` write and again immediately
    after the `"_stage"` write, and assert they are equal — proving no
    full release happened anywhere in between, structurally, on every run,
    with no dependence on thread scheduling at all.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    counting_lock = _CountingRLock()
    object.__setattr__(flow, "_lock", counting_lock)

    release_count_at: dict[str, int] = {}
    original_sealed_assign = RecoveryWorkflow._sealed_assign

    def recording_sealed_assign(self: RecoveryWorkflow, name: str, value: object) -> None:
        original_sealed_assign(self, name, value)
        if name in ("_candidate", "_stage"):
            release_count_at[name] = counting_lock.full_release_count

    RecoveryWorkflow._sealed_assign = recording_sealed_assign
    try:
        candidate = flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        )
    finally:
        RecoveryWorkflow._sealed_assign = original_sealed_assign

    assert flow.holds(candidate)
    assert "_candidate" in release_count_at
    assert "_stage" in release_count_at
    # The actual claim: not one full release of `self._lock` happened
    # between minting the candidate and moving the stage to `COMMITTED`.
    assert release_count_at["_candidate"] == release_count_at["_stage"]


def test_two_real_threads_committing_the_same_workflow_produce_one_candidate(
    observations,
) -> None:
    """R19 (security review): the headline finding — a genuine double commit.

    Round 18 fixed `_sealed_assign`'s terminal-stage guard so a *losing*
    thread's write meets `RecoveryRefused` instead of a bare
    `AttributeError` — but it never serialised the *winners*. A round-19
    review drove two genuinely concurrent, entirely legitimate `commit()`
    calls on one `TRIAL_OPEN` workflow (no hostile input, no `interrupt()`
    involved) using `sys.setswitchinterval` to widen the ordinary
    GIL-scheduling window, and got a real double commit in 322 of 4000
    trials: **both** calls returned successfully, each with its own honestly
    minted `RecoveryCandidate`, and `flow.audit()` ended up holding two
    `RECOVERY_COMPLETED` entries for a workflow whose whole design is
    one-way and audited exactly once. Worse, one of the two legitimately
    *returned* candidates then failed `flow.holds()`, because the loser's
    write clobbered `_candidate` after the winner had already read it back
    — contradicting round 18's own claim that "no write these races contest
    is ever returned to a caller."

    `self._lock`, a per-instance `RLock` each of `start`/`open_trial`/
    `interrupt`/`_sealed_assign` holds for its entire body, and `commit`
    for all of its body except the call into `_require_the_gates` (round
    twenty released the lock there, to avoid holding it across
    `attempt()`'s wait on a human — see `commit`'s own comment above that
    call), closes this: only one call can be inside a locked section, on
    one workflow, at a time. This test's own race lands in the section
    that is still fully locked — the mint and the two final writes — so a
    second concurrent `commit()` racing to reach *that* section cannot
    begin until the first has completely finished it (and moved the stage
    to the terminal `COMMITTED`), meeting `_require_stage`'s ordinary
    refusal there. (A concurrent `commit()` *can* begin reading state and
    reach as far as `_require_the_gates`/`attempt()` while another is
    still in progress — that specific window is what the checkpoints below
    are built to drive into.)

    Forced deterministically at **two** checkpoints, not left to
    GIL-scheduling luck at either: `_sealed_assign` is patched to pause
    **before** performing each thread's first `"_candidate"` write, and
    again before its first `"_stage"` write, each time until *both* threads
    have arrived at that checkpoint and are released together. Pausing
    *before* the real write (not after, as an earlier version of this test
    did — which missed the bug more often than it caught it, because by the
    time both threads had *already written* `_candidate`, whichever one's
    `_stage` write happened to run first after release usually still ended
    up matching `self._candidate`, silently hiding the corruption in that
    specific interleaving) is what makes both effects of the race land
    together: with no lock, both threads perform their `_candidate` writes
    back to back with no reader in between, then both are released to
    perform their `_stage` writes essentially simultaneously — usually
    producing either two `RECOVERY_COMPLETED` entries for one one-way,
    once-audited workflow, or a returned candidate `holds()` denies. With
    `self._lock` in place, "b" blocks at `with self._lock:` before it can
    reach either patched checkpoint at all, so neither of its "arrived"
    signals ever fires and "a" runs both checkpoints, and the whole method,
    alone — the correct, deterministic outcome this test asserts on every
    attempt, every time, against the real fix.

    Even with both checkpoints released together, the final stretch — the
    `object.__setattr__` calls inside `_sealed_assign`'s `"_stage"` branch —
    is only a handful of bytecodes, well under the default scheduler's
    switch granularity; whichever thread the OS wakes first from
    `Event.wait()` can still occasionally run that whole branch before the
    GIL offers the other a turn, which — without the lock — sometimes still
    leaves a single clean winner rather than corruption, purely by luck.
    `sys.setswitchinterval` narrows that window, and repeated attempts (a
    fresh workflow each time) drive the residual chance of every one of
    them landing on that lucky, corruption-free interleaving down — while
    every attempt against the real fix takes the same deterministic,
    lock-blocked path every time, so no number of attempts changes its
    outcome.

    R20 (test-suite review): measured directly against the lock removed —
    `self._lock` replaced with `contextlib.nullcontext()` — a whole *run*
    of this test (5 attempts) missed the corruption 3 times in 40 runs
    (~7.5% of runs), not the "negligible" this docstring used to claim
    outright. Solving `p ** 5 ≈ 0.075` for the per-*attempt* miss rate
    gives `p ≈ 0.6`, matching independent measurements elsewhere of this
    same final stretch. Raised from five attempts to twenty: at that
    per-attempt rate the chance every one of twenty still lands on the
    lucky, corruption-free interleaving is `0.6 ** 20`, on the order of
    `4e-5` — small enough that no measured run has hit it, and every
    attempt against the real fix still takes the same deterministic,
    lock-blocked path regardless, so this only costs wall-clock time, not
    correctness on the passing side.
    """

    def attempt() -> None:
        flow = workflow(observations)
        snap = descriptor()
        flow.start(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            started_by_operator=True,
        )
        flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

        checkpoints = ("_candidate", "_stage")
        arrived = {name: {"a": threading.Event(), "b": threading.Event()} for name in checkpoints}
        release = {name: threading.Event() for name in checkpoints}
        label_of = threading.local()
        original_sealed_assign = RecoveryWorkflow._sealed_assign

        def racy_sealed_assign(self: RecoveryWorkflow, name: str, value: object) -> None:
            label = getattr(label_of, "label", None)
            if label is not None and name in checkpoints and not arrived[name][label].is_set():
                arrived[name][label].set()
                release[name].wait(timeout=30)
            original_sealed_assign(self, name, value)

        RecoveryWorkflow._sealed_assign = racy_sealed_assign
        outcomes: dict[str, dict[str, object]] = {}

        def do_commit(label: str) -> None:
            label_of.label = label
            outcomes[label] = {}
            try:
                candidate = flow.commit(
                    snap,
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                    acquisition=Opens(),
                    confirmed=True,
                )
                outcomes[label]["kind"] = "returned"
                outcomes[label]["candidate"] = candidate
            except RecoveryRefused as refused:
                outcomes[label]["kind"] = "refused"
                outcomes[label]["refusal"] = refused.refusal

        original_switch_interval = sys.getswitchinterval()
        try:
            sys.setswitchinterval(1e-6)
            a_thread = threading.Thread(target=do_commit, args=("a",))
            a_thread.start()
            # First checkpoint: "a" pauses before writing "_candidate". "b"
            # has not started yet, so it cannot possibly arrive here —
            # releasing unblocks "a" alone, which performs its write and
            # moves on towards the second checkpoint.
            assert arrived["_candidate"]["a"].wait(timeout=30)
            release["_candidate"].set()

            b_thread = threading.Thread(target=do_commit, args=("b",))
            b_thread.start()
            # Whether "b" reaches this same checkpoint at all is exactly
            # what `self._lock` decides: present, "b" is still blocked at
            # `with self._lock:` and never arrives; absent, "b" reaches it
            # and sails straight through (`release["_candidate"]` is
            # already set), performing its own "_candidate" write
            # concurrently with "a" already past the first checkpoint and
            # heading for the second.
            arrived["_candidate"]["b"].wait(timeout=0.4)

            # Second checkpoint: both threads pause before writing
            # "_stage", released together — the point where, without the
            # lock, both threads' writes land essentially simultaneously.
            assert arrived["_stage"]["a"].wait(timeout=30)
            stage_b_arrived = arrived["_stage"]["b"].wait(timeout=0.4)
            release["_stage"].set()

            a_thread.join(timeout=30)
            b_thread.join(timeout=30)
        finally:
            sys.setswitchinterval(original_switch_interval)
            RecoveryWorkflow._sealed_assign = original_sealed_assign

        if not stage_b_arrived:
            # The lock worked at every checkpoint "b" could have reached:
            # "a" ran the whole method alone, and "b" only started (and was
            # cleanly refused) once "a" had already finished.
            assert outcomes["a"]["kind"] == "returned"
            assert outcomes["b"]["kind"] == "refused"
            assert outcomes["b"]["refusal"] is Refusal.WORKFLOW_ALREADY_FINISHED
            assert flow.holds(outcomes["a"]["candidate"])
            assert [entry.event for entry in flow.audit()] == [
                SnapshotAuditEvent.RECOVERY_STARTED,
                SnapshotAuditEvent.RECOVERY_TRIAL_OPENED,
                SnapshotAuditEvent.RECOVERY_COMPLETED,
            ]
            return

        # "b" reached both patched checkpoints alongside "a" — the race
        # manifested at the exact place the corruption happens. Without
        # `self._lock` this is *usually* real corruption (either both
        # calls returned — two `RECOVERY_COMPLETED` entries for one
        # one-way, once-audited workflow — or one call returned a
        # candidate that `holds()` denies), asserted here; on the rare
        # attempt where the interleaving still lands cleanly despite the
        # race, these assertions simply pass and the loop below tries
        # again.
        kinds = sorted(outcome["kind"] for outcome in outcomes.values())
        assert kinds == ["refused", "returned"], outcomes
        winner = next(outcome for outcome in outcomes.values() if outcome["kind"] == "returned")
        assert flow.holds(winner["candidate"])
        assert len(flow.audit()) == 3
        assert flow.audit()[-1].event is SnapshotAuditEvent.RECOVERY_COMPLETED

    for _attempt in range(20):
        attempt()


class _BlocksOnAnEvent:
    """An acquisition whose `attempt()` blocks until told to stop, like a
    real operator prompt — used to force `commit()` to sit inside
    `_require_the_gates` for as long as a test needs, without a real human.
    """

    channel = PassphraseChannel.LOCAL_HIDDEN_PROMPT

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def attempt(self) -> AttemptOutcome:
        self.entered.set()
        # A generous timeout, not a tight one — round 27 standardized every
        # other thread-rendezvous wait in this file to `timeout=30` for
        # exactly this reason and a round-28 test-suite review found this
        # one call, a rendezvous wait in every sense (`commit()` sits here
        # until the main test thread calls `self.release.set()`), had been
        # missed by that sweep. Left at 10s under this environment's
        # documented scheduling contention, it can fire before the main
        # thread reaches the release call, producing a confusing
        # `'refused' == 'returned'` failure instead of the clear deadlock
        # diagnosis the test means to give.
        self.release.wait(timeout=30)
        return AttemptOutcome.OPENED


def test_interrupt_does_not_deadlock_against_a_commit_blocked_in_attempt(
    observations,
) -> None:
    """R20 (security review): a genuine circular wait `self._lock` introduced.

    Round 19's fix held `self._lock` across `commit()`'s entire body,
    `_require_the_gates` — and so `acquisition.attempt()`, "the one step in
    this workflow that blocks on a human" — included. A round-20 review
    built the natural integration pattern this breaks: a cancel handler that
    calls `interrupt()` *first*, to record the interruption before tearing
    anything down, and only afterwards releases whatever `attempt()` was
    waiting on. With the lock held across `attempt()`, that is a genuine,
    unbounded circular wait — `commit()` blocked inside `attempt()` holding
    the lock, waiting for a release only the interrupter sends; the
    interrupter blocked on the lock, only sending that release after
    `interrupt()` returns, which it never does. Confirmed live: `interrupt()`
    made no progress in a 20-second window.

    `commit()` no longer holds `self._lock` across the call into
    `_require_the_gates` (see the comment there, and in `__init__`), so this
    same ordering no longer deadlocks: `interrupt()` runs and returns while
    `commit()` is still parked inside `attempt()`, unprotected exactly where
    it needs to be. Once `attempt()` is released, `commit()`'s own
    post-prompt re-check — the ordinary "again, after the prompt" pattern —
    finds the workflow already `INTERRUPTED` (a terminal stage) and refuses
    cleanly, the same vocabulary every other race in this file resolves to.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    acquisition = _BlocksOnAnEvent()
    commit_outcome: dict[str, object] = {}

    def do_commit() -> None:
        try:
            candidate = flow.commit(
                snap,
                observations,
                media_binding_holds=True,
                session_id=SESSION,
                acquisition=acquisition,
                confirmed=True,
            )
            commit_outcome["kind"] = "returned"
            commit_outcome["candidate"] = candidate
        except RecoveryRefused as refused:
            commit_outcome["kind"] = "refused"
            commit_outcome["refusal"] = refused.refusal

    committer = threading.Thread(target=do_commit)
    committer.start()
    # `commit()` is now parked inside `attempt()`, holding no lock while it
    # waits — exactly the scenario finding this test drives.
    assert acquisition.entered.wait(timeout=30)

    interrupt_outcome: dict[str, object] = {}

    def do_interrupt() -> None:
        try:
            flow.interrupt(session_id=SESSION)
            interrupt_outcome["kind"] = "returned"
        except RecoveryRefused as refused:
            interrupt_outcome["kind"] = "refused"
            interrupt_outcome["refusal"] = refused.refusal

    interrupter = threading.Thread(target=do_interrupt)
    interrupter.start()
    # The deadlock, if this fix were absent, is unbounded — no timeout on
    # `interrupt()`'s own side would ever fire, since it is not `interrupt()`
    # waiting on a clock, it is `interrupt()` waiting on a lock nothing will
    # ever release. `join(timeout=...)` here only bounds how long *this test*
    # waits before declaring the deadlock; it does not paper over one.
    # `timeout=30`, not a tight one: round 27 standardized every thread-
    # rendezvous wait in this file to this value under this environment's
    # documented scheduling contention, and a round-29 test-suite review
    # found these two joins — waiting for a real thread to actually finish
    # executing, not merely to be signaled — were left at the older,
    # tighter `timeout=10` alongside `_BlocksOnAnEvent.attempt()`'s own
    # rendezvous wait, which round 28 had already widened in this same test.
    interrupter.join(timeout=30)
    assert not interrupter.is_alive(), (
        "interrupt() deadlocked behind a commit() blocked in attempt()"
    )
    assert interrupt_outcome["kind"] == "returned"
    assert flow.stage is RecoveryStage.INTERRUPTED

    # Only now does the acquisition let go — the ordering the finding is
    # about: record the interruption first, release what was blocking second.
    acquisition.release.set()
    committer.join(timeout=30)
    assert not committer.is_alive(), "commit() never woke up after attempt() returned"
    assert commit_outcome["kind"] == "refused"
    assert commit_outcome["refusal"] is Refusal.WORKFLOW_ALREADY_FINISHED
    # The interruption records once; the blocked commit records nothing.
    assert [entry.event for entry in flow.audit()] == [
        SnapshotAuditEvent.RECOVERY_STARTED,
        SnapshotAuditEvent.RECOVERY_TRIAL_OPENED,
        SnapshotAuditEvent.RECOVERY_INTERRUPTED,
    ]


def test_the_workflow_lock_is_reentrant_not_a_plain_lock(observations) -> None:
    """R20 (test-suite review): the reentrant property, proved directly.

    Downgrading `self._lock` from `threading.RLock` to `threading.Lock`
    is caught by the existing suite — but only as an indefinite hang: an
    ordinary single-threaded gate refusal reenters `_sealed_assign` via
    `_refuse_gate` while `start`/`open_trial`/`commit` already hold the
    lock, and a plain `Lock` deadlocks the thread against itself. That is
    real coverage, but it surfaces as the whole test run hanging past
    whatever external timeout stops it, not a fast, clearly diagnosed
    failure naming what broke. This proves the property directly and
    quickly instead: the same thread can acquire a fresh workflow's
    `_lock` a second time, nested, without blocking — the literal
    definition of reentrant, checked on its own rather than inferred from
    a hang elsewhere.
    """

    flow = workflow(observations)
    acquired_twice = threading.Event()

    def reenter() -> None:
        with flow._lock:
            with flow._lock:
                acquired_twice.set()

    # `daemon=True`: a plain `Lock` mutant deadlocks this thread on its own
    # second `acquire()` call, permanently — with no timeout on a bare
    # `with lock:`. A non-daemon thread stuck like that keeps the whole
    # interpreter alive at process exit regardless of what this test
    # asserts, turning a clean, fast failure back into the indefinite hang
    # this test exists to replace. Daemon means the mutant's failure is
    # this test's own `assert`, not the test runner hanging.
    thread = threading.Thread(target=reenter, daemon=True)
    thread.start()
    thread.join(timeout=30)
    assert not thread.is_alive(), (
        "flow._lock deadlocked on same-thread reentry; it must stay an RLock"
    )
    assert acquired_twice.is_set()


def test_holds_during_an_in_flight_commit_answers_false_until_committed(
    observations,
) -> None:
    """R20 (test-suite review): coverage for `holds()`'s own stated reason
    it asks the stage as well as the object.

    `holds()` reads `_stage`/`_candidate` without taking `self._lock` —
    correct, since the values it reads are ordinary attribute loads,
    atomic under the GIL, and `commit()` always writes the candidate
    strictly before the stage. No existing test drives a concurrent
    `holds()` call in the window `commit()` itself calls out for a
    reason: the docstring's own "and the stage, not only the object" is
    exactly a claim about *this* window, between the candidate write and
    the stage write, and nothing exercised a call landing inside it before
    this test.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    candidate_written = threading.Event()
    let_commit_continue = threading.Event()
    original_sealed_assign = RecoveryWorkflow._sealed_assign

    def racy_sealed_assign(self: RecoveryWorkflow, name: str, value: object) -> None:
        original_sealed_assign(self, name, value)
        if name == "_candidate":
            candidate_written.set()
            let_commit_continue.wait(timeout=30)

    RecoveryWorkflow._sealed_assign = racy_sealed_assign
    commit_outcome: dict[str, object] = {}
    holds_result: dict[str, object] = {}
    try:

        def do_commit() -> None:
            candidate = flow.commit(
                snap,
                observations,
                media_binding_holds=True,
                session_id=SESSION,
                acquisition=Opens(),
                confirmed=True,
            )
            commit_outcome["candidate"] = candidate

        committer = threading.Thread(target=do_commit)
        committer.start()
        assert candidate_written.wait(timeout=30)
        # The candidate is written; the stage is still `TRIAL_OPEN`. A
        # third thread's `holds()` call in this exact window is what the
        # docstring's "and the stage, not only the object" is about.
        assert flow._candidate is not None
        assert flow.stage is RecoveryStage.TRIAL_OPEN

        def do_holds() -> None:
            holds_result["value"] = flow.holds(flow._candidate)

        reader = threading.Thread(target=do_holds)
        reader.start()
        reader.join(timeout=30)
        let_commit_continue.set()
        committer.join(timeout=30)
    finally:
        RecoveryWorkflow._sealed_assign = original_sealed_assign

    assert holds_result["value"] is False
    assert flow.stage is RecoveryStage.COMMITTED
    assert flow.holds(commit_outcome["candidate"]) is True


def test_a_real_second_thread_interrupting_before_commits_candidate_is_written_stays_in_vocabulary(
    observations,
) -> None:
    """R18 (security review, finding 2): the other half of `commit`'s gap.

    The test above races `interrupt()` between the candidate write and the
    stage write. This races it one statement earlier — between
    `_require_an_unfenced_medium()`'s return and `_sealed_assign("_candidate",
    minted)` — so the candidate write itself is the one landing after the
    workflow has gone terminal. Before round 18's fix this met
    `_sealed_assign`'s terminal-stage guard and raised a bare
    `AttributeError`, the same vocabulary break, one statement earlier than
    round 17's own test drove it.

    R19 (security review): round 18's per-call vocabulary fix still left a
    genuine double-commit reachable through a *different* pairing (two
    concurrent `commit()` calls, no `interrupt()` involved — see
    `test_two_real_threads_committing_the_same_workflow_produce_one_candidate`
    below). The real close is `self._lock`, a per-instance `RLock` each of
    `start`/`open_trial`/`interrupt`/`_sealed_assign` holds for its entire
    body, and `commit` for all of its body except the call into
    `_require_the_gates` (round twenty released the lock there, to avoid
    holding it across `attempt()`'s wait on a human). This test's own race
    lands in the section of `commit` that is still fully locked — between
    `_require_an_unfenced_medium()`'s return and the candidate write — so
    `interrupt()` paused here cannot run at all — not just cannot land
    badly — until `commit()` finishes. The outcome is therefore fully
    deterministic now, not merely "stays in vocabulary."
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    fence_checked = threading.Event()
    let_commit_continue = threading.Event()
    original_require_an_unfenced_medium = RecoveryWorkflow._require_an_unfenced_medium

    def racy_require_an_unfenced_medium(self: RecoveryWorkflow) -> None:
        original_require_an_unfenced_medium(self)
        fence_checked.set()
        let_commit_continue.wait(timeout=30)

    RecoveryWorkflow._require_an_unfenced_medium = racy_require_an_unfenced_medium
    commit_outcome: dict[str, object] = {}
    interrupt_outcome: dict[str, object] = {}
    try:

        def do_commit() -> None:
            try:
                candidate = flow.commit(
                    snap,
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                    acquisition=Opens(),
                    confirmed=True,
                )
                commit_outcome["kind"] = "returned"
                commit_outcome["candidate"] = candidate
            except RecoveryRefused as refused:
                commit_outcome["kind"] = "refused"
                commit_outcome["refusal"] = refused.refusal

        def do_interrupt() -> None:
            try:
                flow.interrupt(session_id=SESSION)
                interrupt_outcome["kind"] = "returned"
            except RecoveryRefused as refused:
                interrupt_outcome["kind"] = "refused"
                interrupt_outcome["refusal"] = refused.refusal

        committer = threading.Thread(target=do_commit)
        committer.start()
        assert fence_checked.wait(timeout=30)
        interrupter = threading.Thread(target=do_interrupt)
        interrupter.start()
        let_commit_continue.set()
        committer.join(timeout=30)
        interrupter.join(timeout=30)
    finally:
        RecoveryWorkflow._require_an_unfenced_medium = original_require_an_unfenced_medium

    assert commit_outcome["kind"] == "returned"
    assert flow.stage is RecoveryStage.COMMITTED
    assert flow.holds(commit_outcome["candidate"])
    assert interrupt_outcome["kind"] == "refused"
    assert interrupt_outcome["refusal"] is Refusal.WORKFLOW_ALREADY_FINISHED


def test_a_real_second_thread_interrupting_during_starts_stage_write_completes_cleanly_after(
    observations,
) -> None:
    """R18 (security review, finding 3): the same shape in `start`.

    `start` reads `_require_an_unfenced_medium()` and then writes
    `_stage` to `PREFLIGHT_PASSED`. Round 18 closed the vocabulary break a
    racing `interrupt()` could hit there.

    R19 (security review): `start`'s own body is now held under
    `self._lock` for its whole duration, so `interrupt()`, started while
    `start()` is paused mid-body, cannot run at all until `start()`
    finishes — it can no longer land *inside* `start()`. Unlike `commit()`
    (which leaves the workflow terminal), `start()` leaves it at
    `PREFLIGHT_PASSED`, non-terminal — so the properly-serialised
    `interrupt()` that runs immediately afterwards is not a race outcome to
    refuse at all, it is the *ordinary*, legitimate sequence D8 describes:
    an operator starts a recovery, then stops it. Both calls succeed, in
    that order, with nothing corrupted in between.
    """

    flow = workflow(observations)
    snap = descriptor()

    fence_checked = threading.Event()
    let_start_continue = threading.Event()
    original_require_an_unfenced_medium = RecoveryWorkflow._require_an_unfenced_medium

    def racy_require_an_unfenced_medium(self: RecoveryWorkflow) -> None:
        original_require_an_unfenced_medium(self)
        fence_checked.set()
        let_start_continue.wait(timeout=30)

    RecoveryWorkflow._require_an_unfenced_medium = racy_require_an_unfenced_medium
    start_outcome: dict[str, object] = {}
    interrupt_outcome: dict[str, object] = {}
    try:

        def do_start() -> None:
            try:
                flow.start(
                    snap,
                    observations,
                    media_binding_holds=True,
                    session_id=SESSION,
                    started_by_operator=True,
                )
                start_outcome["kind"] = "returned"
            except RecoveryRefused as refused:
                start_outcome["kind"] = "refused"
                start_outcome["refusal"] = refused.refusal

        def do_interrupt() -> None:
            try:
                flow.interrupt(session_id=SESSION)
                interrupt_outcome["kind"] = "returned"
            except RecoveryRefused as refused:
                interrupt_outcome["kind"] = "refused"
                interrupt_outcome["refusal"] = refused.refusal

        starter = threading.Thread(target=do_start)
        starter.start()
        assert fence_checked.wait(timeout=30)
        # Blocks on `self._lock`, held by the paused `start()`; joined only
        # after the release below.
        interrupter = threading.Thread(target=do_interrupt)
        interrupter.start()
        let_start_continue.set()
        starter.join(timeout=30)
        interrupter.join(timeout=30)
    finally:
        RecoveryWorkflow._require_an_unfenced_medium = original_require_an_unfenced_medium

    assert start_outcome["kind"] == "returned"
    assert interrupt_outcome["kind"] == "returned"
    assert flow.stage is RecoveryStage.INTERRUPTED
    assert [entry.event for entry in flow.audit()] == [
        SnapshotAuditEvent.RECOVERY_STARTED,
        SnapshotAuditEvent.RECOVERY_INTERRUPTED,
    ]


def test_a_real_second_thread_interrupting_during_open_trials_stage_write_completes_cleanly_after(
    observations,
) -> None:
    """R18 (security review, finding 4): the same shape in `open_trial`.

    `open_trial` reads `_require_an_unfenced_medium()` and then writes
    `_stage` to `TRIAL_OPEN`. Round 18 closed the vocabulary break a racing
    `interrupt()` could hit there.

    R19 (security review): the same lock-based close as `start`'s sibling
    test above. `open_trial()` leaves the workflow at `TRIAL_OPEN`,
    non-terminal, so a properly-serialised `interrupt()` immediately after
    is the ordinary legitimate sequence, not a refusal.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )

    fence_checked = threading.Event()
    let_open_trial_continue = threading.Event()
    original_require_an_unfenced_medium = RecoveryWorkflow._require_an_unfenced_medium

    def racy_require_an_unfenced_medium(self: RecoveryWorkflow) -> None:
        original_require_an_unfenced_medium(self)
        fence_checked.set()
        let_open_trial_continue.wait(timeout=30)

    RecoveryWorkflow._require_an_unfenced_medium = racy_require_an_unfenced_medium
    open_trial_outcome: dict[str, object] = {}
    interrupt_outcome: dict[str, object] = {}
    try:

        def do_open_trial() -> None:
            try:
                flow.open_trial(
                    snap, observations, media_binding_holds=True, session_id=SESSION
                )
                open_trial_outcome["kind"] = "returned"
            except RecoveryRefused as refused:
                open_trial_outcome["kind"] = "refused"
                open_trial_outcome["refusal"] = refused.refusal

        def do_interrupt() -> None:
            try:
                flow.interrupt(session_id=SESSION)
                interrupt_outcome["kind"] = "returned"
            except RecoveryRefused as refused:
                interrupt_outcome["kind"] = "refused"
                interrupt_outcome["refusal"] = refused.refusal

        opener = threading.Thread(target=do_open_trial)
        opener.start()
        assert fence_checked.wait(timeout=30)
        interrupter = threading.Thread(target=do_interrupt)
        interrupter.start()
        let_open_trial_continue.set()
        opener.join(timeout=30)
        interrupter.join(timeout=30)
    finally:
        RecoveryWorkflow._require_an_unfenced_medium = original_require_an_unfenced_medium

    assert open_trial_outcome["kind"] == "returned"
    assert interrupt_outcome["kind"] == "returned"
    assert flow.stage is RecoveryStage.INTERRUPTED
    assert [entry.event for entry in flow.audit()] == [
        SnapshotAuditEvent.RECOVERY_STARTED,
        SnapshotAuditEvent.RECOVERY_TRIAL_OPENED,
        SnapshotAuditEvent.RECOVERY_INTERRUPTED,
    ]


def test_two_real_threads_interrupting_the_same_workflow_stay_in_vocabulary(
    observations,
) -> None:
    """R18 (security review, finding 5): `interrupt` racing itself.

    `interrupt` checks `self._stage in TERMINAL_STAGES` once, at entry, and
    writes `_stage` to `INTERRUPTED` later in the same call — with
    `_require_this_sitting` in between. Nothing stops a second, genuinely
    concurrent `interrupt()` call from an equally legitimate caller landing
    in that gap: the loser's entry check already passed, so before round 18's
    fix its own stage write met `_sealed_assign`'s terminal-stage guard and
    raised a bare `AttributeError` rather than the `RecoveryRefused` every
    other terminal encounter in this module answers with.

    R19 (security review): `interrupt`'s whole body is now held under
    `self._lock`, so the second call can no longer run concurrently with the
    first at all — it blocks at the lock the moment it is reached, however
    long the first call pauses. **The winner is therefore whichever thread's
    `interrupt()` call is entered — and so acquires the lock — first, not
    whichever one is left unblocked by an injected pause**: here that is the
    "first" thread (paused *after* it already holds the lock), so it is
    "first" that finishes and returns, and "second" that blocks on the lock
    for the whole pause and then meets an already-terminal workflow once
    unblocked. The outcome inverts from round 18's version of this test for
    exactly that reason — the pause used to leave a genuine gap for another
    thread to race into; now it cannot, because the lock is held across it.
    """

    flow = workflow(observations)
    snap = descriptor()
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )

    sitting_checked = threading.Event()
    let_first_interrupt_continue = threading.Event()
    paused_once = threading.Event()
    original_require_this_sitting = RecoveryWorkflow._require_this_sitting

    def racy_require_this_sitting(self: RecoveryWorkflow, session_id: str) -> None:
        original_require_this_sitting(self, session_id)
        # Only the first call through pauses here, while it already holds
        # `self._lock` — the second call cannot enter `interrupt()`'s body
        # at all until this pause ends and the first call finishes.
        if not paused_once.is_set():
            paused_once.set()
            sitting_checked.set()
            let_first_interrupt_continue.wait(timeout=30)

    RecoveryWorkflow._require_this_sitting = racy_require_this_sitting
    outcomes: dict[str, dict[str, object]] = {}
    try:

        def do_interrupt(label: str) -> None:
            outcomes[label] = {}
            try:
                flow.interrupt(session_id=SESSION)
                outcomes[label]["kind"] = "returned"
            except RecoveryRefused as refused:
                outcomes[label]["kind"] = "refused"
                outcomes[label]["refusal"] = refused.refusal

        first = threading.Thread(target=do_interrupt, args=("first",))
        first.start()
        assert sitting_checked.wait(timeout=30)
        # Blocks on `self._lock`, held by the paused "first" call; joined
        # only after the release below.
        second = threading.Thread(target=do_interrupt, args=("second",))
        second.start()
        let_first_interrupt_continue.set()
        first.join(timeout=30)
        second.join(timeout=30)
    finally:
        RecoveryWorkflow._require_this_sitting = original_require_this_sitting

    # The lock makes this deterministic: "first" already held it when it
    # paused, so "first" always finishes and returns, and "second" — blocked
    # the whole time — always meets the now-terminal workflow afterwards.
    assert outcomes["first"]["kind"] == "returned"
    assert outcomes["second"]["kind"] == "refused"
    assert outcomes["second"]["refusal"] is Refusal.WORKFLOW_ALREADY_FINISHED
    assert flow.stage is RecoveryStage.INTERRUPTED


def test_a_rebound_enum_does_not_shorten_what_completeness_is_asked_against(
    monkeypatch,
) -> None:
    """R9 F2: "the enum cannot be shortened by an assignment" was false.

    `PreflightCheck._member_names_` accepts reassignment, and `tuple
    (PreflightCheck)` then returns whatever is left — so the completeness
    operand this module's own comment called unshortenable was exactly as
    rebindable as `PREFLIGHT_ORDER`, just one more step away. A review shortened
    both with two assignments and authorised a migration over a snapshot whose
    integrity had failed, to an unsupported schema, with no room and no
    binding, having asked one check of ten.

    `_EVERY_CHECK` is fixed at import, so a live shortening is **detected**
    rather than obeyed — not a capability boundary, the same as every other
    limit this module states about a determined caller inside the process, but
    a live rebind is refused rather than answered.
    """

    from azazel_boot import snapshot as module

    medium, snapshot, passing = a_migration(
        snapshot=descriptor(
            fingerprint="snapshot-fingerprint-shortened-enum",
            integrity=SnapshotIntegrity.FAILED,
        ),
        current_schema=5,
        target_schema=1,
        capacity=capacity(required=10**9, available=0),
        binding_holds=False,
        generation_holds=False,
        image_digest_holds=False,
    )

    # `monkeypatch` restores both attributes on teardown, including the enum's
    # own private list — this modifies live interpreter state shared by every
    # other test in the process, and an unrestored shortening would corrupt
    # every later use of `PreflightCheck` in this run.
    original_names = list(PreflightCheck._member_names_)
    monkeypatch.setattr(module, "PREFLIGHT_ORDER", (PreflightCheck.MEDIUM_FENCED,))
    monkeypatch.setattr(PreflightCheck, "_member_names_", ["MEDIUM_FENCED"])
    assert tuple(PreflightCheck) != module._EVERY_CHECK

    shortened = preflight(
        medium,
        snapshot=snapshot,
        capacity=capacity(required=10**9, available=0),
        current_schema=5,
        target_schema=1,
        binding_holds=False,
        generation_holds=False,
        image_digest_holds=False,
    )
    assert shortened.may_migrate is True  # the enum itself now has one member
    with pytest.raises(RecoveryRefused) as refused:
        MigrationLedger().may_migrate(shortened, quarantine=medium)
    assert refused.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK

    monkeypatch.setattr(PreflightCheck, "_member_names_", original_names)
    assert tuple(PreflightCheck) == module._EVERY_CHECK


def test_neither_value_type_hands_its_fingerprint_back_through_vars_or_asdict() -> None:
    """R9 F17: `dataclasses.asdict` walked past both raising hooks.

    `__reduce__` and `__getstate__` refuse serialisation, and the docstring
    each carries says refusing one door and not the other refuses neither.
    Both classes were still `@dataclass`, though, and `dataclasses.asdict`
    does not go through either hook — it calls `dataclasses.fields()` and
    reads each field directly. A review rendered `dataclasses.asdict(snapshot)`
    and `vars(entry)` and read the fingerprint back through the one object
    `docs/snapshot-and-recovery.md` calls "the object actually destined for a
    log", past the exact defence `CapacityReport`'s own docstring narrates
    fixing for a different pair of fields.

    Neither class is a dataclass any more, for the reason `CapacityReport`
    is not one: `dataclasses.fields()` returns nothing for a class dataclasses
    does not know about, so `asdict`/`astuple` refuse rather than walk.
    """

    snapshot = descriptor(fingerprint="snapshot-fingerprint-vars-asdict")
    entry = SnapshotAuditEntry(
        event=SnapshotAuditEvent.SNAPSHOT_WRITTEN,
        schema_version=2,
        fingerprint="snapshot-fingerprint-audit-vars-asdict",
    )

    for value in (snapshot, entry):
        assert not dataclasses.is_dataclass(value)
        with pytest.raises(TypeError):
            vars(value)
        with pytest.raises(TypeError):
            dataclasses.asdict(value)
        with pytest.raises(TypeError):
            dataclasses.astuple(value)
        with pytest.raises(TypeError):
            value.__getstate__()
        with pytest.raises(TypeError):
            value.__reduce__()
        with pytest.raises(TypeError):
            copy.deepcopy(value)
        with pytest.raises(TypeError):
            pickle.dumps(value)

    assert "snapshot-fingerprint-vars-asdict" not in repr(snapshot)
    assert "snapshot-fingerprint-audit-vars-asdict" not in repr(entry)

    # And the ordinary convenience a value type is expected to have is not
    # lost in the process: equal fields compare equal, by exact type.
    assert descriptor(fingerprint="snapshot-fingerprint-eq") == descriptor(
        fingerprint="snapshot-fingerprint-eq"
    )
    assert SnapshotAuditEntry(
        event=SnapshotAuditEvent.RECOVERY_STARTED
    ) == SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_STARTED)
    assert descriptor(fingerprint="snapshot-fingerprint-eq") != descriptor(
        fingerprint="snapshot-fingerprint-other"
    )


def test_both_delattr_docstrings_describe_the_class_they_are_on() -> None:
    """R9 (self-review): the `__delattr__` fix was pasted onto five classes
    whose `__setattr__` has no `_sealed` gate to delete.

    A bulk edit added the same `__delattr__` docstring — a `_sealed` slot, a
    `RecoveryWorkflow` reaching `COMMITTED` with a forged candidate — to every
    class that gained the method, including three in this module
    (`CapacityReport`, `PreflightVerdict`, `RecoveryCandidate`) and two
    elsewhere (`BindingKey`, `CommissionedMode`) whose `__setattr__` refuses
    unconditionally and has no `_sealed` slot at all. The words were accurate
    for `RecoveryWorkflow` and false for the rest — the exact "a claim in a
    docstring is not a property" failure this repository keeps finding
    elsewhere in its own prose.
    """

    for cls in (CapacityReport, PreflightVerdict, RecoveryCandidate):
        assert "_sealed" not in cls.__slots__
        # The wrong docstring claimed a gate this class does not have; the
        # right one says explicitly that there is none.
        assert "no `_sealed` slot" in (cls.__delattr__.__doc__ or "")


def test_the_two_value_types_refuse_direct_slot_assignment_and_a_subclass_eq() -> None:
    """R9 (self-review): three gaps the eq/asdict fix left open, mutation-found.

    `SnapshotDescriptor` and `SnapshotAuditEntry` expose their fields as
    read-only properties, which alone blocks `x.container_version = 5` — a
    property with no setter refuses that by the descriptor protocol, with or
    without `__setattr__`. It does **not** block `x._container_version = 5`,
    the slot the property reads: that is refused only by the class's own
    `__setattr__`, and nothing drove it directly. And `__eq__`'s `type(other)
    is not SnapshotDescriptor` was never driven against a genuine subclass,
    so weakening it to `isinstance` — which would let a subclass's own
    `__eq__` decide the answer, the exact class of attack `_fields_of`
    exists to avoid trusting — was unpinned.
    """

    snapshot = descriptor(fingerprint="snapshot-fingerprint-slot-assign")
    with pytest.raises(AttributeError, match="fixed when it is built"):
        snapshot._container_version = 99
    with pytest.raises(AttributeError, match="fixed when it is built"):
        snapshot._fingerprint = "snapshot-fingerprint-replaced"
    assert snapshot.container_version == 1
    assert snapshot.fingerprint == "snapshot-fingerprint-slot-assign"

    entry = SnapshotAuditEntry(event=SnapshotAuditEvent.SNAPSHOT_WRITTEN, schema_version=1)
    with pytest.raises(AttributeError, match="fixed when it is built"):
        entry._schema_version = 99
    assert entry.schema_version == 1

    class Liar(SnapshotDescriptor):
        def __eq__(self, other: object) -> bool:
            return True

        def __hash__(self) -> int:
            return 0

    liar = Liar(1, 1, SnapshotIntegrity.VERIFIED, "snapshot-fingerprint-liar")
    other = descriptor(fingerprint="snapshot-fingerprint-not-the-liar")
    assert liar == liar  # the subclass's own __eq__, answering for itself
    # But the **real** class's `__eq__` — asked the other way round, which
    # Python tries when the left operand's answer is `NotImplemented` — does
    # not delegate to the subclass and does not agree that they are equal.
    assert SnapshotDescriptor.__eq__(other, liar) is NotImplemented


def test_the_audit_entrys_own_opaque_check_is_not_the_descriptors(observations) -> None:
    """R9 (self-review): the opaque-fingerprint check lives in two `__init__`s.

    `test_a_fingerprint_is_an_opaque_token_and_not_a_rendered_record` drives
    `SnapshotDescriptor` only. `SnapshotAuditEntry` calls the same helper from
    its own constructor, and nothing proved that call was still there.
    """

    for rejected in (
        "capacity_available=17179869184 medium=usb-SN-AA11BB22 host=/dev/nvme0n1p3",
        "/dev/nvme0n1p3",
        "a" * 129,
    ):
        with pytest.raises(TypeError, match="opaque"):
            SnapshotAuditEntry(event=SnapshotAuditEvent.SNAPSHOT_WRITTEN, fingerprint=rejected)

    accepted = SnapshotAuditEntry(
        event=SnapshotAuditEvent.SNAPSHOT_WRITTEN, fingerprint="b3c1d9e07f2a4856"
    )
    assert accepted.fingerprint == "b3c1d9e07f2a4856"


def test_the_gates_own_fence_recheck_is_load_bearing_on_its_own(observations) -> None:
    """R9: the test written for `_require_the_gates`'s post-prompt fence read
    passed for a different reason — `commit`'s own outer re-check.

    `test_the_medium_is_read_again_after_the_passphrase_prompt` drives through
    `commit`, which asks `_require_an_unfenced_medium()` again right before
    minting — a **second**, independent mechanism, added later, sitting
    outside `_require_the_gates` entirely. Disabling the gates' own re-read of
    the fence after `attempt()` left that test green, because the outer check
    caught the same fence and produced the identical refusal, gate and audit.
    The line the test names was not what answered it.

    Driven through `_require_the_gates` directly, which is the only way to
    isolate the two: nothing outside this call can rescue a missing re-read
    inside it.
    """

    quarantine = a_quarantine()

    class PulledDuringThePrompt(Opens):
        def attempt(self):
            quarantine.fence()
            return super().attempt()

    flow = workflow(observations, quarantine=quarantine)
    snap = descriptor(fingerprint="snapshot-fingerprint-fence-inside-gates")
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)
    assert quarantine.is_fenced is False

    with pytest.raises(RecoveryRefused) as refused:
        flow._require_the_gates(
            snap,
            observations,
            session_id=SESSION,
            media_binding_holds=True,
            acquisition=PulledDuringThePrompt(),
            confirmed=True,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert quarantine.is_fenced is True
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.MEDIUM_FENCED


def test_a_fence_landing_between_the_last_check_and_the_mint_is_still_refused(
    observations, monkeypatch
) -> None:
    """R10: the narrow window `_require_an_unfenced_medium` cannot close.

    `commit` asks the fence once more, then builds the candidate, then writes
    `_candidate`, then writes `_stage`. Nothing makes those four lines atomic,
    and a fence raised by device monitoring — the same independent mechanism
    every other re-check in this file exists because of — can land after the
    read and before the last write. A review simulated exactly that window by
    making `RecoveryCandidate.__init__` itself fence the medium, which is not
    a claim that construction is attacker-controlled in production; it is a
    deterministic stand-in for anything that could delay execution between
    two ordinary statements — a scheduler pause, a signal, a thread in a
    multi-threaded caller.

    Before this fix, the write to `_stage` met the seal's own internal fence
    recheck and raised a bare `AttributeError` — outside `RecoveryRefused`,
    so a caller correctly writing `except RecoveryRefused:` crashed instead
    of being refused. `_candidate` was left populated on a workflow stuck at
    `TRIAL_OPEN`, which `holds()` correctly refuses (it asks the stage too),
    so nothing was ever falsely authorised — the defect was strictly the
    escaped exception type.
    """

    quarantine = a_quarantine()
    flow = workflow(observations, quarantine=quarantine)
    snap = descriptor(fingerprint="snapshot-fingerprint-mint-race")
    flow.start(
        snap, observations, media_binding_holds=True, session_id=SESSION, started_by_operator=True
    )
    flow.open_trial(snap, observations, media_binding_holds=True, session_id=SESSION)

    real_init = RecoveryCandidate.__init__

    def _fence_during_construction(self, *args, **keywords):
        quarantine.fence()
        real_init(self, *args, **keywords)

    monkeypatch.setattr(RecoveryCandidate, "__init__", _fence_during_construction)

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            snap,
            observations,
            media_binding_holds=True,
            session_id=SESSION,
            acquisition=Opens(),
            confirmed=True,
        )
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.MEDIUM_FENCED
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.holds(RecoveryCandidate(snap.schema_version, snap.fingerprint)) is False
    assert quarantine.volume_is_quarantined is True


def test_the_opaque_check_refuses_every_unicode_line_boundary() -> None:
    """R10: `\\n`/`\\r` alone missed the other boundaries `splitlines()` knows.

    A review joined three fragments with `\\x0c` (form feed) and `\\u2029`
    (paragraph separator) instead of `\\n`, and the result passed the old
    character-by-character check while `str.splitlines()` — and any
    `.splitlines()`-based log viewer — still read it as three lines.
    """

    for boundary in ("\x0b", "\x0c", "\x85", " ", " "):
        with pytest.raises(TypeError, match="opaque"):
            descriptor(fingerprint=f"line-one{boundary}line-two")
        with pytest.raises(TypeError, match="opaque"):
            SnapshotAuditEntry(
                event=SnapshotAuditEvent.SNAPSHOT_WRITTEN,
                fingerprint=f"line-one{boundary}line-two",
            )

    # And an ordinary single-line value is still accepted.
    assert descriptor(fingerprint="b3c1d9e07f2a4856").fingerprint == "b3c1d9e07f2a4856"


def test_neither_value_types_eq_is_decided_by_a_subclasss_inherited_method() -> None:
    """R10: `type(other) is not X` alone left the *reflected* comparison open.

    `fake == real` tries `real.__eq__(fake)` first — refused, correctly — and
    Python then tries the reflected `fake.__eq__(real)`, which is this same
    method, **inherited**, now running with `self` bound to the subclass
    instance. `type(other) is SnapshotDescriptor` is true from there, so the
    comparison answered `True` for two objects of different exact types
    unless `type(self)` is checked too.
    """

    class FakeDescriptor(SnapshotDescriptor):
        pass

    real = descriptor(fingerprint="snapshot-fingerprint-eq-symmetry")
    fake = FakeDescriptor(
        real.container_version, real.schema_version, real.integrity, real.fingerprint
    )
    # Both directions, and both now correctly `False`: two objects of
    # different exact types, whichever side's `__eq__` Python tries first.
    assert fake != real
    assert real != fake
    # And the type-pinned instance a legitimate decision path builds is
    # unaffected: a real one still equals another real one.
    assert real == descriptor(fingerprint="snapshot-fingerprint-eq-symmetry")

    class FakeEntry(SnapshotAuditEntry):
        pass

    real_entry = SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_STARTED)
    fake_entry = FakeEntry(event=SnapshotAuditEvent.RECOVERY_STARTED)
    assert fake_entry != real_entry
    assert real_entry != fake_entry
    assert real_entry == SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_STARTED)


def test_the_identity_index_does_not_answer_for_a_dead_or_different_object() -> None:
    """R10 (self-review): `id()` alone would have reopened the hazard the
    weak reference exists to close.

    `_WeakIdentityIndex` keys its dict by `id(obj)` specifically so that
    iterating it cannot hand a `Quarantine` back. `id()` values are reused
    once an object is collected, so a bare `id()`-keyed lookup would answer
    for a *different*, unrelated object later allocated at the same address
    as an earlier, now-dead one — the weak reference stored alongside the
    value exists purely to catch that and is asked on every `get`/`in`.
    Deriving the mismatch by natural garbage-collector timing is
    nondeterministic; this drives the check directly, over an entry a real
    lookup could otherwise be fooled by.
    """

    from azazel_boot import snapshot as module

    index = module._WeakIdentityIndex()
    first = a_quarantine()
    index[first] = "value-for-first"
    assert index.get(first) == "value-for-first"
    assert first in index

    # A stand-in for "the id-keyed slot survives after the object it named
    # is gone" — reached deterministically by writing the internal store
    # directly, since natural id reuse depends on allocator timing this test
    # does not control. The store is no longer the index's own attribute
    # (R11: `gc.get_referents` read it straight off `self._by_id`, and
    # ordinary `index._by_id = ...` assignment rebound it outright — see
    # `_INDEX_STORAGE`'s module comment in `snapshot.py`), so reaching it
    # white-box now goes through the module-level registry, keyed by the
    # index instance itself.
    second = a_quarantine()
    assert id(second) != id(first)
    store = module._INDEX_STORAGE.get(index)
    stale_ref, value = store[id(first)]
    store[id(second)] = (stale_ref, value)

    assert index.get(second) is None
    assert second not in index
    # And the entry keyed by its own, correct id is unaffected.
    assert index.get(first) == "value-for-first"
    assert first in index


def test_gc_get_referents_does_not_recover_a_live_medium_from_the_index() -> None:
    """R11 (security review): `gc.get_referents` read `self._by_id` straight
    off the instance, no private name anywhere in the call.

    `_WeakIdentityIndex`'s docstring claimed reaching its store needed
    "`object.__setattr__`-grade access to private state" — a caller doing
    something deliberate and named. That was false in both directions at
    once: `gc.get_referents(idx)` is stdlib, always available, needs no name
    at all, and returns exactly what an object's own `__slots__` hold —
    which, for `__slots__ = ("_by_id",)`, was the live `(weakref, value)`
    dict itself, not a copy. A review turned one call into every `Quarantine`
    any preflight in the process had judged, live — the exact leak this
    class exists to prevent, reached by a route its own review missed.

    The fix stores nothing on the instance: `__slots__` holds only
    `__weakref__`, and the dict lives in `_INDEX_STORAGE`, a module global
    keyed by the index itself (see its comment in `snapshot.py`). This drives
    both halves directly — the read `gc.get_referents` no longer serves, and
    the ordinary attribute writes the docstring also overstated the
    difficulty of.
    """

    from azazel_boot import snapshot as module

    index = module._WeakIdentityIndex()
    medium = a_quarantine(quarantined=False)
    index[medium] = "judged"

    # The read: what an attacker with only the index object, and gc — no
    # private name literal anywhere — gets back.
    referents = gc.get_referents(index)
    assert referents == [module._WeakIdentityIndex], referents
    for referent in referents:
        assert referent is not medium
        if isinstance(referent, dict):
            raise AssertionError("gc.get_referents(index) exposed a dict")

    # The write: ordinary dot assignment, the weakest reach in the language,
    # and `object.__setattr__` alongside it — both refused for the same
    # reason, there is no such slot to hold either.
    with pytest.raises(AttributeError):
        index._by_id = {"forged": "entry"}
    with pytest.raises(AttributeError):
        object.__setattr__(index, "_by_id", {"forged": "entry"})

    # And the index still does its one job correctly throughout.
    assert index.get(medium) == "judged"
    assert medium in index


def test_a_live_medium_is_findable_by_gc_regardless_of_this_module() -> None:
    """R12 (security review): the limit underneath `_WeakIdentityIndex`,
    which no redesign of it reaches — asserted here, per this file's own
    precedent (`test_refusals.py`'s `UnidentifiedHost` test), so the gap is
    on record rather than merely known, and closing it by accident somewhere
    else turns this red rather than leaving nothing to notice.

    `gc.get_objects()` is a full heap walk and needs no name, no import of
    this module and no weak reference at all: a live `Quarantine`, wherever
    it is held, is a member of it in its own right. Filtering by
    `isinstance(x, weakref.WeakKeyDictionary)` also finds `_INDEX_STORAGE`
    directly, and `weakref.ref` instances are themselves walked by `gc.
    get_objects()`, so the entries `_WeakIdentityIndex` stores are reachable
    that way too — but neither of those is the shortest path, and moving
    where the class keeps its store cannot change that, because what is
    found is never the store. It is any live object in the same OS process,
    which is what `gc` exists to enumerate.

    This is why `_WeakIdentityIndex`'s claim is about this module's own
    call surface — no method, return value, exception, repr or log line
    hands a caller a medium it did not already hold — and not about hiding
    a live object from other code sharing the interpreter, which no pure
    -Python technique, in this module or any other, can do.
    """

    medium = a_quarantine(quarantined=True)

    found = [obj for obj in gc.get_objects() if type(obj).__name__ == "Quarantine"]
    assert medium in found

    for obj in found:
        if obj is medium:
            assert obj.is_fenced is False
            obj.fence()
            assert medium.is_fenced is True, (
                "the object gc.get_objects() found and the one this test built "
                "are the same live object, not a copy"
            )


def test_the_index_answers_false_for_a_key_it_never_held() -> None:
    """R11 (test-suite review): `__contains__`'s "no entry at all" branch —
    as opposed to "an entry, but a dead or different object" — was unreached
    by the whole suite, because every existing `in`/`not in` drive presents
    either a key the index holds or one it was made to hold a stale entry
    for. `azazel_boot.snapshot` itself never calls `in` on either module
    index, only `.get()`/`[...] =`, so this is the one place production code
    does not backstop a coverage gap in its own test suite. Inverting the
    branch (`return True`) went undetected; this drives the branch directly.
    """

    from azazel_boot import snapshot as module

    index = module._WeakIdentityIndex()
    never_added = a_quarantine(quarantined=False)

    assert never_added not in index
    assert index.get(never_added) is None


def test_a_dead_referent_is_dropped_from_the_index_not_merely_unreadable() -> None:
    """R11 (test-suite review): `__setitem__`'s weakref cleanup callback
    (`store.pop(oid, None)` on collection) was untested — the identity check
    already proves a dead entry answers `False`/`None`, but proves nothing
    about whether the entry is actually removed. Without the callback the
    same behaviour holds from the outside, while `_by_id` grows one stale
    `(dead weakref, value)` pair per judged-then-dropped medium for the rest
    of the process — a slow leak invisible to every existing assertion,
    which all ask "what does a lookup answer" and none ask "how many entries
    are actually held".
    """

    from azazel_boot import snapshot as module

    index = module._WeakIdentityIndex()
    medium = a_quarantine(quarantined=False)
    index[medium] = "judged"

    store = module._INDEX_STORAGE.get(index)
    assert len(store) == 1

    del medium
    gc.collect()

    assert len(store) == 0, "the dead entry was expected to be dropped, not merely unreadable"


def test_the_mintedness_check_is_not_saved_by_the_medium_check() -> None:
    """R10: `may_migrate`'s own two checks share one `Refusal` member.

    `verdict_was_minted_here` and `_require_the_medium_now`'s own
    `_a_medium_was_judged` check both refuse with
    `VERDICT_NOT_MINTED_BY_A_PREFLIGHT`, with different detail text — so a
    hand-built verdict that answers `False` to both, driven through
    `may_migrate`, cannot tell you which one actually fired. Deleting the
    first check alone left the whole suite green, because the second one
    always caught the same forged verdicts the tests happened to use.

    Isolated here by building a verdict that **is** judged by a medium —
    added to the module's own judged-medium index directly, the way `_mint`
    would — without ever being added to `_MINTED_HERE`. `_require_the_medium_
    now` would accept it; only `verdict_was_minted_here` still refuses it,
    so this is the one input that answers "which check fired" unambiguously.
    """

    from azazel_boot import snapshot as module

    medium = a_quarantine(quarantined=False)
    half_forged = PreflightVerdict(None)
    assert verdict_was_minted_here(half_forged) is False

    # Judged by the medium, the way a real `_mint` call would record it —
    # without ever passing through `_mint` itself, so `_MINTED_HERE` never
    # learns about this verdict.
    module._remember_the_medium(half_forged, medium)
    assert module._a_medium_was_judged(half_forged) is True
    assert verdict_was_minted_here(half_forged) is False

    with pytest.raises(RecoveryRefused) as refused:
        MigrationLedger().may_migrate(half_forged, quarantine=medium)
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT
    assert "a value that merely has the right shape" in refused.value.detail


def test_both_value_types_hash_by_the_same_fields_their_eq_compares() -> None:
    """R10: `__hash__` was written and never driven.

    `hash((SnapshotDescriptor, *_fields_of(self)))` names the type as well as
    the fields, for the same reason `__eq__` pins the exact type: two exact
    types whose fields happen to coincide must not collide with each other
    the way two field-equal instances of the **same** type must. Dropping the
    type discriminator from either class's `__hash__` left the whole suite
    green — nothing had ever called `hash()` on either.
    """

    one = descriptor(fingerprint="snapshot-fingerprint-hash-a")
    same_fields = descriptor(fingerprint="snapshot-fingerprint-hash-a")
    different = descriptor(fingerprint="snapshot-fingerprint-hash-b")
    assert one == same_fields
    assert hash(one) == hash(same_fields)
    assert hash(one) != hash(different)
    # The type discriminator, isolated: two objects whose *fields* collide
    # under `hash(fields)` alone must not necessarily collide once the type
    # is folded in. Driven directly against the implementation's own shape
    # rather than searched for, since a natural hash collision is not
    # something a test should have to go looking for.
    from azazel_boot import snapshot as module

    assert hash(one) == hash((module.SnapshotDescriptor, *module._fields_of(one)))

    a_entry = SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_STARTED, schema_version=1)
    same_entry = SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_STARTED, schema_version=1)
    other_entry = SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_STARTED, schema_version=2)
    assert a_entry == same_entry
    assert hash(a_entry) == hash(same_entry)
    assert hash(a_entry) != hash(other_entry)
    assert hash(a_entry) == hash((SnapshotAuditEntry, *a_entry._fields()))


def test_a_snapshot_audit_entry_subclass_is_refused_the_same_way_the_descriptor_is() -> None:
    """R10: the subclass-eq drive existed for `SnapshotDescriptor` and not
    for `SnapshotAuditEntry`, though both classes carry the identical risk.

    Weakening `SnapshotAuditEntry.__eq__`'s `type(other) is not
    SnapshotAuditEntry` to `isinstance` is exactly the round-four attack
    `_require_a_real_snapshot`'s own docstring narrates for the descriptor,
    replayed on the sibling class nothing drove it against.
    """

    class LiarEntry(SnapshotAuditEntry):
        def __eq__(self, other: object) -> bool:
            return True

        def __hash__(self) -> int:
            return 0

    real = SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_COMPLETED, schema_version=1)
    liar = LiarEntry(event=SnapshotAuditEvent.RECOVERY_REFUSED, schema_version=99)
    assert liar == liar  # the subclass answering for itself, on its own terms
    # The real class's own `__eq__`, asked directly on either side, refuses
    # rather than delegates — what a hostile subclass's *own* overridden
    # `__eq__` separately claims about itself is not this class's to control,
    # the same limit `_require_a_real_snapshot`'s docstring states for the
    # exact-type pin generally: the point is that *this* method does not
    # answer on the subclass's behalf, which both directions show.
    assert SnapshotAuditEntry.__eq__(real, liar) is NotImplemented
    assert SnapshotAuditEntry.__eq__(liar, real) is NotImplemented


def test_the_audit_entrys_fields_are_derived_and_total() -> None:
    """R10: `SnapshotDescriptor` has this test; `SnapshotAuditEntry` did not.

    `_fields()` is what `__eq__` and `__hash__` both compare over, so a field
    silently dropped from its return tuple is a field two otherwise-different
    entries could stop being distinguished by — an audit entry whose
    `schema_version` differs comparing equal, say. Derived from the source
    rather than hand-checked, the way `_fields_of` is for the descriptor, so a
    sixth field added to the class is a field this test notices was left out.
    """

    source = inspect.getsource(SnapshotAuditEntry._fields)
    tree = ast.parse(textwrap.dedent(source))
    returned = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    }
    declared = {name.lstrip("_") for name in SnapshotAuditEntry.__slots__}
    assert returned == declared, (
        "_fields must return every field of SnapshotAuditEntry; "
        f"missing {sorted(declared - returned)}, unknown {sorted(returned - declared)}"
    )

    # And it is total in practice, not only in the source: two entries that
    # differ in exactly one field are unequal, for every field in turn.
    base = {
        "event": SnapshotAuditEvent.RECOVERY_STARTED,
        "check": PreflightCheck.MEDIUM_FENCED,
        "gate": RecoveryGate.MEDIUM_FENCED,
        "schema_version": 1,
        "fingerprint": "snapshot-fingerprint-total-a",
    }
    reference = SnapshotAuditEntry(**base)
    overrides = {
        "event": SnapshotAuditEvent.RECOVERY_REFUSED,
        "check": PreflightCheck.VOLUME_QUARANTINED,
        "gate": RecoveryGate.NOTHING_TO_RECOVER,
        "schema_version": 2,
        "fingerprint": "snapshot-fingerprint-total-b",
    }
    for name, changed in overrides.items():
        varied = dict(base)
        varied[name] = changed
        assert SnapshotAuditEntry(**varied) != reference, name


def test_delattr_is_refused_on_every_class_that_defines_it_not_only_the_sealed_ones() -> None:
    """R10: only the three `_sealed`-gated classes were driven with `del`.

    `test_the_seals_other_door_is_shut_on_every_class_that_has_one` derives
    the *list* of classes with `__delattr__` from the source, and only drives
    `del target._sealed` — which exists on three of the eight. The other
    five refuse **unconditionally**, and nothing had ever called `del` on one
    of them: `SnapshotDescriptor.__delattr__` turned into `pass` left the
    whole suite green.
    """

    snapshot = descriptor(fingerprint="snapshot-fingerprint-delattr")
    with pytest.raises(AttributeError, match="fixed when it is built"):
        del snapshot.fingerprint
    with pytest.raises(AttributeError, match="fixed when it is built"):
        del snapshot._fingerprint

    entry = SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_STARTED)
    with pytest.raises(AttributeError, match="fixed when it is built"):
        del entry.event
    with pytest.raises(AttributeError, match="fixed when it is built"):
        del entry._event

    report = capacity()
    with pytest.raises(AttributeError, match="fixed when it is built"):
        del report._required

    verdict = PreflightVerdict(None)
    with pytest.raises(AttributeError, match="fixed when it is minted"):
        del verdict._refused_by

    candidate = RecoveryCandidate(1, FINGERPRINT)
    with pytest.raises(AttributeError, match="fixed when it is minted"):
        del candidate._schema_version
