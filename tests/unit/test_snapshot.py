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
import inspect
import os
import pickle
import subprocess
import sys
import textwrap
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
from azazel_boot.inventory import collect_interfaces
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(snap, observations, session_id=SESSION)
    return flow.commit(
        snap,
        observations,
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


def test_a_candidate_is_not_a_volume_and_grants_nothing(observations) -> None:
    """It says what was restored. It cannot do anything with it."""

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
        "dataclass",
        "field",
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
    # down. This module reads exactly two things from the quarantine, so that
    # is what it is held to. (`_audit` as a bare name is *this* object's own
    # slot, which is why the check is on the receiver rather than the name.)
    # **`self._quarantine` may appear only as the receiver of those two
    # reads.** The first version matched `self._quarantine.<attr>` as a shape,
    # so aliasing it to a local first — `q = self._quarantine; q._audit.clear()`
    # — made the receiver a plain `Name` that the comprehension never looked
    # at. A re-review emptied the audit and the dispositions that way, with the
    # flags never moving and the whole suite green.
    #
    # Checking the *use* rather than the shape closes the alias, the argument,
    # the tuple unpack and everything else at once: the object never escapes
    # those two expressions, so there is nothing to alias.
    for node in ast.walk(TREE):
        if not (isinstance(node, ast.Attribute) and node.attr == "_quarantine"):
            continue
        if not isinstance(node.ctx, ast.Load):
            continue  # `self._quarantine = quarantine` in __init__, the one write
        reader = [
            outer
            for outer in ast.walk(TREE)
            if isinstance(outer, ast.Attribute) and outer.value is node
        ]
        assert reader, "self._quarantine is used other than as a receiver"
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
    permitted_functions = {"_mint", "__init__", "__setattr__", "_sealed_assign"}
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
            assert isinstance(first, ast.Name) and first.id in (
                {own} | built_here
            ) - {None}, (
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

    ledger = MigrationLedger()
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
    assert ledger.may_migrate(verdict, quarantine=a_quarantine(quarantined=False)) is False

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
        "dataclass",
        "field",
        "Enum",
        "WeakSet",
        "SessionBinding",
        "binding_applies",
        "InterfaceObservation",
        "Quarantine",
        "AttemptOutcome",
        "KeyAcquisition",
        "PassphraseChannel",
    }, f"unexpected imported names: {sorted(named)}"

    assert imported == {
        "__future__",
        "dataclasses",
        "enum",
        # Added deliberately: `_MINTED_HERE` is a `WeakSet` now, because a
        # sentinel stamped onto a verdict is a sentinel a caller can read off
        # one. Imported privately, so it is not a name this module exports.
        "weakref",
        "commissioning",
        "inventory",
        "quarantine",
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
        flow.start(descriptor(), observations, session_id=SESSION, started_by_operator=False)
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
        lambda flow, snap, obs: flow.open_trial(snap, obs, session_id=SESSION),
        lambda flow, snap, obs: flow.commit(
            snap, obs, session_id=SESSION, acquisition=Opens(), confirmed=True
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

    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    assert flow.stage is RecoveryStage.PREFLIGHT_PASSED
    flow.open_trial(snap, observations, session_id=SESSION)
    assert flow.stage is RecoveryStage.TRIAL_OPEN
    flow.commit(snap, observations, session_id=SESSION, acquisition=Opens(), confirmed=True)
    assert flow.stage is RecoveryStage.COMMITTED
    assert flow.stage in TERMINAL_STAGES


def test_a_second_commit_is_refused(observations) -> None:
    """A committed workflow is finished. A further attempt is a new workflow."""

    flow = workflow(observations)
    run_to_commit(flow, observations)

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            descriptor(), observations, session_id=SESSION, acquisition=Opens(), confirmed=True
        )
    assert refused.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED
    assert flow.stage is RecoveryStage.COMMITTED


def test_an_interruption_is_terminal_and_restores_nothing(observations) -> None:
    flow = workflow(observations)
    snap = descriptor()
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(snap, observations, session_id=SESSION)

    flow.interrupt(session_id=SESSION)
    assert flow.stage is RecoveryStage.INTERRUPTED

    for attempt in (
        lambda: flow.open_trial(snap, observations, session_id=SESSION),
        lambda: flow.commit(
            snap, observations, session_id=SESSION, acquisition=Opens(), confirmed=True
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
        flow.start(descriptor(), observations, session_id=SESSION, started_by_operator=True)
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is expected
    assert flow.stage is RecoveryStage.REFUSED


def test_a_binding_from_another_machine_refuses_before_a_key_is_asked_for(
    observations, elsewhere
) -> None:
    """The gates in order: the acquisition is never even invoked."""

    flow = workflow(observations)
    acquisition = Opens()
    flow.start(descriptor(), observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(descriptor(), observations, session_id=SESSION)

    with pytest.raises(RecoveryRefused):
        flow.commit(
            descriptor(),
            elsewhere,
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(snap, observations, session_id=SESSION)

    with pytest.raises(RecoveryRefused):
        flow.commit(
            snap, observations, session_id=SESSION, acquisition=acquisition, confirmed=True
        )
    assert flow.audit()[-1].gate is RecoveryGate.KEY_ACQUISITION


def test_a_confirmation_that_was_not_given_refuses_last(observations) -> None:
    """And a confirmation that *was* given grants nothing by itself: the
    volume is still quarantined afterwards, which the first test drives."""

    flow = workflow(observations)
    snap = descriptor()
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(snap, observations, session_id=SESSION)

    with pytest.raises(RecoveryRefused):
        flow.commit(
            snap, observations, session_id=SESSION, acquisition=Opens(), confirmed=False
        )
    assert flow.audit()[-1].gate is RecoveryGate.OPERATOR_CONFIRMATION


def test_a_snapshot_swapped_under_the_workflow_is_refused(observations) -> None:
    """An older snapshot substituted between the start and the trial.

    The workflow holds what it started on and compares. Re-presenting a
    different descriptor — an older fingerprint, a lower schema version, a
    weakened integrity verdict — is refused rather than used.
    """

    flow = workflow(observations)
    flow.start(descriptor(), observations, session_id=SESSION, started_by_operator=True)

    with pytest.raises(RecoveryRefused) as refused:
        flow.open_trial(descriptor(fingerprint=OLD_FINGERPRINT), observations, session_id=SESSION)
    assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW

    # **Terminal and audited.** It used to raise and leave no trace, so a
    # caller could present a substituted snapshot, be refused, and simply retry
    # with the original — with nothing recording that a swap was attempted. The
    # earlier version of this test asserted the stage was still
    # `PREFLIGHT_PASSED`, i.e. it pinned exactly that.
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.audit()[-1].event is SnapshotAuditEvent.RECOVERY_SNAPSHOT_SUBSTITUTED
    with pytest.raises(RecoveryRefused) as retried:
        flow.open_trial(descriptor(), observations, session_id=SESSION)
    assert retried.value.refusal is Refusal.WORKFLOW_ALREADY_FINISHED

    # And each shape of substitution, on its own fresh workflow.
    for swapped in (
        descriptor(schema_version=2),
        descriptor(integrity=SnapshotIntegrity.INDETERMINATE),
        descriptor(container_version=99),
    ):
        fresh = workflow(observations)
        fresh.start(descriptor(), observations, session_id=SESSION, started_by_operator=True)
        with pytest.raises(RecoveryRefused) as refused:
            fresh.open_trial(swapped, observations, session_id=SESSION)
        assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW
        assert fresh.stage is RecoveryStage.REFUSED

    # L17: the comparison is by **value**, and the prose no longer implies
    # otherwise. An equal-but-distinct descriptor is the same report.
    twin = workflow(observations)
    twin.start(descriptor(), observations, session_id=SESSION, started_by_operator=True)
    equal_but_distinct = descriptor()
    assert equal_but_distinct is not twin._snapshot
    twin.open_trial(equal_but_distinct, observations, session_id=SESSION)
    assert twin.stage is RecoveryStage.TRIAL_OPEN

    # And the swap is refused at **commit** too, not only at the trial.
    with pytest.raises(RecoveryRefused) as at_commit:
        twin.commit(
            descriptor(fingerprint=OLD_FINGERPRINT),
            observations,
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(snap, observations, session_id=SESSION)

    quarantine.fence()

    with pytest.raises(RecoveryRefused):
        flow.commit(snap, observations, session_id=SESSION, acquisition=Opens(), confirmed=True)
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
        second.open_trial(descriptor(), observations, session_id=SESSION)
    assert refused.value.refusal is Refusal.STAGE_SKIPPED


# --------------------------------------------------------------------------
# What may be rendered, and what the audit may hold
# --------------------------------------------------------------------------


def test_no_audit_entry_can_carry_contents_a_figure_or_an_identity() -> None:
    """Checked by field name, because a field is how the rest arrives."""

    names = {field.name for field in dataclasses.fields(SnapshotAuditEntry)}
    assert names == {"event", "check", "gate", "schema_version", "fingerprint"}

    # The loop below cannot fail while the exact set above holds. It is kept
    # because it says *why* those five and no others — a reader adding a sixth
    # edits the set above and then has to answer this list. It is documentation
    # with an assertion's syntax, and is labelled as such rather than counted
    # as a second check.
    for bad in (
        "content", "contents", "payload", "data", "bytes", "block", "record",
        "offset", "size", "length", "capacity", "free", "space", "required",
        "available", "count", "time", "timestamp", "device", "identity",
        "serial", "path", "key", "passphrase", "operator", "detail", "message",
        "reason", "error",
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

    ledger = MigrationLedger()
    verdict = preflight(
        a_quarantine(quarantined=False),
        snapshot=descriptor(),
        capacity=capacity(required=987654321, available=123456789),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )
    assert verdict.refused_by is PreflightCheck.REQUIRED_SPACE
    assert ledger.may_migrate(verdict, quarantine=a_quarantine(quarantined=False)) is False

    rendered = repr(ledger.audit()) + str(ledger.audit())
    assert "987654321" not in rendered
    assert "123456789" not in rendered
    assert ledger.audit() == (
        SnapshotAuditEntry(
            event=SnapshotAuditEvent.MIGRATION_REFUSED, check=PreflightCheck.REQUIRED_SPACE
        ),
    )


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

    rendered = " ".join(
        [repr(flow), repr(candidate), repr(snap), repr(capacity()), repr(MigrationLedger())]
    )
    assert FINGERPRINT not in rendered
    assert acquisition.secret not in rendered
    assert MEDIUM.identity not in rendered
    assert host_fingerprint(observations) not in rendered
    assert SESSION not in rendered

    refused = workflow(observations, quarantine=a_quarantine(fenced=True))
    with pytest.raises(RecoveryRefused) as error:
        refused.start(snap, observations, session_id=SESSION, started_by_operator=True)

    message = str(error.value) + error.value.detail
    for value in (FINGERPRINT, acquisition.secret, MEDIUM.identity, SESSION,
                  host_fingerprint(observations)):
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
    **equality**. A builtin that is not one of these fourteen is not reachable
    by any spelling, because reaching it needs a name, and the name is absent.
    `locals`, `breakpoint`, `globals`, `vars`, `open`, `__import__`, `eval` and
    whatever the next round finds are all refused by the same line, which is
    the difference between a list of what is forbidden and a list of what is
    permitted. Everything after it is a second line, kept because it is cheap.

    What this still does **not** establish is that the module performs no I/O:
    a static scan refuses the shapes it knows. `test_the_workflow_performs_no_
    io_when_it_actually_runs` is the capability check, and it is the one that
    covers what this module *calls*.
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
        "Exception",
        "TypeError",
        "bool",
        "frozenset",
        "getattr",  # and only in the seal's one shape, pinned below
        "int",
        "isinstance",
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
        # Two shapes, both reads of this object's own state with a default:
        # the seal, and the stage the repr renders. The repr needs one because
        # `__init__` validates before it assigns, and the traceback machinery
        # calls `repr` on the half-built object — a clean `TypeError` became an
        # `AttributeError` raised from inside the redacting repr.
        assert isinstance(node.args[1], ast.Constant)
        assert node.args[1].value in {"_sealed", "_stage"}, node.args[1].value

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
        "start", "open_trial", "commit", "interrupt", "audit", "stage", "holds",
    }
    assert driven == {
        name
        for name, _ in inspect.getmembers(RecoveryWorkflow)
        if not name.startswith("_")
    }, "a public method of RecoveryWorkflow is not driven below"
    assert {"audit", "may_migrate", "note_snapshot_written"} == {
        name for name, _ in inspect.getmembers(MigrationLedger) if not name.startswith("_")
    }, "a public method of MigrationLedger is not driven below"

    snap = descriptor()
    for build in (
        lambda flow, q: flow.start(
            snap, observations, session_id=SESSION, started_by_operator=True
        ),
        lambda flow, q: flow.start(
            snap, observations, session_id=SESSION, started_by_operator=False
        ),
        lambda flow, q: flow.open_trial(snap, observations, session_id=SESSION),
        lambda flow, q: flow.commit(
            snap, observations, session_id=SESSION, acquisition=Opens(), confirmed=True
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
    for gate_case in (
        lambda: (a_quarantine(fenced=True), "start", {}),
        lambda: (a_quarantine(quarantined=False), "start", {}),
        lambda: (a_quarantine(), "commit", {"elsewhere": True}),
        lambda: (a_quarantine(), "commit", {"bad_channel": True}),
        lambda: (a_quarantine(), "commit", {"confirmed": False}),
        lambda: (a_quarantine(), "start", {"bad_snapshot": True}),
        lambda: (a_quarantine(), "open_trial", {"swap": True}),
        lambda: (a_quarantine(), "start", {"other_sitting": True}),
        lambda: (a_quarantine(), "start", {"not_operator": True}),
    ):
        quarantine, where, options = gate_case()
        before = (_flags(quarantine), quarantine.audit(), len(quarantine.audit()))
        flow = workflow(observations, quarantine=quarantine)
        good = descriptor()
        try:
            if where != "start":
                flow.start(good, observations, session_id=SESSION, started_by_operator=True)
            if where == "commit":
                flow.open_trial(good, observations, session_id=SESSION)
                flow.commit(
                    good,
                    elsewhere if options.get("elsewhere") else observations,
                    session_id=SESSION,
                    acquisition=Opens(channel=NOT_A_CHANNEL)
                    if options.get("bad_channel")
                    else Opens(),
                    confirmed=options.get("confirmed", True),
                )
            elif where == "open_trial":
                flow.open_trial(
                    descriptor(fingerprint=OLD_FINGERPRINT), observations, session_id=SESSION
                )
            else:
                flow.start(
                    descriptor(integrity=SnapshotIntegrity.FAILED)
                    if options.get("bad_snapshot")
                    else good,
                    observations,
                    session_id="another" if options.get("other_sitting") else SESSION,
                    started_by_operator=not options.get("not_operator"),
                )
        except RecoveryRefused:
            pass
        after = (_flags(quarantine), quarantine.audit(), len(quarantine.audit()))
        assert after == before, f"{where} {options} changed the quarantine"

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
        lambda: ledger.note_snapshot_written(verdict, snap,
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
            lambda: {"quarantine": a_quarantine(fenced=True),
                     "bad_acquisition": True, "confirmed": False, "elsewhere": True},
        ),
        (
            RecoveryGate.NOTHING_TO_RECOVER,
            lambda: {"quarantine": a_quarantine(quarantined=False),
                     "bad_acquisition": True, "confirmed": False, "elsewhere": True},
        ),
        # D8 gate 1, the **target**: a quarantine that never saw the medium.
        # This used to be the host binding wearing gate 1's name, so a recovery
        # committed over a quarantine that had observed no device at all.
        (
            RecoveryGate.TARGET_BINDING,
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
    # The three gates that precede D8's four are refused at `start` already,
    # so a workflow over one of them never reaches the trial. `TARGET_BINDING`
    # joined them when it stopped being the host binding under gate 1's name.
    refused_at_start = (
        RecoveryGate.MEDIUM_FENCED,
        RecoveryGate.NOTHING_TO_RECOVER,
        RecoveryGate.TARGET_BINDING,
    )
    if gate not in refused_at_start:
        flow.start(good, observations, session_id=SESSION, started_by_operator=True)
        flow.open_trial(good, observations, session_id=SESSION)

    snapshot_now = good

    acquisition = Opens(channel=NOT_A_CHANNEL) if options.get("bad_acquisition") else Opens()
    inventory = elsewhere if options.get("elsewhere") else observations

    if gate in refused_at_start:
        with pytest.raises(RecoveryRefused) as refused:
            flow.start(good, inventory, session_id=SESSION, started_by_operator=True)
    else:
        with pytest.raises(RecoveryRefused) as refused:
            flow.commit(
                snapshot_now,
                inventory,
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
            descriptor(**broken), observations, session_id=SESSION, started_by_operator=True
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)

    quarantine.fence()

    with pytest.raises(RecoveryRefused):
        flow.open_trial(snap, observations, session_id=SESSION)
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

    ledger = MigrationLedger()
    forged = PreflightVerdict(None)

    assert verdict_was_minted_here(forged) is False
    with pytest.raises(RecoveryRefused) as refused:
        ledger.may_migrate(forged, quarantine=a_quarantine(quarantined=False))
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT

    with pytest.raises(RecoveryRefused):
        ledger.note_snapshot_written(forged, descriptor(),
            quarantine=a_quarantine(quarantined=False),
        )
    assert ledger.audit() == ()

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
    assert verdict_was_minted_here(minted) is True
    assert ledger.may_migrate(minted, quarantine=a_quarantine(quarantined=False)) is True


def test_a_snapshot_is_recorded_as_written_only_after_the_caller_acted() -> None:
    """M12: `record` asserted the write at permission time.

    In a repository whose every document says no snapshot has been written,
    the audit's only positive classification was a claim about an act that had
    not occurred and might never occur.
    """

    ledger = MigrationLedger()
    judged = descriptor()
    minted = preflight(
        a_quarantine(quarantined=False),
        snapshot=judged,
        capacity=capacity(),
        current_schema=1,
        target_schema=2,
        binding_holds=True,
        generation_holds=True,
        image_digest_holds=True,
    )

    assert ledger.may_migrate(minted, quarantine=a_quarantine(quarantined=False)) is True
    assert ledger.audit() == ()  # permission granted; nothing written yet

    ledger.note_snapshot_written(minted, judged, quarantine=a_quarantine(quarantined=False))
    assert ledger.audit()[-1].event is SnapshotAuditEvent.SNAPSHOT_WRITTEN

    # **The verdict names the snapshot it judged.** It used to name none, so
    # this method could only re-check that *some* passing verdict existed: a
    # re-review recorded `SNAPSHOT_WRITTEN` against a snapshot whose integrity
    # was `FAILED`, on a verdict minted for a different, verified one. Both
    # objects were real and the verdict legitimately minted; nothing tied them.
    other = descriptor(integrity=SnapshotIntegrity.FAILED, schema_version=2)
    with pytest.raises(RecoveryRefused) as refused:
        ledger.note_snapshot_written(minted, other, quarantine=a_quarantine(quarantined=False))
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT

    # An equal-but-distinct descriptor is not the one that was judged either:
    # the tie is identity, because the point is *which* snapshot the preflight
    # actually looked at.
    with pytest.raises(RecoveryRefused):
        ledger.note_snapshot_written(minted, descriptor(),
            quarantine=a_quarantine(quarantined=False),
        )

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
    hostile = Subclassed(1, FINGERPRINT)
    planted = workflow(observations)
    object.__setattr__(planted, "_candidate", hostile)

    assert planted.holds(hostile)  # identity says yes
    assert not candidate_applies_to(planted, hostile)  # the type says no
    assert hostile.authority == ("everything",)

    # An uncommitted workflow holds nothing — including `None`, which is what
    # it holds. `PersistenceSession.holds` was found in exactly this trap.
    fresh = workflow(observations)
    assert not fresh.holds(None)
    assert not candidate_applies_to(fresh, None)
    assert not fresh.holds(candidate)

    # Another workflow's candidate is not this one's.
    other = workflow(observations)
    assert not other.holds(candidate)


def test_a_workflow_refuses_a_stage_asked_for_another_sitting(observations) -> None:
    """M13: `_session_id` was assigned once and read nowhere.

    `__setattr__` claimed "the quarantine, the binding and the sitting cannot
    be replaced", while the sitting was not used at all — so a review committed
    a workflow built for one sitting by passing another's id to every stage.
    """

    flow = workflow(observations)
    with pytest.raises(RecoveryRefused) as refused:
        flow.start(
            descriptor(), observations, session_id="another-sitting", started_by_operator=True
        )
    assert refused.value.refusal is Refusal.NOT_THIS_SITTING
    # Terminal and audited, on the module's own principle that a swap is an
    # event rather than a typo. It used to raise and leave `NOT_STARTED` with
    # an empty audit, so a foreign sitting could probe a live workflow as often
    # as it liked and nothing recorded that it had.
    assert flow.stage is RecoveryStage.REFUSED
    assert [entry.event for entry in flow.audit()] == [
        SnapshotAuditEvent.RECOVERY_FOREIGN_SITTING
    ]


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
    flow.start(good, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(good, observations, session_id=SESSION)

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            descriptor(integrity=SnapshotIntegrity.FAILED),
            observations,
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
    for name in ("_quarantine", "_binding", "_session_id", "_stage", "_snapshot", "_candidate"):
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

    flow.start(descriptor(), observations, session_id=SESSION, started_by_operator=True)
    for name, value in (
        ("_snapshot", descriptor(schema_version=2)),
        ("_pinned", descriptor(schema_version=2)),
    ):
        with pytest.raises(AttributeError, match="pinned when it starts"):
            flow._sealed_assign(name, value)
    with pytest.raises(AttributeError, match="minted by a commit"):
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
    with pytest.raises(RecoveryRefused):
        MigrationLedger().may_migrate(stolen, quarantine=a_quarantine(quarantined=False))


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

    refused = preflight(
        a_quarantine(quarantined=False),
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
            assert held is None or isinstance(held, PreflightCheck | tuple), name

    rebuilt = PreflightVerdict(None)
    assert rebuilt.may_migrate is True
    assert verdict_was_minted_here(rebuilt) is False

    ledger = MigrationLedger()
    with pytest.raises(RecoveryRefused) as error:
        ledger.may_migrate(rebuilt, quarantine=a_quarantine(quarantined=False))
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(snap, observations, session_id=SESSION)

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            snap, observations, session_id=SESSION, acquisition=acquisition, confirmed=True
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

    binding = SessionBinding(
        host_fingerprint=host_fingerprint(observations), session_id=SESSION
    )
    with pytest.raises(TypeError, match="must be a Quarantine"):
        RecoveryWorkflow(NotAQuarantine(), binding, session_id=SESSION)
    with pytest.raises(TypeError, match="must be a SessionBinding"):
        RecoveryWorkflow(a_quarantine(), "not a SessionBinding", session_id=SESSION)
    for bad_sitting in (1234, "", "   ", None):
        with pytest.raises(TypeError, match="session_id"):
            RecoveryWorkflow(a_quarantine(), binding, session_id=bad_sitting)


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
            descriptor(), observations, session_id=SESSION, started_by_operator=False
        )
    assert refused.value.refusal is Refusal.RECOVERY_NOT_STARTED_BY_AN_OPERATOR
    assert flow.stage is RecoveryStage.REFUSED
    assert flow.audit() == (
        SnapshotAuditEntry(event=SnapshotAuditEvent.RECOVERY_REFUSED),
    )

    # And terminal: a real start afterwards is refused, so the attempt cannot
    # be washed away by simply trying again properly.
    with pytest.raises(RecoveryRefused) as again:
        flow.start(descriptor(), observations, session_id=SESSION, started_by_operator=True)
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
        flow.start(descriptor(), observations, session_id=SESSION, started_by_operator=truthy)
    assert flow.stage is RecoveryStage.NOT_STARTED

    good = workflow(observations)
    snap = descriptor()
    good.start(snap, observations, session_id=SESSION, started_by_operator=True)
    good.open_trial(snap, observations, session_id=SESSION)
    with pytest.raises(TypeError, match="confirmed"):
        good.commit(
            snap, observations, session_id=SESSION, acquisition=Opens(), confirmed=truthy
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

    binding = SessionBinding(
        host_fingerprint=host_fingerprint(observations), session_id=SESSION
    )
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
    flow.start(real, observations, session_id=SESSION, started_by_operator=True)

    for stage in (
        lambda item: flow.open_trial(item, observations, session_id=SESSION),
        lambda item: flow.commit(
            item, observations, session_id=SESSION, acquisition=Opens(), confirmed=True
        ),
    ):
        with pytest.raises(TypeError, match="exactly"):
            stage(Substitute())
    assert flow.stage is RecoveryStage.PREFLIGHT_PASSED

    with pytest.raises(TypeError, match="exactly"):
        RecoveryWorkflow(
            a_quarantine(),
            SessionBinding(
                host_fingerprint=host_fingerprint(observations), session_id=SESSION
            ),
            session_id=SESSION,
        ).start(Substitute(), observations, session_id=SESSION, started_by_operator=True)


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
        flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    if stage == "commit":
        flow.open_trial(snap, observations, session_id=SESSION)

    call = {
        "start": lambda: flow.start(
            snap, observations, session_id="elsewhere", started_by_operator=True
        ),
        "open_trial": lambda: flow.open_trial(snap, observations, session_id="elsewhere"),
        "commit": lambda: flow.commit(
            snap, observations, session_id="elsewhere", acquisition=Opens(), confirmed=True
        ),
    }[stage]

    with pytest.raises(RecoveryRefused) as refused:
        call()
    assert refused.value.refusal is Refusal.NOT_THIS_SITTING


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
    declared = {field.name for field in dataclasses.fields(SnapshotDescriptor)}
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(snap, observations, session_id=SESSION)

    with pytest.raises(TypeError, match="requires a key acquisition"):
        flow.commit(snap, observations, session_id=SESSION, acquisition=None, confirmed=True)
    assert flow.stage is RecoveryStage.TRIAL_OPEN
    assert flow.holds(RecoveryCandidate(1, FINGERPRINT)) is False

    # And the honest failing acquisition, for the contrast the finding rests on.
    refused_flow = workflow(observations)
    refused_flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    refused_flow.open_trial(snap, observations, session_id=SESSION)
    with pytest.raises(RecoveryRefused) as refused:
        refused_flow.commit(
            snap,
            observations,
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
        flow.start(descriptor(), observations, session_id=lying, started_by_operator=True)
    assert flow.stage is RecoveryStage.NOT_STARTED

    with pytest.raises(TypeError, match="session_id must be a str exactly"):
        RecoveryWorkflow(
            a_quarantine(),
            SessionBinding(
                host_fingerprint=host_fingerprint(observations), session_id=SESSION
            ),
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(snap, observations, session_id=SESSION)
    assert quarantine.is_fenced is False

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            snap,
            observations,
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)

    object.__setattr__(snap, "schema_version", 2)
    object.__setattr__(snap, "fingerprint", "snapshot-fingerprint-0000")

    with pytest.raises(RecoveryRefused) as refused:
        flow.open_trial(snap, observations, session_id=SESSION)
    assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW
    assert flow.stage is RecoveryStage.REFUSED
    assert SnapshotAuditEvent.RECOVERY_SNAPSHOT_SUBSTITUTED in [
        entry.event for entry in flow.audit()
    ]


def test_the_seal_writes_only_the_four_fields_a_recovery_moves(observations) -> None:
    """R4-6: `_sealed_assign` was a general unsealing method on every instance.

    `__setattr__` refuses ordinary assignment with the words "the quarantine,
    the binding and the sitting cannot be replaced", and the class handed out a
    bound method that replaced any of them. A review used it to resume after
    `interrupt`, to swap the quarantine for an unfenced one, and to jump from
    `NOT_STARTED` straight to `TRIAL_OPEN` and mint a candidate whose entire
    audit was `['recovery_completed']`.

    This is **not** claimed as a capability boundary — `object.__setattr__` is
    not defensible in Python and this module says so about the quarantine. What
    it removes is the accidental reach: the four fields that legitimately move
    are named, and a terminal workflow moves none of them.
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.interrupt(session_id=SESSION)
    assert flow.stage is RecoveryStage.INTERRUPTED
    for name, value in (
        ("_stage", RecoveryStage.TRIAL_OPEN),
        ("_snapshot", descriptor(schema_version=2)),
        ("_candidate", RecoveryCandidate(2, FINGERPRINT)),
    ):
        with pytest.raises(AttributeError, match="has ended"):
            flow._sealed_assign(name, value)
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
        SnapshotAuditEntry(
            event=SnapshotAuditEvent.RECOVERY_STARTED, schema_version=Renders(1)
        )
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)

    with pytest.raises(RecoveryRefused) as refused:
        flow.interrupt(session_id="another-sitting")
    assert refused.value.refusal is Refusal.NOT_THIS_SITTING

    with pytest.raises(TypeError, match="session_id must be a str exactly"):
        flow.interrupt(session_id=type("S", (str,), {})(SESSION))


@pytest.mark.parametrize(
    "stage", ["start", "open_trial", "commit"]
)
def test_every_stage_refuses_observations_that_are_not_observations(
    stage, observations
) -> None:
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
        flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    if stage == "commit":
        flow.open_trial(snap, observations, session_id=SESSION)

    call = {
        "start": lambda items: flow.start(
            snap, items, session_id=SESSION, started_by_operator=True
        ),
        "open_trial": lambda items: flow.open_trial(snap, items, session_id=SESSION),
        "commit": lambda items: flow.commit(
            snap, items, session_id=SESSION, acquisition=Opens(), confirmed=True
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


def _swallow(call, *args, **keywords) -> None:
    """Drive it and keep going. A refusal is the ordinary outcome here."""

    try:
        call(*args, **keywords)
    except (RecoveryRefused, TypeError, AttributeError):
        pass


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
        try:
            state[name] = copy.deepcopy(object.__getattribute__(rule, name))
        except AttributeError:
            state[name] = "<deleted>"
    return state


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

    binding = SessionBinding(
        host_fingerprint=host_fingerprint(observations), session_id=SESSION
    )
    drives = 0
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

        # And twice over one medium, because "a second workflow over the same
        # quarantine" is an input dimension too: a payload firing only on the
        # second would see a guard that always builds the first.
        for _sitting in (1, 2):
            flow = RecoveryWorkflow(rule, binding, session_id=SESSION)
            _swallow(flow.start, snap, observations, session_id=SESSION,
                     started_by_operator=by_operator)
            _swallow(flow.open_trial, snap, observations, session_id=SESSION)
            _swallow(flow.commit, snap, observations, session_id=SESSION,
                     acquisition=Opens(outcome), confirmed=confirmed)
            _swallow(flow.commit, snap, observations, session_id=SESSION,
                     acquisition=Opens(outcome), confirmed=confirmed)
            _swallow(flow.audit)
            _swallow(flow.holds, RecoveryCandidate(schema_version, "x"))
            _swallow(repr, flow)
            _swallow(candidate_applies_to, flow, RecoveryCandidate(schema_version, "x"))
            _swallow(flow.interrupt, session_id=SESSION)

        drives += 1
        assert _whole_quarantine_state(rule) == before, (
            f"the quarantine moved on schema={schema_version} "
            f"container={container_version} integrity={integrity.value} "
            f"room={room} reports_hold={reports_hold}"
        )
        assert _quarantine_defences_intact(rule) == (True,) * 7

    assert drives == 3 * 2 * 3 * 2 * 2 * 2 * 2 * 2 * 2 * len(AttemptOutcome)


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

        def build():
            rule = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
            rule.observe(MEDIUM)
            rule.observe(Device(identity="host-nvme-SN-1", device_class=DeviceClass.HOST_STORAGE))
            rule.quarantine_volume()
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
        prepared = [(build(), snapshot) for snapshot in snapshots]
        fenced = build()
        fenced.fence()

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
                    snapshot, observations, session_id=SESSION, started_by_operator=True
                ),
                lambda: flow.open_trial(snapshot, observations, session_id=SESSION),
                lambda: flow.commit(
                    snapshot,
                    observations,
                    session_id=SESSION,
                    acquisition=Opens(),
                    confirmed=True,
                ),
                lambda: repr(flow.audit()),
                lambda: candidate_applies_to(flow, flow._candidate),
                lambda: flow.interrupt(session_id=SESSION),
            ):
                try:
                    act()
                except Exception:
                    pass

        print(repr([sorted(set(seen)), [event for event, _ in forbidden_at_import]]))
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
    while_running, at_import = ast.literal_eval(finished.stdout.strip())
    assert while_running == [], (
        f"the decision path performed audited operations: {while_running}"
    )
    assert at_import == [], (
        f"the module performed audited operations while importing: {at_import}"
    )


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
        ledger.note_snapshot_written(never_minted, snapshot,
            quarantine=a_quarantine(quarantined=False),
        )
    assert refused.value.refusal is Refusal.VERDICT_NOT_MINTED_BY_A_PREFLIGHT
    assert ledger.audit() == ()


def test_one_preflight_records_one_write_in_any_ledger() -> None:
    """R4: nothing marked a verdict spent.

    One `preflight` over one snapshot produced four `SNAPSHOT_WRITTEN`
    classifications across two ledgers. For an audit whose only positive
    classification is "a snapshot was written", n records for one judged write
    is a false count — and the second ledger is not a second write, which is
    why the spent-ness is kept module-side rather than per-ledger.
    """

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
    first, second = MigrationLedger(), MigrationLedger()
    first.note_snapshot_written(verdict, snapshot, quarantine=a_quarantine(quarantined=False))
    assert len(first.audit()) == 1

    for ledger in (first, second):
        with pytest.raises(RecoveryRefused) as refused:
            ledger.note_snapshot_written(verdict, snapshot,
                quarantine=a_quarantine(quarantined=False),
            )
        assert refused.value.refusal is Refusal.VERDICT_ALREADY_SPENT
    assert len(first.audit()) == 1
    assert second.audit() == ()


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

    snapshot = descriptor(integrity=SnapshotIntegrity.FAILED)
    refused_verdict = preflight(
        a_quarantine(quarantined=False),
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
        ledger.note_snapshot_written(refused_verdict, snapshot,
            quarantine=a_quarantine(quarantined=False),
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
        flow.start(descriptor(), observations, session_id=SESSION, started_by_operator=True)
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.TARGET_BINDING
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
        flow.start(descriptor(), observations, session_id=SESSION, started_by_operator=True)
    assert refused.value.refusal is Refusal.GATE_REFUSED
    assert flow.audit()[-1].gate is RecoveryGate.TARGET_BINDING


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
    assert not [entry for entry in ledger.audit() if entry.event is not
                SnapshotAuditEvent.MIGRATION_REFUSED]


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

    binding = SessionBinding(
        host_fingerprint=host_fingerprint(observations), session_id=SESSION
    )
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
            traceback.TracebackException.from_exception(
                raised.value, capture_locals=True
            ).format()
        )
        assert "RecoveryWorkflow(stage=unbuilt)" in rendered
        assert FINGERPRINT not in rendered
        assert MEDIUM.identity not in rendered


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
            object.__setattr__(snap, "schema_version", 99)
            object.__setattr__(snap, "fingerprint", "a-completely-different-snapshot")
            return super().attempt()

    flow = workflow(observations)
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(snap, observations, session_id=SESSION)

    with pytest.raises(RecoveryRefused) as refused:
        flow.commit(
            snap,
            observations,
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
    flow.start(snap, observations, session_id=SESSION, started_by_operator=True)
    flow.open_trial(snap, observations, session_id=SESSION)

    held = flow._pinned
    assert held is not snap
    assert _fields_of(held) == _fields_of(snap)

    candidate = flow.commit(
        snap, observations, session_id=SESSION, acquisition=Opens(), confirmed=True
    )
    assert candidate.schema_version == 1
    assert flow.audit()[-1].fingerprint == FINGERPRINT
    assert flow.audit()[-1].schema_version == 1


def test_a_preflight_is_free_so_spending_is_keyed_on_the_snapshot() -> None:
    """R5: the write-once defence was one `preflight()` call wide.

    `preflight` is read-only, unlimited and free, so four calls over one
    snapshot mint four distinct spendable verdicts — and one ledger recorded
    four `SNAPSHOT_WRITTEN` classifications for one write, which is the false
    count the WeakSet was added to remove. Spent-ness belongs to the snapshot.
    """

    healthy = a_quarantine(quarantined=False)
    snapshot = descriptor()
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
    assert verdict.evaluated == PREFLIGHT_ORDER

    shortened = PREFLIGHT_ORDER[:1]
    object.__setattr__(verdict, "_evaluated", shortened)
    assert verdict.may_migrate is True
    assert verdict_was_minted_here(verdict) is True

    ledger = MigrationLedger()
    with pytest.raises(RecoveryRefused) as refused:
        ledger.may_migrate(verdict, quarantine=a_quarantine(quarantined=False))
    assert refused.value.refusal is Refusal.VERDICT_DID_NOT_ASK_EVERY_CHECK
    assert ledger.audit() == ()
