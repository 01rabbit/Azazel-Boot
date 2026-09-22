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
import pickle
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
    preflight,
    schema_is_compatible,
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

    exported = {
        name
        for name, value in vars(module).items()
        if not name.startswith("_")
        and getattr(value, "__module__", module.__name__) == module.__name__
    }
    assert exported == {
        "KNOWN_CONTAINER_VERSIONS",
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

    assigned = {
        target.attr
        for node in ast.walk(TREE)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Attribute)
    }
    assert not assigned & {"_fenced", "_volume_quarantined"}

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
    assert ledger.record(verdict, None) is False

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
    assert imported == {
        "__future__",
        "dataclasses",
        "enum",
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

    flow.interrupt()
    assert flow.stage is RecoveryStage.INTERRUPTED

    for attempt in (
        lambda: flow.open_trial(snap, observations, session_id=SESSION),
        lambda: flow.commit(
            snap, observations, session_id=SESSION, acquisition=Opens(), confirmed=True
        ),
        flow.interrupt,
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
    assert flow.audit()[-1].gate is RecoveryGate.TARGET_BINDING


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

    for swapped in (
        descriptor(fingerprint=OLD_FINGERPRINT),
        descriptor(schema_version=2),
        descriptor(integrity=SnapshotIntegrity.INDETERMINATE),
        descriptor(container_version=99),
    ):
        with pytest.raises(RecoveryRefused) as refused:
            flow.open_trial(swapped, observations, session_id=SESSION)
        assert refused.value.refusal is Refusal.SNAPSHOT_CHANGED_UNDER_THE_WORKFLOW
        assert flow.stage is RecoveryStage.PREFLIGHT_PASSED


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

    for bad in (
        "content", "contents", "payload", "data", "bytes", "block", "record",
        "offset", "size", "length", "capacity", "free", "space", "required",
        "available", "count", "time", "timestamp", "device", "identity",
        "serial", "path", "key", "passphrase", "operator", "detail", "message",
        "reason", "error",
    ):
        assert not any(bad in name for name in names), bad


def test_the_audit_vocabulary_is_exactly_seven_classifications() -> None:
    assert {event.value for event in SnapshotAuditEvent} == {
        "migration_refused",
        "snapshot_written",
        "recovery_started",
        "recovery_trial_opened",
        "recovery_completed",
        "recovery_refused",
        "recovery_interrupted",
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
    assert ledger.record(verdict, None) is False

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
    """

    reachable: set[str] = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Name):
            reachable.add(node.id)
        elif isinstance(node, ast.Attribute):
            reachable.add(node.attr)
    assert not reachable & {
        "__builtins__",
        "globals",
        "vars",
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "input",
        "setattr",
        "delattr",
    }
    # `getattr` is exempt for the reason `test_session_mode.py` gives: the
    # `__setattr__` seal reads `_sealed` with it during construction, before
    # the slot exists, so forbidding it would mean forbidding the seal.
    assert not [
        node
        for node in ast.walk(TREE)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Subscript)
    ]

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
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef)
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
