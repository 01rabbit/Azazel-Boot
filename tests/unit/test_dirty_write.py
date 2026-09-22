"""A torn write costs the whole volume, and nothing is called erased.

Azazel-Boot#41, [ADR-0010](../../docs/adr/0010-persistence-key-and-migration.md)
D4 and D5.

**No USB SSD has been pulled mid-write.** Every observation here is three enum
values a caller would have reported; no device, no receipt, no filesystem and
no `/dev` path is involved. These tests exercise the decision. They are not
evidence about hardware, and [threat model](../../docs/threat-model.md) §3.3's
hardware-in-the-loop record does not exist.

The two properties that took the most care:

- **Ambiguity resolves to quarantine.** All twenty-seven observations are
  enumerated, so a future edit that lets one unknown through is a red test
  rather than a branch nobody re-read.
- **Nothing is described as erased.** The data is on the medium. Boot refuses
  to use it, which is a different sentence, and the difference is what an
  operator may later truthfully tell someone about the evidence.
"""

from __future__ import annotations

import ast
import dataclasses
import itertools
from pathlib import Path

import pytest
from conftest import mac_reader
from test_persistence import (  # the synthetic medium, binding and layout
    MEDIA_ARGS,
    MEDIUM,
    SESSION,
    layout,
    session,
    unlock_arguments,
)

from azazel_boot.commissioning import host_fingerprint
from azazel_boot.dirty_write import (
    CLEAN,
    DirtySignal,
    MediumContinuity,
    ReceiptState,
    Verification,
    WriteObservation,
    classify,
)
from azazel_boot.inventory import collect_interfaces
from azazel_boot.persistence import (
    DEGRADED_CAPABILITY,
    OrdinaryAct,
    PersistenceRefused,
    PersistenceState,
    Refusal,
    VolumeAuditEntry,
    VolumeAuditEvent,
)
from azazel_boot.quarantine import Device, DeviceClass, Quarantine

MODULE = Path(__file__).resolve().parents[2] / "src" / "azazel_boot" / "dirty_write.py"
TREE = ast.parse(MODULE.read_text(encoding="utf-8"))

TWO_NIC_MACS = {"enp3s0": "a0:b1:c2:d3:e4:f5", "enx001122334455": "00:11:22:33:44:55"}

#: The six words ADR-0010 D5 refuses. The volume was not any of them.
NEVER_SAID = ("wiped", "cleared", "erased", "destroyed", "shredded", "deleted")


@pytest.fixture
def observations(sysfs_two_nics):
    return collect_interfaces(sysfs_two_nics, permanent_mac_reader=mac_reader(TWO_NIC_MACS))


def _module_code() -> str:
    """The module's identifiers and non-docstring literals.

    Not its raw text. The module docstring *names* the six forbidden words in
    order to say the volume is none of them, and a raw scan would read that
    sentence as a violation of itself — the same self-contradiction
    `test_session_mode.py` hit and fixed.
    """

    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(TREE)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    pieces: list[str] = []
    for node in ast.walk(TREE):
        if isinstance(node, ast.Name):
            pieces.append(node.id)
        elif isinstance(node, ast.Attribute):
            pieces.append(node.attr)
        elif isinstance(node, ast.ClassDef | ast.FunctionDef):
            pieces.append(node.name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings:
                pieces.append(node.value)
    assert docstrings, "the module is expected to carry docstrings"
    return " ".join(pieces)


def observation(**overrides) -> WriteObservation:
    return dataclasses.replace(CLEAN, **overrides)


def torn() -> WriteObservation:
    return observation(receipt=ReceiptState.MISSING)


# --------------------------------------------------------------------------
# Every observation, and which one is clean
# --------------------------------------------------------------------------


ALL_OBSERVATIONS = [
    WriteObservation(receipt=r, continuity=c, verification=v)
    for r, c, v in itertools.product(ReceiptState, MediumContinuity, Verification)
]


def test_exactly_one_of_the_twenty_seven_observations_is_a_clean_write() -> None:
    """Enumerated rather than sampled, so a widened condition is a red test.

    Twenty-six of these are a fault of some kind, and several are faults nobody
    would think to write a case for — an unreadable receipt on a medium that
    stayed put and verified cleanly, for instance. Sampling would have covered
    the obvious ones.
    """

    assert len(ALL_OBSERVATIONS) == 27
    clean = [item for item in ALL_OBSERVATIONS if classify(item) is None]
    assert clean == [CLEAN]


@pytest.mark.parametrize("item", ALL_OBSERVATIONS, ids=lambda o: "-".join(
    (o.receipt.value, o.continuity.value, o.verification.value)
))
def test_every_observation_is_either_clean_or_a_member_of_the_vocabulary(item) -> None:
    """Total, with no third answer and no `None` that means "probably fine"."""

    signal = classify(item)
    if item == CLEAN:
        assert signal is None
    else:
        assert isinstance(signal, DirtySignal)


@pytest.mark.parametrize(
    "unknown",
    [
        observation(continuity=MediumContinuity.NOT_ESTABLISHED),
        observation(verification=Verification.INDETERMINATE),
        observation(receipt=ReceiptState.UNREADABLE),
    ],
)
def test_an_unknown_resolves_to_quarantine_and_never_to_a_clean_write(unknown) -> None:
    """The three "nobody can tell" cases, each with everything else clean.

    This is why the inputs are three-valued enums and not booleans: a `bool` has
    no room for "nobody established this", so a caller would have to pick one of
    the two answers it does have — and under time pressure that is the
    convenient one.
    """

    assert classify(unknown) is not None


def test_the_precedence_is_fixed_and_a_removal_is_named_before_its_symptom() -> None:
    """Several faults arrive together and the audit records one word.

    A pulled medium *causes* the missing receipt, so reporting `receipt_missing`
    there would name the symptom instead of the event.
    """

    everything_wrong = WriteObservation(
        receipt=ReceiptState.MISSING,
        continuity=MediumContinuity.REMOVED_DURING_WRITE,
        verification=Verification.FAILED,
    )
    assert classify(everything_wrong) is DirtySignal.REMOVAL_DURING_WRITE

    assert (
        classify(
            observation(
                receipt=ReceiptState.MISSING, verification=Verification.FAILED
            )
        )
        is DirtySignal.VERIFICATION_FAILED
    )
    assert classify(torn()) is DirtySignal.RECEIPT_MISSING


def test_there_is_no_clean_member_to_compare_against() -> None:
    """`classify` returns `None`, not a `DirtySignal.CLEAN`.

    A member meaning "fine" is a value later code compares against and proceeds
    on — the same reason `SessionMode` has no "undecided" and
    `PersistenceState` has `UNEXAMINED` rather than `ABSENT` for a medium nobody
    looked at.
    """

    assert not any(
        word in member.value for member in DirtySignal for word in ("clean", "ok", "fine", "none")
    )


# --------------------------------------------------------------------------
# The whole volume, one way
# --------------------------------------------------------------------------


def test_a_missing_receipt_quarantines_the_whole_volume(observations) -> None:
    live = session(observations)
    live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
    assert live.status().state is PersistenceState.OPEN

    status = live.report_write(torn(), observations)

    assert status.state is PersistenceState.QUARANTINED
    assert status.writable is False
    assert status.capability is DEGRADED_CAPABILITY
    assert live.volume_is_quarantined


@pytest.mark.parametrize("act", list(OrdinaryAct))
def test_every_ordinary_act_is_refused_on_a_quarantined_volume(act, observations) -> None:
    """All three, with the same refusal. There is no act still ordinary here."""

    live = session(observations)
    live.report_write(torn(), observations)

    with pytest.raises(PersistenceRefused) as refused:
        live.require_ordinary(act)
    assert refused.value.refusal is Refusal.VOLUME_QUARANTINED


@pytest.mark.parametrize("act", list(OrdinaryAct))
def test_an_ordinary_act_is_permitted_before_a_fault(act, observations) -> None:
    """Otherwise the test above would pass against a module that refuses always."""

    session(observations).require_ordinary(act)


def test_the_act_vocabulary_is_exactly_three() -> None:
    assert {act.value for act in OrdinaryAct} == {"read", "write", "export"}


def test_a_surprise_removal_and_a_torn_write_reach_the_same_state(observations) -> None:
    """Not distinguished by capability — ADR-0010 D4 treats them as one condition.

    A consumer that could tell them apart would eventually treat one as the
    milder of the two.
    """

    pulled = session(observations).report_write(
        observation(continuity=MediumContinuity.REMOVED_DURING_WRITE), observations
    )
    interrupted = session(observations).report_write(torn(), observations)

    assert pulled.state is interrupted.state is PersistenceState.QUARANTINED
    assert pulled.capability is interrupted.capability
    assert pulled.writable is interrupted.writable is False


def test_a_clean_write_changes_nothing_and_records_nothing(observations) -> None:
    live = session(observations)
    live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())

    status = live.report_write(CLEAN, observations)

    assert status.state is PersistenceState.OPEN
    assert not live.volume_is_quarantined
    assert live.audit() == ()


def test_the_quarantine_is_one_way_and_there_is_no_call_that_clears_it(observations) -> None:
    """Asserted over the public surface, not by trying the obvious spellings.

    Leaving quarantine is ADR-0010 D8's explicit recovery workflow, which is
    #42 and does not exist. A method here that ended the state would be that
    workflow with its four gates removed.
    """

    live = session(observations)
    live.report_write(torn(), observations)

    surface = {name for name in dir(live) if not name.startswith("__")}
    # `recovery_options` reads what is offered next out of the current state and
    # changes nothing, so it is exempted by exact name rather than by dropping
    # "recover" from the list — which would also exempt a future `recover()`.
    surface -= {"recovery_options"}
    for spelling in ("clear", "reopen", "unquarantine", "reset", "repair", "recover", "resume"):
        assert not any(spelling in name for name in surface), spelling

    with pytest.raises(AttributeError):
        live._volume_quarantined = False
    assert live.volume_is_quarantined


def test_the_medium_reappearing_does_not_lift_the_quarantine(observations) -> None:
    quarantine = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
    live = session(observations, quarantine=quarantine)
    live.report_write(torn(), observations)

    quarantine.observe(MEDIUM)
    quarantine.observe(Device(identity=MEDIUM.identity, device_class=DeviceClass.BOOT_MEDIUM))

    assert live.volume_is_quarantined
    with pytest.raises(PersistenceRefused):
        live.require_ordinary(OrdinaryAct.READ)


def test_quarantine_is_a_capability_change_and_never_an_authority(observations) -> None:
    live = session(observations)
    before = live.status()
    after = live.report_write(torn(), observations)

    assert before.authority == ()
    assert after.authority == ()
    assert after.capability is DEGRADED_CAPABILITY


# --------------------------------------------------------------------------
# Nothing is called erased
# --------------------------------------------------------------------------


def test_no_rendered_string_says_the_volume_was_erased(observations) -> None:
    """Over the status, the refusal, the audit, and the module's own prose.

    The data is on the medium and the [quarantine
    policy](../../docs/quarantine-policy.md) still offers an export of it
    unmodified. Saying "wiped" would be false, and what an operator may later
    tell someone about the evidence depends on it.
    """

    live = session(observations)
    status = live.report_write(torn(), observations)
    with pytest.raises(PersistenceRefused) as refused:
        live.require_ordinary(OrdinaryAct.WRITE)

    rendered = " ".join(
        [
            " ".join(status.reasons),
            repr(status),
            str(refused.value),
            refused.value.detail,
            repr(live.audit()),
            _module_code(),
            *(member.value for member in DirtySignal),
        ]
    ).lower()

    for word in NEVER_SAID:
        assert word not in rendered, f"something claims the volume was {word}"


def test_the_wording_says_boot_will_not_use_it(observations) -> None:
    """The positive half. Absence of the six words is not the same as saying it."""

    status = session(observations).report_write(torn(), observations)
    joined = " ".join(status.reasons)
    assert "will not use this volume in ordinary operation" in joined
    assert "does not repair" in joined


def test_the_quarantined_volume_may_still_be_exported_unmodified(observations) -> None:
    """ADR-0010 D5 leaves the offline-examination export where it was.

    That export is granted on the `Quarantine` under an operator approval, and
    this module cannot reach it — so refusing the *ordinary* export here does
    not close it. Driven rather than asserted about, because "it is a different
    path" is the kind of claim that stops being true quietly.
    """

    from azazel_boot.quarantine import Action, ExportApproval, Verdict

    quarantine = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
    host_disk = Device(identity="host-nvme-SN-1", device_class=DeviceClass.HOST_STORAGE)
    quarantine.observe(MEDIUM)
    quarantine.observe(host_disk)

    live = session(observations, quarantine=quarantine)
    live.report_write(torn(), observations)

    quarantine.approve_export(
        ExportApproval(
            session_id=SESSION,
            target_identity=host_disk.identity,
            reason="offline examination of a volume Boot will not use",
            confirmed=True,
        )
    )
    assert quarantine.evaluate(host_disk, Action.EXPORT_WRITE) is Verdict.ALLOWED

    with pytest.raises(PersistenceRefused):
        live.require_ordinary(OrdinaryAct.EXPORT)


def test_there_is_no_per_record_continuation_anywhere_in_the_surface(observations) -> None:
    """D5: no salvage, no "the earlier ones are fine", no partial mount."""

    live = session(observations)
    live.report_write(torn(), observations)

    surface = {name for name in dir(live) if not name.startswith("_")}
    for spelling in ("record", "salvage", "partial", "mount", "earlier", "before"):
        assert not any(spelling in name for name in surface), spelling


# --------------------------------------------------------------------------
# What the audit may hold
# --------------------------------------------------------------------------


def test_the_audit_holds_the_detection_the_transition_and_the_refusal(
    observations,
) -> None:
    live = session(observations)
    live.report_write(torn(), observations)
    with pytest.raises(PersistenceRefused):
        live.require_ordinary(OrdinaryAct.READ)

    assert live.audit() == (
        VolumeAuditEntry(
            event=VolumeAuditEvent.DIRTY_WRITE_DETECTED, signal=DirtySignal.RECEIPT_MISSING
        ),
        VolumeAuditEntry(
            event=VolumeAuditEvent.VOLUME_QUARANTINED, signal=DirtySignal.RECEIPT_MISSING
        ),
        VolumeAuditEntry(
            event=VolumeAuditEvent.ORDINARY_ACT_REFUSED, act=OrdinaryAct.READ
        ),
    )


def test_the_audit_vocabulary_is_exactly_three_classifications() -> None:
    assert {event.value for event in VolumeAuditEvent} == {
        "dirty_write_detected",
        "volume_quarantined",
        "ordinary_act_refused",
    }


def test_no_audit_entry_can_carry_content_an_offset_a_count_or_an_identity() -> None:
    """Checked by field name, because a field is how the rest arrives."""

    names = {field.name for field in dataclasses.fields(VolumeAuditEntry)}
    assert names == {"event", "signal", "act"}

    forbidden = (
        "content", "payload", "data", "bytes", "record", "offset", "size",
        "length", "count", "time", "timestamp", "device", "identity", "serial",
        "path", "key", "operator", "detail", "message", "reason", "error",
    )
    for bad in forbidden:
        assert not any(bad in name for name in names), bad


def test_nothing_rendered_by_the_audit_carries_a_number_or_an_identity(
    observations,
) -> None:
    """Rendered, not just inspected: an entry reaches a journal as text."""

    live = session(observations)
    live.report_write(torn(), observations)
    with pytest.raises(PersistenceRefused):
        live.require_ordinary(OrdinaryAct.WRITE)

    rendered = repr(live.audit())
    assert MEDIUM.identity not in rendered
    assert host_fingerprint(observations) not in rendered
    assert SESSION not in rendered
    assert not any(character.isdigit() for character in rendered), rendered


def test_the_refusal_names_the_rule_and_not_the_act_or_the_signal(observations) -> None:
    """A refusal message reaches a console and a log on travelling hardware."""

    live = session(observations)
    live.report_write(
        observation(continuity=MediumContinuity.REMOVED_DURING_WRITE), observations
    )
    with pytest.raises(PersistenceRefused) as refused:
        live.require_ordinary(OrdinaryAct.EXPORT)

    detail = str(refused.value) + refused.value.detail
    assert DirtySignal.REMOVAL_DURING_WRITE.value not in detail
    assert MEDIUM.identity not in detail
    assert SESSION not in detail


# --------------------------------------------------------------------------
# The fence wins, and nothing here reaches a host
# --------------------------------------------------------------------------


def test_a_fenced_medium_refuses_before_the_write_is_even_classified(
    observations,
) -> None:
    """The fence takes precedence: classifying would mean reasoning about a
    device that is not there."""

    quarantine = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
    live = session(observations, quarantine=quarantine)
    quarantine.fence()

    with pytest.raises(PersistenceRefused) as refused:
        live.report_write(torn(), observations)
    assert refused.value.refusal is Refusal.SESSION_FENCED
    assert live.audit() == ()
    assert not live.volume_is_quarantined

    with pytest.raises(PersistenceRefused) as refused:
        live.require_ordinary(OrdinaryAct.READ)
    assert refused.value.refusal is Refusal.SESSION_FENCED


def test_nothing_here_clears_a_fence_or_raises_a_capability(observations) -> None:
    quarantine = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
    live = session(observations, quarantine=quarantine)
    live.report_write(torn(), observations)
    quarantine.fence()

    assert quarantine.is_fenced
    assert live.status().state is PersistenceState.FENCED
    assert live.status().capability is DEGRADED_CAPABILITY


def test_this_module_cannot_reach_a_disk_a_device_a_network_or_a_host() -> None:
    """An allowlist. A denylist of module names is one `__import__` wide."""

    imported: set[str] = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0] or ".")

    assert imported == {"__future__", "dataclasses", "enum"}

    called = {
        node.func.id
        for node in ast.walk(TREE)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"__import__", "eval", "exec", "compile", "open", "input"}

    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(TREE)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    used: list[str] = []
    for node in ast.walk(TREE):
        if isinstance(node, ast.Name):
            used.append(node.id)
        elif isinstance(node, ast.Attribute):
            used.append(node.attr)
        elif isinstance(node, ast.ClassDef | ast.FunctionDef):
            used.append(node.name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings:
                used.append(node.value)

    code = " ".join(used)
    for never in ("/dev", "host", "snapshot", "recovery", "export_write", "mount", "repair"):
        assert never not in code, f"dirty_write names {never!r} in code"
