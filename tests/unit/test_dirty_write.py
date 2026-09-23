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
from types import SimpleNamespace

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
    RECOVERY_OPTIONS,
    Capability,
    OrdinaryAct,
    PersistenceRefused,
    PersistenceState,
    PersistenceStatus,
    Refusal,
    UnlockOutcome,
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


def _module_code(tree: ast.Module = TREE, *, docstrings: bool = True) -> str:
    """Everything the module says **except its own module docstring**.

    The class and function docstrings are *included*, and that is the whole
    point: a docstring is where an operator-facing claim actually lives — it
    reaches `help()`, an IDE hover and generated documentation — and
    `docs/persistence.md` says in as many words that no **docstring** claims
    erasure.

    An earlier version excluded docstrings as a category, which made that claim
    unenforceable. A review put *"the volume has been wiped and its contents
    erased and destroyed"* into `classify`'s docstring and the whole suite
    stayed green.

    Only the **module** docstring is exempt, by node identity, because it names
    the six forbidden words in order to say the volume is none of them — the
    self-contradiction `test_session_mode.py` hit. One node, not a category.
    """

    module_docstring = None
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        module_docstring = id(tree.body[0].value)
    assert module_docstring is not None, "the module is expected to carry a docstring"

    pieces: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            pieces.append(node.id)
        elif isinstance(node, ast.Attribute):
            pieces.append(node.attr)
        elif isinstance(node, ast.ClassDef | ast.FunctionDef):
            pieces.append(node.name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # `==`, not `is`: `id()` returns an int, and `is` on two ints
            # beyond the small-integer cache is false even when they are equal.
            if id(node) == module_docstring:
                continue
            if not docstrings and id(node) in _docstring_ids(tree):
                continue
            pieces.append(node.value)
    return " ".join(pieces)


def _docstring_ids(tree: ast.Module) -> set[int]:
    return {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }


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
    assert status.capability is DEGRADED_CAPABILITY
    assert live.volume_is_quarantined
    # `writable` is `state is OPEN`, so asserting it beside the state above
    # restates that line. What is worth pinning is that the property has not
    # been redefined to answer something else.
    assert status.writable is False
    assert PersistenceStatus(
        state=PersistenceState.OPEN, outcome=None, reasons=(), capability=Capability.LITE
    ).writable is True


@pytest.mark.parametrize("act", list(OrdinaryAct))
def test_every_ordinary_act_is_refused_on_a_quarantined_volume(act, observations) -> None:
    """All three, with the same refusal. There is no act still ordinary here."""

    live = session(observations)
    live.report_write(torn(), observations)

    with pytest.raises(PersistenceRefused) as refused:
        live.require_ordinary(act, observations)
    assert refused.value.refusal is Refusal.VOLUME_QUARANTINED


@pytest.mark.parametrize("act", list(OrdinaryAct))
def test_an_ordinary_act_is_permitted_before_a_fault(act, observations) -> None:
    """Otherwise the test above would pass against a module that refuses always."""

    session(observations).require_ordinary(act, observations)


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

    ADR-0010 D8's recovery workflow is `azazel_boot.snapshot` (#42), and it
    does not end the state either: it hands back a **candidate** and leaves the
    quarantine as it found it. A method here that ended the state would be that
    workflow with all of its gates removed.
    """

    live = session(observations)
    live.report_write(torn(), observations)

    # An **exact allowlist**, not a list of spellings. The first version checked
    # seven substrings — clear, reopen, unquarantine, reset, repair, recover,
    # resume — and a review added `lift()`, which clears the flag and returns an
    # un-quarantined status, and the whole suite stayed green. `restore`,
    # `trust`, `permit` and `rehabilitate` walk through the same gap. The docs
    # described this test as asserting the absence "rather than trying the
    # obvious spellings one at a time"; it was precisely the latter.
    assert {name for name in dir(live) if not name.startswith("_")} == {
        "audit",
        "create",
        "fence_after_removal",
        "quarantine",
        "recovery_options",
        "report_write",
        "require_ordinary",
        "session_id",
        "status",
        "unlock",
        "volume_is_quarantined",
    }

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
    with pytest.raises(PersistenceRefused) as refused:
        live.require_ordinary(OrdinaryAct.READ, observations)
    # Named, because a bare `raises(PersistenceRefused)` is satisfied by
    # `SESSION_FENCED` — a different rule reaching the same exception type.
    assert refused.value.refusal is Refusal.VOLUME_QUARANTINED


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
        live.require_ordinary(OrdinaryAct.WRITE, observations)

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


def test_no_string_persistence_can_emit_says_the_volume_was_erased() -> None:
    """The other module, which the scan above never reached.

    `azazel_boot.persistence` holds the reason strings for all four unlock
    faults, every `Refusal` and `UnlockOutcome` value, and `RECOVERY_OPTIONS`.
    A review replaced the D4 unlock reason with *"the dirty volume was
    shredded, erased and destroyed, not repaired"* — a string that lands
    straight in `PersistenceStatus.reasons` — and the suite stayed green,
    because the scan only rendered the `report_write` path.
    """

    # `docstrings=False` here, and the boundary is stated rather than fudged.
    # `azazel_boot.persistence` carries long historical narrative — a review
    # "cleared the fence with one assignment", `q._audit.clear()` "erases the
    # record" — which is prose about *other objects*, not a claim about the
    # volume. Scanning it for six English words would fail on the history that
    # exists to stop the bugs recurring, and a proximity heuristic ("within N
    # characters of 'volume'") is the kind of fuzzy check that stops meaning
    # anything. So what is scanned here is every string this module can
    # **render**: reason strings, refusal details, enum values, recovery lines.
    # `dirty_write`'s docstrings *are* scanned, in the test above.
    persistence_module = (
        Path(__file__).resolve().parents[2] / "src" / "azazel_boot" / "persistence.py"
    )
    scanned = " ".join(
        [
            _module_code(
                ast.parse(persistence_module.read_text(encoding="utf-8")), docstrings=False
            ),
            *(member.value for member in Refusal),
            *(member.value for member in UnlockOutcome),
            *(line for options in RECOVERY_OPTIONS.values() for line in options),
            *(state.value for state in PersistenceState),
        ]
    ).lower()

    for word in NEVER_SAID:
        assert word not in scanned, f"persistence says the volume was {word}"


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
        live.require_ordinary(OrdinaryAct.EXPORT, observations)


def test_there_is_no_per_record_continuation_anywhere_in_the_surface(observations) -> None:
    """D5: no salvage, no "the earlier ones are fine", no partial mount."""

    live = session(observations)
    live.report_write(torn(), observations)

    # Pinned by the allowlist above; this adds the reading that a reviewer
    # checks it *for*, so that widening the allowlist has to confront it.
    surface = {name for name in dir(live) if not name.startswith("_")}
    for spelling in ("record", "salvage", "partial", "mount", "earlier", "before"):
        assert not any(spelling in name for name in surface), spelling
    assert "report_write" in surface  # the scan is not vacuous


# --------------------------------------------------------------------------
# What the audit may hold
# --------------------------------------------------------------------------


def test_the_audit_holds_the_detection_the_transition_and_the_refusal(
    observations,
) -> None:
    live = session(observations)
    live.report_write(torn(), observations)
    with pytest.raises(PersistenceRefused):
        live.require_ordinary(OrdinaryAct.READ, observations)

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
        live.require_ordinary(OrdinaryAct.WRITE, observations)

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
        live.require_ordinary(OrdinaryAct.EXPORT, observations)

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
        live.require_ordinary(OrdinaryAct.READ, observations)
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

    # Attribute calls as well as name calls, and the names that make a call
    # unnecessary. A review added a function to this module with **no import
    # statement at all** that read a file and sent it over TCP:
    #
    #     b = __builtins__ if isinstance(__builtins__, dict) else vars(__builtins__)
    #     handle = b["open"](path, "rb"); payload = handle.read()
    #     net = b["__import__"]("so" + "cket")
    #
    # The import allowlist saw nothing, because there is no import; the call
    # check saw nothing, because `b["open"](...)` is a call on a `Subscript`
    # and `net.socket(...)` is a call on an `Attribute`. An allowlist of
    # imports is not an allowlist of reachability while `__builtins__` is a
    # name in scope.
    reachable: set[str] = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Name):
            reachable.add(node.id)
        elif isinstance(node, ast.Attribute):
            reachable.add(node.attr)
    assert not reachable & {
        "__builtins__",
        "__loader__",
        "__spec__",
        "globals",
        "vars",
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "input",
        "getattr",
        "setattr",
        "delattr",
    }, sorted(reachable & {"__builtins__", "globals", "vars", "eval", "exec", "compile",
                           "__import__", "open", "input", "getattr", "setattr", "delattr"})

    # And no call whose callee is a subscript, which is the shape `b["open"]()`
    # takes. This module indexes nothing and calls nothing it indexed.
    assert not [
        node
        for node in ast.walk(TREE)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Subscript)
    ]

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


def test_the_status_reason_names_the_rule_and_not_the_classification(observations) -> None:
    """The surface a mutation found undecided, decided here.

    `PersistenceStatus.reasons` is operator-facing text: it reaches a screen and
    whatever renders one. A mutation that interpolated the signal into it —
    `f"an interrupted write is suspected ({signal.value}); …"` — survived the
    whole suite, because the refusal was pinned and this was not.

    It is not a confidentiality break: ADR-0010 D4 puts the classification in
    the audit deliberately, so the signal is not a secret. What it is, is a
    second place the same fact would live, with nothing keeping the two in
    agreement and no decision recorded about which one an operator reads.

    So it is decided the same way the refusal is: **the reason names the rule,
    the audit names the classification.** One sentence on the screen for every
    detection, and the word that says which condition it was lives where D4
    put it.
    """

    for item in (
        torn(),
        observation(continuity=MediumContinuity.REMOVED_DURING_WRITE),
        observation(verification=Verification.INDETERMINATE),
        observation(receipt=ReceiptState.UNREADABLE),
    ):
        live = session(observations)
        status = live.report_write(item, observations)
        joined = " ".join(status.reasons)

        signal = classify(item)
        assert signal is not None
        assert signal.value not in joined, joined
        assert not any(member.value in joined for member in DirtySignal)

        # The same sentence every time, whichever condition was observed.
        assert joined == (
            "an interrupted write is suspected; Boot will not use this volume "
            "in ordinary operation, and does not repair it"
        )
        # And the classification is still recorded, where D4 puts it.
        assert live.audit()[0].signal is signal


# --------------------------------------------------------------------------
# Findings from the independent adversarial review, each as its reproduction
# --------------------------------------------------------------------------


def test_a_quarantined_volume_cannot_then_be_unlocked(observations) -> None:
    """C1. `unlock` never consulted the quarantine, and reached `open`.

    A caller that quarantines the volume and then performs an ordinary unlock —
    with `dirty=False`, which it is under no obligation to re-assert — landed in
    `PersistenceState.OPEN`, `writable=True`, `LITE`, and `recovery_options()`
    returned the empty tuple: no reboot instruction and no export offer on a
    volume this module had already judged.

    `test_there_is_no_way_to_open_a_dirty_volume` did not catch it because it
    checks the signature and one call. The route was never through an argument;
    it was through composing two entry points.
    """

    live = session(observations)
    live.report_write(torn(), observations)

    with pytest.raises(PersistenceRefused) as refused:
        live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
    assert refused.value.refusal is Refusal.VOLUME_QUARANTINED

    assert live.status().state is PersistenceState.QUARANTINED
    assert live.status().writable is False
    assert live.status().capability is DEGRADED_CAPABILITY
    assert live.recovery_options() != ()


def test_a_quarantined_volume_cannot_then_be_created_on(observations) -> None:
    """M1. `create` had the same gap, and made the quarantine vanish entirely.

    It returned `LOCKED` and `recovery_options()` offered "attempt an unlock
    with the documented portable passphrase" — on a volume suspected of a torn
    write.
    """

    live = session(observations)
    live.report_write(torn(), observations)

    with pytest.raises(PersistenceRefused) as refused:
        live.create(MEDIUM, layout(), observations, **MEDIA_ARGS)
    assert refused.value.refusal is Refusal.VOLUME_QUARANTINED
    assert live.status().state is PersistenceState.QUARANTINED


def test_a_second_report_on_an_already_quarantined_volume_is_refused(observations) -> None:
    """Judging another write is ordinary operation, and there is none left."""

    live = session(observations)
    live.report_write(torn(), observations)

    with pytest.raises(PersistenceRefused) as refused:
        live.report_write(CLEAN, observations)
    assert refused.value.refusal is Refusal.VOLUME_QUARANTINED


@pytest.mark.parametrize(
    "overrides",
    [
        {"unlocked": False},
        {"integrity_verified": False},
        {"stored_generation": 6, "last_seen_generation": 7},
        {"dirty": True},
    ],
)
def test_every_unlock_fault_quarantines_the_volume_for_real(overrides, observations) -> None:
    """C3. `unlock`'s quarantine and `report_write`'s were two unconnected things.

    `_quarantine_volume` set `PersistenceState.QUARANTINED` on the status and
    nothing else — no shared flag, no audit. So `unlock(dirty=True)`, the
    canonical D4 case, reported `quarantined` while **every ordinary act stayed
    permitted**. The status was a label and the refusal lived somewhere else.

    `test_every_ordinary_act_is_refused_on_a_quarantined_volume` read as a
    general claim but only ever reached quarantine through `report_write`; its
    name was broader than its coverage. This drives the other four ways in.
    """

    live = session(observations)
    status = live.unlock(
        MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments(**overrides)
    )

    assert status.state is PersistenceState.QUARANTINED
    assert live.volume_is_quarantined
    assert live.audit() == (VolumeAuditEntry(event=VolumeAuditEvent.VOLUME_QUARANTINED),)

    for act in OrdinaryAct:
        with pytest.raises(PersistenceRefused) as refused:
            live.require_ordinary(act, observations)
        assert refused.value.refusal is Refusal.VOLUME_QUARANTINED


def test_a_session_rebuilt_over_the_same_medium_is_still_quarantined(observations) -> None:
    """C2. The defeat the fence already suffered, repeated on the flag beside it.

    The quarantine was a flag on the session, so a second `PersistenceSession`
    built from the same quarantine, binding and session id — the three
    arguments a legitimate caller already holds, nothing forged — was born
    un-quarantined, permitted every ordinary act, had an empty audit and
    unlocked to `open`.

    `fence_after_removal`'s own docstring records that exact attack against the
    fence and why the fence moved to the `Quarantine`. The volume quarantine
    had not been given the same treatment, so it was strictly weaker than the
    fence while the docs claimed it was "one-way within the boot".
    """

    quarantine = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
    first = session(observations, quarantine=quarantine)
    first.report_write(torn(), observations)
    assert first.volume_is_quarantined

    second = session(observations, quarantine=quarantine)

    assert second.volume_is_quarantined
    assert second.status().state is PersistenceState.QUARANTINED
    for act in OrdinaryAct:
        with pytest.raises(PersistenceRefused) as refused:
            second.require_ordinary(act, observations)
        assert refused.value.refusal is Refusal.VOLUME_QUARANTINED
    with pytest.raises(PersistenceRefused) as refused:
        second.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
    assert refused.value.refusal is Refusal.VOLUME_QUARANTINED


def test_clearing_the_flag_on_the_session_does_not_clear_the_quarantine(observations) -> None:
    """H2. The guard was the whole of the defence, and `object.__setattr__` went round it.

    It no longer is: the session has no such attribute to write. The
    quarantine's own flag is still reachable that way, and
    `azazel_boot.quarantine` states that limit for the fence in the same words
    — this is defence against a careless caller, not against code already
    running in the process.
    """

    quarantine = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
    live = session(observations, quarantine=quarantine)
    live.report_write(torn(), observations)

    # The session has no such slot any more, so the route does not even reach a
    # value to overwrite — `__slots__` turns it into an `AttributeError`.
    with pytest.raises(AttributeError):
        object.__setattr__(live, "_volume_quarantined", False)
    assert live.volume_is_quarantined
    with pytest.raises(PersistenceRefused) as refused:
        live.require_ordinary(OrdinaryAct.WRITE, observations)
    assert refused.value.refusal is Refusal.VOLUME_QUARANTINED

    with pytest.raises(AttributeError):
        quarantine._volume_quarantined = False
    assert quarantine.volume_is_quarantined


def test_quarantining_the_volume_neither_fences_nor_withdraws_an_approval(
    observations,
) -> None:
    """The trap in C2's fix: reusing `_fenced` would close the §4 export.

    A fence withdraws a standing approval and refuses new ones. The
    offline-examination export exists *because* the volume is untrustworthy, so
    the two flags are separate and this asserts they stay separate.
    """

    from azazel_boot.quarantine import Action, ExportApproval, Verdict

    quarantine = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM.identity)
    host_disk = Device(identity="host-nvme-SN-1", device_class=DeviceClass.HOST_STORAGE)
    quarantine.observe(MEDIUM)
    quarantine.observe(host_disk)

    # The approval is granted *after* the session is built, because `session()`
    # observes both devices and a re-appearance withdraws a standing approval —
    # which is the quarantine policy working, not this change breaking it.
    live = session(observations, quarantine=quarantine)
    quarantine.approve_export(
        ExportApproval(
            session_id=SESSION,
            target_identity=host_disk.identity,
            reason="offline examination of a volume Boot will not use",
            confirmed=True,
        )
    )
    live.report_write(torn(), observations)

    assert not quarantine.is_fenced
    assert quarantine.evaluate(host_disk, Action.EXPORT_WRITE) is Verdict.ALLOWED


@pytest.mark.parametrize(
    "unreadable",
    [
        SimpleNamespace(receipt=None, continuity=None, verification=None),
        SimpleNamespace(
            receipt=ReceiptState.MISSING,
            continuity=MediumContinuity.PRESENT_THROUGHOUT,
            verification=Verification.VERIFIED,
        ),
        "a string",
        None,
    ],
)
def test_something_this_module_cannot_read_is_refused_not_called_clean(unreadable) -> None:
    """H1. Six `is` comparisons then `return None` means unknown *is* clean.

    A `SimpleNamespace` with three `None` fields classified as a clean write.
    So did a duck-typed object carrying the right enum members, which is worse:
    it looks like it works. The module's own claim — "no path that treats an
    unknown as a clean write" — was false on any input the six branches missed.
    """

    with pytest.raises(TypeError):
        classify(unreadable)


def test_an_observation_of_strings_cannot_be_built_at_all() -> None:
    """H1, closed where it is built rather than where it is read.

    `WriteObservation(receipt="missing", continuity="removed_during_write",
    verification="failed")` — three strings naming the worst faults there are —
    classified as a clean write. An annotation is not a check, and the wrong
    import is enough to produce this by accident.
    """

    with pytest.raises(TypeError):
        WriteObservation(
            receipt="missing", continuity="removed_during_write", verification="failed"
        )
    for field, value in (
        ("receipt", ReceiptState.MISSING),
        ("continuity", MediumContinuity.REMOVED_DURING_WRITE),
        ("verification", Verification.FAILED),
    ):
        with pytest.raises(TypeError):
            dataclasses.replace(CLEAN, **{field: value.value})
