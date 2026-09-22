"""The secret never arrives, the mode never moves, and nothing here can write.

Azazel-Boot#40, [ADR-0010](../../docs/adr/0010-persistence-key-and-migration.md)
D1–D3.

The strongest property under test is an **absence**: `azazel_boot.session_mode`
never receives a passphrase. Every earlier round of this work redacted a value
some module held, and each time the container holding it became the next
weakness. A module that is never given the secret has no container to weaken, so
the test that matters asserts the acquisition boundary carries exactly one enum
value and nothing else.

Nothing here has run on hardware. No passphrase has been typed, no volume
opened, and no device of any kind is involved.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import inspect
import pickle
import traceback
from pathlib import Path

import pytest
from conftest import mac_reader

from azazel_boot.commissioning import SessionBinding, bind_session, host_fingerprint
from azazel_boot.inventory import collect_interfaces
from azazel_boot.quarantine import Device, DeviceClass, Quarantine
from azazel_boot.session_mode import (
    ATTEMPT_BUDGET,
    SETTLES_TO_EPHEMERAL,
    AttemptOutcome,
    AuditEntry,
    AuditEvent,
    BootSession,
    CommissionedMode,
    KeyAcquisition,
    ModeRefused,
    NoLocalPrompt,
    PassphraseChannel,
    Refusal,
    SessionMode,
    mode_applies_to,
)

MODULE = Path(__file__).resolve().parents[2] / "src" / "azazel_boot" / "session_mode.py"
TREE = ast.parse(MODULE.read_text(encoding="utf-8"))

BOOT = "boot-1"
SESSION = "s1"
MEDIUM_ID = "usb-boot-medium"
MEDIUM = Device(identity=MEDIUM_ID, device_class=DeviceClass.BOOT_MEDIUM)
HOST_DISK = Device(identity="host-nvme-SN-1", device_class=DeviceClass.HOST_STORAGE)
TWO_NIC_MACS = {"enp3s0": "a0:b1:c2:d3:e4:f5", "enx001122334455": "00:11:22:33:44:55"}

#: Never given to anything under test. Present so a test can assert its absence
#: from every rendered surface.
THE_SECRET = "correct-horse-battery-staple-0001"

#: More prompts than any budget-bounded loop could justify. See `Scripted`.
PROMPT_CEILING = ATTEMPT_BUDGET * 4


@pytest.fixture
def observations(sysfs_two_nics):
    return collect_interfaces(sysfs_two_nics, permanent_mac_reader=mac_reader(TWO_NIC_MACS))


@pytest.fixture
def elsewhere(sysfs_single_nic):
    return collect_interfaces(
        sysfs_single_nic, permanent_mac_reader=mac_reader({"wlp2s0": "12:34:56:78:9a:bc"})
    )


class Scripted:
    """An acquisition that returns a fixed list of outcomes.

    It **holds** the secret, the way a real one would, and never gets a chance
    to pass it anywhere: `attempt()` returns an enum. A test reads
    `self.secret` afterwards to assert it never appeared in anything rendered.

    **Its `__repr__` deliberately renders the secret.** That is not an
    oversight to be tidied up. With the default `object.__repr__` — `<Scripted
    object at 0x…>` — the traceback assertions below pass no matter what, and
    the whole "no acquisition in the refusing frame" property is untested: a
    mutation that put the acquisition in that frame would render an address and
    leak nothing. A real acquisition written by someone who has not read this
    file may well have a `__repr__` like this one, so the hostile case is the
    honest one to test against.
    """

    def __init__(self, *outcomes: AttemptOutcome, channel=PassphraseChannel.LOCAL_HIDDEN_PROMPT):
        self._outcomes = list(outcomes)
        self._channel = channel
        self.secret = THE_SECRET
        self.prompts = 0

    @property
    def channel(self) -> PassphraseChannel:
        return self._channel

    def __repr__(self) -> str:
        return f"Scripted(secret={self.secret!r}, prompts={self.prompts})"

    def attempt(self) -> AttemptOutcome:
        self.prompts += 1
        if self.prompts > PROMPT_CEILING:
            # The budget is the loop's *only* guarantee of termination. A
            # mutation that stops the budget being spent made this source feed
            # rejections forever and hung the run — which is not a caught
            # mutant, it is a hung CI job that looks like a slow one. Refusing
            # here turns "does not terminate" into a red test.
            raise AssertionError(
                f"commission() asked for attempt {self.prompts}; the budget is "
                f"{ATTEMPT_BUDGET} and nothing else bounds the loop"
            )
        return self._outcomes.pop(0) if self._outcomes else AttemptOutcome.REJECTED


def a_quarantine(fenced: bool = False) -> Quarantine:
    rule = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM_ID)
    rule.observe(MEDIUM)
    rule.observe(HOST_DISK)
    if fenced:
        rule.fence()
    return rule


def a_session(observations, *, quarantine=None, binding=None) -> BootSession:
    return BootSession(
        BOOT,
        quarantine or a_quarantine(),
        binding or bind_session(observations, session_id=SESSION),
    )


# --------------------------------------------------------------------------
# The secret never arrives
# --------------------------------------------------------------------------


def test_the_acquisition_boundary_carries_one_enum_and_nothing_else() -> None:
    """The property the whole design rests on, asserted at the Protocol.

    `attempt()` returns an `AttemptOutcome`. There is no `passphrase()`, no
    `key()`, no `read()` and no method that could return a secret — so there is
    nothing for this module to hold, redact, pickle or leak.
    """

    names = {n for n in dir(KeyAcquisition) if not n.startswith("_")}
    assert names == {"channel", "attempt"}
    assert (
        inspect.signature(KeyAcquisition.attempt).return_annotation == "AttemptOutcome"
    )
    for forbidden in ("passphrase", "key", "secret", "read", "disclose", "material"):
        assert not any(forbidden in name for name in names)


def test_no_type_in_this_module_can_hold_a_secret() -> None:
    """Absent vocabulary, checked over every field of every dataclass here."""

    import azazel_boot.session_mode as module

    forbidden = (
        "passphrase",
        "key",
        "secret",
        "credential",
        "material",
        "identity",
        "attempts",
        "remaining",
        "count",
        "detail",
        "message",
        "error",
        "reason",
    )
    for name, value in vars(module).items():
        if not dataclasses.is_dataclass(value) or not isinstance(value, type):
            continue
        if value.__module__ != module.__name__:
            continue  # imported for a signature, not a container this module defines
        fields = {f.name for f in dataclasses.fields(value)}
        for bad in forbidden:
            assert not any(bad in field_name for field_name in fields), (
                f"{name} has a field matching {bad!r}"
            )


def test_nothing_rendered_anywhere_carries_the_secret(observations) -> None:
    """Repr, audit, exception, traceback — the four places it would show up."""

    acquisition = Scripted(AttemptOutcome.REJECTED, AttemptOutcome.OPENED)
    session = a_session(observations)
    decided = session.commission(acquisition, observations, session_id=SESSION)

    rendered = " ".join(
        [
            repr(session),
            repr(decided),
            repr(session.audit()),
            repr(acquisition.channel),
            str(ATTEMPT_BUDGET),
        ]
    )
    assert acquisition.secret not in rendered
    assert THE_SECRET not in rendered

    # And in a refusal's captured-locals traceback, which is what
    # `pytest --showlocals` and a crash reporter build.
    #
    # Scoped to the frames *inside the module under test*. The calling frame
    # holds the acquisition because the caller made it, and asserting over the
    # whole traceback would either fail for that unavoidable reason or — with a
    # test double whose `repr` hides its fields — pass for no reason at all.
    # What this module can be held to is its own frames.
    second = a_session(observations)
    with pytest.raises(ModeRefused) as refused:
        second.commission(
            Scripted(AttemptOutcome.OPENED, channel=None),  # type: ignore[arg-type]
            observations,
            session_id=SESSION,
        )
    summary = traceback.TracebackException.from_exception(refused.value, capture_locals=True)

    assert THE_SECRET not in str(refused.value)

    module_frames = [frame for frame in summary.stack if frame.filename == str(MODULE)]
    assert module_frames, "the refusal must be raised inside the module under test"

    raising = module_frames[-1]
    assert raising.name == "_require_local_hidden_prompt"
    # One boolean, and nothing else, in the frame that actually raises.
    assert set(raising.locals or {}) == {"is_local_hidden"}

    # `commission` is still on the stack and still holds the acquisition it was
    # handed — a frame cannot forget its own parameter. So the secret IS in
    # this traceback, and the module cannot claim otherwise; what it can do is
    # not put the acquisition anywhere a *refusal* has to render, and keep its
    # own refusal frames empty of it.
    commissioning_frame = next(frame for frame in module_frames if frame.name == "commission")
    assert "acquisition" in (commissioning_frame.locals or {})
    assert THE_SECRET in (commissioning_frame.locals or {})["acquisition"]


def test_the_module_reads_no_environment_no_argv_and_no_file() -> None:
    """D1: there is no fallback path for a passphrase to arrive by."""

    imported: set[str] = set()
    attributes: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Attribute):
            attributes.add(node.attr)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)

    assert not imported & {"os", "sys", "pathlib", "shutil", "getpass", "configparser", "json"}
    assert not attributes & {"environ", "getenv", "argv", "read_text", "read_bytes", "open"}
    assert "open" not in calls
    assert "input" not in calls


def test_the_channel_vocabulary_has_one_value_and_no_second_place_to_read_from() -> None:
    """A caller cannot name what does not exist."""

    assert {c.value for c in PassphraseChannel} == {"local_hidden_prompt"}
    for forbidden in ("env", "argv", "command", "config", "file", "network", "arg"):
        assert not any(forbidden in c.value for c in PassphraseChannel)


def test_a_source_on_any_other_channel_is_refused_before_a_prompt(observations) -> None:
    session = a_session(observations)
    acquisition = Scripted(AttemptOutcome.OPENED, channel=None)  # type: ignore[arg-type]

    with pytest.raises(ModeRefused) as refused:
        session.commission(acquisition, observations, session_id=SESSION)
    assert refused.value.refusal is Refusal.CHANNEL_NOT_A_LOCAL_HIDDEN_PROMPT
    assert acquisition.prompts == 0
    assert session.decided is None


# --------------------------------------------------------------------------
# No key means ephemeral, and there is no other answer
# --------------------------------------------------------------------------


@pytest.mark.parametrize("outcome", list(SETTLES_TO_EPHEMERAL))
def test_no_obtainable_key_settles_to_ephemeral_without_spending_budget(
    outcome, observations
) -> None:
    """Both say a key cannot be obtained at all; retrying asks the same absence."""

    acquisition = Scripted(outcome)
    session = a_session(observations)
    decided = session.commission(acquisition, observations, session_id=SESSION)

    assert decided.mode is SessionMode.EPHEMERAL
    assert acquisition.prompts == 1
    assert [entry.event for entry in session.audit()] == [
        AuditEvent.PERSISTENCE_UNAVAILABLE,
        AuditEvent.MODE_SELECTED,
    ]


def test_the_default_acquisition_reads_nothing_and_says_so(observations) -> None:
    """The `no_permanent_mac` shape: the gap is reported, not papered over."""

    assert NoLocalPrompt().attempt() is AttemptOutcome.NO_LOCAL_INPUT_CHANNEL
    session = a_session(observations)
    decided = session.commission(NoLocalPrompt(), observations, session_id=SESSION)
    assert decided.mode is SessionMode.EPHEMERAL


def test_there_is_no_unprotected_volume_and_no_fallback_key() -> None:
    """Asserted as an absence: there is nothing to refuse, so nothing to permit.

    A refusal is one review away from an exception. A vocabulary with no word
    for the thing is not.
    """

    source = " ".join(MODULE.read_text(encoding="utf-8").split()).lower()
    for never in (
        "unprotected",
        "fallback key",
        "plaintext volume",
        "unencrypted",
        "emergency exception",
        "override",
    ):
        assert f"{never} =" not in source
    assert {m.value for m in SessionMode} == {"persistent", "ephemeral"}
    assert not any(
        "unprotected" in o.value or "fallback" in o.value for o in AttemptOutcome
    )


# --------------------------------------------------------------------------
# Five attempts, and what the limit is not claimed to be
# --------------------------------------------------------------------------


def test_the_budget_is_five_and_the_fifth_failure_fixes_ephemeral(observations) -> None:
    acquisition = Scripted(*[AttemptOutcome.REJECTED] * 10)
    session = a_session(observations)
    decided = session.commission(acquisition, observations, session_id=SESSION)

    assert ATTEMPT_BUDGET == 5
    assert acquisition.prompts == 5
    assert decided.mode is SessionMode.EPHEMERAL
    assert [entry.event for entry in session.audit()] == [
        AuditEvent.ATTEMPT_BUDGET_EXHAUSTED,
        AuditEvent.MODE_SELECTED,
    ]


def test_a_success_before_the_budget_runs_out_fixes_persistent(observations) -> None:
    acquisition = Scripted(
        AttemptOutcome.REJECTED, AttemptOutcome.REJECTED, AttemptOutcome.OPENED
    )
    session = a_session(observations)
    decided = session.commission(acquisition, observations, session_id=SESSION)

    assert decided.mode is SessionMode.PERSISTENT
    assert decided.is_persistent
    assert acquisition.prompts == 3


def test_an_interruption_verifies_nothing_so_it_spends_nothing(observations) -> None:
    """Fail-closed: no mode is decided, and the operator may start again.

    Counting it would let an attacker exhaust the budget by interrupting;
    not counting it costs nothing, because an attempt that verified nothing
    told them nothing.
    """

    session = a_session(observations)
    with pytest.raises(ModeRefused) as refused:
        session.commission(
            Scripted(AttemptOutcome.REJECTED, AttemptOutcome.INTERRUPTED),
            observations,
            session_id=SESSION,
        )
    assert refused.value.refusal is Refusal.INPUT_INTERRUPTED
    assert session.decided is None
    assert session.audit() == ()

    # One rejection was spent before the interruption; four remain, and the
    # session can still be commissioned.
    decided = session.commission(
        Scripted(*[AttemptOutcome.REJECTED] * 10), observations, session_id=SESSION
    )
    assert decided.mode is SessionMode.EPHEMERAL


def test_the_budget_belongs_to_the_boot_and_a_new_boot_starts_fresh(observations) -> None:
    """Not claimed as brute-force resistance. This test is what that means.

    A reboot gives five more. An attacker holding the medium reboots as often
    as they like, and ADR-0010 D2 says so in those words rather than implying
    otherwise.
    """

    first = a_session(observations)
    first.commission(Scripted(*[AttemptOutcome.REJECTED] * 10), observations, session_id=SESSION)
    assert first.decided.mode is SessionMode.EPHEMERAL

    next_boot = BootSession(
        "boot-2", a_quarantine(), bind_session(observations, session_id=SESSION)
    )
    acquisition = Scripted(AttemptOutcome.OPENED)
    assert next_boot.commission(acquisition, observations, session_id=SESSION).mode is (
        SessionMode.PERSISTENT
    )

    source = " ".join(MODULE.read_text(encoding="utf-8").split())
    assert "Not brute-force resistance" in source
    assert "Not TPM protection" in source
    assert "no erasure is claimed" in source


def test_a_mistyped_passphrase_and_an_attack_are_the_same_thing_here(observations) -> None:
    """Both degrade to ephemeral. Neither quarantines the volume.

    Treating them identically is the decision, not an oversight: nothing here
    can tell them apart, and a volume quarantined by a typo would cost a
    responder everything they had gathered.
    """

    quarantine = a_quarantine()
    session = a_session(observations, quarantine=quarantine)
    session.commission(Scripted(*[AttemptOutcome.REJECTED] * 10), observations, session_id=SESSION)

    assert session.decided.mode is SessionMode.EPHEMERAL
    assert not quarantine.is_fenced
    assert not [e for e in quarantine.audit() if "quarantin" in e.verdict]


# --------------------------------------------------------------------------
# Decided once, and it cannot move
# --------------------------------------------------------------------------


def test_a_second_commissioning_is_refused(observations) -> None:
    session = a_session(observations)
    session.commission(Scripted(AttemptOutcome.OPENED), observations, session_id=SESSION)

    with pytest.raises(ModeRefused) as refused:
        session.commission(Scripted(AttemptOutcome.OPENED), observations, session_id=SESSION)
    assert refused.value.refusal is Refusal.MODE_ALREADY_FIXED


def test_an_ephemeral_session_cannot_become_persistent_later(observations) -> None:
    """D3, and the thing D3 exists to prevent, in one test."""

    session = a_session(observations)
    decided = session.commission(NoLocalPrompt(), observations, session_id=SESSION)
    assert decided.mode is SessionMode.EPHEMERAL

    # The operator finds the passphrase a minute later. It changes nothing.
    with pytest.raises(ModeRefused):
        session.commission(Scripted(AttemptOutcome.OPENED), observations, session_id=SESSION)
    assert session.decided is decided
    assert session.decided.mode is SessionMode.EPHEMERAL

    with pytest.raises(AttributeError):
        decided._mode = SessionMode.PERSISTENT  # noqa: SLF001 - the attack
    with pytest.raises(AttributeError):
        session._mode = CommissionedMode(SessionMode.PERSISTENT, BOOT)  # noqa: SLF001


def test_a_mode_from_elsewhere_is_not_this_boots_answer(observations) -> None:
    """Checked by identity, so a constructed or copied one is not it."""

    session = a_session(observations)
    decided = session.commission(Scripted(AttemptOutcome.OPENED), observations, session_id=SESSION)

    assert mode_applies_to(session, decided)
    assert not mode_applies_to(session, CommissionedMode(SessionMode.PERSISTENT, BOOT))

    for attempt in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError):
            attempt(decided)


def test_a_mode_is_a_capability_and_never_an_authority(observations) -> None:
    for outcome, expected in (
        (AttemptOutcome.OPENED, SessionMode.PERSISTENT),
        (AttemptOutcome.NO_KEY_MATERIAL, SessionMode.EPHEMERAL),
    ):
        session = BootSession(
            BOOT, a_quarantine(), bind_session(observations, session_id=SESSION)
        )
        decided = session.commission(Scripted(outcome), observations, session_id=SESSION)
        assert decided.mode is expected
        assert decided.authority == ()


# --------------------------------------------------------------------------
# Fail-closed, before anything is typed
# --------------------------------------------------------------------------


def test_a_fenced_medium_refuses_before_a_prompt_is_shown(observations) -> None:
    session = a_session(observations, quarantine=a_quarantine(fenced=True))
    acquisition = Scripted(AttemptOutcome.OPENED)

    with pytest.raises(ModeRefused) as refused:
        session.commission(acquisition, observations, session_id=SESSION)
    assert refused.value.refusal is Refusal.MEDIUM_FENCED
    assert acquisition.prompts == 0
    assert session.decided is None


def test_a_record_from_another_machine_or_sitting_refuses_before_a_prompt(
    observations, elsewhere
) -> None:
    session = a_session(observations)
    acquisition = Scripted(AttemptOutcome.OPENED)

    with pytest.raises(ModeRefused) as refused:
        session.commission(acquisition, elsewhere, session_id=SESSION)
    assert refused.value.refusal is Refusal.NOT_THIS_HOST_OR_SESSION
    assert acquisition.prompts == 0

    with pytest.raises(ModeRefused) as refused:
        session.commission(acquisition, observations, session_id="s-other")
    assert refused.value.refusal is Refusal.NOT_THIS_HOST_OR_SESSION
    assert acquisition.prompts == 0


def test_a_host_with_no_identifiable_nic_refuses_rather_than_matching_everything(
    observations, sysfs_mac_only
) -> None:
    """`UnidentifiedHost`'s closure, reached through this module."""

    unidentifiable = collect_interfaces(
        sysfs_mac_only, permanent_mac_reader=mac_reader({"eth0": "de:ad:be:ef:00:01"})
    )
    session = a_session(observations)
    with pytest.raises(ModeRefused) as refused:
        session.commission(Scripted(AttemptOutcome.OPENED), unidentifiable, session_id=SESSION)
    assert refused.value.refusal is Refusal.NOT_THIS_HOST_OR_SESSION


def test_a_boot_session_needs_a_boot_id() -> None:
    with pytest.raises(ValueError, match="boot_id is required"):
        BootSession("   ", a_quarantine(), SessionBinding(host_fingerprint="x", session_id=SESSION))


def test_the_session_refuses_reassignment_and_serialisation(observations) -> None:
    session = a_session(observations)
    with pytest.raises(TypeError):
        pickle.dumps(session)
    for name in ("_spent", "_mode", "_quarantine", "_binding", "_boot_id"):
        with pytest.raises(AttributeError):
            setattr(session, name, None)


# --------------------------------------------------------------------------
# The audit holds three classifications and nothing else
# --------------------------------------------------------------------------


def test_the_audit_vocabulary_is_exactly_three_classifications() -> None:
    assert {e.value for e in AuditEvent} == {
        "mode_selected",
        "persistence_unavailable",
        "attempt_budget_exhausted",
    }
    assert {f.name for f in dataclasses.fields(AuditEntry)} == {"event", "mode"}


def test_no_audit_entry_can_carry_a_count_a_secret_or_an_identity(observations) -> None:
    """Rendered, not just inspected: an entry reaches a journal as text."""

    session = a_session(observations)
    session.commission(Scripted(*[AttemptOutcome.REJECTED] * 10), observations, session_id=SESSION)
    rendered = repr(session.audit())

    for forbidden in (THE_SECRET, MEDIUM_ID, BOOT, SESSION, host_fingerprint(observations)):
        assert forbidden not in rendered
    for digit in "12345":
        assert f"attempts={digit}" not in rendered
        assert f"remaining={digit}" not in rendered
    assert "5" not in rendered.replace("SessionMode", "").replace("AuditEvent", "")


def test_a_refusal_that_changes_nothing_records_nothing(observations) -> None:
    """Three refusals, no audit entries — the quarantine records its own."""

    for make, kwargs in (
        (lambda: a_session(observations, quarantine=a_quarantine(fenced=True)), {}),
        (lambda: a_session(observations), {"session_id": "s-other"}),
    ):
        session = make()
        with pytest.raises(ModeRefused):
            session.commission(
                Scripted(AttemptOutcome.OPENED),
                observations,
                session_id=kwargs.get("session_id", SESSION),
            )
        assert session.audit() == ()


# --------------------------------------------------------------------------
# Nothing else is reachable from here
# --------------------------------------------------------------------------


def test_this_module_cannot_reach_a_disk_a_device_a_network_or_a_vm() -> None:
    """Statically, so a later convenience call is a red test, not a review note."""

    imported: set[str] = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])

    assert not imported & {
        "os",
        "sys",
        "subprocess",
        "shutil",
        "socket",
        "urllib",
        "http",
        "ctypes",
        "pathlib",
        "tempfile",
    }

    # Over *code*, not prose: every identifier the module uses and every string
    # literal that is not a docstring. The module docstring says in words that a
    # snapshot and an export are unreachable, and a raw text scan would call that
    # sentence a violation of itself. Comments never enter an AST at all.
    doc_values = {
        ast.get_docstring(node, clean=False)
        for node in ast.walk(TREE)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and ast.get_docstring(node, clean=False) is not None
    }
    assert doc_values, "the module is expected to carry docstrings"

    used: list[str] = []
    for node in ast.walk(TREE):
        if isinstance(node, ast.Name):
            used.append(node.id)
        elif isinstance(node, ast.Attribute):
            used.append(node.attr)
        elif isinstance(node, ast.arg):
            used.append(node.arg)
        elif isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            used.append(node.name)
        elif isinstance(node, ast.alias):
            used.append(node.asname or node.name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            used.append(node.value)

    code = " ".join(item for item in used if item not in doc_values)

    for never in (
        "approve_export",
        "export_write",
        "create_vm",
        "install_in_vm",
        "download",
        "snapshot",
        "recovery",
        "/dev",
        "write_text",
        "write_bytes",
        "mount",
    ):
        assert never not in code, f"session_mode names {never!r} in code"


def test_commissioning_a_mode_changes_no_verdict_anywhere(observations) -> None:
    """Driven with the quarantine before and after, in both modes.

    A mode is a capability statement. If deciding one moved a verdict, it would
    be an authority, which is the thing every layer of this product refuses to
    become.
    """

    from azazel_boot.quarantine import Action, Verdict

    for outcome in (AttemptOutcome.OPENED, AttemptOutcome.NO_KEY_MATERIAL):
        quarantine = a_quarantine()
        before = {action: quarantine.evaluate(HOST_DISK, action) for action in Action}

        session = BootSession(
            BOOT, quarantine, bind_session(observations, session_id=SESSION)
        )
        session.commission(Scripted(outcome), observations, session_id=SESSION)

        after = {action: quarantine.evaluate(HOST_DISK, action) for action in Action}
        assert before == after
        assert all(verdict is Verdict.BLOCKED for verdict in after.values())
        assert not quarantine.is_fenced


def test_the_budget_constant_is_pinned_rather_than_parametrized_over_itself() -> None:
    """The shape `test_denylist_shape.py` exists to catch, pinned here too."""

    assert ATTEMPT_BUDGET == 5
    assert SETTLES_TO_EPHEMERAL == (
        AttemptOutcome.NO_KEY_MATERIAL,
        AttemptOutcome.NO_LOCAL_INPUT_CHANNEL,
    )


def test_every_refusal_is_one_this_module_actually_raises() -> None:
    """A member nothing raises is vocabulary a caller will branch on regardless.

    The first draft of this module carried a `NOT_THIS_BOOT` that no code path
    constructed. Read from the outside it looks like a reachable outcome, and a
    caller writing `if refusal is NOT_THIS_BOOT` gets a branch that never runs
    and never fails — which is worse than not having the branch. This asserts
    the enum against the refusals the source actually builds, so the next one is
    a red test.
    """

    constructed = {
        node.attr
        for node in ast.walk(TREE)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "Refusal"
    }
    declared = {member.name for member in Refusal}

    assert declared == constructed, (
        f"declared but never raised: {sorted(declared - constructed)}"
    )
    assert declared == {
        "MODE_ALREADY_FIXED",
        "NOT_THIS_HOST_OR_SESSION",
        "MEDIUM_FENCED",
        "INPUT_INTERRUPTED",
        "CHANNEL_NOT_A_LOCAL_HIDDEN_PROMPT",
    }


def test_no_rendering_carries_the_boot_id_or_how_many_attempts_were_made(observations) -> None:
    """Two mutation survivors, turned into the test that would have caught them.

    Printing `_boot_id` from `CommissionedMode.__repr__`, and printing `_spent`
    from `BootSession.__repr__`, both left the whole suite green. The module's
    docstrings claimed neither appears; nothing checked it.

    ADR-0010 D2 says the attempt count reaches no journal, no audit and no
    screen. A count in a `repr` is a count in every traceback, every debugger
    frame and every exception a caller logs — which is all three at once. The
    boot id names the sitting and belongs in no rendered line either.

    **A count is digits**, so the claim is asserted as the absence of any digit
    rather than as the absence of one particular number: `assert "3" not in
    rendered` passes the moment the count is four.
    """

    acquisition = Scripted(
        AttemptOutcome.REJECTED, AttemptOutcome.REJECTED, AttemptOutcome.OPENED
    )
    session = a_session(observations)
    decided = session.commission(acquisition, observations, session_id=SESSION)
    assert acquisition.prompts == 3

    surfaces = (
        repr(session),
        repr(decided),
        repr(session.decided),
        repr(session.audit()),
        str(session.audit()),
    )
    for rendered in surfaces:
        assert BOOT not in rendered, rendered
        assert not any(character.isdigit() for character in rendered), rendered

    # And the same after the budget is spent, where the count is at its largest
    # and an "attempts remaining" line is most tempting.
    spent = a_session(observations)
    spent.commission(Scripted(), observations, session_id=SESSION)
    for rendered in (repr(spent), repr(spent.decided), repr(spent.audit())):
        assert BOOT not in rendered, rendered
        assert not any(character.isdigit() for character in rendered), rendered


def test_a_commissioned_mode_has_no_equality_of_its_own(observations) -> None:
    """Why `is` and `==` are the same test today, and why that is not a property.

    Mutating `BootSession.holds` from `self._mode is mode` to `== mode`
    survived the whole suite. It is an equivalent mutant — `CommissionedMode`
    inherits object's identity equality, so the two expressions agree — but
    that agreement is a coincidence of what the class does *not* define.

    An `__eq__` added later, for a log line or a test convenience, would
    silently turn every identity check in this module into a value check, and a
    `CommissionedMode` built by hand with the right two fields would then be
    accepted as the one this boot minted. So the absence is pinned: adding an
    `__eq__` is a red test, not a quiet change of meaning.
    """

    assert CommissionedMode.__eq__ is object.__eq__
    assert CommissionedMode.__hash__ is object.__hash__

    session = a_session(observations)
    decided = session.commission(Scripted(AttemptOutcome.OPENED), observations, session_id=SESSION)

    forged = CommissionedMode(decided.mode, BOOT)
    assert forged.mode is decided.mode
    assert forged != decided
    assert not session.holds(forged)
    assert not mode_applies_to(session, forged)


def test_no_refusal_message_carries_a_host_a_session_or_a_device(observations, elsewhere) -> None:
    """Every refusal path, checked against every identity in play.

    A mutation that rebuilt `NOT_THIS_HOST_OR_SESSION` as
    `f"another machine: {self._binding!r}"` survived the whole suite.
    `SessionBinding` is a plain dataclass with no redacting `__repr__`, so that
    message renders the host fingerprint in full — and a `ModeRefused` message
    reaches a terminal, a journal, a crash report and a test failure line.

    ADR-0010 D10 is that these values appear in none of those. The refusal
    names the **rule**, and the rule is the whole of what it may say.
    """

    binding = bind_session(observations, session_id=SESSION)
    fingerprint = host_fingerprint(observations)

    refusals: list[ModeRefused] = []

    def collect(session, acquisition, inventory, *, session_id=SESSION):
        with pytest.raises(ModeRefused) as refused:
            session.commission(acquisition, inventory, session_id=session_id)
        refusals.append(refused.value)

    # not this host
    collect(a_session(observations, binding=binding), Scripted(AttemptOutcome.OPENED), elsewhere)
    # not this sitting
    collect(
        a_session(observations, binding=binding),
        Scripted(AttemptOutcome.OPENED),
        observations,
        session_id="another-sitting",
    )
    # a fenced medium
    collect(
        a_session(observations, quarantine=a_quarantine(fenced=True), binding=binding),
        Scripted(AttemptOutcome.OPENED),
        observations,
    )
    # a channel that is not a hidden local prompt
    collect(
        a_session(observations, binding=binding),
        Scripted(AttemptOutcome.OPENED, channel=None),  # type: ignore[arg-type]
        observations,
    )
    # the prompt was stopped
    collect(
        a_session(observations, binding=binding),
        Scripted(AttemptOutcome.INTERRUPTED),
        observations,
    )
    # the mode is already decided
    fixed = a_session(observations, binding=binding)
    fixed.commission(Scripted(AttemptOutcome.OPENED), observations, session_id=SESSION)
    collect(fixed, Scripted(AttemptOutcome.OPENED), observations)

    assert {refusal.refusal for refusal in refusals} == set(Refusal), (
        "every refusal path must be exercised, or this test guards only some of them"
    )

    never = (
        fingerprint,
        binding.host_fingerprint,
        SESSION,
        "another-sitting",
        BOOT,
        MEDIUM_ID,
        HOST_DISK.identity,
        THE_SECRET,
        *TWO_NIC_MACS.values(),
        *TWO_NIC_MACS.keys(),
    )
    for refusal in refusals:
        for rendered in (str(refusal), refusal.detail, repr(refusal.refusal)):
            for value in never:
                assert value not in rendered, f"{refusal.refusal.name} rendered {value!r}"
            assert not any(character.isdigit() for character in rendered), rendered
