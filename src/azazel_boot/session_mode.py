"""Persistent or ephemeral, decided once, and the secret never comes in here.

[ADR-0010](../../docs/adr/0010-persistence-key-and-migration.md) D1, D2 and D3,
implemented. Azazel-Boot#40.

**The passphrase does not reach this module.** Not as an argument, not in a
wrapper, not behind a `disclose()`. A :class:`KeyAcquisition` performs the
prompt and the unlock attempt elsewhere and reports **one enum value** back;
this module decides what that means. Every earlier round of this work redacted a
value that a module held — a repr, a pickle, a traceback frame — and each time
the next weakness was the container. A module that never receives the secret has
no container to weaken, and `tests/unit/test_session_mode.py` asserts that the
only thing crossing the boundary is a member of :class:`AttemptOutcome`.

**The limit of that, stated rather than discovered:** `commission` is handed an
acquisition object and its frame holds it for the duration of the call, so a
captured-locals traceback renders whatever that object's `__repr__` renders.
Nothing here can prevent it. What this module guarantees is narrower and real:
it never asks for the secret, never stores it, never puts it in an audit, an
exception message or a `repr` of its own, and raises its refusals from frames
that hold one boolean.

**The mode is decided once and cannot move.** A :class:`CommissionedMode` is
minted by one :class:`BootSession` at commissioning and is checked by identity.
There is no promotion, no demotion and no re-binding: a session that starts
ephemeral stays ephemeral for the life of the boot (D3), because opening
mid-session means checking a binding against a machine whose state has already
moved.

**No key means ephemeral, and there is no other answer.** There is no
unprotected volume, no fallback key, and no code path that reads a passphrase
from an environment variable, a command-line argument or a configuration file —
:class:`PassphraseChannel` has no value for any of them, and this module reads
no environment, no `sys.argv` and no file. A caller cannot name what does not
exist (D1).

## What is deliberately not claimed

- **Not brute-force resistance.** Five attempts per boot (D2) bound what a
  *running* session can be ground down to while an operator is elsewhere. An
  attacker holding the medium reboots as often as they like, and gets five more
  each time. Resistance to offline attack is a property of the key derivation,
  which ADR-0010 does not decide and this module does not implement.
- **Not TPM protection.** Nothing here seals anything to a platform. `VERIFIED_FIRMWARE`
  is where platform-sealed material would come from, and on a borrowed laptop it
  is absent by definition.
- **Not erasure of secrets from memory.** Python cannot guarantee it: strings
  are immutable, copies are made by the interpreter, and `gc` and the allocator
  do as they please. **So no erasure is claimed.** What is done instead is to
  minimise retention and copies — by never accepting the secret here at all —
  and to audit only transitions that contain none.
- **Not a distinction between a mistake and an attack.** A mistyped passphrase
  and a hostile guess are indistinguishable, and both degrade to ephemeral
  rather than quarantining the volume. Treating them identically is the point.

## What cannot be reached from here

Host storage, a USB write, a VM, the network, an export and a snapshot are all
unreachable. Recovery may request one outcome-only attempt through this
session's budget, but this module does not implement or perform recovery.
`tests/unit/test_session_mode.py` asserts that the module has no I/O path and
drives the quarantine before and after commissioning to show its verdicts do
not move.

Nothing here has run on hardware. No passphrase has been attempted, no volume
opened, sealed or created on any device.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from azazel_boot.commissioning import SessionBinding, binding_applies
from azazel_boot.inventory import InterfaceObservation
from azazel_boot.quarantine import Quarantine
from azazel_boot.refusals import Refused

#: D2's budget: five verification attempts in one boot.
#:
#: The number is a decision, not a derivation. It is written here once and
#: pinned by a test rather than parametrized over itself.
ATTEMPT_BUDGET = 5


class SessionMode(Enum):
    """What this boot is, decided once.

    Two values, and no third for "not yet" — an undecided session is the
    absence of a `CommissionedMode`, not a mode that means undecided. A third
    value would be something later code could compare against and proceed on.
    """

    PERSISTENT = "persistent"
    EPHEMERAL = "ephemeral"


class PassphraseChannel(Enum):
    """Where a passphrase may be typed. There is exactly one.

    There is deliberately **no value** for an environment variable, a
    command-line argument, a configuration file, a network source or a file on
    disk. Each of those is a place a secret is read by something other than the
    person holding it, and each leaves the secret somewhere afterwards — in a
    process listing, a shell history, a backup, a log.

    A source that declares this channel and in fact reads `os.environ` is code
    running in this process, and `azazel_boot.quarantine` states the limit that
    applies to all of them: Python has no way to prevent it. What the type does
    is remove every *other* answer, so a caller cannot name one.
    """

    LOCAL_HIDDEN_PROMPT = "local_hidden_prompt"


class AttemptOutcome(Enum):
    """The **whole** of what an acquisition may tell this module.

    No passphrase, no key, no device identity, no error string, no exception, no
    count. One member of this enum, which is a value this module defines and the
    acquisition selects.

    `REJECTED` and `OPENED` each represent a passphrase attempt and spend one
    slot. `INTERRUPTED` means no passphrase was tried, so it spends nothing and
    leaves commissioning undecided. The two `NO_…` outcomes settle straight to
    ephemeral because they say a key is not obtainable at all.
    """

    #: The volume opened. The acquisition verified it; this module did not.
    OPENED = "opened"
    #: A passphrase was tried and did not open the volume. Spends budget.
    REJECTED = "rejected"
    #: No key material of any kind is obtainable.
    NO_KEY_MATERIAL = "no_key_material"
    #: There is no hidden local prompt to type into — no TTY, no console.
    NO_LOCAL_INPUT_CHANNEL = "no_local_input_channel"
    #: The operator stopped. Nothing was verified.
    INTERRUPTED = "interrupted"


#: The outcomes that settle the mode to ephemeral immediately, without spending
#: budget. Both say a key cannot be obtained at all, so retrying asks the same
#: question of the same absent thing.
SETTLES_TO_EPHEMERAL = (
    AttemptOutcome.NO_KEY_MATERIAL,
    AttemptOutcome.NO_LOCAL_INPUT_CHANNEL,
)


class AuditEvent(Enum):
    """The only things this module writes to an audit. Exactly three.

    Each is a **classification**. None carries a secret, an identity, an attempt
    count or an error detail, and `AuditEntry` has no field that could hold one.
    """

    MODE_SELECTED = "mode_selected"
    PERSISTENCE_UNAVAILABLE = "persistence_unavailable"
    ATTEMPT_BUDGET_EXHAUSTED = "attempt_budget_exhausted"


@dataclass(frozen=True)
class AuditEntry:
    """One classification, and at most the mode it concerns.

    There is no `detail`, `message`, `reason`, `attempts`, `remaining`,
    `identity`, `passphrase` or `error` field. A free-text field is how a secret
    or a host identity reaches an audit, and the rule is that neither does.
    """

    event: AuditEvent
    mode: SessionMode | None = None


class Refusal(Enum):
    """Why an operation was refused. Every member is raised.

    A member nothing raises is vocabulary a reader will assume is reachable and
    a caller will branch on. The set is pinned by a test against the refusals
    this module actually constructs, so an unraised member is a red test rather
    than a comment nobody reads.
    """

    MODE_ALREADY_FIXED = "mode_already_fixed"
    NOT_THIS_HOST_OR_SESSION = "not_this_host_or_session"
    MEDIUM_FENCED = "medium_fenced"
    INPUT_INTERRUPTED = "input_interrupted"
    CHANNEL_NOT_A_LOCAL_HIDDEN_PROMPT = "channel_not_a_local_hidden_prompt"
    ATTEMPT_IN_PROGRESS = "attempt_in_progress"


class ModeRefused(Refused):
    """No mode was decided, and nothing changed.

    The detail names the rule. It never carries a passphrase, a key, a device
    identity, an attempt count or an underlying error — these messages reach a
    terminal, a journal and a test failure, and each of those is somewhere a
    secret would then live.
    """

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


class KeyAcquisition(Protocol):
    """Prompts, attempts, and reports one enum value.

    It is a Protocol so that the implementation — which does touch a console —
    lives outside `azazel_boot`, the way `permanent_mac_reader` does for the
    ioctl this package may not perform.

    It has **no method that returns a secret.** There is no `passphrase()`, no
    `key()`, no `read()`. `attempt()` returns an :class:`AttemptOutcome`, and
    `channel` says where it took input from.
    """

    @property
    def channel(self) -> PassphraseChannel:
        """Where this acquisition takes input from. Checked before it is used."""

    def attempt(self) -> AttemptOutcome:
        """Prompt once, try once, and say only what happened."""


class NoLocalPrompt:
    """The default acquisition: it reads nothing, and says so.

    `azazel_boot.inventory.no_permanent_mac` is the same shape for the same
    reason. Prompting on a console is an act, and this package's bootstrap may
    not perform one (#1, enforced by `tests/unit/test_boundary_static.py`), so
    the default reports that there is no channel and every session that uses it
    becomes ephemeral.

    That is not a gap being papered over. It **is** the gap, reported: a
    component permitted to drive a console injects a real acquisition, and until
    one exists Boot does not open persistence.
    """

    @property
    def channel(self) -> PassphraseChannel:
        return PassphraseChannel.LOCAL_HIDDEN_PROMPT

    def attempt(self) -> AttemptOutcome:
        return AttemptOutcome.NO_LOCAL_INPUT_CHANNEL


class CommissionedMode:
    """The mode, as an object one boot minted. Checked by identity.

    It is not a value a caller can build meaningfully: what makes it the mode is
    that the `BootSession` that decided it is holding this exact object. A copy,
    a pickle and a rebuild are not it, which is the shape that survived four
    rounds of review on `azazel_boot.writer` and `azazel_boot.persistence`.
    """

    __slots__ = ("_mode", "_boot_id")

    def __init__(self, mode: SessionMode, boot_id: str) -> None:
        object.__setattr__(self, "_mode", mode)
        object.__setattr__(self, "_boot_id", boot_id)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(
            "a CommissionedMode is fixed when it is decided; a session that "
            "started ephemeral stays ephemeral until the machine reboots"
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
            "a CommissionedMode is fixed when it is decided; a session that "
            "started ephemeral stays ephemeral until the machine reboots"
        )

    def __reduce__(self):
        raise TypeError(
            "a CommissionedMode is not serialisable; it belongs to one boot, "
            "not to a file that outlives it"
        )

    def __getstate__(self):
        """The other door `__reduce__` closes, which was left open.

        `object.__getstate__` is a public method on every object since 3.11:
        it hands back the instance state — `__dict__`, or the slots by name —
        with no pickling involved, so `value.__getstate__()` read every field
        the redacting `__repr__` above exists to keep out of a log. Refusing
        one serialisation door and not the other is refusing neither.
        """

        raise TypeError("a CommissionedMode does not hand back its fields")

    def __repr__(self) -> str:
        return f"CommissionedMode(mode={self._mode.value}, boot=<redacted>)"

    @property
    def mode(self) -> SessionMode:
        return self._mode

    @property
    def is_persistent(self) -> bool:
        """**Not a permission, and not proof this boot decided it.**

        Any caller can build a `CommissionedMode(SessionMode.PERSISTENT, …)`
        and it will answer `True` here, because this property reads the two
        fields it was handed and nothing else. What makes a mode *this boot's*
        answer is that the session minted it, which only
        :func:`mode_applies_to` can tell you.

        So the rule for a caller is: ask `mode_applies_to(session, mode)`
        first, and read this afterwards. This accessor is kept because a mode
        that cannot say what it is would be answered by reading `_mode`
        instead, which is worse.
        """

        return self._mode is SessionMode.PERSISTENT

    @property
    def authority(self) -> tuple[()]:
        """Empty in both modes. A mode is a capability, never an authority."""

        return ()


class BootSession:
    """One boot: one attempt budget, one mode, and neither is reusable.

    Not a dataclass and not a value. The budget and the decided mode are its
    whole state, and a caller that could assign to them could grant itself
    attempts or change the mode — which is the thing D2 and D3 exist to prevent.
    `azazel_boot.quarantine` states the limit this shares: `object.__setattr__`
    writes the slot regardless and Python has no way to stop it. Defence against
    a careless caller, not a seal.
    """

    __slots__ = (
        "_boot_id",
        "_quarantine",
        "_binding",
        "_spent",
        "_mode",
        "_audit",
        "_attempt_lock",
        "_sealed",
    )

    def __init__(
        self,
        boot_id: str,
        quarantine: Quarantine,
        binding: SessionBinding | None,
    ) -> None:
        object.__setattr__(self, "_sealed", False)
        if not boot_id.strip():
            raise ValueError("boot_id is required; an attempt budget belongs to one boot")
        self._boot_id = boot_id
        self._quarantine = quarantine
        self._binding = binding
        self._spent = 0
        self._mode: CommissionedMode | None = None
        self._audit: list[AuditEntry] = []
        self._attempt_lock = threading.Lock()
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError(
                "a BootSession is sealed after construction; the attempt "
                "budget and the decided mode cannot be replaced"
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

        raise AttributeError("a BootSession is sealed after construction")

    def __reduce__(self):
        raise TypeError("a BootSession is not serialisable")

    def __getstate__(self):
        """The other door `__reduce__` closes, which was left open.

        `object.__getstate__` is a public method on every object since 3.11:
        it hands back the instance state — `__dict__`, or the slots by name —
        with no pickling involved, so `value.__getstate__()` read every field
        the redacting `__repr__` above exists to keep out of a log. Refusing
        one serialisation door and not the other is refusing neither.
        """

        raise TypeError("a BootSession does not hand back its fields")

    def __repr__(self) -> str:
        """Redacted, including the budget.

        How many attempts remain is not printed anywhere — a counter on a
        screen is a counter in a photograph of a screen, and a counter in a
        repr is one in every traceback.
        """

        decided = self._mode.mode.value if self._mode is not None else "undecided"
        return f"BootSession(mode={decided}, boot=<redacted>)"

    @property
    def decided(self) -> CommissionedMode | None:
        return self._mode

    def audit(self) -> tuple[AuditEntry, ...]:
        return tuple(self._audit)

    def owns(self, quarantine: Quarantine, binding: SessionBinding) -> bool:
        """Whether a workflow carries this boot's exact bound objects."""

        return (
            type(quarantine) is Quarantine
            and quarantine is self._quarantine
            and type(binding) is SessionBinding
            and binding is self._binding
        )

    def holds(self, mode: CommissionedMode) -> bool:
        """Whether this is the object this boot decided. Checked by identity.

        The `is not None` is not redundant. Without it an undecided session
        answers `True` for `None` — and `None` is exactly what `decided`
        returns while undecided, so a caller writing
        `if session.holds(session.decided)` opened the gate in the one state it
        exists to close. An adversarial review found it; the annotation said
        `CommissionedMode` and nothing enforced the annotation.
        """

        return self._mode is not None and self._mode is mode

    def commission(
        self,
        acquisition: KeyAcquisition,
        observations: tuple[InterfaceObservation, ...],
        *,
        session_id: str,
    ) -> CommissionedMode:
        """Commission under the same serialized budget used by recovery."""

        if not self._attempt_lock.acquire(blocking=False):
            raise ModeRefused(
                Refusal.ATTEMPT_IN_PROGRESS,
                "a key acquisition is already in progress",
            )
        try:
            return self._commission_with_budget(
                acquisition, observations, session_id=session_id
            )
        finally:
            self._attempt_lock.release()

    def select_ephemeral(self) -> CommissionedMode:
        """Fix this boot as ephemeral without requesting key material.

        The prototype runtime has no safe persistence/key path. It therefore
        creates its sole BootSession with no host binding and settles the mode
        before any persistence workflow can be exposed. This method cannot
        promote a session or spend an acquisition attempt.
        """

        if not self._attempt_lock.acquire(blocking=False):
            raise ModeRefused(
                Refusal.ATTEMPT_IN_PROGRESS,
                "a key acquisition is already in progress",
            )
        try:
            if self._mode is None:
                self._record(AuditEvent.PERSISTENCE_UNAVAILABLE)
                return self._fix(SessionMode.EPHEMERAL)
            if self._mode.mode is SessionMode.EPHEMERAL:
                return self._mode
            raise ModeRefused(
                Refusal.MODE_ALREADY_FIXED,
                "a persistent mode cannot be replaced during this boot",
            )
        finally:
            self._attempt_lock.release()

    def _commission_with_budget(
        self,
        acquisition: KeyAcquisition,
        observations: tuple[InterfaceObservation, ...],
        *,
        session_id: str,
    ) -> CommissionedMode:
        """Decide the mode, once, for this boot.

        The order is load-bearing and every step before the prompt is a refusal
        that costs nothing: a fenced medium, a record that does not belong to
        this host and session, a channel that is not a hidden local prompt, and
        a mode already decided are all settled **before** an operator is asked
        to type anything.
        """

        self._require_undecided()
        self._require_this_host(observations, session_id=session_id)
        self._require_the_medium_is_not_fenced()
        _require_local_hidden_prompt(
            is_local_hidden=acquisition.channel is PassphraseChannel.LOCAL_HIDDEN_PROMPT
        )

        while True:
            try:
                outcome = acquisition.attempt()
            except Exception:
                # The provider may have reached its verifier before failing to
                # report an outcome. Charge conservatively so retrying a broken
                # provider cannot bypass the per-boot ceiling.
                self._spend()
                if self._spent >= ATTEMPT_BUDGET:
                    self._record(AuditEvent.ATTEMPT_BUDGET_EXHAUSTED)
                    self._fix(SessionMode.EPHEMERAL)
                raise

            # Re-checked every iteration, not only before the first prompt.
            # The loop spans an operator typing up to five passphrases, which
            # is as much wall-clock time as they take — and the medium can be
            # pulled during it. Checking once meant a medium removed after the
            # first prompt still commissioned a persistent mode over a fence.
            self._require_the_medium_is_not_fenced()

            if outcome is AttemptOutcome.OPENED:
                self._spend()
                if self._spent == ATTEMPT_BUDGET:
                    self._record(AuditEvent.ATTEMPT_BUDGET_EXHAUSTED)
                return self._fix(SessionMode.PERSISTENT)
            if outcome in SETTLES_TO_EPHEMERAL:
                self._record(AuditEvent.PERSISTENCE_UNAVAILABLE)
                return self._fix(SessionMode.EPHEMERAL)
            if outcome is AttemptOutcome.INTERRUPTED:
                # Nothing was verified, so nothing is spent and no mode is
                # decided. Fail-closed: without a mode, nothing that needs one
                # runs, and the operator may start commissioning again.
                raise ModeRefused(
                    Refusal.INPUT_INTERRUPTED,
                    "the prompt was stopped before anything was tried; no mode "
                    "is decided and nothing runs until one is",
                )

            self._spend()
            if self._spent >= ATTEMPT_BUDGET:
                self._record(AuditEvent.ATTEMPT_BUDGET_EXHAUSTED)
                return self._fix(SessionMode.EPHEMERAL)

    def attempt_with_budget(
        self,
        acquisition: KeyAcquisition,
        *,
        session_id: str,
    ) -> AttemptOutcome | None:
        """Serialize acquisition with commissioning and other recovery calls."""

        if not self._attempt_lock.acquire(blocking=False):
            return None
        try:
            return self._attempt_with_budget_locked(acquisition, session_id=session_id)
        finally:
            self._attempt_lock.release()

    def _attempt_with_budget_locked(
        self,
        acquisition: KeyAcquisition,
        *,
        session_id: str,
    ) -> AttemptOutcome | None:
        """Ask for one recovery key under this boot's commissioning budget.

        `RecoveryWorkflow` does not own a counter: new workflows over this
        same session cannot buy more guesses. The recovery only exists for an
        already-quarantined volume, and it can use a persistent session's
        remaining budget but never reopen a session fixed ephemeral. Exhaustion
        leaves the commissioned mode untouched (D3); the quarantined volume
        remains unavailable for this boot (D4).
        """

        channel = getattr(acquisition, "channel", None)
        acquire = getattr(acquisition, "attempt", None)
        if type(channel) is not PassphraseChannel or not callable(acquire):
            raise TypeError("acquisition must implement KeyAcquisition")
        if (
            type(session_id) is not str
            or self._binding is None
            or type(self._binding.session_id) is not str
            or type(self._quarantine.session_id) is not str
            or session_id != self._binding.session_id
            or session_id != self._quarantine.session_id
        ):
            return None
        if self._mode is None or self._mode.mode is SessionMode.EPHEMERAL:
            return None
        if self._quarantine.is_fenced:
            return None
        if not self._quarantine.volume_is_quarantined:
            return None
        if channel is not PassphraseChannel.LOCAL_HIDDEN_PROMPT:
            return None
        if self._spent >= ATTEMPT_BUDGET:
            return None

        try:
            outcome = acquire()
        except Exception:
            # A provider error does not prove that no verification was tried.
            self._spend()
            if self._spent >= ATTEMPT_BUDGET:
                self._record(AuditEvent.ATTEMPT_BUDGET_EXHAUSTED)
            raise
        if type(outcome) is not AttemptOutcome:
            # Likewise, an invalid response cannot establish that the provider
            # did no work, so do not let a retry get a free invocation.
            self._spend()
            if self._spent >= ATTEMPT_BUDGET:
                self._record(AuditEvent.ATTEMPT_BUDGET_EXHAUSTED)
            raise TypeError("acquisition must return an exact AttemptOutcome value")
        if outcome in (AttemptOutcome.REJECTED, AttemptOutcome.OPENED):
            self._spend()
            if self._spent == ATTEMPT_BUDGET:
                self._record(AuditEvent.ATTEMPT_BUDGET_EXHAUSTED)
        if self._quarantine.is_fenced:
            return None
        return outcome

    # -- internals ---------------------------------------------------------

    def _require_undecided(self) -> None:
        if self._mode is not None:
            raise ModeRefused(
                Refusal.MODE_ALREADY_FIXED,
                "the mode is decided once, at commissioning; changing it needs "
                "a reboot",
            )

    def _require_this_host(
        self, observations: tuple[InterfaceObservation, ...], *, session_id: str
    ) -> None:
        # The comparison is made here and only its answer travels onward, so
        # the frame that *raises* holds neither the sitting's id nor the
        # inventory. This frame and `commission` above still hold both, because
        # they were handed them — see `_require_local_hidden_prompt` for why
        # that limit is stated rather than claimed away.
        _refuse_foreign_record(
            applies=(
                self._binding is not None
                and binding_applies(self._binding, observations, session_id=session_id)
            )
        )

    def _require_the_medium_is_not_fenced(self) -> None:
        if self._quarantine.is_fenced:
            raise ModeRefused(
                Refusal.MEDIUM_FENCED,
                "the medium was removed; a mode is not decided over it and no "
                "prompt is shown",
            )

    def _spend(self) -> None:
        self._sealed_assign("_spent", self._spent + 1)

    def _fix(self, mode: SessionMode) -> CommissionedMode:
        decided = CommissionedMode(mode, self._boot_id)
        self._sealed_assign("_mode", decided)
        self._record(AuditEvent.MODE_SELECTED, mode)
        return decided

    def _record(self, event: AuditEvent, mode: SessionMode | None = None) -> None:
        self._audit.append(AuditEntry(event=event, mode=mode))

    def _sealed_assign(self, name: str, value: object) -> None:
        """The two fields this object updates about itself, and only these.

        Written through one place so that `__setattr__` can refuse everything
        from outside without the class having to make an exception for itself.
        """

        object.__setattr__(self, name, value)


def _require_local_hidden_prompt(*, is_local_hidden: bool) -> None:
    """Raise from a frame holding one boolean and nothing else.

    **What this does and does not buy.** The raising frame has no acquisition
    in it, so the innermost frame a crash reporter prints renders one boolean.
    It does **not** keep the acquisition out of the traceback: `commission` is
    still on the stack and still holds the parameter it was handed, and a
    frame cannot forget its own argument. If an acquisition's `__repr__`
    renders what it is holding, a captured-locals traceback shows it from
    *that* frame — which is the acquisition's choice, not this module's.
    `tests/unit/test_session_mode.py` asserts both halves, using a double
    whose `__repr__` deliberately leaks, because a double with the default
    `__repr__` makes the assertion pass no matter what.
    """

    if not is_local_hidden:
        raise ModeRefused(
            Refusal.CHANNEL_NOT_A_LOCAL_HIDDEN_PROMPT,
            "a passphrase is typed at a hidden local prompt; there is no other "
            "channel, and an environment variable, an argument or a file is "
            "somewhere the secret stays afterwards",
        )


def _refuse_foreign_record(*, applies: bool) -> None:
    """Raise from a frame holding one boolean, for the reason above.

    The inventory and the binding are not locals here, with the same limit:
    `commission` above still holds the observations. What keeps the host's
    identities out of a rendered traceback is
    `azazel_boot.inventory.InterfaceObservation.__repr__`, which redacts them —
    the mistake made once in `azazel_boot.persistence` and fixed there. This
    frame is the second line of that defence, not the first.
    """

    if not applies:
        raise ModeRefused(
            Refusal.NOT_THIS_HOST_OR_SESSION,
            "this record was made on another machine or in another sitting; a "
            "mode is decided for the host in front of the operator",
        )


def mode_applies_to(session: BootSession, mode: CommissionedMode) -> bool:
    """Whether a mode belongs to this boot's session, by identity.

    A `CommissionedMode` from an earlier boot is not this boot's answer, and a
    constructed one is nobody's. Callers check here rather than reading
    `mode.mode` and believing it.
    """

    return session.holds(mode)
