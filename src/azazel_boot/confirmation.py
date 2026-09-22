"""What an operator is shown, what they type twice, and what that does not buy.

Azazel-Boot#9's remaining half. `commissioning.assess` says what an inventory
permits and `describe_for_operator` says what may be shown about one interface;
this is the screen those two feed, and the two-stage confirmation that follows.

Three properties, and each is the answer to a specific way this goes wrong.

**A confirmation is a fact about hardware. It is not permission.**
[The threat model](../../docs/threat-model.md) §6 names the attack directly: *"A
confirmation is treated as an authorization — the operator 'approved' the
interface, therefore the action is approved."* So :class:`Confirmation` has no
method, no field and no relationship that any other module consults.
`azazel_boot.persistence`, `azazel_boot.quarantine` and `azazel_boot.writer`
cannot be handed one; their signatures have nowhere to put it. Writing, opening
and exporting still pass the target binding, the issued approval, the fence and
their own second confirmation, exactly as before — and a test drives each of
those three with a completed confirmation in hand to show the answers do not
move.

**The screen never overstates.** `UNVERIFIED_PLATFORM` is the expected class on
a borrowed laptop, and :data:`TRUST_WORDING` maps it to a sentence about what
cannot be claimed. The words `safe`, `secure`, `verified`, `trusted`,
`compatible`, `supported`, `certified`, `guaranteed` and `protected` appear in
no rendered line, and a test scans every line of every screen for them. A class
cannot be raised by a successful boot, a passing self-check or an operator's
assertion, and there is no code path here that raises one at all.

**The screen carries no identifier the operator did not read off the hardware.**
No permanent MAC, no serial, no asset tag, no TPM identifier, no filesystem
path, no operator name. `interface_key` is `bus_path|permanent_mac`, so it is
absent too — which is why an interface is chosen by a **per-session code**
rather than by its identity, the same shape `azazel_boot.media.MediaSession`
uses for write targets.

One judgement is recorded rather than hidden: the bus position **is** shown,
and only when the interface has no physical label. It is not a serial, a MAC or
a filesystem path, it is the same for every machine of that model, and without
it an operator facing two unlabelled ports has no way to answer the question at
all. Showing it always would disclose more than the question needs; never
showing it would make the screen unanswerable. A reviewer who disagrees should
say so — the alternative is that the flow cannot distinguish two bare sockets.

Nothing here has been shown to an operator. No confirmation has been made on
any hardware, and `azazel_boot` still has no user interface of any kind: what
exists is the content of the screen and the rules about it, as data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from azazel_boot.commissioning import (
    ROLES,
    Assessment,
    CommissioningState,
    describe_for_operator,
)
from azazel_boot.inventory import InterfaceObservation


class PlatformTrust(Enum):
    """[The threat model](../../docs/threat-model.md) §2's three classes.

    Mirrored here rather than imported because nothing in `src/` defines them
    yet; `tests/unit/test_confirmation.py` pins this tuple against the document
    so the mirror cannot drift from what it mirrors.

    The class is **determined and displayed, never assumed and never silently
    upgraded**. There is no function in this module that returns a higher class
    than it was given, and a test asserts the absence.
    """

    VERIFIED_FIRMWARE = "VERIFIED_FIRMWARE"
    EXTERNALLY_VERIFIED_MEDIA = "EXTERNALLY_VERIFIED_MEDIA"
    UNVERIFIED_PLATFORM = "UNVERIFIED_PLATFORM"


#: What each class is allowed to say on a screen, in the weakest form that is
#: still true. The `UNVERIFIED_PLATFORM` line is the one that matters: it is the
#: expected class on a borrowed laptop, and the sentence has to survive a
#: stressed reader skimming it.
#:
#: These are the **only** strings the trust line may be built from. A renderer
#: that composed its own would be a second vocabulary, which is the failure
#: `test_commissioning.py` already records once.
TRUST_WORDING = {
    PlatformTrust.VERIFIED_FIRMWARE: (
        "this machine's firmware checked Boot's signature before running it"
    ),
    PlatformTrust.EXTERNALLY_VERIFIED_MEDIA: (
        "this machine's firmware did not check Boot; the medium was checked "
        "somewhere else, before it was brought here"
    ),
    PlatformTrust.UNVERIFIED_PLATFORM: (
        "nothing checked Boot on this machine, and nothing here can tell you "
        "whether the machine itself was already interfered with. what you see "
        "below is what Boot could read, not a finding about this laptop"
    ),
}

#: Words a screen may not contain, in any line, in any state.
#:
#: They are the promotions `UNVERIFIED_PLATFORM` exists to prevent. A stressed
#: operator reading "verified" takes it as a finding about the laptop, and the
#: whole point of the class is that there is no such finding.
FORBIDDEN_ASSURANCE_WORDS = (
    "safe",
    "secure",
    "verified",
    "trusted",
    "compatible",
    "supported",
    "certified",
    "guaranteed",
    "protected",
    "validated",
    "approved",
)

#: What Boot is permitted to do once a role is confirmed, in the operator's
#: words. Every entry is something Boot does to itself; none of them is an
#: action against the host or the network.
PERMITTED_AFTER_CONFIRMATION = (
    "record which port you pointed at, for this sitting only",
    "read what the hardware reports about that port, without sending anything",
)

#: What stays refused regardless of what is confirmed. Stated on the screen
#: because the operator's mental model of "I approved it" is exactly the
#: mistake §6 names.
REFUSED_REGARDLESS = (
    "writing anything to this laptop's own disks",
    "starting capture, enforcement or deception",
    "deciding or enforcing anything — Azazel-Edge does that, before and after",
    "carrying this confirmation to another laptop, or to a later sitting",
)


class ScreenRefusal(Enum):
    NOTHING_TO_CONFIRM = "nothing_to_confirm"
    UNKNOWN_CHOICE_CODE = "unknown_choice_code"
    CHOICE_CODE_ALREADY_USED = "choice_code_already_used"
    ROLE_NOT_OFFERED = "role_not_offered"
    FIRST_STAGE_NOT_SHOWN = "first_stage_not_shown"
    RESTATEMENT_DID_NOT_MATCH = "restatement_did_not_match"
    NOT_THIS_SESSION = "not_this_session"


class ConfirmationRefused(Exception):
    """The confirmation did not happen.

    The detail names the rule. It never echoes a code, a label, an identity or
    a role the caller supplied: a refusal reaches a terminal and a journal, and
    the values come from an inventory of somebody else's laptop.
    """

    def __init__(self, refusal: ScreenRefusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclass(frozen=True)
class OfferedInterface:
    """One row of the screen: a code, and what the operator can look at.

    There is no `identity`, `permanent_mac`, `serial`, `bus_path` or
    `interface_key` field. `locator` holds the bus position **only** when the
    interface has no physical label, and says which of the two it is through
    `locator_is_a_label`.
    """

    code: str
    locator: str
    locator_is_a_label: bool
    connection: str
    #: Empty when the interface can carry a confirmed role. Otherwise the
    #: inventory's own reason codes, which are a fixed vocabulary this package
    #: writes — not values read off the hardware.
    unavailable_because: tuple[str, ...] = ()

    @property
    def is_offerable(self) -> bool:
        return not self.unavailable_because


@dataclass(frozen=True)
class Screen:
    """What would be printed, as lines, plus the rows the operator picks from.

    `lines` is the whole of what reaches a terminal. A test renders a screen
    from an inventory full of MACs, serials and paths and asserts that none of
    them is in it.
    """

    lines: tuple[str, ...]
    offered: tuple[OfferedInterface, ...] = field(default_factory=tuple)

    def __repr__(self) -> str:
        return f"Screen(lines={len(self.lines)}, offered={len(self.offered)})"


@dataclass(frozen=True)
class Confirmation:
    """A fact the operator asserted about hardware. **It authorises nothing.**

    It holds the choice code — which is meaningless outside the session that
    issued it — and the role word. It holds no device, no identity, no
    capability and no expiry, because it is not a lease.

    `authority` is `()` in every instance, as on
    `azazel_boot.persistence.PersistenceStatus`, and for the same reason: this
    is the field somebody would reach for when arguing that a confirmation
    should count for something.
    """

    code: str
    role: str
    session_id: str

    @property
    def authority(self) -> tuple[()]:
        """Empty, always. Azazel-Edge's arbiter decides; a confirmation does not."""

        return ()

    def __repr__(self) -> str:
        return f"Confirmation(role={self.role!r}, code=<redacted>, session=<redacted>)"


#: The reason a row carries when the interface reads as complete but the
#: assessment still will not have it — two ports claiming one composite
#: identity, most of all. A fixed token, like the inventory's own reasons, so a
#: screen never renders prose that came from hardware.
NOT_OFFERED_BY_THE_ASSESSMENT = "not_offered_by_the_assessment"


def _describe(
    observation: InterfaceObservation, code: str, assessment: Assessment
) -> OfferedInterface:
    """One row, built from `describe_for_operator` and then narrowed.

    `describe_for_operator` is the merged contract and is used as it stands;
    what happens here is that two of its four fields are **dropped**. It returns
    `identity`, which is `bus_path|permanent_mac` — the composite identity — and
    the rule for this screen is that no raw hardware identifier reaches a
    terminal. The bus position survives only as a fallback locator.

    **Whether a row may be chosen is the assessment's answer, not this
    function's.** The first version read `observation.incomplete_reasons` alone,
    which is a different question: two interfaces presenting one composite
    identity are each individually complete, so both rows said "choose me"
    while `assess` had already returned `COMMISSIONING_REQUIRED` and offered no
    role at all. A test caught it. Re-deciding what another module decided is
    the mistake `azazel_boot.persistence` was rebuilt to stop making, and it is
    the same mistake here.
    """

    described = describe_for_operator(observation)
    label = described["physical_label"]
    has_label = label != "unlabelled"
    reasons = tuple(observation.incomplete_reasons)
    if not reasons and (
        observation.interface_key not in assessment.commissionable_keys
        or not assessment.offerable_roles
    ):
        reasons = (NOT_OFFERED_BY_THE_ASSESSMENT,)
    return OfferedInterface(
        code=code,
        locator=label if has_label else described["bus_position"],
        locator_is_a_label=has_label,
        connection=described["connection"],
        unavailable_because=reasons,
    )


class ConfirmationScreen:
    """One sitting. Issues codes, shows two stages, and grants nothing.

    Not a dataclass and not a value: the codes it issued and the ones already
    spent are the only state it has, and a caller that could assign to them
    could confirm the same port twice or resolve a code it made up.
    `azazel_boot.quarantine` states the limit this shares — `object.__setattr__`
    writes the slot regardless, and Python has no way to prevent it. Defence
    against a careless caller, not a seal.
    """

    __slots__ = ("_session_id", "_trust", "_offered", "_spent", "_shown", "_sealed")

    def __init__(self, session_id: str, trust: PlatformTrust) -> None:
        object.__setattr__(self, "_sealed", False)
        if not session_id.strip():
            raise ValueError("session_id is required; a confirmation binds to one sitting")
        self._session_id = session_id
        self._trust = trust
        self._offered: dict[str, tuple[OfferedInterface, Assessment]] = {}
        self._spent: set[str] = set()
        self._shown: set[str] = set()
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError(
                "a ConfirmationScreen is sealed after construction; the codes "
                "it issued and the ones already spent cannot be replaced"
            )
        object.__setattr__(self, name, value)

    def __reduce__(self):
        raise TypeError("a ConfirmationScreen is not serialisable")

    def __repr__(self) -> str:
        return (
            f"ConfirmationScreen(trust={self._trust.value}, "
            f"offered={len(self._offered)}, spent={len(self._spent)})"
        )

    @property
    def trust(self) -> PlatformTrust:
        """Displayed, never raised. There is no setter and no upgrade path."""

        return self._trust

    def first_stage(
        self, observations: tuple[InterfaceObservation, ...], assessment: Assessment
    ) -> Screen:
        """The choosing screen: what is here, what may be confirmed, what is not.

        Codes are issued per call and are scoped to this sitting, so a code from
        an earlier screen does not resolve to whatever now occupies that
        position — the substitution would otherwise happen upstream of every
        check.
        """

        rows: list[OfferedInterface] = []
        for index, observation in enumerate(observations, start=1):
            code = f"{self._session_id[:2]}-{index:02d}"
            row = _describe(observation, code, assessment)
            rows.append(row)
            if row.is_offerable:
                self._offered[code] = (row, assessment)

        lines = [
            "before you confirm anything:",
            f"  {TRUST_WORDING[self._trust]}",
            "",
            f"  Boot will: {PERMITTED_AFTER_CONFIRMATION[0]}",
        ]
        lines += [f"            {item}" for item in PERMITTED_AFTER_CONFIRMATION[1:]]
        lines += ["", f"  Boot will not: {REFUSED_REGARDLESS[0]}"]
        lines += [f"                 {item}" for item in REFUSED_REGARDLESS[1:]]
        lines += ["", _state_line(assessment.state), ""]

        if not rows:
            lines.append("  no network ports were found to ask you about")
        for row in rows:
            where = (
                f"the port labelled {row.locator}"
                if row.locator_is_a_label
                else f"the {row.connection} port at position {row.locator} "
                "(it carries no label, so this is the only way to point at it)"
            )
            if row.is_offerable:
                lines.append(f"  [{row.code}] {where}")
            else:
                lines.append(
                    f"  [--] {where} — cannot be confirmed: "
                    f"{', '.join(row.unavailable_because)}"
                )

        if assessment.offerable_roles:
            lines += ["", "  roles you may confirm one of:"]
            lines += [f"    {role}" for role in assessment.offerable_roles]
        for reason in assessment.reasons:
            lines.append(f"  note: {reason}")

        self._shown.add("first")
        return Screen(lines=tuple(lines), offered=tuple(rows))

    def second_stage(self, code: str, role: str) -> Screen:
        """The restating screen: exactly one port, exactly one role, said back.

        Two stages rather than one because the failure being defended against is
        a stressed operator agreeing to something they did not read. The second
        screen names one thing, and the phrase they type is built from it.
        """

        row, assessment = self._resolve(code, role)
        where = (
            f"the port labelled {row.locator}"
            if row.locator_is_a_label
            else f"the {row.connection} port at position {row.locator}"
        )
        lines = (
            "read this back before you type it:",
            "",
            f"  you are saying that {where}",
            f"  is the one you want Boot to record as: {role}",
            "",
            f"  {TRUST_WORDING[self._trust]}",
            "",
            "  this records what you pointed at. it does not let Boot do "
            "anything it could not do a moment ago, and it does not decide "
            "anything — Azazel-Edge does that, before and after.",
            "",
            f"  to confirm, type: {restatement_for(row, role)}",
        )
        del assessment
        self._shown.add(code)
        return Screen(lines=lines, offered=(row,))

    def confirm(self, code: str, role: str, restatement: str) -> Confirmation:
        """Record the fact, once, after the second stage was actually shown."""

        row, _ = self._resolve(code, role)
        if code not in self._shown:
            raise ConfirmationRefused(
                ScreenRefusal.FIRST_STAGE_NOT_SHOWN,
                "the restating screen is shown before the phrase is accepted; "
                "otherwise the second stage is a step a caller can skip",
            )
        if restatement.strip().lower() != restatement_for(row, role):
            raise ConfirmationRefused(
                ScreenRefusal.RESTATEMENT_DID_NOT_MATCH,
                "the phrase is built from the port and the role, so one answer "
                "cannot stand for a different port or a different role",
            )
        self._spent.add(code)
        return Confirmation(code=code, role=role, session_id=self._session_id)

    # -- internals ---------------------------------------------------------

    def _resolve(self, code: str, role: str) -> tuple[OfferedInterface, Assessment]:
        if code in self._spent:
            raise ConfirmationRefused(
                ScreenRefusal.CHOICE_CODE_ALREADY_USED,
                "a code names one port for one confirmation in this sitting",
            )
        if code not in self._offered:
            raise ConfirmationRefused(
                ScreenRefusal.UNKNOWN_CHOICE_CODE,
                "this code was not issued by this screen; a code from an "
                "earlier listing names a position, not a port",
            )
        row, assessment = self._offered[code]
        if role not in assessment.offerable_roles:
            raise ConfirmationRefused(
                ScreenRefusal.ROLE_NOT_OFFERED,
                "the roles on offer come from what the inventory permits, not "
                "from what a caller asks for",
            )
        return row, assessment


def restatement_for(row: OfferedInterface, role: str) -> str:
    """The phrase, built from the port and the role so it cannot be reused.

    A shared "yes" would let one answer stand for whichever port the caller
    asked about last, which is the same mistake as a single confirmation phrase
    for three different acts.
    """

    return f"{row.locator.lower()} is {role}"


def _state_line(state: CommissioningState) -> str:
    """One sentence per state, in the weakest form that is still true."""

    return {
        CommissioningState.COMMISSIONING_REQUIRED: (
            "  Boot cannot tell these ports apart well enough to ask you. "
            "nothing is confirmed and nothing will be."
        ),
        CommissioningState.OBSERVE_ONLY: (
            "  this laptop has one usable port, so Boot can only watch. that is "
            "the intended outcome here, not a fault."
        ),
        CommissioningState.AWAITING_OPERATOR_CONFIRMATION: (
            "  Boot can tell these ports apart. it has assigned nothing, and "
            "will not until you say which is which."
        ),
    }[state]


def rendered_words(screen: Screen) -> set[str]:
    """Every word on the screen, lowercased. For the test that forbids some."""

    words: set[str] = set()
    for line in screen.lines:
        words.update("".join(c if c.isalpha() else " " for c in line).lower().split())
    return words


def offerable_roles_are_known(assessment: Assessment) -> bool:
    """The roles offered are the registered ones, never a caller's invention."""

    return set(assessment.offerable_roles) <= set(ROLES)
