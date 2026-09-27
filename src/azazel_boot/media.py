"""Which media may be offered as a write target, and how one is named.

`docs/builder-writer-contract.md` section 7.1 is the decision this module
implements: **a device path is never a name on the public surface**. A path is
not something an operator can be sure of — it changes between enumerations, it
is reused after a reboot, and the one they read a minute ago may now belong to
the disk they cannot afford to lose. A target code exists so that the identity
the operator confirmed and the device the writer opens are the same object,
checked, rather than the same string, trusted.

Three properties carry the safety here. They are enforced as far as Python
enforces anything — an immutable value object, a read-only mapping, a code that
resolves once — which puts every accidental misuse out of reach and leaves
`object.__setattr__` and `gc.get_referents` where they always are. The boundary
is the process, and the write service is the component that boundary is drawn
around (contract section 8).

*A candidate carries no model and no serial.* The dataclass has no field for
them, so a rendering cannot leak what the model cannot hold. The stable
`identity` **is** a field — the writer needs it — so it is kept out of renderings
by an explicit `__repr__` rather than by absence, and contract section 7.6
covers it too.

*An ineligible device is never given a code.* It is listed with its refusal so
an operator can see why their disk is not offered, and there is no code to type
for it. A refusal that can still be selected is a prompt, and a prompt is
something people click through.

*A code names one enumeration, and is spent by one use.* The code carries the
enumeration it came from, so a code written down before a re-listing does not
resolve afterwards — it does not silently come to mean whichever device now
occupies that position. An adversarial review found exactly that defect in the
first version of this module: `m1-01` was reissued by the next listing and a
code an operator had noted for a blank stick resolved to an evidence disk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from enum import Enum

from .refusals import Refused

#: Fields the screen may carry: enough for a human to identify the object in
#: front of them, and nothing that identifies it to anyone else.
# Hardware location, labels, and stable identifiers remain backend-only. The
# operator-facing list contains capacity plus the ephemeral target code, not a
# serial, bus address, model, label, or kernel node.
SCREEN_FIELDS = ("capacity_bytes",)


class Eligibility(Enum):
    """Whether a device may be offered, and if not, why not.

    The order of the refusals below is the order they are checked in: the most
    consequential mistake an operator could make is named first.
    """

    ELIGIBLE = "eligible"
    INTERNAL_DISK = "internal_disk"
    HOLDS_RUNNING_ROOT = "holds_running_root"
    REMOVABILITY_UNKNOWN = "removability_unknown"
    MOUNTED = "mounted"


class Refusal(Enum):
    UNKNOWN_CODE = "unknown_code"
    ALREADY_USED = "already_used"


class SelectionRefused(Refused):
    """A target code did not resolve to an offered candidate."""

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


class DeviceIdentity:
    """A stable device identity that no accidental rendering can print.

    `repr=False` on a dataclass stops `repr`, and an adversarial review then
    pulled the identity straight back out with `dataclasses.asdict` — which is
    what a `--json` output or an audit line actually calls. Holding the value in
    an opaque object fixes that class of leak rather than one instance of it:
    `asdict` yields this object, `json.dumps` refuses it loudly instead of
    serialising it quietly, and a caller that genuinely needs the value asks for
    it by name.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", value) is None
        ):
            raise ValueError("device identity must be an opaque token, not a path")
        object.__setattr__(self, "_value", value)

    def __setattr__(self, name: str, value: object) -> None:
        """Immutable after construction.

        A review made this object mutable's consequence concrete: the writer
        hands the same identity to the unmounter and then to the raw writer, so
        a port that assigned to it between those two calls changed what was
        opened **after** every refusal had been evaluated. The host's internal
        disk was written and the medium was reported valid. A write target that
        can change under the checks is not a target.
        """

        raise AttributeError("a DeviceIdentity is immutable once constructed")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("a DeviceIdentity is immutable once constructed")

    def __copy__(self) -> DeviceIdentity:
        """Immutable, so a copy is itself. Copying is not a leak; pickling is."""

        return self

    def __deepcopy__(self, memo: dict) -> DeviceIdentity:
        return self

    def __reduce__(self):
        """Refuse to pickle, rather than writing the value into a file or a queue."""

        raise TypeError(
            "a DeviceIdentity is not serialisable; ask for the value explicitly "
            "if a component genuinely needs it"
        )

    def __getstate__(self):
        """The other door `__reduce__` closes, which was left open.

        `object.__getstate__` is a public method on every object since 3.11:
        it hands back the instance state — `__dict__`, or the slots by name —
        with no pickling involved, so `value.__getstate__()` read every field
        the redacting `__repr__` above exists to keep out of a log. Refusing
        one serialisation door and not the other is refusing neither.
        """

        raise TypeError("a DeviceIdentity does not hand back its fields")

    def disclose(self) -> str:
        """The raw value, for the one component that must open the device."""

        return self._value

    def __repr__(self) -> str:
        return "DeviceIdentity(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def __eq__(self, other: object) -> bool:
        """Deliberate, and it costs something.

        The writer compares identities to detect a substitution, so equality has
        to work — which also makes any holder of a candidate an oracle for a
        guessed identity. That trade is taken knowingly: without it the
        re-verification cannot exist at all.
        """

        return isinstance(other, DeviceIdentity) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)


@dataclass(frozen=True, repr=False)
class MediaCandidate:
    """A device as enumerated.

    There is no `model` field and no `serial` field. The enumeration source may
    read them; this model cannot carry them, so nothing downstream can print,
    log, export or publish them.
    """

    identity: DeviceIdentity
    capacity_bytes: int
    partition_table: str | None
    bus_path: str
    physical_label: str | None
    removable: bool | None
    mounted: bool
    internal: bool
    holds_running_root: bool

    def __repr__(self) -> str:
        """Redacted: a default repr would print the identity into any log.

        `logging.info("%s", candidate)`, an f-string, a traceback with captured
        locals — each of those is a rendering nobody wrote, and the identity is
        what contract section 7.6 keeps off them.
        """

        return (
            f"MediaCandidate(identity=<redacted>, capacity_bytes={self.capacity_bytes}, "
            f"partition_table={self.partition_table!r}, bus_path=<redacted>, "
            f"physical_label=<redacted>, removable={self.removable}, "
            f"mounted={self.mounted}, internal={self.internal}, "
            f"holds_running_root={self.holds_running_root})"
        )


@dataclass(frozen=True, repr=False)
class MediaOffer:
    """One enumerated device, with a code if it may be written to."""

    candidate: MediaCandidate
    eligibility: Eligibility
    target_code: str | None

    def __repr__(self) -> str:
        return (
            f"MediaOffer(candidate={self.candidate!r}, "
            f"eligibility={self.eligibility}, target_code={self.target_code!r})"
        )

    def describe_for_screen(self) -> dict[str, object]:
        """What an operator sees. Identity never appears here."""

        screen: dict[str, object] = {
            name: getattr(self.candidate, name) for name in SCREEN_FIELDS
        }
        screen["eligibility"] = self.eligibility.value
        screen["target_code"] = self.target_code
        return screen


def assess(candidate: MediaCandidate) -> Eligibility:
    """Decide whether a device may be offered at all.

    `removable is None` means the attribute could not be determined, and unknown
    is not removable. Treating it as removable would be the writer deciding, on
    an operator's behalf, that a disk it could not classify is safe to erase.
    """

    if candidate.internal:
        return Eligibility.INTERNAL_DISK
    if candidate.holds_running_root:
        return Eligibility.HOLDS_RUNNING_ROOT
    if candidate.removable is not True:
        return Eligibility.REMOVABILITY_UNKNOWN
    if candidate.mounted:
        return Eligibility.MOUNTED
    return Eligibility.ELIGIBLE


class MediaSession:
    """One enumeration, and the codes it issued.

    A session is deliberately not persistent. `list-media` and `write` are two
    commands in one sitting, and a code that outlived the sitting would name a
    device that may no longer be there.
    """

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._enumeration = 0
        self._offered: dict[str, MediaCandidate] = {}
        #: Spent codes, kept for the whole session. Clearing this on a new
        #: listing would make a spent code usable again.
        self._used: set[str] = set()

    def offer(self, candidates: list[MediaCandidate]) -> tuple[MediaOffer, ...]:
        """Assess every candidate; issue a code only to the eligible ones.

        Each listing gets its own code space. A code from an earlier listing
        therefore fails to resolve rather than resolving to whichever device now
        occupies that position — the substitution would otherwise happen here,
        upstream of every check the writer performs.
        """

        self._enumeration += 1
        self._offered = {}
        offers: list[MediaOffer] = []
        issued = 0
        for candidate in candidates:
            eligibility = assess(candidate)
            code: str | None = None
            if eligibility is Eligibility.ELIGIBLE:
                issued += 1
                code = f"{self.session_id}-{self._enumeration}-{issued:02d}"
                self._offered[code] = candidate
            offers.append(MediaOffer(candidate, eligibility, code))
        return tuple(offers)

    def claim(self, target_code: str) -> MediaCandidate:
        """Resolve a code to the candidate as it was enumerated, once."""

        if target_code in self._used:
            raise SelectionRefused(
                Refusal.ALREADY_USED, "a code names one write, and this one is spent"
            )
        if target_code not in self._offered:
            raise SelectionRefused(
                Refusal.UNKNOWN_CODE,
                "the code was not issued by the current listing; re-run list-media "
                "and read the code off the device you mean",
            )
        self._used.add(target_code)
        return self._offered[target_code]


def candidate_field_names() -> tuple[str, ...]:
    """The model's own field names, for the test that asserts what it cannot hold."""

    return tuple(field.name for field in fields(MediaCandidate))
