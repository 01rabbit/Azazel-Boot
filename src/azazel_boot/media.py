"""Which media may be offered as a write target, and how one is named.

`docs/builder-writer-contract.md` section 7.1 is the decision this module
implements: **a device path is never a name on the public surface**. A path is
not something an operator can be sure of — it changes between enumerations, it
is reused after a reboot, and the one they read a minute ago may now belong to
the disk they cannot afford to lose. A target code exists so that the identity
the operator confirmed and the device the writer opens are the same object,
checked, rather than the same string, trusted.

Three properties are structural rather than enforced by care:

*A candidate carries no model and no serial.* Not "does not print them" — the
dataclass has no field for them, so a rendering cannot leak what the model
cannot hold (contract section 7.6).

*An ineligible device is never given a code.* It is listed with its refusal so
an operator can see why their disk is not offered, and there is no code to type
for it. A refusal that can still be selected is a prompt, and a prompt is
something people click through.

*A code belongs to one session and one use.* Codes are issued per enumeration.
A code from an earlier listing does not resolve, so a device cannot be selected
against a view of the world that has since changed.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum

#: Fields the screen may carry: enough for a human to identify the object in
#: front of them, and nothing that identifies it to anyone else.
SCREEN_FIELDS = ("capacity_bytes", "bus_path", "physical_label")


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


class SelectionRefused(Exception):
    """A target code did not resolve to an offered candidate."""

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclass(frozen=True)
class MediaCandidate:
    """A device as enumerated.

    There is no `model` field and no `serial` field. The enumeration source may
    read them; this model cannot carry them, so nothing downstream can print,
    log, export or publish them.
    """

    identity: str
    capacity_bytes: int
    partition_table: str | None
    bus_path: str
    physical_label: str | None
    removable: bool | None
    mounted: bool
    internal: bool
    holds_running_root: bool


@dataclass(frozen=True)
class MediaOffer:
    """One enumerated device, with a code if it may be written to."""

    candidate: MediaCandidate
    eligibility: Eligibility
    target_code: str | None

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
        self._offered: dict[str, MediaCandidate] = {}
        self._used: set[str] = set()

    def offer(self, candidates: list[MediaCandidate]) -> tuple[MediaOffer, ...]:
        """Assess every candidate; issue a code only to the eligible ones."""

        self._offered = {}
        self._used = set()
        offers: list[MediaOffer] = []
        issued = 0
        for candidate in candidates:
            eligibility = assess(candidate)
            code: str | None = None
            if eligibility is Eligibility.ELIGIBLE:
                issued += 1
                code = f"{self.session_id}-{issued:02d}"
                self._offered[code] = candidate
            offers.append(MediaOffer(candidate, eligibility, code))
        return tuple(offers)

    def claim(self, target_code: str) -> MediaCandidate:
        """Resolve a code to the candidate as it was enumerated, once."""

        if target_code in self._used:
            raise SelectionRefused(Refusal.ALREADY_USED, target_code)
        if target_code not in self._offered:
            raise SelectionRefused(
                Refusal.UNKNOWN_CODE,
                "the code was not issued by this listing; re-run list-media",
            )
        self._used.add(target_code)
        return self._offered[target_code]


def candidate_field_names() -> tuple[str, ...]:
    """The model's own field names, for the test that asserts what it cannot hold."""

    return tuple(field.name for field in fields(MediaCandidate))
