"""Whether a Knowledge Lite artifact may be read, and what happens when it may not.

Azazel-Boot#16, and the consumer half of the program's SO-06 objective. Knowledge
ADR-0015 D7 draws the line this module sits on:

    Knowledge produces and signs; it does not decide where an artifact is
    installed, when it is trusted, or **what a consumer does on its absence**.

What a consumer does on its absence is the whole subject here, and the answer is
always the same shape: **the deterministic Core keeps working and the capability
state degrades to CORE.** Nothing about a missing, corrupt, expired or unsigned
artifact may move or widen an authority. Azazel-Edge's deterministic arbiter
decides and enforces in every one of these cases, exactly as it does when the
artifact is perfect.

Three Boot-specific conditions shape the decision, and none of them applies to a
permanently installed node:

*Absence is a normal configuration.* A medium handed out in an emergency may
simply not carry Lite. That is not a failure to report as one.

*Expiry is the default state.* An offline medium is never updated, so an expired
artifact is the expected case rather than the exceptional one. It is admitted
**with its freshness label intact** — withholding the label would be worse than
withholding the data, because a consumer would then treat stale indicators as
current.

*The medium can vanish mid-read.* `docs/threat-model.md` §4 requires the Core to
be RAM-resident and to continue. This module therefore never holds an admission
open across a read: an admission is a decision about bytes already verified, not
a promise that a device still exists.

**Verification is injected and the default refuses.** Knowledge signs Lite
artifacts with Ed25519 (PyNaCl), which the standard library cannot verify, and
this repository's bootstrap is standard-library only (issue #1, enforced by
`tests/unit/test_boundary_static.py`). So a Boot that has not been given a
verifier admits **nothing** — a build that forgot to wire verification ends up
with no data rather than with unverified data.

This module reads no artifact and writes no cache. It decides admission. The
staged reader that would act on the decision is operational code and does not
exist yet; `AdmissionDecision.staging_rule` states the contract it must meet.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

#: The capability state every refusal resolves to. `CORE` is a capability
#: state, never an authority level: degrading to it narrows what the node can
#: do and moves no decision rights whatsoever.
DEGRADED_CAPABILITY = "CORE"

#: What a consumer must do while an artifact is being replaced. Stated here
#: because the reader that will enforce it does not exist yet, and a contract
#: written down can be implemented against; one left implicit cannot.
STAGING_RULE = (
    "a replacement is admitted into a staging location and becomes readable by "
    "a single atomic rename; a reader therefore observes the previous artifact "
    "or the next one, and never a partially written state"
)


class Admission(str, Enum):
    """The outcome of deciding about one artifact."""

    #: Verified and usable. `freshness` says whether it is current.
    ADMITTED = "ADMITTED"
    #: Nothing is present. A normal configuration for an emergency medium.
    ABSENT = "ABSENT"
    #: A verifier rejected it. Its bytes never reach the read-only cache.
    REFUSED = "REFUSED"
    #: No verifier was configured, so nothing can be trusted and nothing is
    #: admitted. Distinct from REFUSED: the artifact was never judged.
    UNVERIFIABLE = "UNVERIFIABLE"


class Freshness(str, Enum):
    """Whether an admitted artifact's contents are current.

    An expired artifact is still admitted. Withholding the *label* would be
    worse than withholding the data: a consumer would treat stale indicators as
    current, which is the one outcome worse than having none.
    """

    CURRENT = "CURRENT"
    EXPIRED = "EXPIRED"
    #: Admitted, but the artifact does not say when it expires. Treated as
    #: expired for every decision; recorded separately so an operator can tell
    #: "stale" from "unlabelled".
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class AdmissionDecision:
    """Descriptive. It admits bytes to a cache; it authorizes nothing."""

    admission: Admission
    #: Always `CORE` on anything but ADMITTED, and never an authority level.
    capability: str
    #: Present only when ADMITTED.
    freshness: Freshness | None
    #: Why, in the words an operator and an audit record both get. Non-empty.
    reasons: tuple[str, ...]
    #: The verifier's own refusal text, passed through unchanged. Knowledge
    #: owns that vocabulary; Boot does not enumerate or reinterpret it, so a
    #: new Knowledge refusal code needs no change here.
    verifier_detail: str = ""

    @property
    def usable(self) -> bool:
        return self.admission is Admission.ADMITTED

    @property
    def staging_rule(self) -> str:
        return STAGING_RULE


def refuse_everything(_artifact: object) -> tuple[bool, str]:
    """The default verifier: it verifies nothing, and says so.

    Knowledge signs with Ed25519, which needs a cryptographic library the
    bootstrap may not carry. A Boot that has not been given a real verifier
    must therefore admit nothing. Returning "unverified" rather than raising
    keeps the refusal on the same path as every other one, so it is reported
    the same way instead of becoming an exception somebody catches.
    """

    return False, "no signature verifier is configured"


def decide(
    artifact_present: bool,
    *,
    verifier=refuse_everything,
    artifact: object = None,
    expires_at: str | None = None,
    as_of: str | None = None,
) -> AdmissionDecision:
    """Decide about one artifact, failing closed on anything short of proof.

    ``expires_at`` and ``as_of`` are ISO-8601 strings compared lexicographically,
    which is correct for the normalized UTC form Knowledge emits. ``as_of`` is
    supplied by the caller rather than read from a clock, so the same inputs
    always give the same decision and a decision is reproducible in a replay.
    Without ``as_of`` freshness cannot be evaluated, and unevaluated is treated
    as expired.
    """

    if not artifact_present:
        return AdmissionDecision(
            admission=Admission.ABSENT,
            capability=DEGRADED_CAPABILITY,
            freshness=None,
            reasons=(
                "no Knowledge Lite artifact is present on this medium; a medium "
                "handed out without one is a normal configuration, not a fault",
                "the deterministic Core is unaffected and keeps every decision "
                "and enforcement right it already had",
            ),
        )

    if verifier is refuse_everything:
        accepted, detail = refuse_everything(artifact)
        return AdmissionDecision(
            admission=Admission.UNVERIFIABLE,
            capability=DEGRADED_CAPABILITY,
            freshness=None,
            reasons=(
                "no verifier is configured, so the artifact was never judged and "
                "none of its bytes may enter the read-only cache",
                "this is the state of a build that did not wire verification: it "
                "yields no data rather than unverified data",
            ),
            verifier_detail=detail,
        )

    try:
        accepted, detail = verifier(artifact)
    except Exception as exc:  # noqa: BLE001 - a verifier that raises is a refusal
        return AdmissionDecision(
            admission=Admission.REFUSED,
            capability=DEGRADED_CAPABILITY,
            freshness=None,
            reasons=(
                "the verifier raised instead of answering; an artifact that could "
                "not be judged is refused, never admitted",
            ),
            verifier_detail=f"{type(exc).__name__}: {exc}",
        )

    if not accepted:
        return AdmissionDecision(
            admission=Admission.REFUSED,
            capability=DEGRADED_CAPABILITY,
            freshness=None,
            reasons=(
                "the artifact failed verification; none of its bytes enter the "
                "read-only cache",
                "the deterministic Core is unaffected and keeps every decision "
                "and enforcement right it already had",
            ),
            verifier_detail=detail,
        )

    freshness = _freshness(expires_at, as_of)
    reasons = ["the artifact verified and may be read"]
    if freshness is Freshness.EXPIRED:
        reasons.append(
            "its contents are expired and are labelled as such; an offline "
            "medium is never updated, so this is the expected state rather than "
            "an exceptional one"
        )
    elif freshness is Freshness.UNKNOWN:
        reasons.append(
            "it carries no expiry, so freshness cannot be established and is "
            "treated as expired for every decision"
        )

    return AdmissionDecision(
        admission=Admission.ADMITTED,
        # Admission does not raise capability on its own: what a verified
        # artifact enables is decided elsewhere, against topology, assets and
        # health as well. This records only that its bytes may be read.
        capability=DEGRADED_CAPABILITY,
        freshness=freshness,
        reasons=tuple(reasons),
        verifier_detail=detail,
    )


def _freshness(expires_at: str | None, as_of: str | None) -> Freshness:
    if not expires_at:
        return Freshness.UNKNOWN
    if not as_of:
        # No reference time means freshness was not evaluated. Unevaluated is
        # not evidence of currency, so it counts as expired.
        return Freshness.EXPIRED
    return Freshness.CURRENT if as_of < expires_at else Freshness.EXPIRED
