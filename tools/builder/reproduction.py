"""Compare two evaluation records, and say exactly what the comparison settled.

`ADR-0002` D1.3 is specific: "**Two independent builders** must agree. One
builder producing the same digest twice on the same machine is not the claim
being made." This module refuses the comparison that would quietly make the
weaker claim — two records from the same host do not get compared at all.

Two further refusals exist for the same reason: records built from different
input closures, or for different profiles, are not evidence about
reproducibility. They are evidence about two different builds.

The verdict is deliberately asymmetric:

- a **mismatch** refuses the selection. It is recorded as evidence and is not a
  retry: `ADR-0009` D8 P4 and issue #26 both say a failure to reproduce is a
  build failure, and re-running until the digests agree is how a real
  non-determinism becomes an occasional mystery instead of a finding;
- a **match** decides nothing. It satisfies the measurement C1 asks for, and
  C2-C9, the Fabric provisioning gate and the supply-chain record are exactly
  where they were. `SelectionVerdict.NOT_DECIDED` is the only honest value, and
  there is no `SELECTED` member for a caller to reach for.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum

from .evaluation import EvaluationRecord


class SelectionVerdict(Enum):
    """What the comparison did to the builder selection.

    There is no `SELECTED`. A selection is an ADR (`ADR-0009` D8 P7), never the
    output of a comparison.
    """

    NOT_DECIDED = "not_decided"
    REFUSED = "refused"


class Refusal(Enum):
    NOT_AN_EVALUATION_RECORD = "not_an_evaluation_record"
    NOT_INDEPENDENT = "not_independent"
    DIFFERENT_INPUTS = "different_inputs"
    DIFFERENT_PROFILE = "different_profile"


class ComparisonRefused(Exception):
    """The two records are not a reproduction attempt, so there is no result."""

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclass(frozen=True)
class ReproductionResult:
    """The measured digest pair, and what it did and did not settle."""

    profile_id: str
    build_input_digest: str
    digest_pair: tuple[str, str]
    reproduced: bool
    verdict: SelectionVerdict
    outstanding: tuple[str, ...]

    def evidence(self) -> str:
        """The filed form. A mismatch is kept, not resolved by another attempt."""

        document = asdict(self)
        document["digest_pair"] = list(self.digest_pair)
        document["verdict"] = self.verdict.value
        document["outstanding"] = list(self.outstanding)
        return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


#: What a reproduced pair leaves open. Quoted into every result so that a
#: green comparison cannot be presented on its own as a settled selection.
OUTSTANDING_AFTER_A_REPRODUCTION = (
    "C2-C9 are not established by a digest pair (ADR-0002 D3)",
    "C5, deterministic control of the initramfs, is measured separately and eliminates first",
    "the Fabric provisioning-contract gate is not satisfied by an import (ADR-0009 D8 P5)",
    "the supply-chain consequences of the tool are not recorded (ADR-0002 D4.3)",
    "the selection happens in an ADR, not here (ADR-0009 D8 P7)",
)


def compare(first: EvaluationRecord, second: EvaluationRecord) -> ReproductionResult:
    """Compare two independently produced records, or refuse to."""

    for record in (first, second):
        if record.record_type != "evaluation":
            raise ComparisonRefused(Refusal.NOT_AN_EVALUATION_RECORD, record.record_type)

    if first.build_host_id == second.build_host_id:
        raise ComparisonRefused(
            Refusal.NOT_INDEPENDENT,
            "both records come from one build host; two runs on one machine are "
            "not the two-builder claim (ADR-0002 D1.3)",
        )
    if first.profile_id != second.profile_id:
        raise ComparisonRefused(
            Refusal.DIFFERENT_PROFILE, f"{first.profile_id} vs {second.profile_id}"
        )
    if first.build_input_digest != second.build_input_digest:
        raise ComparisonRefused(
            Refusal.DIFFERENT_INPUTS,
            "the records were built from different input closures, so they say "
            "nothing about reproducibility",
        )

    reproduced = first.unsigned_payload_digest == second.unsigned_payload_digest
    return ReproductionResult(
        profile_id=first.profile_id,
        build_input_digest=first.build_input_digest,
        digest_pair=(first.unsigned_payload_digest, second.unsigned_payload_digest),
        reproduced=reproduced,
        verdict=SelectionVerdict.NOT_DECIDED if reproduced else SelectionVerdict.REFUSED,
        outstanding=OUTSTANDING_AFTER_A_REPRODUCTION if reproduced else (),
    )
