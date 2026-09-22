"""A digest pair is evidence. It is not a decision, and a mismatch is not a retry.

Two properties are worth more than the rest of this file. First, two records
from one host are not compared at all — `ADR-0002` D1.3 says one builder
producing the same digest twice is not the claim, and the cheapest way to make
that claim by accident is to compare two runs and report agreement. Second,
`SelectionVerdict` has no `SELECTED` member, so a caller cannot promote a
reproduced pair into a builder selection; that happens in an ADR
(`ADR-0009` D8 P7) or not at all.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.builder.evaluation import STAMP, EvaluationRecord  # noqa: E402
from tools.builder.reproduction import (  # noqa: E402
    ComparisonRefused,
    Refusal,
    SelectionVerdict,
    compare,
)


def record(
    *,
    host: str = "0123456789abcdef",
    payload_digest: str = "sha256:" + "1" * 64,
    input_digest: str = "sha256:" + "2" * 64,
    profile: str = "responder-eval",
    record_type: str = "evaluation",
) -> EvaluationRecord:
    return EvaluationRecord(
        record_type=record_type,
        record_version=1,
        release_disposition=STAMP,
        profile_id=profile,
        quarantine_policy="quarantine.v1",
        git_revision="0" * 40,
        builder_name="fake-builder",
        builder_version="0.0.0",
        build_input_digest=input_digest,
        source_date_epoch=1735689600,
        unsigned_payload_digest=payload_digest,
        payload_bytes=7,
        build_host_id=host,
        build_time="2026-09-22T00:00:00Z",
    )


def test_two_runs_on_one_host_are_not_a_reproduction() -> None:
    with pytest.raises(ComparisonRefused) as refused:
        compare(record(), record())
    assert refused.value.refusal is Refusal.NOT_INDEPENDENT


def test_records_built_from_different_inputs_are_not_compared() -> None:
    with pytest.raises(ComparisonRefused) as refused:
        compare(
            record(host="a" * 16),
            record(host="b" * 16, input_digest="sha256:" + "3" * 64),
        )
    assert refused.value.refusal is Refusal.DIFFERENT_INPUTS


def test_records_for_different_profiles_are_not_compared() -> None:
    with pytest.raises(ComparisonRefused) as refused:
        compare(record(host="a" * 16), record(host="b" * 16, profile="something-else"))
    assert refused.value.refusal is Refusal.DIFFERENT_PROFILE


def test_a_release_record_is_not_evidence_here() -> None:
    with pytest.raises(ComparisonRefused) as refused:
        compare(record(host="a" * 16), record(host="b" * 16, record_type="release"))
    assert refused.value.refusal is Refusal.NOT_AN_EVALUATION_RECORD


def test_a_mismatch_refuses_the_selection_and_keeps_both_digests() -> None:
    """The pair is reported as measured, whichever way it came out."""

    left = record(host="a" * 16, payload_digest="sha256:" + "1" * 64)
    right = record(host="b" * 16, payload_digest="sha256:" + "9" * 64)
    result = compare(left, right)
    assert result.reproduced is False
    assert result.verdict is SelectionVerdict.REFUSED
    assert result.digest_pair == (left.unsigned_payload_digest, right.unsigned_payload_digest)


def test_a_mismatch_is_filed_as_evidence_rather_than_resolved() -> None:
    result = compare(
        record(host="a" * 16, payload_digest="sha256:" + "1" * 64),
        record(host="b" * 16, payload_digest="sha256:" + "9" * 64),
    )
    filed = json.loads(result.evidence())
    assert filed["reproduced"] is False
    assert filed["verdict"] == "refused"
    assert len(filed["digest_pair"]) == 2


def test_a_match_decides_nothing_and_says_what_is_still_open() -> None:
    result = compare(record(host="a" * 16), record(host="b" * 16))
    assert result.reproduced is True
    assert result.verdict is SelectionVerdict.NOT_DECIDED
    outstanding = " ".join(result.outstanding)
    assert "C5" in outstanding
    assert "Fabric" in outstanding
    assert "ADR" in outstanding


def test_there_is_no_verdict_that_selects_a_builder() -> None:
    """Absent vocabulary, not guarded vocabulary: the value does not exist."""

    assert {member.value for member in SelectionVerdict} == {"not_decided", "refused"}
