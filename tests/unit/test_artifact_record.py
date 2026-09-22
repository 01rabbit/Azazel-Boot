"""An artifact record is the whole record, and a digest match is not permission.

The contract calls the record "the only thing a later reader has", so this
module refuses a document that is not exactly the agreed eighteen fields:
a missing one is a fact that is gone, and an extra one is a claim nobody agreed
to carry.

`test_an_unsigned_artifact_is_never_writable` is the test to argue with if this
design is wrong. Boot has no signing key, so it makes every real artifact
unwritable today. That is the state of the product — `docs/release-policy.md`
section 1 lists the key, the role and the signed artifact as things that do not
exist — and a writer that accepted a digest-only artifact would be trusting a
record whose author nobody checked.
"""

from __future__ import annotations

import json

import pytest

from azazel_boot.artifact import (
    COMPATIBILITY_CLAIMS,
    OPTIONAL_FIELDS,
    RECORD_FIELDS,
    RecordRefused,
    Refusal,
    VerificationOutcome,
    VerificationRefusal,
    parse,
    parse_json,
    verify,
)

DIGEST = "sha256:" + "1" * 64


def a_record(**overrides) -> dict:
    document = {
        "image_version": "0.0.0",
        "git_revision": "0" * 40,
        "builder_version": "0.0.0",
        "debian_snapshot": "snapshot:20260101T000000Z",
        "package_manifest": "sha256:" + "2" * 64,
        "firmware_manifest": "sha256:" + "3" * 64,
        "sbom": "sha256:" + "4" * 64,
        "source_date_epoch": 1735689600,
        "build_input_digest": "sha256:" + "5" * 64,
        "partition_layout_digest": "sha256:" + "6" * 64,
        "root_filesystem_digest": "sha256:" + "7" * 64,
        "boot_chain_identity": "shim+grub+linux-image-6.12",
        "unsigned_payload_digest": DIGEST,
        "signed_artifact_digest": None,
        "signature": None,
        "build_time": "2026-09-22T00:00:00Z",
        "compatibility_claim": "candidate",
        "quarantine_policy_version": "quarantine.v1",
    }
    document.update(overrides)
    return {name: value for name, value in document.items() if value is not ...}


def signed_record(**overrides) -> dict:
    return a_record(
        signed_artifact_digest="sha256:" + "8" * 64, signature="sig", **overrides
    )


def test_the_record_is_the_eighteen_fields_of_the_contract() -> None:
    assert len(RECORD_FIELDS) == 18
    assert len(set(RECORD_FIELDS)) == 18


def test_a_complete_record_parses() -> None:
    record = parse(a_record())
    assert record.unsigned_payload_digest == DIGEST
    assert record.is_signed is False


@pytest.mark.parametrize(
    "name", [name for name in RECORD_FIELDS if name not in OPTIONAL_FIELDS]
)
def test_a_missing_field_is_refused(name: str) -> None:
    document = a_record()
    del document[name]
    with pytest.raises(RecordRefused) as refused:
        parse(document)
    assert refused.value.refusal is Refusal.MISSING_FIELD
    assert refused.value.detail == name


def test_an_unknown_field_is_refused() -> None:
    """A record does not grow a field by being written with one."""

    with pytest.raises(RecordRefused) as refused:
        parse(a_record(release_channel="stable"))
    assert refused.value.refusal is Refusal.UNKNOWN_FIELD


@pytest.mark.parametrize("value", ["", "   ", None])
def test_an_empty_required_field_is_refused(value) -> None:
    with pytest.raises(RecordRefused) as refused:
        parse(a_record(boot_chain_identity=value))
    assert refused.value.refusal in {Refusal.EMPTY_FIELD, Refusal.MISSING_FIELD}


@pytest.mark.parametrize(
    "claim", ["verified", "supported", "hardware-verified", "HARDWARE_VERIFIED", "", None]
)
def test_a_compatibility_claim_outside_the_two_values_is_refused(claim) -> None:
    """Contract section 3.2: there is no third value, and none is inferred."""

    with pytest.raises(RecordRefused) as refused:
        parse(a_record(compatibility_claim=claim))
    assert refused.value.refusal in {
        Refusal.UNKNOWN_COMPATIBILITY_CLAIM,
        Refusal.EMPTY_FIELD,
    }


@pytest.mark.parametrize("claim", COMPATIBILITY_CLAIMS)
def test_both_agreed_compatibility_claims_parse(claim: str) -> None:
    assert parse(a_record(compatibility_claim=claim)).compatibility_claim == claim


def test_an_unsigned_record_is_valid_because_nothing_is_signed_yet() -> None:
    """Contract section 3: absent is a valid value for the signing fields."""

    record = parse(a_record())
    assert record.is_signed is False


def test_a_signature_without_a_subject_digest_is_refused() -> None:
    with pytest.raises(RecordRefused) as refused:
        parse(a_record(signature="sig"))
    assert refused.value.refusal is Refusal.SIGNATURE_WITHOUT_SUBJECT


def test_a_document_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(RecordRefused) as refused:
        parse(["not", "a", "record"])
    assert refused.value.refusal is Refusal.NOT_AN_OBJECT
    with pytest.raises(RecordRefused):
        parse_json("{oops")


def test_a_digest_mismatch_refuses() -> None:
    result = verify(parse(a_record()), "sha256:" + "9" * 64)
    assert result.outcome is VerificationOutcome.REFUSED
    assert result.refusal is VerificationRefusal.DIGEST_MISMATCH
    assert result.may_be_written is False


def test_an_unsigned_artifact_is_never_writable() -> None:
    """A digest proves the file matches its record, not who wrote the record."""

    result = verify(parse(a_record()), DIGEST)
    assert result.outcome is VerificationOutcome.DIGEST_ONLY
    assert result.refusal is VerificationRefusal.UNSIGNED
    assert result.may_be_written is False


def test_a_signed_artifact_without_a_verifier_is_not_writable() -> None:
    """The default verifies nothing, so a forgotten wiring cannot write."""

    result = verify(parse(signed_record()), DIGEST)
    assert result.outcome is VerificationOutcome.DIGEST_ONLY
    assert result.refusal is VerificationRefusal.NO_VERIFIER
    assert result.may_be_written is False


def test_a_signature_the_verifier_rejects_refuses() -> None:
    result = verify(parse(signed_record()), DIGEST, signature_verifier=lambda _r, _s: False)
    assert result.outcome is VerificationOutcome.REFUSED
    assert result.refusal is VerificationRefusal.SIGNATURE_INVALID


def test_only_a_verified_signature_authorises_a_write() -> None:
    result = verify(parse(signed_record()), DIGEST, signature_verifier=lambda _r, _s: True)
    assert result.outcome is VerificationOutcome.SIGNATURE_VERIFIED
    assert result.may_be_written is True


@pytest.mark.parametrize("name", OPTIONAL_FIELDS)
@pytest.mark.parametrize("value", ["", "   "])
def test_a_present_but_empty_optional_field_is_refused(name: str, value: str) -> None:
    """Absent is valid; present and empty is a truncated record reading as signed."""

    with pytest.raises(RecordRefused) as refused:
        parse(a_record(**{name: value}))
    assert refused.value.refusal is Refusal.EMPTY_FIELD


def test_an_empty_signature_does_not_read_as_signed() -> None:
    with pytest.raises(RecordRefused):
        parse(a_record(signature="", signed_artifact_digest="sha256:" + "8" * 64))


def test_a_verification_names_the_record_and_the_bytes_it_is_about() -> None:
    """A verification that named nothing authorised writing a different artifact."""

    result = verify(parse(signed_record()), DIGEST, signature_verifier=lambda _r, _s: True)
    assert result.measured_digest == DIGEST
    assert result.record_digest == DIGEST
    assert result.is_about(parse(signed_record()), DIGEST) is True
    assert result.is_about(parse(signed_record()), "sha256:" + "0" * 64) is False
    other = a_record(unsigned_payload_digest="sha256:" + "f" * 64)
    assert result.is_about(parse(other), DIGEST) is False


def test_an_evaluation_record_does_not_parse_as_a_release_record() -> None:
    """ADR-0009 D8.1: an evaluation build cannot become writable by renaming."""

    evaluation = {
        "record_type": "evaluation",
        "release_disposition": "NON-RELEASABLE / EVALUATION ONLY",
        "unsigned_payload_digest": DIGEST,
    }
    with pytest.raises(RecordRefused) as refused:
        parse_json(json.dumps(evaluation))
    assert refused.value.refusal is Refusal.UNKNOWN_FIELD
