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
    REFERENCE_FIELDS,
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
        "package_manifest_ref": "manifests/packages.json",
        "package_manifest_digest": "sha256:" + "2" * 64,
        "firmware_manifest_ref": "manifests/firmware.json",
        "firmware_manifest_digest": "sha256:" + "3" * 64,
        "sbom_ref": "sbom/payload.spdx.json",
        "sbom_digest": "sha256:" + "4" * 64,
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


def test_the_record_carries_references_rather_than_the_manifests_themselves() -> None:
    """ADR-0009 D2, revised: scalars in the record, documents in the artifact."""

    assert len(set(RECORD_FIELDS)) == len(RECORD_FIELDS) == 21
    for name in ("package_manifest", "firmware_manifest", "sbom"):
        assert name not in RECORD_FIELDS
        assert {f"{name}_ref", f"{name}_digest"} <= set(RECORD_FIELDS)


@pytest.mark.parametrize("name", REFERENCE_FIELDS)
@pytest.mark.parametrize(
    "reference",
    [
        "https://example.invalid/packages.json",
        "http://example.invalid/x",
        "/etc/passwd",
        "../outside/packages.json",
        "manifests/../../outside.json",
        "manifests/./packages.json",
        "..",
        "manifests\\packages.json",
        "manifests//packages.json",
    ],
)
def test_a_reference_that_can_leave_the_artifact_is_refused(name, reference) -> None:
    """A record that can name something outside itself is a fetch instruction."""

    with pytest.raises(RecordRefused) as refused:
        parse(a_record(**{name: reference}))
    assert refused.value.refusal is Refusal.REFERENCE_ESCAPES_THE_ARTIFACT


@pytest.mark.parametrize("name", REFERENCE_FIELDS)
def test_an_empty_reference_is_refused_as_an_empty_field(name) -> None:
    """A reference to nothing is a missing fact, not an escaping one."""

    with pytest.raises(RecordRefused) as refused:
        parse(a_record(**{name: ""}))
    assert refused.value.refusal is Refusal.EMPTY_FIELD


@pytest.mark.parametrize(
    "reference", ["packages.json", "manifests/packages.json", "a/b/c/d.spdx.json"]
)
def test_a_normalised_relative_reference_inside_the_artifact_parses(reference) -> None:
    assert parse(a_record(sbom_ref=reference))["sbom_ref"] == reference


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
    assert result.record_fingerprint == parse(signed_record()).fingerprint()
    assert result.is_about(parse(signed_record()), DIGEST) is True
    assert result.is_about(parse(signed_record()), "sha256:" + "0" * 64) is False
    other = a_record(unsigned_payload_digest="sha256:" + "f" * 64)
    assert result.is_about(parse(other), DIGEST) is False


def test_a_verification_is_about_the_whole_record_not_just_the_payload() -> None:
    """Two records sharing a payload digest are not interchangeable.

    The record is "the only thing a later reader has": a different
    `compatibility_claim`, `quarantine_policy_version` or `git_revision` is a
    different set of facts travelling with the same bytes.
    """

    signed = parse(signed_record())
    result = verify(signed, DIGEST, signature_verifier=lambda _r, _s: True)
    for field, value in (
        ("compatibility_claim", "hardware_verified"),
        ("quarantine_policy_version", "quarantine.v0"),
        ("git_revision", "b" * 40),
    ):
        impostor = parse({**signed.fields, field: value})
        assert impostor.unsigned_payload_digest == signed.unsigned_payload_digest
        assert result.is_about(impostor, DIGEST) is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (False, Refusal.NOT_A_SCALAR),
        (0, Refusal.EMPTY_FIELD),
        (1, Refusal.EMPTY_FIELD),
        ([], Refusal.NOT_A_SCALAR),
        ({}, Refusal.NOT_A_SCALAR),
    ],
)
def test_a_signature_that_is_not_a_string_is_refused(value, expected) -> None:
    """`str(False)` is not blank, so a looser check let all of these read as signed."""

    with pytest.raises(RecordRefused) as refused:
        parse(a_record(signature=value, signed_artifact_digest="sha256:" + "8" * 64))
    assert refused.value.refusal is expected


def test_a_boolean_is_not_an_integer_here() -> None:
    """`bool` subclasses `int`, so a record saying `source_date_epoch: true`
    would otherwise parse as a number."""

    with pytest.raises(RecordRefused) as refused:
        parse(a_record(source_date_epoch=True))
    assert refused.value.refusal is Refusal.NOT_A_SCALAR


def test_a_field_that_is_not_a_scalar_is_refused() -> None:
    """`fingerprint()` must be total: an unserialisable value used to escape as
    a bare `TypeError`, past the one `except` this package's refusals exist for."""

    with pytest.raises(RecordRefused) as refused:
        parse(a_record(package_manifest_digest={"a", "b"}))
    assert refused.value.refusal is Refusal.NOT_A_SCALAR


def test_a_record_cannot_be_edited_after_it_is_parsed() -> None:
    """A review mutated a record after a verification had been bound to it."""

    record = parse(a_record())
    with pytest.raises(TypeError):
        record.fields["compatibility_claim"] = "hardware_verified"  # type: ignore[index]


def test_every_refusal_in_these_modules_shares_one_base() -> None:
    """A caller that means "do not write unless everything is in order" needs one except."""

    from azazel_boot.media import SelectionRefused
    from azazel_boot.refusals import Refused
    from azazel_boot.writer import WriteRefused

    for kind in (RecordRefused, SelectionRefused, WriteRefused):
        assert issubclass(kind, Refused)


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
