"""The artifact record, and what it takes for an artifact to pass `verify`.

`docs/builder-writer-contract.md` section 3 fixes eighteen fields. This module
parses them, refuses a record that is not exactly that shape, and answers one
question about a file: may it be written to a medium?

Two decisions here are stricter than they look, and both are deliberate.

**Verification is injected, and the default verifier refuses.** Boot signs
nothing and verifies nothing today: there is no key, no role and no signed
artifact (`docs/release-policy.md` section 1), and Ed25519 is not in the
standard library this bootstrap is limited to. A Boot that has not been given a
verifier therefore verifies nothing — a build that forgot to wire signing ends
up unable to write, rather than writing something nobody checked. This mirrors
`lite_cache`, where the default admits nothing for the same reason.

**A digest match is not enough to write.** `VerificationOutcome` distinguishes a
record whose digest matched from one whose signature also verified, and only the
second may reach `write`. A digest proves the file matches its own record; it
proves nothing about who produced that record. Since no signing exists yet, the
practical consequence is that **nothing can currently be written**, which is the
accurate state of this product rather than a limitation to work around.

An evaluation build (`ADR-0009` D8.1) is not a release artifact and does not
parse as one: its record has no signature field to verify, so it cannot become
something `write` accepts by being renamed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from .refusals import Refused

#: The eighteen fields of `docs/builder-writer-contract.md` section 3, in the
#: order that document lists them. A record is this set exactly: a missing field
#: is a fact that is gone, and an extra one is a claim nobody agreed to carry.
RECORD_FIELDS = (
    "image_version",
    "git_revision",
    "builder_version",
    "debian_snapshot",
    "package_manifest",
    "firmware_manifest",
    "sbom",
    "source_date_epoch",
    "build_input_digest",
    "partition_layout_digest",
    "root_filesystem_digest",
    "boot_chain_identity",
    "unsigned_payload_digest",
    "signed_artifact_digest",
    "signature",
    "build_time",
    "compatibility_claim",
    "quarantine_policy_version",
)

#: Fields that may be absent because the thing they describe may not exist yet.
#: Everything else is required (contract section 3: "a field absent from it is a
#: fact that is gone").
OPTIONAL_FIELDS = ("signed_artifact_digest", "signature")

#: Contract section 3.2. There is no third value, and none is inferred.
COMPATIBILITY_CLAIMS = ("candidate", "hardware_verified")


class Refusal(Enum):
    NOT_AN_OBJECT = "not_an_object"
    UNKNOWN_FIELD = "unknown_field"
    MISSING_FIELD = "missing_field"
    EMPTY_FIELD = "empty_field"
    UNKNOWN_COMPATIBILITY_CLAIM = "unknown_compatibility_claim"
    SIGNATURE_WITHOUT_SUBJECT = "signature_without_subject"


class RecordRefused(Refused):
    """The document is not an artifact record. There is no partial record."""

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


class VerificationOutcome(Enum):
    """What was established about an artifact.

    `write` accepts `SIGNATURE_VERIFIED` and nothing else. `DIGEST_ONLY` is a
    real result — the file matches its record — and it is not an authorisation:
    an unsigned record says nothing about who wrote it.
    """

    SIGNATURE_VERIFIED = "signature_verified"
    DIGEST_ONLY = "digest_only"
    REFUSED = "refused"


class VerificationRefusal(Enum):
    DIGEST_MISMATCH = "digest_mismatch"
    UNSIGNED = "unsigned"
    NO_VERIFIER = "no_verifier"
    SIGNATURE_INVALID = "signature_invalid"


@dataclass(frozen=True)
class ArtifactRecord:
    """One build's record, parsed. Field access is by name, never by position."""

    fields: dict[str, object]

    def __getitem__(self, name: str) -> object:
        return self.fields[name]

    def fingerprint(self) -> str:
        """A digest over the **whole** record, canonically serialised.

        An adversarial review bound a verification to the payload digest alone
        and then attached a different record — unsigned, claiming
        `hardware_verified`, naming another quarantine policy — to a write whose
        bytes were honest. The record is "the only thing a later reader has",
        so what a verification is about has to be all eighteen fields.
        """

        canonical = json.dumps(
            self.fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()

    @property
    def unsigned_payload_digest(self) -> str:
        return str(self.fields["unsigned_payload_digest"])

    @property
    def compatibility_claim(self) -> str:
        return str(self.fields["compatibility_claim"])

    @property
    def is_signed(self) -> bool:
        """A signature is a non-empty string. `False`, `0`, `[]` and `{}` are not.

        The first version asked whether the field was `not None`, so any falsy
        non-null value read as signed and reached the verifier as `str(value)`.
        """

        signature = self.fields.get("signature")
        return isinstance(signature, str) and bool(signature.strip())


@dataclass(frozen=True)
class Verification:
    """The answer, the reason when the answer is no, and **what it is about**.

    An adversarial review found the first version of this type carried only an
    outcome. A caller could then pair a verified artifact's `Verification` with
    a different record and a different file, and the writer — which checked only
    "some verification succeeded" — would write the unverified image and label
    the medium valid. So the answer now names its subject, and the writer
    compares both digests against what it is actually about to write.
    """

    outcome: VerificationOutcome
    #: The digest measured over the artifact that was checked.
    measured_digest: str
    #: A digest over every field of the record that was checked.
    record_fingerprint: str
    refusal: VerificationRefusal | None = None

    @property
    def may_be_written(self) -> bool:
        """Only a verified signature authorises a destructive write."""

        return self.outcome is VerificationOutcome.SIGNATURE_VERIFIED

    def is_about(self, record: ArtifactRecord, measured_digest: str) -> bool:
        """Whether this answer is about *this* record and *these* bytes."""

        return (
            self.record_fingerprint == record.fingerprint()
            and self.measured_digest == measured_digest
        )


#: A signature verifier: (record, signature) -> bool. There is no default
#: implementation; `verify` without one refuses.
SignatureVerifier = Callable[[ArtifactRecord, str], bool]


def parse(document: object) -> ArtifactRecord:
    """Parse a record, or refuse with the first cause found."""

    if not isinstance(document, dict):
        raise RecordRefused(Refusal.NOT_AN_OBJECT, type(document).__name__)

    unknown = sorted(set(document) - set(RECORD_FIELDS))
    if unknown:
        raise RecordRefused(Refusal.UNKNOWN_FIELD, _bounded(str(unknown)))

    for name in RECORD_FIELDS:
        if name in OPTIONAL_FIELDS:
            # Absent is a valid value here. Present and not a non-empty string
            # is not: an empty signature — or `false`, or `0`, or `[]` — would
            # otherwise read as signed, which is the one place where a
            # malformed record decides whether a medium may be written.
            present = document.get(name)
            if present is not None and not (isinstance(present, str) and present.strip()):
                raise RecordRefused(Refusal.EMPTY_FIELD, name)
            continue
        if name not in document:
            raise RecordRefused(Refusal.MISSING_FIELD, name)
        value = document[name]
        if value is None or (isinstance(value, str) and not value.strip()):
            raise RecordRefused(Refusal.EMPTY_FIELD, name)

    claim = document["compatibility_claim"]
    if claim not in COMPATIBILITY_CLAIMS:
        raise RecordRefused(Refusal.UNKNOWN_COMPATIBILITY_CLAIM, _bounded(repr(claim)))

    if document.get("signature") is not None and document.get("signed_artifact_digest") is None:
        raise RecordRefused(
            Refusal.SIGNATURE_WITHOUT_SUBJECT,
            "a signature attests a subject digest; without one there is nothing "
            "it attests to",
        )

    return ArtifactRecord(fields=dict(document))


def parse_json(text: str) -> ArtifactRecord:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise RecordRefused(Refusal.NOT_AN_OBJECT, str(error)) from None
    return parse(document)


def verify(
    record: ArtifactRecord,
    measured_digest: str,
    *,
    signature_verifier: SignatureVerifier | None = None,
) -> Verification:
    """Check a measured artifact against its record.

    `measured_digest` is taken over the artifact's own bytes by the caller. This
    module opens no file: what it is given is what it judges.
    """

    about = {
        "measured_digest": measured_digest,
        "record_fingerprint": record.fingerprint(),
    }
    if measured_digest != record.unsigned_payload_digest:
        return Verification(
            VerificationOutcome.REFUSED, refusal=VerificationRefusal.DIGEST_MISMATCH, **about
        )
    if not record.is_signed:
        return Verification(
            VerificationOutcome.DIGEST_ONLY, refusal=VerificationRefusal.UNSIGNED, **about
        )
    if signature_verifier is None:
        return Verification(
            VerificationOutcome.DIGEST_ONLY, refusal=VerificationRefusal.NO_VERIFIER, **about
        )
    if not signature_verifier(record, str(record["signature"])):
        return Verification(
            VerificationOutcome.REFUSED,
            refusal=VerificationRefusal.SIGNATURE_INVALID,
            **about,
        )
    return Verification(VerificationOutcome.SIGNATURE_VERIFIED, **about)


def _bounded(value: str, limit: int = 120) -> str:
    """Keep an untrusted value from becoming an unbounded log line."""

    return value if len(value) <= limit else value[:limit] + "...(truncated)"
