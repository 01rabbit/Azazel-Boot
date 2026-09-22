"""The safety boundary around a destructive write, and nothing else.

This module decides. It opens no device and no file: unmounting, raw writing,
reading a medium back and measuring an artifact are injected ports, so the
decision logic can be exercised in full without a block device anywhere near it.
Where the real ports will live is the write service
(`docs/builder-writer-contract.md` section 8) — the only component that opens a
block device for writing.

Two rounds of adversarial review shaped what is here, and each round found the
previous version's safety to be a story rather than an enforcement:

**An authorisation is an object the authority issued, not a value a caller
holds.** The first version let `execute` trust any `Authorised` it was handed.
The second minted a nonce — and a nonce is a bearer token, so one
`dataclasses.replace` carried it onto a `Planned` naming a different artifact
and a different device, with the same result: an unverified image on the medium,
reported valid. So there is no token at all now. The authority keeps the
`Planned` objects it issued and `execute` checks **object identity**, which
nothing a caller constructs can satisfy. An authorisation is removed from that
set the moment `execute` accepts it, so neither a success nor a refusal leaves
it usable again.

**A verification names its subject — the whole record.** The first version
passed the record, the `Verification` and the path as three unrelated arguments.
The second bound the verification to the payload digest, which left the other
seventeen fields free: a review attached an unsigned record claiming
`hardware_verified` to a write whose bytes were honest. The binding is now a
digest over every field.

**Re-verification compares what an operator actually chose by.** Comparing the
identity a probe was queried with against the identity it returned is `x != x`
for any honest probe. The attributes an operator physically identifies the
object by — the bus position and the label — are compared too, so a device that
moved ports or lost its tag between listing and write stops the write.

A medium that fails its read-back is never labelled valid. There is no outcome
meaning "written" on its own.

Persistence is not here. Creating encrypted persistence is a separate explicit
operation on the USB medium only (contract section 7.5), and nothing in this
module can start it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .artifact import ArtifactRecord, Verification
from .media import DeviceIdentity, Eligibility, MediaCandidate, MediaSession, assess
from .refusals import Refused

#: The operator types this, exactly, to authorise the destruction. It is a
#: sentence rather than "y" because the act is not reversible.
DESTRUCTIVE_CONFIRMATION = "ERASE THIS MEDIUM"

#: Attributes re-read before the write and compared with the enumeration.
#: `bus_path` and `physical_label` are here because they are what the operator
#: used to pick the object in front of them; comparing only machine attributes
#: would accept a different stick of the same model in a different port.
REVERIFIED_ATTRIBUTES = (
    "identity",
    "removable",
    "capacity_bytes",
    "partition_table",
    "bus_path",
    "physical_label",
)


class Refusal(Enum):
    ARTIFACT_NOT_VERIFIED = "artifact_not_verified"
    VERIFICATION_IS_ABOUT_SOMETHING_ELSE = "verification_is_about_something_else"
    TARGET_NOT_ELIGIBLE = "target_not_eligible"
    TARGET_CODE_MISMATCH = "target_code_mismatch"
    DESTRUCTION_NOT_CONFIRMED = "destruction_not_confirmed"
    AUTHORISATION_NOT_ISSUED = "authorisation_not_issued"
    AUTHORISATION_ALREADY_SPENT = "authorisation_already_spent"
    TARGET_DISAPPEARED = "target_disappeared"
    TARGET_SUBSTITUTED = "target_substituted"
    NOW_INELIGIBLE = "now_ineligible"
    UNMOUNT_FAILED = "unmount_failed"


class WriteRefused(Refused):
    """Nothing was written. Every refusal in this module happens before any write."""

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


class WriteOutcome(Enum):
    """What happened. There is no value meaning "written but unchecked".

    A medium whose read-back did not match the record is not a Boot medium, and
    a word that sounded like success would eventually be read as one.
    """

    WRITTEN_AND_VERIFIED = "written_and_verified"
    VERIFICATION_FAILED = "verification_failed"


class DeviceProbe(Protocol):
    """Re-reads a device's attributes at write time.

    The contract a real implementation must meet: `reread(identity)` resolves
    the **same object** `RawWriter.write(identity)` will open, or returns None.
    This module cannot check that, and says so rather than implying otherwise.
    """

    def reread(self, identity: DeviceIdentity) -> MediaCandidate | None: ...


class Unmounter(Protocol):
    def unmount(self, identity: DeviceIdentity) -> bool: ...


class RawWriter(Protocol):
    """Writes the artifact to the device. The only thing here that destroys data."""

    def write(self, identity: DeviceIdentity, artifact_path: str) -> int: ...


class MediumReader(Protocol):
    """Reads the medium back and returns a digest over `length` bytes."""

    def digest(self, identity: DeviceIdentity, length: int) -> str | None: ...


class ArtifactReader(Protocol):
    """Measures the artifact file: its digest and its length."""

    def measure(self, artifact_path: str) -> tuple[str, int]: ...


@dataclass(frozen=True, repr=False)
class Planned:
    """An artifact and a target, neither confirmed by anyone yet.

    What makes this the authority's issue is the object itself: the authority
    keeps the ones it made, and `execute` compares by identity. There is
    deliberately no token field — a token can be copied onto another object,
    and a review did exactly that.
    """

    target_code: str
    enumerated: MediaCandidate
    record: ArtifactRecord
    artifact_path: str
    artifact_bytes: int
    artifact_digest: str

    def __repr__(self) -> str:
        """Redacted: the enumerated device's identity and the host path stay out."""

        return (
            f"Planned(target_code={self.target_code!r}, "
            f"enumerated={self.enumerated!r}, artifact_path=<redacted>, "
            f"artifact_bytes={self.artifact_bytes})"
        )


@dataclass(frozen=True, repr=False)
class TargetConfirmed:
    """The operator typed the target code back."""

    plan: Planned

    def __repr__(self) -> str:
        return f"TargetConfirmed(target_code={self.plan.target_code!r})"


@dataclass(frozen=True, repr=False)
class Authorised:
    """The operator confirmed the destruction, separately."""

    confirmed: TargetConfirmed

    def __repr__(self) -> str:
        return f"Authorised(target_code={self.confirmed.plan.target_code!r})"


@dataclass(frozen=True)
class WriteResult:
    """The outcome, and whether this medium may be described as a Boot medium."""

    outcome: WriteOutcome
    target_code: str
    expected_digest: str
    measured_digest: str | None
    expected_bytes: int
    written_bytes: int

    @property
    def medium_is_valid(self) -> bool:
        return self.outcome is WriteOutcome.WRITTEN_AND_VERIFIED


@dataclass(frozen=True)
class Inspection:
    """What a medium turned out to contain."""

    matches: bool
    expected_digest: str
    measured_digest: str | None

    @property
    def describes_the_record(self) -> bool:
        """A mismatched medium is reported as a mismatch, never as the record."""

        return self.matches


class WriteAuthority:
    """Issues authorisations, and is the only thing `execute` will accept them from.

    It holds the enumeration session, so a target comes from `list-media` by
    construction rather than by a caller remembering to claim it.
    """

    def __init__(self, session: MediaSession, *, artifact_reader: ArtifactReader) -> None:
        self._session = session
        self._artifact_reader = artifact_reader
        #: The `Planned` objects this authority made. Membership is tested by
        #: identity, never by equality: `__eq__` is generated over the fields,
        #: and a caller who controls the fields controls equality.
        self._issued: list[Planned] = []

    def plan(
        self,
        *,
        target_code: str,
        record: ArtifactRecord,
        verification: Verification,
        artifact_path: str,
    ) -> Planned:
        """Claim the target, re-measure the artifact, and refuse before anyone is asked.

        The order matters: everything that can refuse does so before the operator
        is prompted for anything, so a confirmation is never collected for a
        write that was never going to happen.
        """

        if not verification.may_be_written:
            raise WriteRefused(
                Refusal.ARTIFACT_NOT_VERIFIED,
                f"verification outcome is {verification.outcome.value}; writing an "
                "artifact nobody verified makes it indistinguishable from one that was",
            )

        digest, size = self._artifact_reader.measure(artifact_path)
        if not verification.is_about(record, digest):
            raise WriteRefused(
                Refusal.VERIFICATION_IS_ABOUT_SOMETHING_ELSE,
                "the verification was not obtained for this record and these bytes",
            )

        enumerated = self._session.claim(target_code)
        eligibility = assess(enumerated)
        if eligibility is not Eligibility.ELIGIBLE:
            raise WriteRefused(Refusal.TARGET_NOT_ELIGIBLE, eligibility.value)

        planned = Planned(
            target_code=target_code,
            enumerated=enumerated,
            record=record,
            artifact_path=artifact_path,
            artifact_bytes=size,
            artifact_digest=digest,
        )
        self._issued.append(planned)
        return planned

    def execute(
        self,
        authorised: Authorised,
        *,
        probe: DeviceProbe,
        unmounter: Unmounter,
        raw_writer: RawWriter,
        reader: MediumReader,
    ) -> WriteResult:
        """Re-verify, unmount, write, read back. Refuses before writing, never after."""

        planned = authorised.confirmed.plan
        for index, issued in enumerate(self._issued):
            if issued is planned:
                # Spent on entry: a refusal below must not leave an
                # authorisation that succeeds on a retry. A substitution is
                # "refused, not a warning and not a prompt" (contract 7.2), and
                # an authorisation that survives the refusal is a prompt.
                del self._issued[index]
                break
        else:
            raise WriteRefused(
                Refusal.AUTHORISATION_NOT_ISSUED,
                "this authorisation was not issued by this authority; a plan is "
                "made by plan(), never constructed or copied by a caller",
            )

        current = probe.reread(planned.enumerated.identity)
        if current is None:
            raise WriteRefused(
                Refusal.TARGET_DISAPPEARED,
                "the device enumerated for this code is no longer present",
            )

        for attribute in REVERIFIED_ATTRIBUTES:
            if getattr(current, attribute) != getattr(planned.enumerated, attribute):
                raise WriteRefused(
                    Refusal.TARGET_SUBSTITUTED,
                    f"{attribute} changed after enumeration; this is not the device "
                    "the operator confirmed",
                )

        eligibility = assess(current)
        if eligibility is not Eligibility.ELIGIBLE:
            raise WriteRefused(Refusal.NOW_INELIGIBLE, eligibility.value)

        if not unmounter.unmount(current.identity):
            raise WriteRefused(
                Refusal.UNMOUNT_FAILED,
                "the device could not be released; writing under a live mount "
                "corrupts whatever is using it",
            )

        written = raw_writer.write(current.identity, planned.artifact_path)
        # The extent verified is the artifact's own length, measured here, not
        # the number the writer reports about its own work.
        measured = reader.digest(current.identity, planned.artifact_bytes)
        expected = planned.record.unsigned_payload_digest
        verified = measured == expected and written == planned.artifact_bytes
        return WriteResult(
            outcome=(
                WriteOutcome.WRITTEN_AND_VERIFIED if verified else WriteOutcome.VERIFICATION_FAILED
            ),
            target_code=planned.target_code,
            expected_digest=expected,
            measured_digest=measured,
            expected_bytes=planned.artifact_bytes,
            written_bytes=written,
        )


def confirm_target(planned: Planned, typed_code: str) -> TargetConfirmed:
    """The operator retypes the code. Compared exactly; nothing is normalised."""

    if typed_code != planned.target_code:
        raise WriteRefused(Refusal.TARGET_CODE_MISMATCH, "the code typed back did not match")
    return TargetConfirmed(plan=planned)


def confirm_destruction(confirmed: TargetConfirmed, typed_phrase: str) -> Authorised:
    """A second, separate confirmation of the destructive act itself."""

    if typed_phrase != DESTRUCTIVE_CONFIRMATION:
        raise WriteRefused(
            Refusal.DESTRUCTION_NOT_CONFIRMED,
            "the destruction was not confirmed in the required words",
        )
    return Authorised(confirmed=confirmed)


def inspect(
    *,
    candidate: MediaCandidate,
    record: ArtifactRecord,
    length: int,
    reader: MediumReader,
) -> Inspection:
    """Report what a medium contains, matched against a record.

    It takes a candidate from a listing rather than a bare identity string, so
    no device name enters through this door either. It is read-only: threat
    model section 3 permits an operator-initiated read of a host device, and
    this is the only verb that could perform one.
    """

    measured = reader.digest(candidate.identity, length)
    expected = record.unsigned_payload_digest
    return Inspection(
        matches=measured == expected, expected_digest=expected, measured_digest=measured
    )
