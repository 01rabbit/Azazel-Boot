"""The safety boundary around a destructive write, and nothing else.

This module decides. It opens no device, runs no command, and mounts nothing:
unmounting, raw writing and reading back are injected ports, so the decision
logic can be exercised in full without a block device anywhere near it. Where
the real ports will live is the write service (`docs/builder-writer-contract.md`
section 8) — the only component that opens a block device for writing.

Three shapes carry most of the safety:

**Two confirmations are two types.** `plan` produces a `Planned`,
`confirm_target` a `TargetConfirmed`, `confirm_destruction` an `Authorised`, and
`execute` takes only an `Authorised`. A caller cannot skip a confirmation by
passing a flag, because there is no flag — there is a value it does not have.

**The device is re-checked after the operator chose it.** Removability,
capacity, partition table and stable identity are read again at write time and
compared with the enumeration the code was issued against. A mismatch is a
refusal, not a warning: substitution between listing and writing is the attack
and the accident this check exists for, and a prompt at that moment is a prompt
someone confirms.

**A medium that fails its read-back is never labelled valid.** There is no
outcome meaning "written" on its own. `WRITTEN_AND_VERIFIED` requires the
read-back digest to match the record; anything else is `VERIFICATION_FAILED`,
and `inspect` reports the mismatch rather than the record.

Persistence is not here. Creating encrypted persistence is a separate explicit
operation on the USB medium only (contract section 7.5), and nothing in this
module can start it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .artifact import ArtifactRecord, Verification
from .media import Eligibility, MediaCandidate, assess

#: The operator types this, exactly, to authorise the destruction. It is a
#: sentence rather than "y" because the act is not reversible.
DESTRUCTIVE_CONFIRMATION = "ERASE THIS MEDIUM"

#: Attributes re-read before the write and compared with the enumeration.
REVERIFIED_ATTRIBUTES = ("identity", "removable", "capacity_bytes", "partition_table")


class Refusal(Enum):
    ARTIFACT_NOT_VERIFIED = "artifact_not_verified"
    TARGET_CODE_MISMATCH = "target_code_mismatch"
    DESTRUCTION_NOT_CONFIRMED = "destruction_not_confirmed"
    TARGET_DISAPPEARED = "target_disappeared"
    TARGET_SUBSTITUTED = "target_substituted"
    NOW_INELIGIBLE = "now_ineligible"
    UNMOUNT_FAILED = "unmount_failed"


class WriteRefused(Exception):
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
    """Re-reads a device's attributes at write time."""

    def reread(self, identity: str) -> MediaCandidate | None: ...


class Unmounter(Protocol):
    def unmount(self, identity: str) -> bool: ...


class RawWriter(Protocol):
    """Writes the artifact to the device. The only thing here that destroys data."""

    def write(self, identity: str, artifact_path: str) -> int: ...


class MediumReader(Protocol):
    """Reads the medium back and returns a digest over `length` bytes."""

    def digest(self, identity: str, length: int) -> str | None: ...


@dataclass(frozen=True)
class Planned:
    """An artifact and a target, neither confirmed by anyone yet."""

    target_code: str
    enumerated: MediaCandidate
    record: ArtifactRecord
    artifact_path: str
    artifact_bytes: int


@dataclass(frozen=True)
class TargetConfirmed:
    """The operator typed the target code back."""

    plan: Planned


@dataclass(frozen=True)
class Authorised:
    """The operator confirmed the destruction, separately."""

    confirmed: TargetConfirmed


@dataclass(frozen=True)
class WriteResult:
    """The outcome, and whether this medium may be described as a Boot medium."""

    outcome: WriteOutcome
    target_code: str
    expected_digest: str
    measured_digest: str | None

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


def plan(
    *,
    target_code: str,
    enumerated: MediaCandidate,
    record: ArtifactRecord,
    verification: Verification,
    artifact_path: str,
    artifact_bytes: int,
) -> Planned:
    """Refuse an unverified artifact before an operator is asked anything."""

    if not verification.may_be_written:
        raise WriteRefused(
            Refusal.ARTIFACT_NOT_VERIFIED,
            f"verification outcome is {verification.outcome.value}; writing an "
            "artifact nobody verified makes it indistinguishable from one that was",
        )
    return Planned(
        target_code=target_code,
        enumerated=enumerated,
        record=record,
        artifact_path=artifact_path,
        artifact_bytes=artifact_bytes,
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


def execute(
    authorised: Authorised,
    *,
    probe: DeviceProbe,
    unmounter: Unmounter,
    raw_writer: RawWriter,
    reader: MediumReader,
) -> WriteResult:
    """Re-verify, unmount, write, read back. Refuses before writing, never after."""

    planned = authorised.confirmed.plan
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
    measured = reader.digest(current.identity, written)
    expected = planned.record.unsigned_payload_digest
    outcome = (
        WriteOutcome.WRITTEN_AND_VERIFIED
        if measured == expected
        else WriteOutcome.VERIFICATION_FAILED
    )
    return WriteResult(
        outcome=outcome,
        target_code=planned.target_code,
        expected_digest=expected,
        measured_digest=measured,
    )


def inspect(
    *,
    identity: str,
    record: ArtifactRecord,
    length: int,
    reader: MediumReader,
) -> Inspection:
    """Report what a medium contains, matched against a record."""

    measured = reader.digest(identity, length)
    expected = record.unsigned_payload_digest
    return Inspection(
        matches=measured == expected, expected_digest=expected, measured_digest=measured
    )
