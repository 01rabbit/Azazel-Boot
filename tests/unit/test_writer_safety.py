"""The destructive write, exercised in full without a block device in sight.

The ports are file-backed: the "device" is an ordinary file this test wrote, so
a mistake in the code under test destroys a temporary file and nothing else.
**No test here touches a real device, a loop device or `/dev`.**

Several tests below exist because an adversarial review defeated the first
version of this module, and each of those names what it defeated:

- an `Authorised` built by hand reached `execute` and the medium was erased and
  reported valid;
- a `Verification` obtained for one artifact authorised writing a different one;
- a spent target code was reissued by the next listing and resolved to another
  disk;
- the identity re-check compared a value with itself.

Those are the tests to keep if this file is ever cut down.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from azazel_boot import writer as writer_module
from azazel_boot.artifact import Verification, VerificationOutcome, VerificationRefusal, parse
from azazel_boot.artifact import verify as verify_artifact
from azazel_boot.media import DeviceIdentity, MediaCandidate, MediaSession
from azazel_boot.writer import (
    DESTRUCTIVE_CONFIRMATION,
    REVERIFIED_ATTRIBUTES,
    Authorised,
    Planned,
    Refusal,
    TargetConfirmed,
    WriteAuthority,
    WriteOutcome,
    WriteRefused,
    inspect,
)

PAYLOAD = b"an image, for the purposes of this test"
DIGEST = "sha256:" + hashlib.sha256(PAYLOAD).hexdigest()
OTHER = b"a different image entirely"
OTHER_DIGEST = "sha256:" + hashlib.sha256(OTHER).hexdigest()
IDENTITY = DeviceIdentity("stable-identity-1")
IDENTITY_VALUE = "stable-identity-1"


def record(digest: str = DIGEST):
    return parse(
        {
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
            "unsigned_payload_digest": digest,
            "signed_artifact_digest": "sha256:" + "8" * 64,
            "signature": "sig",
            "build_time": "2026-09-22T00:00:00Z",
            "compatibility_claim": "candidate",
            "quarantine_policy_version": "quarantine.v1",
        }
    )


def candidate(**overrides) -> MediaCandidate:
    attributes = {
        "identity": IDENTITY,
        "capacity_bytes": 64 * 1000**3,
        "partition_table": "gpt",
        "bus_path": "usb-0:1.2",
        "physical_label": "blue tag",
        "removable": True,
        "mounted": False,
        "internal": False,
        "holds_running_root": False,
    }
    attributes.update(overrides)
    return MediaCandidate(**attributes)


class Device:
    """A file standing in for a medium. The only thing these tests can destroy."""

    def __init__(self, path: Path, *, truncate_to: int | None = None) -> None:
        self.path = path
        self.path.write_bytes(b"")
        self._truncate_to = truncate_to

    def write(self, identity: DeviceIdentity, artifact_path: str) -> int:
        data = Path(artifact_path).read_bytes()
        if self._truncate_to is not None:
            data = data[: self._truncate_to]
        self.path.write_bytes(data)
        return len(data)

    def digest(self, identity: DeviceIdentity, length: int) -> str | None:
        data = self.path.read_bytes()[:length]
        if not data:
            return None
        return "sha256:" + hashlib.sha256(data).hexdigest()

    @property
    def written(self) -> bytes:
        return self.path.read_bytes()


class Files:
    """The artifact reader port: measures a file the way the real one will."""

    def measure(self, artifact_path: str) -> tuple[str, int]:
        data = Path(artifact_path).read_bytes()
        return "sha256:" + hashlib.sha256(data).hexdigest(), len(data)


class Probe:
    """A probe keyed by identity, the way a real one is."""

    def __init__(self, devices: dict[DeviceIdentity, MediaCandidate] | None = None) -> None:
        self._devices = {IDENTITY: candidate()} if devices is None else devices

    def reread(self, identity: DeviceIdentity) -> MediaCandidate | None:
        return self._devices.get(identity)


class Unmounter:
    def __init__(self, *, succeeds: bool = True) -> None:
        self._succeeds = succeeds

    def unmount(self, identity: DeviceIdentity) -> bool:
        return self._succeeds


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    path = tmp_path / "boot.img"
    path.write_bytes(PAYLOAD)
    return path


def verified_for(rec, path: Path) -> Verification:
    digest, _ = Files().measure(str(path))
    return verify_artifact(rec, digest, signature_verifier=lambda _r, _s: True)


def an_authority(offered: MediaCandidate | None = None) -> tuple[WriteAuthority, str]:
    session = MediaSession("m1")
    offers = session.offer([offered if offered is not None else candidate()])
    return WriteAuthority(session, artifact_reader=Files()), offers[0].target_code


def authorised_write(artifact: Path, authority: WriteAuthority, code: str) -> Authorised:
    rec = record()
    planned = authority.plan(
        target_code=code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    return authority.confirm_destruction(
        authority.confirm_target(planned, code), DESTRUCTIVE_CONFIRMATION
    )


# --- the happy path -------------------------------------------------------


def test_a_verified_signed_artifact_is_written_and_read_back(
    tmp_path: Path, artifact: Path
) -> None:
    authority, code = an_authority()
    device = Device(tmp_path / "device")
    result = authority.execute(
        authorised_write(artifact, authority, code),
        probe=Probe(),
        unmounter=Unmounter(),
        raw_writer=device,
        reader=device,
    )
    assert result.outcome is WriteOutcome.WRITTEN_AND_VERIFIED
    assert result.medium_is_valid is True
    assert device.written == PAYLOAD


# --- an authorisation is issued, not asserted -----------------------------


def test_an_authorisation_built_by_hand_is_refused(tmp_path: Path, artifact: Path) -> None:
    """The first review's finding: one line reached `execute` with nothing checked."""

    authority, _ = an_authority()
    device = Device(tmp_path / "device")
    forged = Authorised(
        confirmed=TargetConfirmed(
            plan=Planned(
                target_code="m1-1-01",
                enumerated=candidate(),
                record=record(),
                artifact_path=str(artifact),
                artifact_bytes=len(PAYLOAD),
                artifact_digest=DIGEST,
                record_fingerprint=record().fingerprint(),
            )
        )
    )
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            forged, probe=Probe(), unmounter=Unmounter(), raw_writer=device, reader=device
        )
    assert refused.value.refusal is Refusal.AUTHORISATION_NOT_ISSUED
    assert device.written == b""


def test_a_copy_of_an_issued_plan_is_refused(tmp_path: Path, artifact: Path) -> None:
    """The second review's finding: a token can be copied onto another object.

    `dataclasses.replace` works on a frozen dataclass, so a plan issued for one
    artifact and one device was retargeted to any other — and the write was
    reported valid. Membership is object identity for exactly this reason.
    """

    other = tmp_path / "evil.img"
    other.write_bytes(OTHER)
    authority, code = an_authority()
    rec = record()
    planned = authority.plan(
        target_code=code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    retargeted = dataclasses.replace(
        planned,
        record=record(OTHER_DIGEST),
        artifact_path=str(other),
        artifact_bytes=len(OTHER),
        artifact_digest=OTHER_DIGEST,
    )
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        authority.confirm_target(retargeted, code)
    assert refused.value.refusal is Refusal.AUTHORISATION_NOT_ISSUED
    assert device.written == b""


def test_an_authorisation_refused_by_execute_is_not_usable_again(
    tmp_path: Path, artifact: Path
) -> None:
    """A substitution is refused, not warned about — and not retryable."""

    authority, code = an_authority()
    authorisation = authorised_write(artifact, authority, code)
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as first:
        authority.execute(
            authorisation,
            probe=Probe(),
            unmounter=Unmounter(succeeds=False),
            raw_writer=device,
            reader=device,
        )
    assert first.value.refusal is Refusal.UNMOUNT_FAILED
    with pytest.raises(WriteRefused) as second:
        authority.execute(
            authorisation,
            probe=Probe(),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert second.value.refusal is Refusal.AUTHORISATION_NOT_ISSUED
    assert device.written == b""


def test_an_authorisation_from_another_authority_is_refused(
    tmp_path: Path, artifact: Path
) -> None:
    mine, _ = an_authority()
    theirs, their_code = an_authority()
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        mine.execute(
            authorised_write(artifact, theirs, their_code),
            probe=Probe(),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.AUTHORISATION_NOT_ISSUED
    assert device.written == b""


def test_an_authorisation_cannot_be_replayed(tmp_path: Path, artifact: Path) -> None:
    """One authorisation, one write."""

    authority, code = an_authority()
    device = Device(tmp_path / "device")
    authorisation = authorised_write(artifact, authority, code)
    authority.execute(
        authorisation, probe=Probe(), unmounter=Unmounter(), raw_writer=device, reader=device
    )
    second = Device(tmp_path / "second")
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            authorisation,
            probe=Probe(),
            unmounter=Unmounter(),
            raw_writer=second,
            reader=second,
        )
    assert refused.value.refusal is Refusal.AUTHORISATION_NOT_ISSUED
    assert second.written == b""


# --- a verification names its subject --------------------------------------


@pytest.mark.parametrize(
    "verification",
    [
        Verification(
            VerificationOutcome.DIGEST_ONLY, DIGEST, DIGEST, VerificationRefusal.UNSIGNED
        ),
        Verification(
            VerificationOutcome.DIGEST_ONLY, DIGEST, DIGEST, VerificationRefusal.NO_VERIFIER
        ),
        Verification(
            VerificationOutcome.REFUSED, "sha256:" + "0" * 64, DIGEST,
            VerificationRefusal.DIGEST_MISMATCH,
        ),
    ],
)
def test_an_artifact_that_did_not_pass_verify_is_refused_before_anything_else(
    artifact: Path, verification: Verification
) -> None:
    authority, code = an_authority()
    with pytest.raises(WriteRefused) as refused:
        authority.plan(
            target_code=code,
            record=record(),
            verification=verification,
            artifact_path=str(artifact),
        )
    assert refused.value.refusal is Refusal.ARTIFACT_NOT_VERIFIED


def test_a_verification_obtained_for_another_artifact_authorises_nothing(
    tmp_path: Path, artifact: Path
) -> None:
    """The review's second finding: the unsigned image was written and called valid."""

    other = tmp_path / "other.img"
    other.write_bytes(OTHER)
    authority, code = an_authority()
    with pytest.raises(WriteRefused) as refused:
        authority.plan(
            target_code=code,
            record=record(OTHER_DIGEST),
            verification=verified_for(record(), artifact),
            artifact_path=str(other),
        )
    assert refused.value.refusal is Refusal.VERIFICATION_IS_ABOUT_SOMETHING_ELSE


def test_a_verification_for_another_record_with_the_same_payload_authorises_nothing(
    artifact: Path,
) -> None:
    """Binding to the payload digest alone leaves seventeen fields free.

    A review attached an unsigned record claiming `hardware_verified` to a write
    whose bytes were honest. The record is what a later reader has.
    """

    signed = record()
    impostor = parse(
        {
            **signed.fields,
            "signature": None,
            "signed_artifact_digest": None,
            "compatibility_claim": "hardware_verified",
            "quarantine_policy_version": "quarantine.v0",
        }
    )
    authority, code = an_authority()
    with pytest.raises(WriteRefused) as refused:
        authority.plan(
            target_code=code,
            record=impostor,
            verification=verified_for(signed, artifact),
            artifact_path=str(artifact),
        )
    assert refused.value.refusal is Refusal.VERIFICATION_IS_ABOUT_SOMETHING_ELSE


def test_a_verification_for_this_record_but_another_file_authorises_nothing(
    tmp_path: Path, artifact: Path
) -> None:
    other = tmp_path / "other.img"
    other.write_bytes(OTHER)
    authority, code = an_authority()
    with pytest.raises(WriteRefused) as refused:
        authority.plan(
            target_code=code,
            record=record(),
            verification=verified_for(record(), artifact),
            artifact_path=str(other),
        )
    assert refused.value.refusal is Refusal.VERIFICATION_IS_ABOUT_SOMETHING_ELSE


# --- the target comes from a listing ---------------------------------------


def test_the_target_is_claimed_from_the_listing_rather_than_asserted(
    artifact: Path,
) -> None:
    authority, code = an_authority()
    rec = record()
    planned = authority.plan(
        target_code=code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    assert planned.enumerated.identity == IDENTITY


def test_a_code_that_was_never_issued_does_not_plan(artifact: Path) -> None:
    from azazel_boot.media import SelectionRefused

    authority, _ = an_authority()
    rec = record()
    with pytest.raises(SelectionRefused):
        authority.plan(
            target_code="m1-9-99",
            record=rec,
            verification=verified_for(rec, artifact),
            artifact_path=str(artifact),
        )


def test_an_ineligible_device_cannot_be_planned_against(artifact: Path) -> None:
    """A session offers no code for one, so this is defence in depth."""

    session = MediaSession("m1")
    session.offer([candidate()])
    authority = WriteAuthority(session, artifact_reader=Files())
    session._offered["m1-1-01"] = candidate(internal=True)  # noqa: SLF001 - forced state
    rec = record()
    with pytest.raises(WriteRefused) as refused:
        authority.plan(
            target_code="m1-1-01",
            record=rec,
            verification=verified_for(rec, artifact),
            artifact_path=str(artifact),
        )
    assert refused.value.refusal is Refusal.TARGET_NOT_ELIGIBLE


# --- the two confirmations -------------------------------------------------


@pytest.mark.parametrize("typed", ["m1-1-02", "M1-1-01", "m1-1-1", " m1-1-01", ""])
def test_a_target_code_typed_back_wrongly_refuses(artifact: Path, typed: str) -> None:
    authority, code = an_authority()
    rec = record()
    planned = authority.plan(
        target_code=code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    with pytest.raises(WriteRefused) as refused:
        authority.confirm_target(planned, typed)
    assert refused.value.refusal is Refusal.TARGET_CODE_MISMATCH


@pytest.mark.parametrize("typed", ["y", "yes", "erase this medium", "ERASE", ""])
def test_the_destruction_must_be_confirmed_in_the_required_words(
    artifact: Path, typed: str
) -> None:
    authority, code = an_authority()
    rec = record()
    planned = authority.plan(
        target_code=code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    with pytest.raises(WriteRefused) as refused:
        authority.confirm_destruction(authority.confirm_target(planned, code), typed)
    assert refused.value.refusal is Refusal.DESTRUCTION_NOT_CONFIRMED


# --- substitution after the operator chose ---------------------------------


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("capacity_bytes", 32 * 1000**3),
        ("partition_table", "mbr"),
        ("removable", None),
        ("bus_path", "usb-0:3.1"),
        ("physical_label", "red tag"),
    ],
)
def test_a_device_substituted_after_enumeration_is_refused(
    tmp_path: Path, artifact: Path, attribute: str, value
) -> None:
    """Same identity, different object: what the operator picked is gone."""

    assert attribute in REVERIFIED_ATTRIBUTES
    authority, code = an_authority()
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            authorised_write(artifact, authority, code),
            probe=Probe({IDENTITY: candidate(**{attribute: value})}),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.TARGET_SUBSTITUTED
    assert device.written == b""


def test_the_bus_position_and_the_label_are_re_verified() -> None:
    """They are what an operator physically identifies the object by."""

    assert {"bus_path", "physical_label"} <= set(REVERIFIED_ATTRIBUTES)


def test_a_probe_that_answers_with_another_device_is_refused(
    tmp_path: Path, artifact: Path
) -> None:
    authority, code = an_authority()
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            authorised_write(artifact, authority, code),
            probe=Probe({IDENTITY: candidate(identity="a-different-device")}),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.TARGET_SUBSTITUTED
    assert device.written == b""


def test_neither_confirmation_can_be_skipped(tmp_path: Path, artifact: Path) -> None:
    """A review wrapped a genuine plan and wrote with neither confirmation typed."""

    authority, code = an_authority()
    rec = record()
    planned = authority.plan(
        target_code=code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            Authorised(confirmed=TargetConfirmed(plan=planned)),
            probe=Probe(),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.AUTHORISATION_NOT_ISSUED
    assert device.written == b""


def test_a_confirmation_cannot_be_used_twice(artifact: Path) -> None:
    authority, code = an_authority()
    rec = record()
    planned = authority.plan(
        target_code=code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    confirmed = authority.confirm_target(planned, code)
    authority.confirm_destruction(confirmed, DESTRUCTIVE_CONFIRMATION)
    with pytest.raises(WriteRefused) as refused:
        authority.confirm_destruction(confirmed, DESTRUCTIVE_CONFIRMATION)
    assert refused.value.refusal is Refusal.AUTHORISATION_NOT_ISSUED


def test_a_plan_whose_record_changed_after_verification_is_refused(
    tmp_path: Path, artifact: Path
) -> None:
    """The binding is re-asserted at the point of use, not only at plan time."""

    authority, code = an_authority()
    rec = record()
    planned = authority.plan(
        target_code=code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    authorisation = authority.confirm_destruction(
        authority.confirm_target(planned, code), DESTRUCTIVE_CONFIRMATION
    )
    # Reach the check itself: `dataclasses.replace` would make a new object and
    # the identity check would fire first, leaving this branch untested.
    impostor = parse(
        {
            **rec.fields,
            "signature": None,
            "signed_artifact_digest": None,
            "compatibility_claim": "hardware_verified",
        }
    )
    object.__setattr__(planned, "record", impostor)

    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            authorisation,
            probe=Probe(),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.RECORD_CHANGED_AFTER_VERIFICATION
    assert device.written == b""


def test_a_mistyped_code_costs_the_retype_and_nothing_else(artifact: Path) -> None:
    """Retiring the plan on a typo sent the operator back through `list-media`.

    That is the step the whole design exists to protect — re-identifying a
    physical device under time pressure — and there was no security in it: the
    code is a field of the plan the caller already holds.
    """

    authority, code = an_authority()
    rec = record()
    planned = authority.plan(
        target_code=code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    with pytest.raises(WriteRefused) as refused:
        authority.confirm_target(planned, "m1-1-99")
    assert refused.value.refusal is Refusal.TARGET_CODE_MISMATCH
    confirmed = authority.confirm_target(planned, code)

    with pytest.raises(WriteRefused) as phrase:
        authority.confirm_destruction(confirmed, "yes")
    assert phrase.value.refusal is Refusal.DESTRUCTION_NOT_CONFIRMED
    assert authority.confirm_destruction(confirmed, DESTRUCTIVE_CONFIRMATION) is not None


def test_an_earlier_step_passed_to_execute_is_refused(tmp_path: Path, artifact: Path) -> None:
    """A `Planned` or a `TargetConfirmed` used to die on an `AttributeError`."""

    authority, code = an_authority()
    rec = record()
    planned = authority.plan(
        target_code=code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    device = Device(tmp_path / "device")
    for step in (planned, authority.confirm_target(planned, code)):
        with pytest.raises(WriteRefused) as refused:
            authority.execute(
                step,  # type: ignore[arg-type]
                probe=Probe(),
                unmounter=Unmounter(),
                raw_writer=device,
                reader=device,
            )
        assert refused.value.refusal is Refusal.AUTHORISATION_NOT_ISSUED
    assert device.written == b""


def test_a_port_that_raises_is_a_refusal_not_a_stray_exception(
    tmp_path: Path, artifact: Path
) -> None:
    """`refusals.Refused` is what a caller catches; a port must not escape it."""

    class BrokenProbe:
        def reread(self, identity):
            raise RuntimeError("the bus went away")

    authority, code = an_authority()
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            authorised_write(artifact, authority, code),
            probe=BrokenProbe(),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.PORT_MISBEHAVED
    assert device.written == b""


def test_a_port_cannot_change_the_write_target_it_was_handed(
    tmp_path: Path, artifact: Path
) -> None:
    """The regression a review found: the internal disk was written, medium valid."""

    class MutatingUnmounter:
        def unmount(self, identity) -> bool:
            identity._value = "a-different-device"  # noqa: SLF001 - the attack
            return True

    authority, code = an_authority()
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            authorised_write(artifact, authority, code),
            probe=Probe(),
            unmounter=MutatingUnmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.PORT_MISBEHAVED
    assert device.written == b""


def test_a_device_that_disappeared_is_refused(tmp_path: Path, artifact: Path) -> None:
    authority, code = an_authority()
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            authorised_write(artifact, authority, code),
            probe=Probe({}),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.TARGET_DISAPPEARED
    assert device.written == b""


@pytest.mark.parametrize(
    "change", [{"internal": True}, {"mounted": True}, {"holds_running_root": True}]
)
def test_a_device_that_became_ineligible_is_refused(
    tmp_path: Path, artifact: Path, change: dict
) -> None:
    authority, code = an_authority()
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            authorised_write(artifact, authority, code),
            probe=Probe({IDENTITY: candidate(**change)}),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.NOW_INELIGIBLE
    assert device.written == b""


def test_a_device_that_could_not_be_released_is_refused(
    tmp_path: Path, artifact: Path
) -> None:
    authority, code = an_authority()
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            authorised_write(artifact, authority, code),
            probe=Probe(),
            unmounter=Unmounter(succeeds=False),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.UNMOUNT_FAILED
    assert device.written == b""


# --- what a medium may be called -------------------------------------------


def test_a_medium_that_fails_its_read_back_is_never_valid(
    tmp_path: Path, artifact: Path
) -> None:
    authority, code = an_authority()
    device = Device(tmp_path / "device", truncate_to=5)
    result = authority.execute(
        authorised_write(artifact, authority, code),
        probe=Probe(),
        unmounter=Unmounter(),
        raw_writer=device,
        reader=device,
    )
    assert result.outcome is WriteOutcome.VERIFICATION_FAILED
    assert result.medium_is_valid is False


def test_a_short_write_fails_verification_on_its_own_terms(
    tmp_path: Path, artifact: Path
) -> None:
    """The extent verified is the artifact's length, not the writer's own claim."""

    authority, code = an_authority()
    device = Device(tmp_path / "device", truncate_to=len(PAYLOAD) - 1)
    result = authority.execute(
        authorised_write(artifact, authority, code),
        probe=Probe(),
        unmounter=Unmounter(),
        raw_writer=device,
        reader=device,
    )
    assert result.written_bytes != result.expected_bytes
    assert result.outcome is WriteOutcome.VERIFICATION_FAILED


def test_there_is_no_outcome_meaning_written_but_unchecked() -> None:
    assert {member.value for member in WriteOutcome} == {
        "written_and_verified",
        "verification_failed",
    }


def test_an_unreadable_medium_is_not_verified(tmp_path: Path, artifact: Path) -> None:
    class Silent(Device):
        def digest(self, identity: DeviceIdentity, length: int) -> str | None:
            return None

    authority, code = an_authority()
    device = Silent(tmp_path / "device")
    result = authority.execute(
        authorised_write(artifact, authority, code),
        probe=Probe(),
        unmounter=Unmounter(),
        raw_writer=device,
        reader=device,
    )
    assert result.outcome is WriteOutcome.VERIFICATION_FAILED
    assert result.medium_is_valid is False


def test_inspect_reports_a_mismatch_rather_than_the_record(tmp_path: Path) -> None:
    device = Device(tmp_path / "device")
    device.path.write_bytes(OTHER)
    result = inspect(
        candidate=candidate(), record=record(), length=len(OTHER), reader=device
    )
    assert result.matches is False
    assert result.describes_the_record is False


def test_inspect_confirms_a_medium_that_matches(tmp_path: Path) -> None:
    device = Device(tmp_path / "device")
    device.path.write_bytes(PAYLOAD)
    result = inspect(
        candidate=candidate(), record=record(), length=len(PAYLOAD), reader=device
    )
    assert result.matches is True
    assert result.measured_digest == DIGEST


# --- identity stays off every rendering ------------------------------------


def test_no_rendering_of_a_plan_or_a_candidate_prints_the_identity(
    tmp_path: Path, artifact: Path
) -> None:
    """A default repr reaches a log through an f-string nobody thought about."""

    session = MediaSession("m1")
    offers = session.offer([candidate()])
    authority = WriteAuthority(session, artifact_reader=Files())
    rec = record()
    planned = authority.plan(
        target_code=offers[0].target_code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    confirmed = authority.confirm_target(planned, offers[0].target_code)
    authorisation = authority.confirm_destruction(confirmed, DESTRUCTIVE_CONFIRMATION)

    for rendered in (
        repr(candidate()),
        repr(offers[0]),
        repr(planned),
        repr(confirmed),
        repr(authorisation),
        f"{offers[0]}",
        str(candidate().identity),
    ):
        assert IDENTITY_VALUE not in rendered, f"identity leaked into {rendered!r}"
    assert str(artifact) not in repr(planned)


def test_serialising_a_candidate_or_a_plan_does_not_yield_the_raw_identity(
    artifact: Path,
) -> None:
    """`asdict` walks past a redacted `__repr__`; it is how a `--json` output is built."""

    session = MediaSession("m1")
    offers = session.offer([candidate()])
    authority = WriteAuthority(session, artifact_reader=Files())
    rec = record()
    planned = authority.plan(
        target_code=offers[0].target_code,
        record=rec,
        verification=verified_for(rec, artifact),
        artifact_path=str(artifact),
    )
    for structure in (dataclasses.asdict(offers[0]), dataclasses.asdict(candidate())):
        assert IDENTITY_VALUE not in repr(structure)
        assert IDENTITY_VALUE not in json.dumps(structure, default=str)
    assert IDENTITY_VALUE not in repr(dataclasses.astuple(candidate()))
    # A plan is not serialisable at all: its record is a read-only mapping, and
    # refusing loudly beats writing a plan into a queue or a cache.
    with pytest.raises(TypeError):
        dataclasses.asdict(planned)


# --- what this module is allowed to touch ----------------------------------


def test_no_module_in_this_change_names_a_device_path() -> None:
    """Contract section 7.1, checked across all three modules rather than one."""

    from azazel_boot import artifact as artifact_module
    from azazel_boot import media as media_module

    for module in (writer_module, media_module, artifact_module):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert "/dev" not in node.value, (
                    f"{module.__name__} carries a device path literal: {node.value!r}"
                )


def test_the_writer_opens_nothing_itself() -> None:
    """Unmounting, writing, reading back and measuring are all ports.

    The blacklist is the honest form of this check: it names the ways this
    module could open something, and `open()` needs no import, so the real
    guarantee is that every filesystem effect is behind a Protocol.
    """

    tree = ast.parse(Path(writer_module.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    assert not imported & {"os", "subprocess", "shutil", "pathlib", "ctypes", "io", "mmap", "fcntl"}
    assert "open" not in calls
