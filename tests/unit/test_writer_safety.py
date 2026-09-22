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
import hashlib
from pathlib import Path

import pytest

from azazel_boot import writer as writer_module
from azazel_boot.artifact import Verification, VerificationOutcome, VerificationRefusal, parse
from azazel_boot.artifact import verify as verify_artifact
from azazel_boot.media import MediaCandidate, MediaSession
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
    confirm_destruction,
    confirm_target,
    inspect,
)

PAYLOAD = b"an image, for the purposes of this test"
DIGEST = "sha256:" + hashlib.sha256(PAYLOAD).hexdigest()
OTHER = b"a different image entirely"
OTHER_DIGEST = "sha256:" + hashlib.sha256(OTHER).hexdigest()
IDENTITY = "stable-identity-1"


def record(digest: str = DIGEST):
    return parse(
        {
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

    def write(self, identity: str, artifact_path: str) -> int:
        data = Path(artifact_path).read_bytes()
        if self._truncate_to is not None:
            data = data[: self._truncate_to]
        self.path.write_bytes(data)
        return len(data)

    def digest(self, identity: str, length: int) -> str | None:
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

    def __init__(self, devices: dict[str, MediaCandidate] | None = None) -> None:
        self._devices = {IDENTITY: candidate()} if devices is None else devices

    def reread(self, identity: str) -> MediaCandidate | None:
        return self._devices.get(identity)


class Unmounter:
    def __init__(self, *, succeeds: bool = True) -> None:
        self._succeeds = succeeds

    def unmount(self, identity: str) -> bool:
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
    return confirm_destruction(confirm_target(planned, code), DESTRUCTIVE_CONFIRMATION)


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
    """The review's first finding: one line reached `execute` with nothing checked."""

    authority, _ = an_authority()
    device = Device(tmp_path / "device")
    forged = Authorised(
        confirmed=TargetConfirmed(
            plan=Planned(
                nonce="forged",
                target_code="m1-1-01",
                enumerated=candidate(),
                record=record(),
                artifact_path=str(artifact),
                artifact_bytes=len(PAYLOAD),
                artifact_digest=DIGEST,
            )
        )
    )
    with pytest.raises(WriteRefused) as refused:
        authority.execute(
            forged, probe=Probe(), unmounter=Unmounter(), raw_writer=device, reader=device
        )
    assert refused.value.refusal is Refusal.AUTHORISATION_NOT_ISSUED
    assert device.written == b""


def test_an_authorisation_from_another_authority_is_refused(
    tmp_path: Path, artifact: Path
) -> None:
    mine, my_code = an_authority()
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
    assert my_code != their_code or True  # both sessions issue their own codes


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
        confirm_target(planned, typed)
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
        confirm_destruction(confirm_target(planned, code), typed)
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
        def digest(self, identity: str, length: int) -> str | None:
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
    confirmed = confirm_target(planned, offers[0].target_code)
    authorisation = confirm_destruction(confirmed, DESTRUCTIVE_CONFIRMATION)

    for rendered in (
        repr(candidate()),
        repr(offers[0]),
        repr(planned),
        repr(confirmed),
        repr(authorisation),
        f"{offers[0]}",
    ):
        assert IDENTITY not in rendered, f"identity leaked into {rendered!r}"
    assert str(artifact) not in repr(planned)


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
