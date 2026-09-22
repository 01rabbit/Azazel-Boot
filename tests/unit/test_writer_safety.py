"""The destructive write, exercised in full without a block device in sight.

The ports are file-backed: the "device" is an ordinary file this test wrote,
so a mistake in the code under test destroys a temporary file and nothing else.
**No test here touches a real device, a loop device or `/dev`**, and
`test_the_writer_module_names_no_device_path` keeps it that way by reading the
module's syntax tree rather than trusting this docstring.

The tests are grouped by the four things that must not happen: writing an
artifact nobody verified, writing without both confirmations, writing to a
device that is no longer the one the operator chose, and calling a medium valid
when its read-back did not match.
"""

from __future__ import annotations

import ast
import hashlib
import inspect as inspect_module
from pathlib import Path

import pytest

from azazel_boot import writer as writer_module
from azazel_boot.artifact import Verification, VerificationOutcome, VerificationRefusal, parse
from azazel_boot.media import MediaCandidate
from azazel_boot.writer import (
    DESTRUCTIVE_CONFIRMATION,
    REVERIFIED_ATTRIBUTES,
    Authorised,
    Refusal,
    WriteOutcome,
    WriteRefused,
    confirm_destruction,
    confirm_target,
    execute,
    inspect,
    plan,
)

PAYLOAD = b"an image, for the purposes of this test"
DIGEST = "sha256:" + hashlib.sha256(PAYLOAD).hexdigest()
CODE = "m1-01"


def record():
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
            "unsigned_payload_digest": DIGEST,
            "signed_artifact_digest": "sha256:" + "8" * 64,
            "signature": "sig",
            "build_time": "2026-09-22T00:00:00Z",
            "compatibility_claim": "candidate",
            "quarantine_policy_version": "quarantine.v1",
        }
    )


def candidate(**overrides) -> MediaCandidate:
    attributes = {
        "identity": "stable-identity-1",
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


VERIFIED = Verification(VerificationOutcome.SIGNATURE_VERIFIED)


class Device:
    """A file standing in for a medium. The only thing these tests can destroy."""

    def __init__(self, path: Path, *, truncate_to: int | None = None) -> None:
        self.path = path
        self.path.write_bytes(b"")
        self._truncate_to = truncate_to

    # RawWriter
    def write(self, identity: str, artifact_path: str) -> int:
        data = Path(artifact_path).read_bytes()
        if self._truncate_to is not None:
            data = data[: self._truncate_to]
        self.path.write_bytes(data)
        return len(data)

    # MediumReader
    def digest(self, identity: str, length: int) -> str | None:
        data = self.path.read_bytes()[:length]
        if not data:
            return None
        return "sha256:" + hashlib.sha256(data).hexdigest()

    @property
    def written(self) -> bytes:
        return self.path.read_bytes()


class Probe:
    def __init__(self, current: MediaCandidate | None) -> None:
        self._current = current

    def reread(self, identity: str) -> MediaCandidate | None:
        return self._current


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


def authorised(artifact: Path, enumerated: MediaCandidate | None = None) -> Authorised:
    planned = plan(
        target_code=CODE,
        enumerated=enumerated if enumerated is not None else candidate(),
        record=record(),
        verification=VERIFIED,
        artifact_path=str(artifact),
        artifact_bytes=len(PAYLOAD),
    )
    return confirm_destruction(confirm_target(planned, CODE), DESTRUCTIVE_CONFIRMATION)


def test_a_verified_signed_artifact_is_written_and_read_back(
    tmp_path: Path, artifact: Path
) -> None:
    device = Device(tmp_path / "device")
    result = execute(
        authorised(artifact),
        probe=Probe(candidate()),
        unmounter=Unmounter(),
        raw_writer=device,
        reader=device,
    )
    assert result.outcome is WriteOutcome.WRITTEN_AND_VERIFIED
    assert result.medium_is_valid is True
    assert device.written == PAYLOAD


@pytest.mark.parametrize(
    "verification",
    [
        Verification(VerificationOutcome.DIGEST_ONLY, VerificationRefusal.UNSIGNED),
        Verification(VerificationOutcome.DIGEST_ONLY, VerificationRefusal.NO_VERIFIER),
        Verification(VerificationOutcome.REFUSED, VerificationRefusal.DIGEST_MISMATCH),
    ],
)
def test_an_artifact_that_did_not_pass_verify_is_refused_before_anything_else(
    artifact: Path, verification: Verification
) -> None:
    """Refused at planning time, before an operator is asked to confirm anything."""

    with pytest.raises(WriteRefused) as refused:
        plan(
            target_code=CODE,
            enumerated=candidate(),
            record=record(),
            verification=verification,
            artifact_path=str(artifact),
            artifact_bytes=len(PAYLOAD),
        )
    assert refused.value.refusal is Refusal.ARTIFACT_NOT_VERIFIED


@pytest.mark.parametrize("typed", ["m1-02", "M1-01", "m1-1", " m1-01", ""])
def test_a_target_code_typed_back_wrongly_refuses(artifact: Path, typed: str) -> None:
    planned = plan(
        target_code=CODE,
        enumerated=candidate(),
        record=record(),
        verification=VERIFIED,
        artifact_path=str(artifact),
        artifact_bytes=len(PAYLOAD),
    )
    with pytest.raises(WriteRefused) as refused:
        confirm_target(planned, typed)
    assert refused.value.refusal is Refusal.TARGET_CODE_MISMATCH


@pytest.mark.parametrize("typed", ["y", "yes", "erase this medium", "ERASE", ""])
def test_the_destruction_must_be_confirmed_in_the_required_words(
    artifact: Path, typed: str
) -> None:
    planned = plan(
        target_code=CODE,
        enumerated=candidate(),
        record=record(),
        verification=VERIFIED,
        artifact_path=str(artifact),
        artifact_bytes=len(PAYLOAD),
    )
    confirmed = confirm_target(planned, CODE)
    with pytest.raises(WriteRefused) as refused:
        confirm_destruction(confirmed, typed)
    assert refused.value.refusal is Refusal.DESTRUCTION_NOT_CONFIRMED


def test_the_two_confirmations_are_types_rather_than_flags() -> None:
    """A caller cannot skip a confirmation, because there is no flag to pass."""

    signature = inspect_module.signature(execute)
    assert signature.parameters["authorised"].annotation == "Authorised"
    assert "force" not in signature.parameters
    assert "yes" not in signature.parameters


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("identity", "a-different-device"),
        ("capacity_bytes", 32 * 1000**3),
        ("partition_table", "mbr"),
        ("removable", None),
    ],
)
def test_a_device_substituted_after_enumeration_is_refused(
    tmp_path: Path, artifact: Path, attribute: str, value
) -> None:
    """Refused, not warned about: a prompt here is a prompt someone confirms."""

    assert attribute in REVERIFIED_ATTRIBUTES
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        execute(
            authorised(artifact),
            probe=Probe(candidate(**{attribute: value})),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.TARGET_SUBSTITUTED
    assert device.written == b""


def test_a_device_that_disappeared_is_refused(tmp_path: Path, artifact: Path) -> None:
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        execute(
            authorised(artifact),
            probe=Probe(None),
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
    """Eligibility is re-decided at write time, not inherited from the listing."""

    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        execute(
            authorised(artifact),
            probe=Probe(candidate(**change)),
            unmounter=Unmounter(),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.NOW_INELIGIBLE
    assert device.written == b""


def test_a_device_that_could_not_be_released_is_refused(
    tmp_path: Path, artifact: Path
) -> None:
    device = Device(tmp_path / "device")
    with pytest.raises(WriteRefused) as refused:
        execute(
            authorised(artifact),
            probe=Probe(candidate()),
            unmounter=Unmounter(succeeds=False),
            raw_writer=device,
            reader=device,
        )
    assert refused.value.refusal is Refusal.UNMOUNT_FAILED
    assert device.written == b""


def test_a_medium_that_fails_its_read_back_is_never_valid(
    tmp_path: Path, artifact: Path
) -> None:
    device = Device(tmp_path / "device", truncate_to=5)
    result = execute(
        authorised(artifact),
        probe=Probe(candidate()),
        unmounter=Unmounter(),
        raw_writer=device,
        reader=device,
    )
    assert result.outcome is WriteOutcome.VERIFICATION_FAILED
    assert result.medium_is_valid is False
    assert result.measured_digest != result.expected_digest


def test_there_is_no_outcome_meaning_written_but_unchecked() -> None:
    assert {member.value for member in WriteOutcome} == {
        "written_and_verified",
        "verification_failed",
    }


def test_inspect_reports_a_mismatch_rather_than_the_record(tmp_path: Path) -> None:
    device = Device(tmp_path / "device")
    device.path.write_bytes(b"something else entirely")
    result = inspect(identity="stable-identity-1", record=record(), length=23, reader=device)
    assert result.matches is False
    assert result.describes_the_record is False
    assert result.measured_digest != result.expected_digest


def test_inspect_confirms_a_medium_that_matches(tmp_path: Path) -> None:
    device = Device(tmp_path / "device")
    device.path.write_bytes(PAYLOAD)
    result = inspect(
        identity="stable-identity-1", record=record(), length=len(PAYLOAD), reader=device
    )
    assert result.matches is True
    assert result.measured_digest == DIGEST


def test_an_unreadable_medium_is_not_verified(tmp_path: Path, artifact: Path) -> None:
    class Silent(Device):
        def digest(self, identity: str, length: int) -> str | None:
            return None

    device = Silent(tmp_path / "device")
    result = execute(
        authorised(artifact),
        probe=Probe(candidate()),
        unmounter=Unmounter(),
        raw_writer=device,
        reader=device,
    )
    assert result.outcome is WriteOutcome.VERIFICATION_FAILED
    assert result.medium_is_valid is False


def test_the_writer_module_names_no_device_path() -> None:
    """Contract section 7.1: no `/dev/...` reaches the public surface."""

    source = Path(writer_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert "/dev/" not in node.value, f"a device path literal appeared: {node.value!r}"


def test_the_writer_opens_nothing_itself() -> None:
    """Unmounting, writing and reading back are ports, so this module is testable."""

    tree = ast.parse(Path(writer_module.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module)
    assert not imported & {"os", "subprocess", "shutil", "pathlib", "ctypes"}
