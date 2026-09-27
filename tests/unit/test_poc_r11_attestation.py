"""R11-only detached PoC attestation stays separate from release verification."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import tools.poc_r11_attestation as attestation
from tools.poc_r11_attestation import (
    CLASSIFICATION,
    PROFILE,
    R11_LAYOUT_EVIDENCE_SHA256,
    R11_MANIFEST_SHA256,
    R11_POLICY,
    R11_SHA256,
    R11_SIZE,
    AttestationPolicy,
    AttestationRefused,
    PocAttestationVerification,
    create_attestation,
    verification_for_r11_writer,
    verify_attestation,
)

from azazel_boot.artifact import VerificationOutcome, parse
from azazel_boot.artifact import verify as verify_release_record
from azazel_boot.media import DeviceIdentity, MediaCandidate, MediaSession
from azazel_boot.writer import WriteAuthority


def synthetic_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path, bytes, str, AttestationPolicy]:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is required for Ed25519 attestation tests")

    payload = tmp_path / "synthetic-r11.iso"
    payload.write_bytes(b"synthetic whole-device R11 fixture\0" * 3)
    layout = tmp_path / "synthetic-layout-evidence.txt"
    layout.write_bytes(b"synthetic whole-device hybrid ISO layout evidence\n")
    private_key = tmp_path / "temporary-ed25519.pem"
    public_key = tmp_path / "temporary-ed25519.pub.pem"
    public_der = tmp_path / "temporary-ed25519.pub.der"
    subprocess.run(
        [openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [openssl, "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            openssl,
            "pkey",
            "-pubin",
            "-in",
            str(public_key),
            "-outform",
            "DER",
            "-out",
            str(public_der),
        ],
        check=True,
        capture_output=True,
    )
    policy = AttestationPolicy(
        profile=PROFILE,
        sha256=hashlib.sha256(payload.read_bytes()).hexdigest(),
        size=payload.stat().st_size,
        manifest_sha256="a" * 64,
        layout_evidence_sha256=hashlib.sha256(layout.read_bytes()).hexdigest(),
    )
    # Test-only replacement of the module's compiled exact-byte policy. The
    # production API has no caller-supplied policy parameter.
    monkeypatch.setattr(attestation, "R11_POLICY", policy)
    return (
        payload,
        layout,
        private_key,
        public_key.read_bytes(),
        hashlib.sha256(public_der.read_bytes()).hexdigest(),
        policy,
    )


def signed_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, bytes, str, AttestationPolicy, bytes]:
    payload, layout, private_key, public_key, pin, policy = synthetic_fixture(
        tmp_path, monkeypatch
    )
    detached = create_attestation(payload, layout, private_key)
    return payload, layout, public_key, pin, policy, detached


def r11_record(payload_digest: str):
    return parse(
        {
            "image_version": "poc-r1",
            "git_revision": "0" * 40,
            "builder_version": "0.0.0",
            "debian_snapshot": "snapshot:20260914T120000Z",
            "package_manifest_ref": "manifests/packages.json",
            "package_manifest_digest": "sha256:" + "1" * 64,
            "firmware_manifest_ref": "manifests/firmware.json",
            "firmware_manifest_digest": "sha256:" + "2" * 64,
            "sbom_ref": "sbom/payload.spdx.json",
            "sbom_digest": "sha256:" + "3" * 64,
            "source_date_epoch": 1789387200,
            "build_input_digest": "sha256:" + "4" * 64,
            "partition_layout_digest": "sha256:" + "5" * 64,
            "root_filesystem_digest": "sha256:" + "6" * 64,
            "boot_chain_identity": "debian-grub-efi-unverified",
            "unsigned_payload_digest": payload_digest,
            "signed_artifact_digest": None,
            "signature": None,
            "build_time": "2026-09-26T00:00:00Z",
            "compatibility_claim": "candidate",
            "quarantine_policy_version": "quarantine.v1",
        }
    )


def resign_document(
    tmp_path: Path, document: dict[str, object], private_key: Path
) -> bytes:
    """Resign a modified canonical envelope to test policy rejection explicitly."""

    openssl = shutil.which("openssl")
    assert openssl is not None
    unsigned = {name: value for name, value in document.items() if name != "signature_ed25519"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("ascii")
    message = b"Azazel-Boot R11 detached PoC attestation v1\0" + canonical
    message_path = tmp_path / "changed-message.bin"
    signature_path = tmp_path / "changed-signature.bin"
    message_path.write_bytes(message)
    subprocess.run(
        [
            openssl,
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key),
            "-in",
            str(message_path),
            "-out",
            str(signature_path),
        ],
        check=True,
        capture_output=True,
    )
    document["signature_ed25519"] = base64.b64encode(signature_path.read_bytes()).decode("ascii")
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


def test_production_policy_is_pinned_to_exact_r11_and_boot_only_claim() -> None:
    assert R11_POLICY == AttestationPolicy(
        profile="r11-hybrid-iso-whole-device",
        sha256="3aa21d1c9c97dd74a5d981d17216738e16c2c066cb01dba454cd30e76a297dfa",
        size=396_689_408,
        manifest_sha256="e36d116ccec45750b84c7d2765094128b8a724e45b91273172cf96a2ae8eeb9a",
        layout_evidence_sha256=(
            "0df49e0166cde3208a71e9ed7b30f3337ed1c1a9880171269a736489606d7378"
        ),
    )
    assert PROFILE == "r11-hybrid-iso-whole-device"
    assert R11_SHA256 == R11_POLICY.sha256
    assert R11_SIZE == R11_POLICY.size
    assert R11_MANIFEST_SHA256 == R11_POLICY.manifest_sha256
    assert R11_LAYOUT_EVIDENCE_SHA256 == R11_POLICY.layout_evidence_sha256
    assert CLASSIFICATION == "unsigned-prototype/boot-only"


def test_valid_attestation_returns_distinct_non_authorizing_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, layout, public_key, pin, policy, detached = signed_fixture(tmp_path, monkeypatch)
    result = verify_attestation(
        payload, layout, detached, public_key, pinned_public_key_sha256=pin
    )

    assert type(result) is PocAttestationVerification
    assert result.signature_verified is True
    assert result.profile == PROFILE
    assert result.measured_sha256 == policy.sha256
    assert result.measured_size == policy.size
    assert result.manifest_sha256 == policy.manifest_sha256
    assert result.layout_evidence_sha256 == policy.layout_evidence_sha256
    assert result.classification == CLASSIFICATION
    assert result.public_key_sha256 == pin
    assert not hasattr(result, "may_be_written")


def test_valid_r11_attestation_is_scoped_into_native_write_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, layout, public_key, pin, _policy, detached = signed_fixture(tmp_path, monkeypatch)
    digest = "sha256:" + hashlib.sha256(payload.read_bytes()).hexdigest()
    record = r11_record(digest)
    evidence = verification_for_r11_writer(
        record,
        payload,
        layout,
        detached,
        public_key,
        pinned_public_key_sha256=pin,
    )

    assert evidence.may_be_written
    assert evidence.profile == PROFILE
    assert verify_release_record(record, digest).outcome is VerificationOutcome.DIGEST_ONLY

    session = MediaSession("r11-poc-session")
    offered = session.offer(
        [
            MediaCandidate(
                identity=DeviceIdentity("synthetic-r11-target"),
                capacity_bytes=R11_SIZE + 1024,
                partition_table="hybrid-iso9660",
                bus_path="hidden",
                physical_label="hidden",
                removable=True,
                mounted=False,
                internal=False,
                holds_running_root=False,
            )
        ]
    )
    class ArtifactReader:
        def measure(self, artifact_path: str) -> tuple[str, int]:
            data = Path(artifact_path).read_bytes()
            return "sha256:" + hashlib.sha256(data).hexdigest(), len(data)

    authority = WriteAuthority(session, artifact_reader=ArtifactReader())
    plan = authority.plan(
        target_code=offered[0].target_code,
        record=record,
        verification=evidence,
        artifact_path=str(payload),
    )
    assert plan.verification_profile == PROFILE


def test_missing_or_malformed_out_of_band_pin_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, layout, public_key, _pin, _policy, detached = signed_fixture(tmp_path, monkeypatch)
    for pin in (None, "", "0" * 63, "G" * 64):
        with pytest.raises(AttestationRefused, match="out-of-band public-key pin"):
            verify_attestation(payload, layout, detached, public_key, pinned_public_key_sha256=pin)


def test_wrong_key_or_wrong_out_of_band_pin_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, layout, public_key, pin, policy, detached = signed_fixture(tmp_path, monkeypatch)
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    _payload, _layout, _key, other_public, _other_pin, _policy = synthetic_fixture(
        other_dir, monkeypatch
    )
    monkeypatch.setattr(attestation, "R11_POLICY", policy)
    with pytest.raises(AttestationRefused, match="out-of-band.*pin"):
        verify_attestation(payload, layout, detached, public_key, pinned_public_key_sha256="1" * 64)
    with pytest.raises(AttestationRefused, match="out-of-band.*pin"):
        verify_attestation(payload, layout, detached, other_public, pinned_public_key_sha256=pin)


def test_tampered_signature_and_noncanonical_document_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, layout, public_key, pin, _policy, detached = signed_fixture(tmp_path, monkeypatch)
    document = json.loads(detached)
    signature = bytearray(base64.b64decode(document["signature_ed25519"]))
    signature[0] ^= 1
    document["signature_ed25519"] = base64.b64encode(signature).decode("ascii")
    changed = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")

    with pytest.raises(AttestationRefused, match="signature verification failed"):
        verify_attestation(payload, layout, changed, public_key, pinned_public_key_sha256=pin)
    with pytest.raises(AttestationRefused, match="not canonical"):
        verify_attestation(
            payload,
            layout,
            json.dumps(json.loads(detached), indent=2).encode("ascii"),
            public_key,
            pinned_public_key_sha256=pin,
        )


def test_altered_payload_or_layout_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, layout, private_key, public_key, pin, _policy = synthetic_fixture(
        tmp_path, monkeypatch
    )
    detached = create_attestation(payload, layout, private_key)
    payload.write_bytes(payload.read_bytes() + b"altered")
    with pytest.raises(AttestationRefused, match="exact-byte policy"):
        verify_attestation(payload, layout, detached, public_key, pinned_public_key_sha256=pin)

    payload.write_bytes(b"synthetic whole-device R11 fixture\0" * 3)
    layout.write_bytes(b"altered layout evidence")
    with pytest.raises(AttestationRefused, match="layout evidence"):
        verify_attestation(payload, layout, detached, public_key, pinned_public_key_sha256=pin)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("profile", "unsigned-firmware-prototype"),
        ("payload_sha256", "b" * 64),
        ("payload_size", 999),
        ("manifest_sha256", "c" * 64),
        ("layout_evidence_sha256", "d" * 64),
        ("classification", "release/signed"),
    ],
)
def test_resigned_but_policy_mismatched_claims_refuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    payload, layout, private_key, public_key, pin, _policy = synthetic_fixture(
        tmp_path, monkeypatch
    )
    document = json.loads(create_attestation(payload, layout, private_key))
    document[field] = value
    changed = resign_document(tmp_path, document, private_key)
    with pytest.raises(AttestationRefused, match="unexpected"):
        verify_attestation(payload, layout, changed, public_key, pinned_public_key_sha256=pin)


def test_bad_profile_cannot_be_passed_as_a_caller_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, layout, private_key, _public_key, _pin, _policy = synthetic_fixture(
        tmp_path, monkeypatch
    )
    invalid = AttestationPolicy(
        profile="unsigned-firmware-prototype",
        sha256=hashlib.sha256(payload.read_bytes()).hexdigest(),
        size=payload.stat().st_size,
        manifest_sha256="a" * 64,
        layout_evidence_sha256=hashlib.sha256(layout.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(attestation, "R11_POLICY", invalid)
    with pytest.raises(AttestationRefused, match="not an R11 boot-only policy"):
        create_attestation(payload, layout, private_key)


def test_malformed_json_shape_or_signature_encoding_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, layout, public_key, pin, _policy, detached = signed_fixture(tmp_path, monkeypatch)
    with pytest.raises(AttestationRefused, match="unexpected shape"):
        verify_attestation(
            payload,
            layout,
            b'{"profile":"r11-hybrid-iso-whole-device"}',
            public_key,
            pinned_public_key_sha256=pin,
        )

    document = json.loads(detached)
    document["signature_ed25519"] = "%%%"
    malformed = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(AttestationRefused, match="signature encoding"):
        verify_attestation(payload, layout, malformed, public_key, pinned_public_key_sha256=pin)
