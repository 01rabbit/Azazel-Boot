"""Detached Ed25519 attestation for the R11 boot-only prototype.

This module is deliberately separate from the product artifact verifier and
writer. A successful result is evidence that a pinned key attested to the exact
R11 bytes and classification; it is not a release verification or write
authorization. The default policy is permanently pinned to the recorded R11
prototype. Callers must supply the public-key pin out of band.

Ed25519 operations are delegated to the system OpenSSL executable so this
developer-only tool does not add a runtime Python crypto dependency. Private
keys are supplied by the caller; this module never creates or persists one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

PROFILE: Final = "r11-hybrid-iso-whole-device"
R11_SHA256: Final = "3aa21d1c9c97dd74a5d981d17216738e16c2c066cb01dba454cd30e76a297dfa"
R11_SIZE: Final = 396_689_408
R11_MANIFEST_SHA256: Final = "e36d116ccec45750b84c7d2765094128b8a724e45b91273172cf96a2ae8eeb9a"
# SHA-256 of the checked xorriso layout report accompanying R11. This is an
# evidence-file digest, not a claim that the ISO has the separate P1/P2/P3 map.
R11_LAYOUT_EVIDENCE_SHA256: Final = (
    "0df49e0166cde3208a71e9ed7b30f3337ed1c1a9880171269a736489606d7378"
)
CLASSIFICATION: Final = "unsigned-prototype/boot-only"
SCHEMA: Final = "azazel-boot-r11-poc-attestation-v1"


@dataclass(frozen=True)
class AttestationPolicy:
    """Exact byte and claim pins. Non-production policies are for tests only."""

    profile: str
    sha256: str
    size: int
    manifest_sha256: str
    layout_evidence_sha256: str
    classification: str = CLASSIFICATION


R11_POLICY: Final = AttestationPolicy(
    profile=PROFILE,
    sha256=R11_SHA256,
    size=R11_SIZE,
    manifest_sha256=R11_MANIFEST_SHA256,
    layout_evidence_sha256=R11_LAYOUT_EVIDENCE_SHA256,
)


@dataclass(frozen=True)
class PocAttestationVerification:
    """Distinct evidence result; intentionally carries no writer authority."""

    profile: str
    measured_sha256: str
    measured_size: int
    manifest_sha256: str
    layout_evidence_sha256: str
    classification: str
    public_key_sha256: str
    signature_verified: bool


class AttestationRefused(ValueError):
    """The detached statement, key pin, or measured payload did not match."""


_FIELDS: Final = frozenset(
    {
        "schema",
        "profile",
        "payload_sha256",
        "payload_size",
        "manifest_sha256",
        "layout_evidence_sha256",
        "classification",
        "public_key_sha256",
        "signature_ed25519",
    }
)
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN = b"Azazel-Boot R11 detached PoC attestation v1\0"


def create_attestation(
    payload_path: Path,
    layout_evidence_path: Path,
    private_key_path: Path,
) -> bytes:
    """Create canonical detached JSON using a caller-provided Ed25519 key.

    This does not create/store a key or claim that the key is trusted. The
    returned document must be distributed alongside an out-of-band public-key
    pin. The production default accepts only the exact recorded R11 payload.
    """

    payload_digest, payload_size = _measure(Path(payload_path))
    policy = R11_POLICY
    _check_policy(policy)
    if payload_digest != policy.sha256 or payload_size != policy.size:
        raise AttestationRefused("payload does not match the selected exact-byte policy")
    if _file_sha256(Path(layout_evidence_path)) != policy.layout_evidence_sha256:
        raise AttestationRefused("layout evidence does not match the exact R11 policy")

    openssl = _openssl()
    with tempfile.TemporaryDirectory(prefix="az-r11-attest-") as temporary:
        directory = Path(temporary)
        public_pem = directory / "public.pem"
        public_der = directory / "public.der"
        message_path = directory / "message.bin"
        signature_path = directory / "signature.bin"
        _run(openssl, "pkey", "-in", str(private_key_path), "-pubout", "-out", str(public_pem))
        _run(
            openssl,
            "pkey",
            "-pubin",
            "-in",
            str(public_pem),
            "-outform",
            "DER",
            "-out",
            str(public_der),
        )
        public_key_sha256 = _file_sha256(public_der)
        unsigned = _statement(policy, public_key_sha256)
        message_path.write_bytes(_message(unsigned))
        _run(
            openssl,
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key_path),
            "-in",
            str(message_path),
            "-out",
            str(signature_path),
        )
        document = {
            **unsigned,
            "signature_ed25519": base64.b64encode(signature_path.read_bytes()).decode("ascii"),
        }
        return _json_bytes(document)


def verify_attestation(
    payload_path: Path,
    layout_evidence_path: Path,
    detached_document: bytes,
    public_key_pem: bytes,
    *,
    pinned_public_key_sha256: str | None,
) -> PocAttestationVerification:
    """Verify exact payload, canonical detached statement, signature, and key pin.

    The SHA-256 pin is over the public key's DER SubjectPublicKeyInfo and must
    come from a channel independent of this detached document. Missing pins
    always refuse. The result is not accepted by the normal artifact verifier
    and cannot authorize media writes.
    """

    policy = R11_POLICY
    _check_policy(policy)
    if pinned_public_key_sha256 is None or not _HEX_256.fullmatch(pinned_public_key_sha256):
        raise AttestationRefused("a valid out-of-band public-key pin is required")

    document = _parse_document(detached_document)
    claimed_key_pin = document["public_key_sha256"]
    if claimed_key_pin != pinned_public_key_sha256:
        raise AttestationRefused("detached statement does not match the out-of-band key pin")

    payload_digest, payload_size = _measure(Path(payload_path))
    expected = _statement(policy, pinned_public_key_sha256)
    for field, expected_value in expected.items():
        if document.get(field) != expected_value:
            raise AttestationRefused(f"detached statement has an unexpected {field}")
    if payload_digest != policy.sha256 or payload_size != policy.size:
        raise AttestationRefused("measured payload does not match the exact-byte policy")
    if _file_sha256(Path(layout_evidence_path)) != policy.layout_evidence_sha256:
        raise AttestationRefused("measured layout evidence does not match the exact R11 policy")

    signature_text = document["signature_ed25519"]
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, TypeError) as error:
        raise AttestationRefused("signature encoding is invalid") from error
    if len(signature) != 64:
        raise AttestationRefused("Ed25519 signature must be exactly 64 bytes")

    openssl = _openssl()
    with tempfile.TemporaryDirectory(prefix="az-r11-verify-") as temporary:
        directory = Path(temporary)
        public_path = directory / "public.pem"
        public_der = directory / "public.der"
        message_path = directory / "message.bin"
        signature_path = directory / "signature.bin"
        public_path.write_bytes(public_key_pem)
        _run(
            openssl,
            "pkey",
            "-pubin",
            "-in",
            str(public_path),
            "-outform",
            "DER",
            "-out",
            str(public_der),
        )
        actual_key_pin = _file_sha256(public_der)
        if actual_key_pin != pinned_public_key_sha256:
            raise AttestationRefused("provided public key does not match the out-of-band pin")
        message_path.write_bytes(_message(expected))
        signature_path.write_bytes(signature)
        try:
            _run(
                openssl,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_path),
                "-rawin",
                "-in",
                str(message_path),
                "-sigfile",
                str(signature_path),
            )
        except AttestationRefused as error:
            raise AttestationRefused("Ed25519 signature verification failed") from error

    return PocAttestationVerification(
        profile=policy.profile,
        measured_sha256=payload_digest,
        measured_size=payload_size,
        manifest_sha256=policy.manifest_sha256,
        layout_evidence_sha256=policy.layout_evidence_sha256,
        classification=policy.classification,
        public_key_sha256=pinned_public_key_sha256,
        signature_verified=True,
    )


def verification_for_r11_writer(
    record: object,
    payload_path: Path,
    layout_evidence_path: Path,
    detached_document: bytes,
    public_key_pem: bytes,
    *,
    pinned_public_key_sha256: str | None,
):
    """Bridge valid R11 PoC evidence to a visibly scoped writer result.

    This helper is intentionally in developer tooling, not the product CLI.
    It leaves `artifact.verify()` unchanged and can issue only the fixed R11
    profile after verifying the exact payload, layout evidence and out-of-band
    pin. The writer result remains labeled with the PoC profile.
    """

    result = verify_attestation(
        payload_path,
        layout_evidence_path,
        detached_document,
        public_key_pem,
        pinned_public_key_sha256=pinned_public_key_sha256,
    )
    digest = "sha256:" + result.measured_sha256
    if getattr(record, "unsigned_payload_digest", None) != digest:
        raise AttestationRefused("artifact record digest does not identify the attested R11 bytes")
    if getattr(record, "is_signed", True) or getattr(
        record, "compatibility_claim", None
    ) != "candidate":
        raise AttestationRefused("R11 attestation requires an unsigned candidate record")

    # This private bridge registers only the already-verified, exact R11 scope.
    # The normal release verifier is not called or modified by this adapter.
    from azazel_boot.artifact import _issue_r11_poc_verification

    try:
        return _issue_r11_poc_verification(
            record,
            digest,
            profile=PROFILE,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise AttestationRefused(
            "R11 writer verification could not be bound to the record"
        ) from error


def _statement(policy: AttestationPolicy, key_pin: str) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "profile": policy.profile,
        "payload_sha256": policy.sha256,
        "payload_size": policy.size,
        "manifest_sha256": policy.manifest_sha256,
        "layout_evidence_sha256": policy.layout_evidence_sha256,
        "classification": policy.classification,
        "public_key_sha256": key_pin,
    }


def _check_policy(policy: AttestationPolicy) -> None:
    if (
        not isinstance(policy, AttestationPolicy)
        or not isinstance(policy.profile, str)
        or policy.profile != PROFILE
        or not isinstance(policy.classification, str)
        or policy.classification != CLASSIFICATION
        or not isinstance(policy.sha256, str)
        or not _HEX_256.fullmatch(policy.sha256)
        or not isinstance(policy.manifest_sha256, str)
        or not _HEX_256.fullmatch(policy.manifest_sha256)
        or not isinstance(policy.layout_evidence_sha256, str)
        or not _HEX_256.fullmatch(policy.layout_evidence_sha256)
        or not isinstance(policy.size, int)
        or isinstance(policy.size, bool)
        or policy.size <= 0
    ):
        raise AttestationRefused("policy is not an R11 boot-only policy")


def _parse_document(raw: bytes) -> dict[str, object]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AttestationRefused("detached document is not valid JSON") from error
    if not isinstance(document, dict) or set(document) != _FIELDS:
        raise AttestationRefused("detached document has an unexpected shape")
    if _json_bytes(document) != raw:
        raise AttestationRefused("detached document is not canonical JSON")
    if (
        not isinstance(document["payload_size"], int)
        or isinstance(document["payload_size"], bool)
        or not isinstance(document["signature_ed25519"], str)
        or any(not isinstance(document[field], str) for field in _FIELDS - {"payload_size"})
    ):
        raise AttestationRefused("detached document has invalid field types")
    return document


def _measure(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
    except OSError as error:
        raise AttestationRefused("payload could not be measured") from error
    return digest.hexdigest(), size


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _message(value: object) -> bytes:
    return _DOMAIN + _json_bytes(value)


def _openssl() -> str:
    executable = shutil.which("openssl")
    if executable is None:
        raise AttestationRefused("OpenSSL is required for Ed25519 operations")
    return executable


def _run(executable: str, *arguments: str) -> None:
    try:
        result = subprocess.run(
            [executable, *arguments],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AttestationRefused("OpenSSL operation could not be completed") from error
    if result.returncode != 0:
        raise AttestationRefused("OpenSSL rejected the key or signature")
