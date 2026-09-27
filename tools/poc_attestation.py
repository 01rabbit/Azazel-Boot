"""Local, offline attestation adapter for explicitly labelled PoC artifacts.

This is developer tooling, not a release signer and not part of azazel_boot.
The private key stays outside the repository. Verification requires an
independently pinned public key and the system OpenSSL command.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path


PREFIX = "azazel-poc-ed25519-v1:"
PROFILE = "unsigned-firmware-prototype"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PIN = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPENSSL_TIMEOUT_SECONDS = 10
_MAX_PUBLIC_KEY_BYTES = 16_384
_MAX_SIGNATURE_BYTES = 256


class AttestationRefused(ValueError):
    """A PoC signature did not meet this adapter's fixed contract."""


def _record_fields(record: object) -> Mapping[str, object]:
    fields = getattr(record, "fields", None)
    if not isinstance(fields, Mapping):
        raise AttestationRefused("invalid prototype record")
    return fields


def _message(record: object) -> bytes:
    fields = _record_fields(record)
    # This adapter cannot attest a release or a claimed hardware-verified image.
    if fields.get("image_version") != "poc-r1":
        raise AttestationRefused("not the fixed PoC image profile")
    if fields.get("compatibility_claim") != "candidate":
        raise AttestationRefused("prototype compatibility claim changed")
    if fields.get("signed_artifact_digest") is not None:
        raise AttestationRefused("release signature field is not empty")
    for name in ("unsigned_payload_digest", "partition_layout_digest"):
        value = fields.get(name)
        if type(value) is not str or not _DIGEST.fullmatch(value):
            raise AttestationRefused("prototype digest is malformed")

    # Sign the complete scalar artifact record except fields that would make
    # the signature self-referential. The separate profile string prevents this
    # local attestation from being interpreted as a production release role.
    unsigned = {
        key: value
        for key, value in fields.items()
        if key not in {"signature", "signed_artifact_digest"}
    }
    envelope = {"profile": PROFILE, "record": unsigned}
    return json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _run(args: list[str], *, data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            args,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=_OPENSSL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AttestationRefused("local attestation tool unavailable") from None


def _read_public_key(path: str | os.PathLike[str]) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            if not os.path.isfile(path):
                raise AttestationRefused("public key is not a regular file")
            key = stream.read(_MAX_PUBLIC_KEY_BYTES + 1)
    except (OSError, AttestationRefused):
        raise AttestationRefused("public key unavailable") from None
    if not key or len(key) > _MAX_PUBLIC_KEY_BYTES:
        raise AttestationRefused("public key unavailable")
    return key


def public_key_fingerprint(public_key: bytes, *, openssl: str = "openssl") -> str:
    """Return SHA-256 over canonical DER SubjectPublicKeyInfo bytes."""

    with tempfile.TemporaryDirectory(prefix="azazel-poc-key-") as temp:
        source = Path(temp) / "public.pem"
        source.write_bytes(public_key)
        result = _run(
            [openssl, "pkey", "-pubin", "-in", str(source), "-outform", "DER"]
        )
    if result.returncode != 0 or not result.stdout:
        raise AttestationRefused("public key is invalid")
    return "sha256:" + hashlib.sha256(result.stdout).hexdigest()


def sign_prototype(
    record: object,
    private_key_path: str | os.PathLike[str],
    *,
    openssl: str = "openssl",
) -> str:
    """Sign a fixed-profile prototype record; the key is read only by OpenSSL."""

    fields = _record_fields(record)
    if fields.get("signature") is not None:
        raise AttestationRefused("prototype record is already signed")
    message = _message(record)
    try:
        key_stat = os.stat(private_key_path, follow_symlinks=False)
    except OSError:
        raise AttestationRefused("local PoC signing key unavailable") from None
    if not os.path.isfile(private_key_path) or key_stat.st_mode & 0o077:
        raise AttestationRefused("local PoC signing key permissions refused")
    # Ed25519 OpenSSL's one-shot interface requires a seekable input file.
    # The signed message contains only public record metadata and digests.
    with tempfile.TemporaryDirectory(prefix="azazel-poc-sign-") as temp:
        payload = Path(temp) / "message.bin"
        payload.write_bytes(message)
        result = _run(
            [
                openssl,
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                os.fspath(private_key_path),
                "-in",
                str(payload),
            ]
        )
    if result.returncode != 0 or len(result.stdout) != 64:
        raise AttestationRefused("local PoC signing failed")
    encoded = base64.urlsafe_b64encode(result.stdout).decode("ascii").rstrip("=")
    return PREFIX + encoded


def verify_prototype(
    record: object,
    signature: str,
    *,
    public_key_path: str | os.PathLike[str],
    expected_public_key_fingerprint: str,
    openssl: str = "openssl",
) -> bool:
    """Check the local profile, exact record, Ed25519 signature and out-of-band pin."""

    if type(signature) is not str or not signature.startswith(PREFIX):
        return False
    if type(expected_public_key_fingerprint) is not str or not _PIN.fullmatch(
        expected_public_key_fingerprint
    ):
        return False
    try:
        encoded = signature[len(PREFIX) :]
        if not encoded or len(encoded) > 128 or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
            return False
        raw_sig = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if len(raw_sig) != 64:
            return False
        public_key = _read_public_key(public_key_path)
        if public_key_fingerprint(public_key, openssl=openssl) != expected_public_key_fingerprint:
            return False
        message = _message(record)
        with tempfile.TemporaryDirectory(prefix="azazel-poc-verify-") as temp:
            pub = Path(temp) / "public.pem"
            sig = Path(temp) / "signature.bin"
            payload = Path(temp) / "message.bin"
            pub.write_bytes(public_key)
            sig.write_bytes(raw_sig)
            payload.write_bytes(message)
            result = _run(
                [
                    openssl,
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(pub),
                    "-sigfile",
                    str(sig),
                    "-in",
                    str(payload),
                ]
            )
        return result.returncode == 0
    except (AttestationRefused, ValueError, OSError):
        return False
