"""Privileged Linux writer boundary for a same-process target-code session.

The backend implementation is present for review, but physical execution is a
private build-time review gate that defaults to false. No environment variable,
CLI option, or caller flag can enable it. All device node paths remain private to this
module and are resolved from the session's opaque identity.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from azazel_boot.artifact import ArtifactRecord, Verification
from azazel_boot.linux_media import LinuxMediaSession, _Block
from azazel_boot.media import DeviceIdentity, MediaCandidate
from azazel_boot.writer import (
    ArtifactReader,
    Authorised,
    DeviceProbe,
    MediumReader,
    Planned,
    RawWriter,
    Refusal,
    Unmounter,
    WriteAuthority,
    WriteMayHaveStarted,
    WriteRefused,
    WriteResult,
)


def _physical_writer_reviewed() -> bool:
    """Build-time gate. The default installation has no runtime opt-in."""

    return False


class PhysicalWriterUnavailable(RuntimeError):
    """The destructive backend is deliberately disabled pending review."""


@dataclass(frozen=True, repr=False)
class _VerifiedArtifact:
    record: ArtifactRecord
    verification: Verification
    path: str = field(repr=False)

    def __repr__(self) -> str:
        return "_VerifiedArtifact(<redacted>)"


class VerifiedArtifactStore(Protocol):
    """Root-owned lookup by opaque artifact code; no caller-supplied path."""

    def resolve(self, artifact_code: str) -> _VerifiedArtifact: ...


class _LinuxBlockPorts(DeviceProbe, Unmounter, RawWriter, MediumReader):
    """Private Linux ports. Every entry point has the review gate as its first act."""

    def __init__(self, media: LinuxMediaSession, *, effective_uid: Callable[[], int]) -> None:
        self._media = media
        self._effective_uid = effective_uid
        self._lock = threading.RLock()
        self._write_fd: dict[str, int] = {}
        self._active_permit: object | None = None

    def _gate(self, permit: object | None = None) -> None:
        if not _physical_writer_reviewed():
            raise PhysicalWriterUnavailable(
                "physical writer is disabled pending independent review"
            )
        if self._effective_uid() != 0:
            raise PhysicalWriterUnavailable("privileged writer service is required")
        if permit is None or permit is not self._active_permit:
            raise PhysicalWriterUnavailable("authorized transaction capability is required")

    def _bind_permit(self, permit: object) -> None:
        if self._active_permit is not None:
            raise PhysicalWriterUnavailable("another write transaction is active")
        self._active_permit = permit

    def _retire_permit(self, permit: object) -> None:
        if self._active_permit is permit:
            self._active_permit = None

    def reread(self, identity: DeviceIdentity, *, _permit: object) -> MediaCandidate | None:
        self._gate(_permit)
        candidate, _ = self._media._reread_identity(identity)  # noqa: SLF001
        return candidate

    def unmount(self, identity: DeviceIdentity, *, _permit: object) -> bool:
        self._gate(_permit)
        candidate, _ = self._media._reread_identity(identity)  # noqa: SLF001
        # Mounted devices are refused, never implicitly unmounted. The operator
        # must release them and obtain a fresh list-media target code.
        return not candidate.mounted

    def write(
        self,
        identity: DeviceIdentity,
        artifact_path: str,
        expected_digest: str,
        expected_bytes: int,
        *,
        _permit: object,
    ) -> int:
        self._gate(_permit)
        token = identity.disclose()
        source_fd = self._open_artifact(artifact_path, expected_digest, expected_bytes)
        target_fd: int | None = None
        attempted = False
        written_total = 0
        try:
            _, block = self._media._reread_identity(identity)  # noqa: SLF001
            target_fd = self._open_target(block, _permit=_permit)
            # Re-enumerate after opening; the held fd and its major/minor must
            # still identify the single target code selected in this session.
            _, after_open = self._media._reread_identity(identity)  # noqa: SLF001
            if not self._same_open_target(target_fd, block, after_open):
                raise PhysicalWriterUnavailable("target changed during final recheck")
            offset = 0
            while offset < expected_bytes:
                chunk = os.pread(source_fd, min(1024 * 1024, expected_bytes - offset), offset)
                if not chunk:
                    raise PhysicalWriterUnavailable("verified artifact ended unexpectedly")
                written = 0
                while written < len(chunk):
                    count = os.pwrite(target_fd, chunk[written:], offset + written)
                    attempted = True
                    if count <= 0:
                        raise OSError("target write did not make progress")
                    written += count
                    written_total += count
                offset += len(chunk)
            os.fsync(target_fd)
            self._write_fd[token] = target_fd
            target_fd = None
            return offset
        except Exception as error:
            if attempted and target_fd is not None:
                # Retain the exact opened object for best-effort read-back. A
                # failed write/fsync is an uncertain, possibly partial write,
                # never a pre-write refusal.
                self._write_fd[token] = target_fd
                target_fd = None
                raise WriteMayHaveStarted(
                    f"write interrupted ({type(error).__name__})",
                    bytes_attempted=written_total,
                ) from None
            if isinstance(error, PhysicalWriterUnavailable):
                raise
            raise PhysicalWriterUnavailable(
                f"write refused before first write attempt ({type(error).__name__})"
            ) from None
        finally:
            cleanup_failed = False
            try:
                os.close(source_fd)
            except OSError:
                cleanup_failed = True
            if target_fd is not None:
                try:
                    os.close(target_fd)
                except OSError:
                    cleanup_failed = True
            if cleanup_failed:
                if attempted:
                    raise WriteMayHaveStarted(
                        "descriptor cleanup failed after a write attempt",
                        bytes_attempted=written_total,
                    ) from None
                raise PhysicalWriterUnavailable("descriptor cleanup failed before write")

    def digest(
        self, identity: DeviceIdentity, length: int, *, _permit: object
    ) -> str | None:
        self._gate(_permit)
        token = identity.disclose()
        fd = self._write_fd.pop(token, None)
        if fd is None or length <= 0:
            raise PhysicalWriterUnavailable("read-back has no active write transaction")
        try:
            digest = hashlib.sha256()
            offset = 0
            while offset < length:
                chunk = os.pread(fd, min(1024 * 1024, length - offset), offset)
                if not chunk:
                    raise PhysicalWriterUnavailable("read-back ended before the expected extent")
                digest.update(chunk)
                offset += len(chunk)
            return "sha256:" + digest.hexdigest()
        finally:
            os.close(fd)

    @staticmethod
    def _open_artifact(path: str, expected_digest: str, expected_bytes: int) -> int:
        if expected_bytes <= 0:
            raise PhysicalWriterUnavailable("artifact extent is invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError:
            raise PhysicalWriterUnavailable("verified artifact is unavailable") from None
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_bytes:
                raise PhysicalWriterUnavailable("artifact identity or size changed")
            digest = hashlib.sha256()
            offset = 0
            # Snapshot and hash the exact bytes that will be sent. A private,
            # unlinked temporary file prevents a concurrent writer from
            # changing the already-verified source between hash and write.
            with tempfile.TemporaryFile(mode="w+b") as snapshot:
                while offset < expected_bytes:
                    chunk = os.pread(fd, min(1024 * 1024, expected_bytes - offset), offset)
                    if not chunk:
                        raise PhysicalWriterUnavailable(
                            "artifact ended before its expected extent"
                        )
                    snapshot.write(chunk)
                    digest.update(chunk)
                    offset += len(chunk)
                after = os.fstat(fd)
                if (before.st_dev, before.st_ino, before.st_size) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                ):
                    raise PhysicalWriterUnavailable("artifact changed while snapshotting")
                if "sha256:" + digest.hexdigest() != expected_digest:
                    raise PhysicalWriterUnavailable("artifact digest changed before write")
                snapshot.flush()
                os.fsync(snapshot.fileno())
                return os.dup(snapshot.fileno())
        finally:
            os.close(fd)

    def _open_target(self, block: _Block, *, _permit: object) -> int:
        self._gate(_permit)
        if block.major is None or block.minor is None:
            raise PhysicalWriterUnavailable("target device number is unavailable")
        flags = (
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_EXCL", 0)
        )
        try:
            fd = os.open(block.node, flags)
        except OSError:
            raise PhysicalWriterUnavailable("target could not be exclusively opened") from None
        info = os.fstat(fd)
        if not stat.S_ISBLK(info.st_mode) or (os.major(info.st_rdev), os.minor(info.st_rdev)) != (
            block.major,
            block.minor,
        ):
            os.close(fd)
            raise PhysicalWriterUnavailable("opened object is not the selected block device")
        return fd

    @staticmethod
    def _same_open_target(fd: int, listed: _Block, current: _Block) -> bool:
        info = os.fstat(fd)
        devno = (os.major(info.st_rdev), os.minor(info.st_rdev))
        return (
            stat.S_ISBLK(info.st_mode)
            and listed.stable_key is not None
            and current.stable_key == listed.stable_key
            and (listed.major, listed.minor) == devno
            and (current.major, current.minor) == devno
            and not current.mounted
            and not current.root
            and not current.root_unknown
            and current.transport == "usb"
            and current.removable is True
        )


class LinuxPrivilegedWriteService:
    """Same-session writer authority intended to live only in a root service.

    The artifact store is selected by trusted service configuration. Public
    callers provide only target/artifact codes and confirmations, never paths.
    The current hard gate prevents every physical write until reviewed.
    """

    def __init__(
        self,
        media: LinuxMediaSession,
        artifact_store: VerifiedArtifactStore,
        artifact_reader: ArtifactReader,
        *,
        effective_uid: Callable[[], int] = os.geteuid,
    ) -> None:
        if effective_uid() != 0:
            raise PhysicalWriterUnavailable("privileged writer service is required")
        self._media = media
        self._store = artifact_store
        self._effective_uid = effective_uid
        self._authority = WriteAuthority(media._session, artifact_reader=artifact_reader)  # noqa: SLF001
        self._ports = _LinuxBlockPorts(media, effective_uid=effective_uid)
        self._lock = threading.RLock()

    def list_media(self):
        return self._media.list_media()

    def inspect(self, target_code: str, *, expected_digest: str, length: int):
        return self._media.inspect(
            target_code, expected_digest=expected_digest, length=length
        )

    def plan(self, target_code: str, artifact_code: str) -> Planned:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", artifact_code) is None:
            raise WriteRefused(
                Refusal.ARTIFACT_NOT_VERIFIED,
                "artifact code is invalid",
            )
        material = self._store.resolve(artifact_code)
        return self._authority.plan(
            target_code=target_code,
            record=material.record,
            verification=material.verification,
            artifact_path=material.path,
        )

    def confirm_target(self, planned: Planned, typed_code: str):
        return self._authority.confirm_target(planned, typed_code)

    def confirm_destruction(self, confirmed, typed_phrase: str) -> Authorised:
        return self._authority.confirm_destruction(confirmed, typed_phrase)

    def execute(self, authorised: Authorised) -> WriteResult:
        # This is the first operation in the destructive endpoint. Until an
        # independent review changes the source-level gate, no port is called.
        if not _physical_writer_reviewed():
            raise PhysicalWriterUnavailable(
                "physical writing is disabled pending independent review"
            )
        if self._effective_uid() != 0:
            raise PhysicalWriterUnavailable("privileged writer service is required")
        with self._lock:
            permit = object()
            self._ports._bind_permit(permit)  # noqa: SLF001
            try:
                return self._authority.execute(
                    authorised,
                    probe=_BoundProbe(self._ports, permit),
                    unmounter=_BoundUnmounter(self._ports, permit),
                    raw_writer=_BoundRawWriter(self._ports, permit),
                    reader=_BoundMediumReader(self._ports, permit),
                )
            finally:
                self._ports._retire_permit(permit)  # noqa: SLF001


class _BoundProbe:
    def __init__(self, ports: _LinuxBlockPorts, permit: object) -> None:
        self._ports = ports
        self._permit = permit

    def reread(self, identity: DeviceIdentity) -> MediaCandidate | None:
        return self._ports.reread(identity, _permit=self._permit)


class _BoundUnmounter:
    def __init__(self, ports: _LinuxBlockPorts, permit: object) -> None:
        self._ports = ports
        self._permit = permit

    def unmount(self, identity: DeviceIdentity) -> bool:
        return self._ports.unmount(identity, _permit=self._permit)


class _BoundRawWriter:
    def __init__(self, ports: _LinuxBlockPorts, permit: object) -> None:
        self._ports = ports
        self._permit = permit

    def write(
        self, identity: DeviceIdentity, artifact_path: str, expected_digest: str,
        expected_bytes: int,
    ) -> int:
        return self._ports.write(
            identity, artifact_path, expected_digest, expected_bytes,
            _permit=self._permit,
        )


class _BoundMediumReader:
    def __init__(self, ports: _LinuxBlockPorts, permit: object) -> None:
        self._ports = ports
        self._permit = permit

    def digest(self, identity: DeviceIdentity, length: int) -> str | None:
        return self._ports.digest(identity, length, _permit=self._permit)
