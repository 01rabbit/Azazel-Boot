"""Linux read-only media discovery bound to one in-process media session.

This module keeps kernel device names and stable hardware identifiers inside
the backend. Public callers receive only ``MediaOffer`` values with opaque,
single-session target codes. No function in this module writes to a device.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from azazel_boot.media import (
    DeviceIdentity,
    Eligibility,
    MediaCandidate,
    MediaOffer,
    MediaSession,
    SelectionRefused,
    assess,
)
from azazel_boot.refusals import Refused
from azazel_boot.writer import REVERIFIED_ATTRIBUTES, Inspection


class LinuxMediaRefused(Refused):
    """Sanitized refusal; messages never include node names or device IDs."""


@dataclass(frozen=True, repr=False)
class _Block:
    node: str
    kname: str
    kind: str
    bytes: int
    removable: bool | None
    transport: str | None
    partition_table: str | None
    major: int | None
    minor: int | None
    stable_key: str | None = field(repr=False)
    bus_position: str | None
    mounted: bool
    root: bool
    root_unknown: bool

    def __repr__(self) -> str:
        return "_Block(<redacted>)"


class BlockInventory(Protocol):
    def enumerate(self) -> tuple[_Block, ...]: ...


class ReadOnlyBlockReader(Protocol):
    def digest(self, block: _Block, length: int) -> str | None: ...


def _optional_bool(value: object) -> bool | None:
    if value is True or value == 1:
        return True
    if value is False or value == 0:
        return False
    return None


def _mountpoints(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str) and item)
    return ()


def _bus_position(sysfs_root: Path, kname: str) -> str | None:
    device_link = sysfs_root / "class" / "block" / kname / "device"
    try:
        resolved = Path(os.path.realpath(device_link))
        value = str(resolved)
    except OSError:
        return None
    # Linux USB topology components (for example 2-1.3) identify the port,
    # without displaying model, serial, WWN, or the kernel device node.
    matches = [
        part
        for part in value.split("/")
        if re.fullmatch(r"\d+-\d+(?:\.\d+)*", part)
    ]
    return matches[-1] if matches else None


class LinuxLsblkInventory:
    """Read-only lsblk/sysfs inventory. It never opens a block device."""

    def __init__(self, *, sysfs_root: Path = Path("/sys")) -> None:
        self._sysfs_root = sysfs_root

    def enumerate(self) -> tuple[_Block, ...]:
        if not sys.platform.startswith("linux"):
            raise LinuxMediaRefused("native media discovery is supported on Linux only")
        try:
            result = subprocess.run(
                [
                    "lsblk",
                    "--json",
                    "--bytes",
                    "--paths",
                    "--output",
                    "PATH,KNAME,TYPE,SIZE,RM,TRAN,PKNAME,PTTYPE,WWN,SERIAL,MAJ:MIN,MOUNTPOINTS",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            document = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            raise LinuxMediaRefused("Linux block inventory is unavailable") from None

        if not isinstance(document, dict) or not isinstance(document.get("blockdevices"), list):
            raise LinuxMediaRefused("Linux block inventory is malformed")

        nodes: list[dict[str, object]] = []

        def flatten(entries: list[object], parent: str | None = None) -> None:
            for value in entries:
                if not isinstance(value, dict):
                    raise LinuxMediaRefused("Linux block inventory is malformed")
                kname = value.get("kname")
                if not isinstance(kname, str) or not kname:
                    raise LinuxMediaRefused("Linux block identity is unavailable")
                node = dict(value)
                node["_parent"] = value.get("pkname") or parent
                nodes.append(node)
                children = value.get("children")
                if children is not None:
                    if not isinstance(children, list):
                        raise LinuxMediaRefused("Linux block inventory is malformed")
                    flatten(children, kname)

        flatten(document["blockdevices"])
        by_kname = {str(item["kname"]): item for item in nodes}
        if len(by_kname) != len(nodes):
            raise LinuxMediaRefused("duplicate Linux block identities")

        root_names = {
            str(item["kname"])
            for item in nodes
            if "/" in _mountpoints(item.get("mountpoints"))
        }
        root_unknown = not root_names

        def disk_ancestor(kname: str) -> str | None:
            seen: set[str] = set()
            current = kname
            while current and current not in seen:
                seen.add(current)
                item = by_kname.get(current)
                if item is None:
                    return None
                if item.get("type") == "disk":
                    return current
                parent = item.get("_parent")
                current = str(parent) if parent else ""
            return None

        root_disks = {disk_ancestor(name) for name in root_names}
        root_ancestor_unknown = bool(root_names) and None in root_disks
        root_disks.discard(None)

        blocks: list[_Block] = []
        for item in nodes:
            if item.get("type") != "disk":
                continue
            node = item.get("path")
            kname = item.get("kname")
            size = item.get("size")
            tran = item.get("tran")
            major_minor = item.get("maj:min")
            rm = _optional_bool(item.get("rm"))
            if (
                not isinstance(node, str)
                or not node.startswith("/dev/")
                or not isinstance(kname, str)
                or type(size) is not int
                or size <= 0
            ):
                # An unclassifiable entry is omitted; it cannot receive a code.
                continue
            major: int | None = None
            minor: int | None = None
            if isinstance(major_minor, str) and ":" in major_minor:
                try:
                    major, minor = (int(part) for part in major_minor.split(":", 1))
                except ValueError:
                    major = minor = None

            descendants = {kname}
            changed = True
            while changed:
                changed = False
                for child in nodes:
                    if (
                        child.get("_parent") in descendants
                        and child.get("kname") not in descendants
                    ):
                        descendants.add(str(child["kname"]))
                        changed = True
            mounted = any(
                "mountpoints" not in by_kname[name]
                or bool(_mountpoints(by_kname[name].get("mountpoints")))
                for name in descendants
                if name in by_kname
            )
            stable_components = (
                str(item.get("wwn") or ""),
                str(item.get("serial") or ""),
                kname,
            )
            stable_value = "\x1f".join(stable_components)
            stable_key = (
                hashlib.sha256(stable_value.encode("utf-8")).hexdigest()
                if stable_components[0] or stable_components[1]
                else None
            )
            bus = _bus_position(self._sysfs_root, kname)
            blocks.append(
                _Block(
                    node=node,
                    kname=kname,
                    kind="disk",
                    bytes=size,
                    removable=rm,
                    transport=tran.lower() if isinstance(tran, str) else None,
                    partition_table=(
                        str(item["pttype"]) if item.get("pttype") is not None else None
                    ),
                    major=major,
                    minor=minor,
                    stable_key=stable_key,
                    bus_position=bus,
                    mounted=mounted,
                    root=root_unknown or root_ancestor_unknown or kname in root_disks,
                    root_unknown=root_unknown or root_ancestor_unknown,
                )
            )
        return tuple(blocks)


class LinuxReadOnlyBlockReader:
    """Reads a bounded digest from a revalidated block node; never writes."""

    def digest(self, block: _Block, length: int) -> str | None:
        if (
            length <= 0
            or length > block.bytes
            or block.major is None
            or block.minor is None
        ):
            raise LinuxMediaRefused("requested inspection extent is invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(block.node, flags)
        except OSError:
            raise LinuxMediaRefused("target is no longer readable") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISBLK(info.st_mode):
                raise LinuxMediaRefused("target is not a block device")
            if (os.major(info.st_rdev), os.minor(info.st_rdev)) != (block.major, block.minor):
                raise LinuxMediaRefused("target identity changed")
            digest = hashlib.sha256()
            offset = 0
            while offset < length:
                chunk = os.pread(fd, min(1024 * 1024, length - offset), offset)
                if not chunk:
                    raise LinuxMediaRefused("target ended before the requested extent")
                digest.update(chunk)
                offset += len(chunk)
            return "sha256:" + digest.hexdigest()
        finally:
            os.close(fd)


class LinuxMediaSession:
    """One ephemeral target-code session for read-only list-media and inspect."""

    def __init__(
        self,
        inventory: BlockInventory,
        reader: ReadOnlyBlockReader,
        *,
        session_id: str | None = None,
    ) -> None:
        self._inventory = inventory
        self._reader = reader
        self._session = MediaSession(session_id or "m-" + secrets.token_hex(8))
        self._blocks_by_token: dict[str, _Block] = {}
        self._candidates_by_token: dict[str, MediaCandidate] = {}
        self._blocks_by_code: dict[str, _Block] = {}

    @classmethod
    def from_system(cls) -> LinuxMediaSession:
        if not sys.platform.startswith("linux"):
            raise LinuxMediaRefused("native media discovery is supported on Linux only")
        return cls(LinuxLsblkInventory(), LinuxReadOnlyBlockReader())

    def list_media(self) -> tuple[MediaOffer, ...]:
        blocks = self._inventory.enumerate()
        self._blocks_by_token.clear()
        self._candidates_by_token.clear()
        self._blocks_by_code.clear()
        stable_counts: dict[str, int] = {}
        for block in blocks:
            if block.stable_key is not None:
                stable_counts[block.stable_key] = stable_counts.get(block.stable_key, 0) + 1
        candidates: list[MediaCandidate] = []
        candidate_blocks: list[_Block] = []
        for block in blocks:
            token = secrets.token_hex(24)
            duplicate = block.stable_key is None or stable_counts.get(block.stable_key) != 1
            transport = block.transport
            removable = (
                block.removable
                if transport == "usb" and block.bus_position is not None
                else None
            )
            candidate = MediaCandidate(
                identity=DeviceIdentity(token),
                capacity_bytes=block.bytes,
                partition_table=block.partition_table,
                bus_path=(
                    f"USB port {block.bus_position}"
                    if transport == "usb" and block.bus_position is not None
                    else "unclassified"
                ),
                physical_label="USB mass storage" if transport == "usb" else None,
                removable=removable,
                mounted=block.mounted,
                internal=(
                    transport != "usb"
                    or duplicate
                    or block.major is None
                    or block.minor is None
                ),
                holds_running_root=block.root or block.root_unknown,
            )
            candidates.append(candidate)
            candidate_blocks.append(block)
            self._blocks_by_token[token] = block
            self._candidates_by_token[token] = candidate

        offers = self._session.offer(candidates)
        for offer, block in zip(offers, candidate_blocks, strict=True):
            if offer.target_code is not None and offer.eligibility is Eligibility.ELIGIBLE:
                self._blocks_by_code[offer.target_code] = block
        return offers

    def _resolve_current(self, target_code: str) -> tuple[MediaCandidate, _Block]:
        try:
            listed = self._session.claim(target_code)
        except SelectionRefused:
            raise LinuxMediaRefused("target code is unknown, expired, or already used") from None
        original = self._blocks_by_code.pop(target_code, None)
        if original is None:
            raise LinuxMediaRefused("target code is unknown, expired, or already used")
        token = listed.identity.disclose()
        if (
            original.stable_key is None
            or self._blocks_by_token.get(token) is not original
            or self._candidates_by_token.get(token) is not listed
        ):
            # Session identities are opaque tokens, not hardware keys. This
            # branch should be unreachable; retain fail-closed behavior if the
            # private code-to-block association is ever corrupted.
            raise LinuxMediaRefused("target code no longer matches its private listing")
        candidate, block = self._reread_identity(listed.identity)
        return candidate, block

    def _reread_identity(self, identity: DeviceIdentity) -> tuple[MediaCandidate, _Block]:
        token = identity.disclose()
        original = self._blocks_by_token.get(token)
        listed = self._candidates_by_token.get(token)
        if original is None or listed is None:
            raise LinuxMediaRefused("target identity is not part of this session")
        current = self._inventory.enumerate()
        matches = [block for block in current if block.stable_key == original.stable_key]
        if original.stable_key is None or len(matches) != 1:
            raise LinuxMediaRefused("target identity could not be re-established")
        block = matches[0]
        listed_block = original
        if (block.major, block.minor) != (listed_block.major, listed_block.minor):
            raise LinuxMediaRefused("target device number changed since enumeration")
        if block.root_unknown or block.root:
            raise LinuxMediaRefused("target may contain the running root filesystem")
        candidate = MediaCandidate(
            identity=identity,
            capacity_bytes=block.bytes,
            partition_table=block.partition_table,
            bus_path=(
                f"USB port {block.bus_position}"
                if block.transport == "usb" and block.bus_position is not None
                else "unclassified"
            ),
            physical_label="USB mass storage" if block.transport == "usb" else None,
            removable=(
                block.removable
                if block.transport == "usb" and block.bus_position is not None
                else None
            ),
            mounted=block.mounted,
            internal=(
                block.transport != "usb"
                or block.major is None
                or block.minor is None
            ),
            holds_running_root=block.root or block.root_unknown,
        )
        for attribute in REVERIFIED_ATTRIBUTES:
            if getattr(candidate, attribute) != getattr(listed, attribute):
                raise LinuxMediaRefused("target changed since enumeration")
        if assess(candidate) is not Eligibility.ELIGIBLE:
            raise LinuxMediaRefused("target is no longer eligible")
        return candidate, block

    def _block_for_identity(self, identity: DeviceIdentity) -> _Block:
        token = identity.disclose()
        block = self._blocks_by_token.get(token)
        if block is None:
            raise LinuxMediaRefused("target identity is not part of this session")
        return block

    def inspect(
        self,
        target_code: str,
        *,
        expected_digest: str,
        length: int,
    ) -> Inspection:
        """Revalidate a listed target and inspect its prefix read-only."""

        _, block = self._resolve_current(target_code)
        if length <= 0 or length > block.bytes:
            raise LinuxMediaRefused("requested inspection extent is invalid")
        measured = self._reader.digest(block, length)
        return Inspection(
            matches=measured == expected_digest,
            expected_digest=expected_digest,
            measured_digest=measured,
        )

    def _claim_for_privileged_writer(self, target_code: str) -> tuple[MediaCandidate, _Block]:
        """Private handoff reserved for the separately reviewed privileged service."""

        return self._resolve_current(target_code)
