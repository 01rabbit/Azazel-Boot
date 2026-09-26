#!/usr/bin/env python3
"""Record unnormalized host observations of an ISO-extracted root filesystem."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


def _decode_mount_field(value: str) -> str:
    """Decode the octal escapes used by /proc/self/mountinfo."""
    result = bytearray()
    index = 0
    raw = value.encode("utf-8", errors="surrogateescape")
    while index < len(raw):
        if raw[index:index + 1] == b"\\" and index + 3 < len(raw):
            digits = raw[index + 1:index + 4]
            if all(byte in b"01234567" for byte in digits):
                result.append(int(digits, 8))
                index += 4
                continue
        result.append(raw[index])
        index += 1
    return result.decode("utf-8", errors="surrogateescape")


def _mount_for(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    candidates: list[tuple[int, dict[str, Any]]] = []
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError as exc:
        return {"status": "not_observed", "error": f"{type(exc).__name__}: {exc}"}

    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        fields = left.split()
        filesystem = right.split()
        if len(fields) < 6 or len(filesystem) < 3:
            continue
        mount_point = Path(_decode_mount_field(fields[4]))
        try:
            resolved.relative_to(mount_point)
        except ValueError:
            continue
        candidates.append((len(str(mount_point)), {
            "status": "observed",
            "mount_id": fields[0],
            "parent_mount_id": fields[1],
            "device_major_minor": fields[2],
            "root": _decode_mount_field(fields[3]),
            "mount_point": str(mount_point),
            "mount_options": fields[5].split(","),
            "optional_fields": fields[6:],
            "filesystem_type": filesystem[0],
            "source": _decode_mount_field(filesystem[1]),
            "super_options": filesystem[2].split(","),
        }))
    if not candidates:
        return {"status": "not_observed", "error": "no matching mountinfo entry"}
    return max(candidates, key=lambda candidate: candidate[0])[1]


def _statvfs(path: Path) -> dict[str, Any]:
    try:
        value = os.statvfs(path)
    except OSError as exc:
        return {"status": "not_observed", "error": f"{type(exc).__name__}: {exc}"}
    return {
        "status": "observed",
        "block_size": value.f_bsize,
        "fragment_size": value.f_frsize,
        "blocks_total": value.f_blocks,
        "blocks_free": value.f_bfree,
        "blocks_available": value.f_bavail,
        "inodes_total": value.f_files,
        "inodes_free": value.f_ffree,
        "inodes_available": getattr(value, "f_favail", None),
        "filesystem_id": value.f_fsid,
        "flags": value.f_flag,
        "name_max": value.f_namemax,
    }


def _stat(path: Path) -> dict[str, Any]:
    value = path.stat(follow_symlinks=False)
    return {
        "mode": value.st_mode,
        "mode_octal": format(stat.S_IMODE(value.st_mode), "04o"),
        "file_type": stat.filemode(value.st_mode),
        "uid": value.st_uid,
        "gid": value.st_gid,
        "inode": value.st_ino,
        "size": value.st_size,
        "blocks": getattr(value, "st_blocks", None),
        "block_size": getattr(value, "st_blksize", None),
        "nlink": value.st_nlink,
        "atime_ns": getattr(value, "st_atime_ns", None),
        "mtime_ns": getattr(value, "st_mtime_ns", None),
        "ctime_ns": getattr(value, "st_ctime_ns", None),
        "birthtime_ns": getattr(value, "st_birthtime_ns", None),
    }


def _xattrs(path: Path) -> dict[str, Any]:
    """Capture every readable xattr byte-for-byte; ACL xattrs are not special-cased."""
    if not hasattr(os, "listxattr") or not hasattr(os, "getxattr"):
        return {
            "status": "not_observed",
            "error": "xattr APIs are unavailable in this Python runtime",
            "values": [],
        }
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        return {
            "status": "not_observed",
            "error": f"{type(exc).__name__}: {exc}",
            "values": [],
        }
    values = []
    for name in sorted(names):
        try:
            raw = os.getxattr(path, name, follow_symlinks=False)
            values.append({
                "name": name,
                "name_bytes_base64": base64.b64encode(os.fsencode(name)).decode("ascii"),
                "value_hex": raw.hex(),
                "value_base64": base64.b64encode(raw).decode("ascii"),
                "length": len(raw),
                "read_status": "observed",
            })
        except OSError as exc:
            values.append({
                "name": name,
                "name_bytes_base64": base64.b64encode(os.fsencode(name)).decode("ascii"),
                "read_status": "not_observed",
                "error": f"{type(exc).__name__}: {exc}",
            })
    return {"status": "observed", "values": values}


def inspect(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"root is not a directory: {root}")

    nodes: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []
    normalized_names: list[dict[str, str]] = []

    def walk(directory: Path, relative: Path) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError as exc:
            directories.append({
                "path": relative.as_posix() or ".",
                "path_bytes_base64": base64.b64encode(os.fsencode(relative.as_posix() or ".")).decode("ascii"),
                "entry_count": None,
                "raw_readdir_order": None,
                "status": "not_observed",
                "error": f"{type(exc).__name__}: {exc}",
            })
            return

        directory_path = relative.as_posix() or "."
        raw_order = []
        child_dirs: list[tuple[Path, Path]] = []
        for entry in entries:
            name = entry.name
            child_relative = relative / name
            relative_name = child_relative.as_posix()
            name_bytes = os.fsencode(name)
            path_bytes = os.fsencode(relative_name)
            raw_order.append({
                "name": name,
                "name_bytes_base64": base64.b64encode(name_bytes).decode("ascii"),
                "path": relative_name,
                "path_bytes_base64": base64.b64encode(path_bytes).decode("ascii"),
            })
            normalized_names.append({
                "path": relative_name,
                "path_bytes_base64": base64.b64encode(path_bytes).decode("ascii"),
            })
            child_path = Path(entry.path)
            try:
                metadata = _stat(child_path)
                xattrs = _xattrs(child_path)
                nodes.append({
                    "path": relative_name,
                    "path_bytes_base64": base64.b64encode(path_bytes).decode("ascii"),
                    "name": name,
                    "name_bytes_base64": base64.b64encode(name_bytes).decode("ascii"),
                    "stat": metadata,
                    "xattrs": xattrs,
                    "status": "observed",
                })
                if stat.S_ISDIR(metadata["mode"]):
                    child_dirs.append((child_path, child_relative))
            except OSError as exc:
                nodes.append({
                    "path": relative_name,
                    "path_bytes_base64": base64.b64encode(path_bytes).decode("ascii"),
                    "name": name,
                    "name_bytes_base64": base64.b64encode(name_bytes).decode("ascii"),
                    "status": "not_observed",
                    "error": f"{type(exc).__name__}: {exc}",
                    "stat": None,
                    "xattrs": None,
                })

        directories.append({
            "path": directory_path,
            "path_bytes_base64": base64.b64encode(os.fsencode(directory_path)).decode("ascii"),
            "entry_count": len(entries),
            "raw_readdir_order": raw_order,
            "status": "observed",
        })
        for child, child_relative in child_dirs:
            walk(child, child_relative)

    root_stat = _stat(root)
    filesystem_stat = _statvfs(root)
    walk(root, Path())
    normalized_names.sort(key=lambda item: item["path_bytes_base64"])
    inspector_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return {
        "schema": "azazel-payload/rootfs-extraction-diagnostics@1",
        "inspector_sha256": f"sha256:{inspector_digest}",
        "observation": {
            "scope": "read-only host observations after extracting the ISO-embedded SquashFS with unsquashfs",
            "root": str(root),
            "filesystem": {
                "mount": _mount_for(root),
                "statvfs": filesystem_stat,
                "block_size": filesystem_stat.get("block_size") if filesystem_stat["status"] == "observed" else None,
            },
            "creation_order": None,
            "creation_order_status": "not_observed",
            "creation_order_explanation": (
                "Directory enumeration and filesystem metadata do not recover the order in "
                "which entries were created; raw readdir order is recorded separately."
            ),
            "root_stat": root_stat,
            "root_xattrs": _xattrs(root),
        },
        "directories_in_observation_order": directories,
        "nodes_in_observation_order": nodes,
        "normalized_name_set": normalized_names,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="unsquashfs extraction root")
    parser.add_argument("--output", required=True, type=Path, help="diagnostics JSON output path")
    args = parser.parse_args()
    report = inspect(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
