#!/usr/bin/env python3
"""Record initramfs cpio order, metadata, file bytes and compression headers."""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import subprocess
import zlib
from pathlib import Path
from typing import Any


CPIO_MAGICS = (b"070701", b"070702")
GZIP_MAGIC = b"\x1f\x8b\x08"
XZ_MAGIC = b"\xfd7zXZ\x00"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def align4(offset: int) -> int:
    return (offset + 3) & ~3


def parse_newc(data: bytes) -> tuple[list[dict[str, Any]], int]:
    if data[:6] not in CPIO_MAGICS:
        raise ValueError("initramfs segment is not a newc cpio archive")
    entries = []
    offset = 0
    for order in range(1_000_000):
        if offset + 110 > len(data):
            raise ValueError("truncated newc cpio header")
        magic = data[offset:offset + 6]
        if magic not in CPIO_MAGICS:
            raise ValueError(f"unexpected cpio magic at byte {offset}: {magic!r}")
        fields = [int(data[offset + 6 + i * 8:offset + 14 + i * 8], 16) for i in range(13)]
        (ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
         rdevmajor, rdevminor, namesize, check) = fields
        name_start = offset + 110
        name_end = name_start + namesize
        if namesize < 1 or name_end > len(data) or data[name_end - 1] != 0:
            raise ValueError("invalid or truncated newc filename")
        name = data[name_start:name_end - 1].decode("utf-8", errors="surrogateescape")
        data_start = align4(name_end)
        data_end = data_start + filesize
        next_offset = align4(data_end)
        if data_end > len(data) or next_offset > len(data):
            raise ValueError(f"truncated newc payload for {name!r}")
        content = data[data_start:data_end]
        if magic == b"070702" and (sum(content) & 0xFFFFFFFF) != check:
            raise ValueError(f"newc CRC mismatch for {name!r}")
        if name == "TRAILER!!!":
            return entries, next_offset
        entries.append({
            "order": order,
            "path": name,
            "ino": ino,
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "nlink": nlink,
            "mtime": mtime,
            "filesize": filesize,
            "devmajor": devmajor,
            "devminor": devminor,
            "rdevmajor": rdevmajor,
            "rdevminor": rdevminor,
            "check": check,
            "content_sha256": sha256(content),
        })
        offset = next_offset
    raise ValueError("newc archive exceeds the entry safety limit")


def compression_segment(data: bytes, offset: int) -> tuple[str, bytes, dict[str, Any], int]:
    tail = data[offset:]
    if tail.startswith(GZIP_MAGIC):
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        unpacked = decoder.decompress(tail)
        if not decoder.eof:
            raise ValueError("truncated gzip initramfs segment")
        consumed = len(tail) - len(decoder.unused_data)
        if consumed <= 0:
            raise ValueError("empty gzip initramfs segment")
        flags = tail[3]
        header = {
            "mtime": int.from_bytes(tail[4:8], "little"),
            "flags": flags,
            "xfl": tail[8],
            "os": tail[9],
            "fixed_header_hex": tail[:10].hex(),
        }
        return "gzip", unpacked, header, consumed
    if tail.startswith(XZ_MAGIC):
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        unpacked = decoder.decompress(tail)
        if not decoder.eof:
            raise ValueError("truncated xz initramfs segment")
        consumed = len(tail) - len(decoder.unused_data)
        if consumed <= 0:
            raise ValueError("empty xz initramfs segment")
        return "xz", unpacked, {"header_hex": tail[:12].hex()}, consumed
    if tail.startswith(b"\x28\xb5\x2f\xfd"):
        compressed = tail
        try:
            unpacked = subprocess.check_output(
                ["zstd", "--decompress", "--stdout", "--no-progress"],
                input=compressed,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ValueError("cannot decode pinned zstd initramfs segment") from exc
        return "zstd", unpacked, {"frame_header_hex": compressed[:18].hex()}, len(compressed)
    if tail.startswith(b"\x04\x22\x4d\x18"):
        raise ValueError("lz4 initramfs segment is unsupported by this inspector")
    raise ValueError(f"unrecognized initramfs segment at byte {offset}")


def inspect(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    offset = 0
    segments = []
    while offset < len(data):
        while offset < len(data) and data[offset] == 0:
            offset += 1
        if offset == len(data):
            break
        segment_offset = offset
        if data[offset:offset + 6] in CPIO_MAGICS:
            compression = "none"
            unpacked = data[offset:]
            header: dict[str, Any] = {}
            consumed = 0
        else:
            compression, unpacked, header, consumed = compression_segment(data, offset)
        entries, archive_bytes = parse_newc(unpacked)
        if compression == "none":
            consumed = archive_bytes
            compressed_bytes = data[offset:offset + consumed]
        else:
            if archive_bytes != len(unpacked.rstrip(b"\x00")):
                trailing = unpacked[archive_bytes:]
                if any(trailing):
                    raise ValueError("unexpected non-zero bytes after compressed cpio archive")
            compressed_bytes = data[offset:offset + consumed]
        segments.append({
            "index": len(segments),
            "compression": compression,
            "offset": segment_offset,
            "compressed_size": consumed,
            "compressed_sha256": sha256(compressed_bytes),
            "uncompressed_cpio_size": archive_bytes,
            "uncompressed_cpio_sha256": sha256(unpacked[:archive_bytes]),
            "compression_header": header,
            "entries": entries,
        })
        offset += consumed
    if not segments:
        raise ValueError("initramfs has no recognized cpio segment")
    return {
        "schema": "azazel-payload/initramfs-inspection@1",
        "artifact": path.name,
        "artifact_sha256": sha256(data),
        "artifact_size": len(data),
        "segments": segments,
        "entry_count": sum(len(segment["entries"]) for segment in segments),
        "trailing_zero_bytes": len(data) - offset,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initramfs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    measurement = inspect(args.initramfs)
    args.output.write_text(json.dumps(measurement, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"segments": len(measurement["segments"]), "entries": measurement["entry_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
