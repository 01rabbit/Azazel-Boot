from __future__ import annotations

import gzip
import tempfile
import unittest
from pathlib import Path

from tools.payload.inspect_initramfs import inspect


def newc_archive(records: list[tuple[str, bytes, int]]) -> bytes:
    result = bytearray()

    def append_record(name: str, content: bytes, inode: int, mtime: int) -> None:
        encoded_name = name.encode() + b"\0"
        fields = (
            inode, 0o100644, 12, 34, 1, mtime, len(content),
            0, 0, 0, 0, len(encoded_name), 0,
        )
        result.extend(b"070701" + b"".join(f"{field:08x}".encode() for field in fields))
        result.extend(encoded_name)
        result.extend(b"\0" * ((-len(result)) % 4))
        result.extend(content)
        result.extend(b"\0" * ((-len(result)) % 4))

    for inode, (name, content, mtime) in enumerate(records, start=1):
        append_record(name, content, inode, mtime)
    append_record("TRAILER!!!", b"", 0, 0)
    return bytes(result)


class InitramfsInspectionTests(unittest.TestCase):
    def test_records_cpio_order_metadata_bytes_and_compression_header(self) -> None:
        first = newc_archive([("early-file", b"early", 123)])
        second = newc_archive([("init", b"main", 456), ("scripts/ORDER", b"a\nb\n", 789)])
        image = first + gzip.compress(second, mtime=987654321)
        with tempfile.TemporaryDirectory() as directory:
            image_path = Path(directory) / "initrd.img"
            image_path.write_bytes(image)
            report = inspect(image_path)

        self.assertEqual([segment["compression"] for segment in report["segments"]], ["none", "gzip"])
        self.assertEqual(
            [entry["path"] for entry in report["segments"][1]["entries"]],
            ["init", "scripts/ORDER"],
        )
        init_entry = report["segments"][1]["entries"][0]
        self.assertEqual((init_entry["ino"], init_entry["uid"], init_entry["gid"], init_entry["mtime"]), (1, 12, 34, 456))
        self.assertEqual(report["segments"][1]["compression_header"]["mtime"], 987654321)
        self.assertEqual(report["entry_count"], 3)

    def test_truncated_cpio_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image_path = Path(directory) / "initrd.img"
            image_path.write_bytes(b"070701truncated")
            with self.assertRaisesRegex(ValueError, "truncated"):
                inspect(image_path)


if __name__ == "__main__":
    unittest.main()
