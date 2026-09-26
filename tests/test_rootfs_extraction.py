from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from tools.payload.inspect_rootfs_extraction import inspect


class RootfsExtractionDiagnosticsTests(unittest.TestCase):
    def test_captures_raw_directory_order_and_unormalized_stat_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rootfs"
            root.mkdir()
            (root / "z-last").write_text("last")
            (root / "a-first").write_text("first")
            (root / "subdir").mkdir()
            (root / "subdir" / "child").write_bytes(b"child")

            with os.scandir(root) as entries:
                expected_order = [entry.name for entry in entries]
            report = inspect(root)

        observation = report["observation"]
        self.assertEqual(report["schema"], "azazel-payload/rootfs-extraction-diagnostics@1")
        self.assertEqual(
            [entry["name"] for entry in report["directories_in_observation_order"][0]["raw_readdir_order"]],
            expected_order,
        )
        self.assertEqual(report["directories_in_observation_order"][0]["entry_count"], 3)
        self.assertIsNone(observation["creation_order"])
        self.assertEqual(observation["creation_order_status"], "not_observed")
        self.assertEqual(observation["filesystem"]["statvfs"]["status"], "observed")
        nodes = {node["path"]: node for node in report["nodes_in_observation_order"]}
        self.assertEqual(nodes["z-last"]["stat"]["size"], 4)
        self.assertIn("blocks", nodes["z-last"]["stat"])
        self.assertIn("nlink", nodes["z-last"]["stat"])
        self.assertIn("atime_ns", nodes["z-last"]["stat"])
        self.assertIn("xattrs", nodes["z-last"])

    @unittest.skipUnless(os.name == "posix", "requires POSIX byte filenames")
    def test_preserves_non_utf8_filename_as_base64_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rootfs"
            root.mkdir()
            raw_path = os.fsencode(root) + b"/name-\xff"
            try:
                fd = os.open(raw_path, os.O_CREAT | os.O_WRONLY, 0o600)
            except OSError as exc:
                self.skipTest(f"host filesystem rejects non-UTF-8 names: {exc}")
            os.close(fd)

            report = inspect(root)

        node = report["nodes_in_observation_order"][0]
        self.assertEqual(node["name_bytes_base64"], "bmFtZS3/")
        self.assertEqual(node["status"], "observed")


if __name__ == "__main__":
    unittest.main()
