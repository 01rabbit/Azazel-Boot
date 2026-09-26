from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tools.payload.compare_rootfs_extraction import (
    compare_documents,
    compare_files,
    main,
)


def diagnostics() -> dict:
    return {
        "schema": "azazel-payload/rootfs-extraction-diagnostics@1",
        "inspector_sha256": "sha256:" + "a" * 64,
        "observation": {
            "scope": "fixture",
            "root": "/build/rootfs",
            "filesystem": {
                "mount": {"status": "observed", "filesystem_type": "ext4"},
                "statvfs": {
                    "status": "observed",
                    "block_size": 4096,
                    "blocks_total": 100,
                    "blocks_free": 50,
                    "filesystem_id": 1,
                },
                "block_size": 4096,
            },
            "creation_order": None,
            "creation_order_status": "not_observed",
            "creation_order_explanation": "not available",
            "root_stat": {"inode": 10, "size": 4096, "blocks": 8, "block_size": 4096},
            "root_xattrs": {"status": "observed", "values": []},
        },
        "directories_in_observation_order": [
            {
                "path": ".",
                "entry_count": 2,
                "status": "observed",
                "raw_readdir_order": [
                    {"name": "one", "path": "one", "name_bytes_base64": "b25l"},
                    {"name": "two", "path": "two", "name_bytes_base64": "dHdv"},
                ],
            },
        ],
        "nodes_in_observation_order": [
            {
                "path": "one",
                "path_bytes_base64": "b25l",
                "name": "one",
                "name_bytes_base64": "b25l",
                "status": "observed",
                "stat": {
                    "mode": 33188,
                    "inode": 11,
                    "size": 3,
                    "blocks": 8,
                    "block_size": 4096,
                    "nlink": 1,
                    "mtime_ns": 100,
                },
                "xattrs": {
                    "status": "observed",
                    "values": [
                        {
                            "name": "system.posix_acl_access",
                            "value_hex": "0102",
                            "length": 2,
                        },
                    ],
                },
            },
            {
                "path": "two",
                "path_bytes_base64": "dHdv",
                "name": "two",
                "name_bytes_base64": "dHdv",
                "status": "observed",
                "stat": {
                    "mode": 33188,
                    "inode": 12,
                    "size": 3,
                    "blocks": 8,
                    "block_size": 4096,
                    "nlink": 1,
                    "mtime_ns": 100,
                },
                "xattrs": {"status": "observed", "values": []},
            },
        ],
        "normalized_name_set": [
            {"path": "one", "path_bytes_base64": "b25l"},
            {"path": "two", "path_bytes_base64": "dHdv"},
        ],
    }


class RootfsExtractionComparisonTests(unittest.TestCase):
    def test_reports_unmodified_fixture_as_strictly_identical(self) -> None:
        original = diagnostics()
        report = compare_documents(original, json.loads(json.dumps(original)))
        self.assertTrue(report["strict_identical"])
        self.assertEqual(report["diagnostics"]["mismatch_count"], 0)

    def test_preserves_order_stat_xattr_and_statvfs_differences(self) -> None:
        a = diagnostics()
        b = diagnostics()
        # These fields are frequently hidden by normalization; all stay visible.
        b["directories_in_observation_order"][0]["raw_readdir_order"].reverse()
        b["nodes_in_observation_order"][0], b["nodes_in_observation_order"][1] = (
            b["nodes_in_observation_order"][1],
            b["nodes_in_observation_order"][0],
        )
        b["nodes_in_observation_order"][1]["stat"]["blocks"] = 16
        b["nodes_in_observation_order"][1]["stat"]["inode"] = 999
        b["nodes_in_observation_order"][1]["xattrs"]["values"][0]["value_hex"] = (
            "010203"
        )
        b["observation"]["filesystem"]["statvfs"]["blocks_free"] = 49

        report = compare_documents(a, b, sample_limit=3)
        self.assertFalse(report["strict_identical"])
        categories = report["diagnostics"]["mismatches"]["categories"]
        self.assertGreater(categories["directory_readdir_order"]["mismatch_count"], 0)
        self.assertGreater(
            categories["recursive_node_observation_order"]["mismatch_count"], 0
        )
        self.assertEqual(categories["stat"]["fields"]["stat.blocks"], 1)
        self.assertEqual(categories["stat"]["fields"]["stat.inode"], 1)
        self.assertGreater(categories["xattrs_acl"]["mismatch_count"], 0)
        self.assertEqual(categories["statvfs"]["fields"]["statvfs.blocks_free"], 1)
        self.assertEqual(report["diagnostics"]["mismatches"]["samples_limit"], 3)
        self.assertEqual(len(report["diagnostics"]["mismatches"]["samples"]), 3)
        self.assertGreater(report["diagnostics"]["mismatch_count"], 3)

    def test_path_set_and_creation_order_unavailable_are_compared(self) -> None:
        a, b = diagnostics(), diagnostics()
        b["nodes_in_observation_order"].pop()
        b["observation"]["creation_order_status"] = "observed"
        report = compare_documents(a, b)
        categories = report["diagnostics"]["mismatches"]["categories"]
        self.assertIn("exact_path_set", categories)
        self.assertEqual(
            categories["creation_order"]["fields"]["creation_order_status"], 1
        )

    def test_file_digests_and_optional_build_artifact_digest_equality(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            diag_a, diag_b = root / "a.json", root / "b.json"
            bytes_a = json.dumps(diagnostics(), sort_keys=True).encode() + b"\n"
            bytes_b = (
                json.dumps(diagnostics(), indent=2, sort_keys=True).encode() + b"\n"
            )
            diag_a.write_bytes(bytes_a)
            diag_b.write_bytes(bytes_b)
            build_a, build_b = root / "build-a.json", root / "build-b.json"
            result = {
                "schema": "azazel-payload/build-result@4",
                "payload_digest": "sha256:p",
                "kernel_digest": "sha256:k",
                "initramfs_digest": "sha256:i",
                "squashfs_digest": "sha256:s",
            }
            build_a.write_text(json.dumps(result))
            result["payload_digest"] = "sha256:different"
            build_b.write_text(json.dumps(result))

            report = compare_files(
                diag_a, diag_b, build_result_a=build_a, build_result_b=build_b
            )
            self.assertFalse(report["diagnostics"]["raw_files_identical"])
            self.assertTrue(report["diagnostics"]["semantic_json_identical"])
            self.assertEqual(
                report["diagnostics"]["a"]["sha256"],
                "sha256:" + hashlib.sha256(bytes_a).hexdigest(),
            )
            artifacts = report["build_artifact_digests"]["fields"]
            self.assertFalse(artifacts["payload_sha256"]["equal"])
            self.assertTrue(artifacts["kernel_sha256"]["equal"])

    def test_cli_emits_report_and_refuses_to_overwrite_an_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            a, b = root / "a.json", root / "b.json"
            a.write_text(json.dumps(diagnostics()))
            changed = diagnostics()
            changed["observation"]["root"] = "/another/root"
            b.write_text(json.dumps(changed))

            output = io.StringIO()
            with redirect_stdout(output):
                status = main(["--diagnostics-a", str(a), "--diagnostics-b", str(b)])
            self.assertEqual(status, 1)
            self.assertFalse(json.loads(output.getvalue())["strict_identical"])

            original_a = a.read_bytes()
            with (
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                main(
                    [
                        "--diagnostics-a",
                        str(a),
                        "--diagnostics-b",
                        str(b),
                        "--output",
                        str(a),
                    ]
                )
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(a.read_bytes(), original_a)


if __name__ == "__main__":
    unittest.main()
