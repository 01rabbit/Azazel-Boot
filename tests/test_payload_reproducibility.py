from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.payload.compare_builds import compare_builds, compare_extracted_metadata


class BuildComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.a = root / "build-a"
        self.b = root / "build-b"
        self.a.mkdir()
        self.b.mkdir()
        for build in (self.a, self.b):
            (build / "work/binary/live").mkdir(parents=True)
            artifacts = {
                "vmlinuz": b"kernel",
                "initrd.img": b"initramfs",
                "payload.iso": b"payload",
                "work/binary/live/filesystem.squashfs": b"squashfs",
                "filesystem.packages": b"linux-image-amd64 6.12.1\n",
                "c5-manifest.json": b"{}\n",
                "c5-result.json": b"{}\n",
                "azazel-nexus-prototype.deb": b"prototype deb\n",
                "nexus-package-summary.json": b"{}\n",
                "iso-extracted/filesystem.squashfs": b"squashfs",
                "rootfs-extracted/usr/share/azazel-nexus/azazel-nexus-prototype.deb": b"prototype deb\n",
                "iso-squashfs-extract.log": b"extract ok\n",
                "iso-unsquashfs.log": b"unsquashfs ok\n",
            }
            for name, content in artifacts.items():
                path = build / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            package_hash = hashlib.sha256(
                (build / "azazel-nexus-prototype.deb").read_bytes()
            ).hexdigest()
            (build / "azazel-nexus-prototype.deb.sha256").write_text(
                f"{package_hash}  azazel-nexus-prototype.deb\n"
            )
            (build / "rootfs-extracted/usr/share/azazel-nexus/azazel-nexus-prototype.deb.sha256").write_text(
                f"{package_hash}  azazel-nexus-prototype.deb\n"
            )
            def raw_digest(name: str) -> str:
                return hashlib.sha256((build / name).read_bytes()).hexdigest()

            (build / "components.sha256").write_text(
                "a" * 64 + "  ./EFI/bootx64.efi\n"
                + raw_digest("vmlinuz") + "  ./live/vmlinuz\n"
                + raw_digest("initrd.img") + "  ./live/initrd.img\n"
                + raw_digest("work/binary/live/filesystem.squashfs")
                + "  ./live/filesystem.squashfs\n"
            )
            (build / "rootfs-content.sha256").write_text("c" * 64 + "  ./etc/os-release\n")
            (build / "rootfs-metadata.tsv").write_text("etc/os-release\tf\t644\t0:0\t1\t10\t123\t\n")
            (build / "initrd-listing.txt").write_text("init\nscripts/init-top/ORDER\n")
            (build / "initrd-metadata.tsv").write_text("init\tf\t755\t0:0\t1\t10\t123\t\n")
            (build / "initrd-type.txt").write_text("gzip compressed data\n")
            (build / "initramfs-inspection.json").write_text(json.dumps({
                "segments": [{
                    "compression": "gzip",
                    "offset": 0,
                    "compressed_size": 100,
                    "compressed_sha256": "8" * 64,
                    "uncompressed_cpio_size": 200,
                    "uncompressed_cpio_sha256": "9" * 64,
                    "compression_header": {"mtime": 0},
                    "entries": [{"order": 1, "path": "init", "ino": 1, "mtime": 0}],
                }],
                "entry_count": 1,
            }))
            (build / "iso-boot.txt").write_text("El Torito boot record\n")
            (build / "iso-files.txt").write_text("/live/filesystem.squashfs\n")
            builder_environment = {
                "base_image": {"filename": "base.qcow2", "sha256": "1" * 64},
                "builder_seed_iso": {"filename": "seed.iso", "sha256": "2" * 64},
            }
            package_versions = [{"name": "live-build", "version": "1.0"}]
            manifest = {
                "inputs": {
                    "recipe": {"sha256": "e" * 64},
                    "rootfs_normalizer": {"sha256": "4" * 64},
                    "reproducibility_comparator": {"sha256": "3" * 64},
                    "toolchain_lock": {"sha256": "f" * 64},
                    "c5_inspector": {"sha256": "7" * 64},
                    "qemu_c5_runner": {"sha256": "0" * 64},
                    "initramfs_inspector": {"sha256": "2" * 64},
                    "nexus_deb_packager": {"sha256": "1" * 64},
                    "nexus_qemu_runner": {"sha256": "2" * 64},
                },
                "c5": {"evaluator_sha256": "6" * 64, "policy_sha256": "5" * 64},
                "normalization": {"source_date_epoch": 1789387200},
                "target": {"architecture": "amd64"},
                "builder_environment": builder_environment,
                "builder": {"packages": package_versions},
                "source": {"repositories": {"azazel": {"commit": "a" * 40}}},
            }
            manifest_bytes = json.dumps(manifest).encode()
            (build / "build-input-manifest.json").write_bytes(manifest_bytes)
            manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
            (build / "build-input-manifest.sha256").write_text(
                f"{manifest_sha256}  build-input-manifest.json\n"
            )

            def artifact_digest(name: str) -> str:
                return "sha256:" + hashlib.sha256((build / name).read_bytes()).hexdigest()

            manifest = {
                "schema": "azazel-payload/build-result@4",
                "build_input_manifest_digest": "sha256:" + manifest_sha256,
                "recipe_sha256": "e" * 64,
                "rootfs_normalizer_sha256": "4" * 64,
                "reproducibility_comparator_sha256": "3" * 64,
                "toolchain_lock_sha256": "f" * 64,
                "architecture": "amd64",
                "source_date_epoch": 1789387200,
                "input_manifest_start_sha256": "sha256:" + manifest_sha256,
                "input_manifest_end_sha256": "sha256:" + manifest_sha256,
                "frozen_inputs_start_sha256": "sha256:" + "a" * 64,
                "frozen_inputs_end_sha256": "sha256:" + "a" * 64,
                "builder_instance_id_sha256": "sha256:" + ("b" if build == self.a else "c") * 64,
                "evidence_report_digests": {
                    name: artifact_digest(name)
                    for name in (
                        "components.sha256", "filesystem.packages",
                        "initrd-listing.txt", "initrd-type.txt",
                        "initramfs-inspection.json", "initrd-metadata.tsv",
                        "rootfs-content.sha256", "rootfs-metadata.tsv",
                        "iso-boot.txt", "iso-files.txt",
                        "c5-manifest.json", "c5-result.json",
                        "nexus-package-summary.json",
                        "iso-squashfs-extract.log", "iso-unsquashfs.log",
                    )
                },
                "builder_environment": builder_environment,
                "builder_tool_versions": package_versions,
                "source_repositories": {"azazel": {"commit": "a" * 40}},
                "c5_inspector_sha256": "7" * 64,
                "qemu_c5_runner_sha256": "0" * 64,
                "initramfs_inspector_sha256": "2" * 64,
                "c5_evaluator_sha256": "6" * 64,
                "c5_policy_sha256": "5" * 64,
                "nexus_deb_packager_sha256": "1" * 64,
                "nexus_qemu_runner_sha256": "2" * 64,
                "nexus_package_digest": artifact_digest("azazel-nexus-prototype.deb"),
                "nexus_package_in_iso_rootfs_digest": artifact_digest("rootfs-extracted/usr/share/azazel-nexus/azazel-nexus-prototype.deb"),
                "iso_embedded_squashfs_digest": artifact_digest("iso-extracted/filesystem.squashfs"),
                "nexus_package_sha256_sidecar_digest": artifact_digest("azazel-nexus-prototype.deb.sha256"),
                "nexus_package_summary_digest": artifact_digest("nexus-package-summary.json"),
                "kernel_digest": artifact_digest("vmlinuz"),
                "initramfs_digest": artifact_digest("initrd.img"),
                "squashfs_digest": artifact_digest("work/binary/live/filesystem.squashfs"),
                "payload_digest": artifact_digest("payload.iso"),
                "c5_manifest_digest": artifact_digest("c5-manifest.json"),
                "c5_result_digest": artifact_digest("c5-result.json"),
                "component_digest_manifest": "components.sha256",
                "rootfs_file_content_manifest": "rootfs-content.sha256",
                "rootfs_metadata": "rootfs-metadata.tsv",
                "initramfs_entry_listing": "initrd-listing.txt",
                "initramfs_container_type": "initrd-type.txt",
                "initramfs_inspection": "initramfs-inspection.json",
                "initramfs_extracted_metadata": "initrd-metadata.tsv",
                "iso_boot_metadata": "iso-boot.txt",
                "iso_file_metadata": "iso-files.txt",
            }
            (build / "build-result.json").write_text(json.dumps(manifest))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_extracted_metadata_ignores_host_inode_numbers(self) -> None:
        left = Path(self.temp.name) / "metadata-a.tsv"
        right = Path(self.temp.name) / "metadata-b.tsv"
        left.write_text("etc/os-release\tf\t644\t0:0\t101\t10\t123\t\n")
        right.write_text("etc/os-release\tf\t644\t0:0\t902\t10\t123\t\n")

        compared = compare_extracted_metadata(left, right)

        self.assertTrue(compared["equal"])
        self.assertEqual(compared["ignored_extraction_observations"]["counts"]["host_inode"], 1)

    def test_initramfs_extraction_ignores_directory_time_but_not_file_time(self) -> None:
        left = Path(self.temp.name) / "metadata-a.tsv"
        right = Path(self.temp.name) / "metadata-b.tsv"
        left.write_text(
            "scripts\td\t755\t0:0\t101\t4096\t100\t\n"
            "scripts/init\tf\t755\t0:0\t102\t10\t123\t\n"
        )
        right.write_text(
            "scripts\td\t755\t0:0\t902\t4096\t200\t\n"
            "scripts/init\tf\t755\t0:0\t903\t10\t124\t\n"
        )

        compared = compare_extracted_metadata(
            left, right, transient_directory_mtime=True
        )

        self.assertFalse(compared["equal"])
        self.assertEqual(compared["changed_paths"], ["scripts/init"])
        self.assertEqual(
            compared["ignored_extraction_observations"]["counts"]["extracted_directory_mtime"],
            1,
        )

    def test_rootfs_extraction_can_ignore_directory_size_only(self) -> None:
        left = Path(self.temp.name) / "metadata-a.tsv"
        right = Path(self.temp.name) / "metadata-b.tsv"
        left.write_text("usr/share/man/man7\td\t755\t0:0\t101\t16384\t123\t\n")
        right.write_text("usr/share/man/man7\td\t755\t0:0\t902\t20480\t123\t\n")

        compared = compare_extracted_metadata(
            left, right, ignore_extracted_directory_size=True
        )

        self.assertTrue(compared["equal"])
        self.assertEqual(
            compared["ignored_extraction_observations"]["counts"]["extracted_directory_size"],
            1,
        )
        self.assertEqual(
            compared["ignored_extraction_observations"]["paths_sample"],
            ["usr/share/man/man7"],
        )

    def test_directory_size_normalization_preserves_other_metadata_and_paths(self) -> None:
        left = Path(self.temp.name) / "metadata-a.tsv"
        right = Path(self.temp.name) / "metadata-b.tsv"
        left.write_text(
            "one\td\t755\t0:0\t101\t16384\t123\t\n"
            "removed\td\t755\t0:0\t102\t4096\t123\t\n"
        )
        right.write_text(
            "one\td\t700\t1:1\t902\t20480\t124\t\n"
            "added\td\t755\t0:0\t903\t4096\t123\t\n"
        )

        compared = compare_extracted_metadata(
            left, right, ignore_extracted_directory_size=True
        )

        self.assertFalse(compared["equal"])
        self.assertEqual(compared["changed_paths"], ["added", "one", "removed"])

    def test_directory_size_normalization_does_not_ignore_file_size_or_content(self) -> None:
        left = Path(self.temp.name) / "metadata-a.tsv"
        right = Path(self.temp.name) / "metadata-b.tsv"
        left.write_text("usr/share/data\tf\t644\t0:0\t101\t10\t123\t\n")
        right.write_text("usr/share/data\tf\t644\t0:0\t902\t11\t123\t\n")

        compared = compare_extracted_metadata(
            left, right, ignore_extracted_directory_size=True
        )

        self.assertFalse(compared["equal"])
        self.assertEqual(compared["changed_paths"], ["usr/share/data"])

    def test_equal_payloads_require_and_report_same_locked_inputs(self) -> None:
        result = compare_builds(self.a, self.b)
        self.assertEqual(result["result"], "reproduced")
        self.assertIsNone(result["first_divergence"])
        self.assertTrue(result["same_pinned_inputs"])
        self.assertIn("post_build_analyzer_source", result["analyzer"]["digest_scope"])
        self.assertEqual(
            result["analyzer"]["post_build_analyzer_sha256"],
            result["analyzer"]["sha256"],
        )
        self.assertEqual(
            result["analyzer"]["frozen_build_comparator_sha256"],
            result["analyzer"]["pinned_build_comparator_sha256"],
        )
        self.assertIn(
            "distinct from this post-build analyzer digest",
            result["analyzer"]["pinned_build_comparator_digest_scope"],
        )

    def test_rootfs_extracted_directory_size_is_reported_as_observation(self) -> None:
        metadata_a = self.a / "rootfs-metadata.tsv"
        metadata_b = self.b / "rootfs-metadata.tsv"
        metadata_a.write_text(
            "etc/os-release\tf\t644\t0:0\t1\t10\t123\t\n"
            "usr/lib/systemd/system\td\t755\t0:0\t2\t16384\t123\t\n"
        )
        metadata_b.write_text(
            "etc/os-release\tf\t644\t0:0\t1\t10\t123\t\n"
            "usr/lib/systemd/system\td\t755\t0:0\t3\t20480\t123\t\n"
        )
        for build, metadata in ((self.a, metadata_a), (self.b, metadata_b)):
            result_path = build / "build-result.json"
            result = json.loads(result_path.read_text())
            result["evidence_report_digests"]["rootfs-metadata.tsv"] = (
                "sha256:" + hashlib.sha256(metadata.read_bytes()).hexdigest()
            )
            result_path.write_text(json.dumps(result))

        measured = compare_builds(self.a, self.b)

        self.assertTrue(measured["checks"]["rootfs_metadata"])
        self.assertEqual(
            measured["rootfs"]["metadata_comparison"]["ignored_extraction_observations"]
            ["counts"]["extracted_directory_size"],
            1,
        )
        self.assertIn(
            "not payload directory metadata",
            measured["rootfs"]["metadata_comparison"]["ignored_extraction_observations"]
            ["details"]["extracted_directory_size"],
        )

    def test_rootfs_content_difference_remains_a_reproducibility_failure(self) -> None:
        content_b = self.b / "rootfs-content.sha256"
        content_b.write_text("d" * 64 + "  ./etc/os-release\n")
        result_path = self.b / "build-result.json"
        result = json.loads(result_path.read_text())
        result["evidence_report_digests"]["rootfs-content.sha256"] = (
            "sha256:" + hashlib.sha256(content_b.read_bytes()).hexdigest()
        )
        result_path.write_text(json.dumps(result))

        measured = compare_builds(self.a, self.b)

        self.assertFalse(measured["checks"]["rootfs_file_contents"])
        self.assertEqual(measured["first_divergence"], "rootfs_file_contents")

    def test_different_manifest_is_not_a_reproducibility_comparison(self) -> None:
        result_path = self.b / "build-result.json"
        result = json.loads(result_path.read_text())
        input_manifest_path = self.b / "build-input-manifest.json"
        input_manifest = json.loads(input_manifest_path.read_text())
        input_manifest["target"]["architecture"] = "arm64"
        manifest_bytes = json.dumps(input_manifest).encode()
        input_manifest_path.write_bytes(manifest_bytes)
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        (self.b / "build-input-manifest.sha256").write_text(
            f"{manifest_sha256}  build-input-manifest.json\n"
        )
        result["architecture"] = "arm64"
        result["build_input_manifest_digest"] = "sha256:" + manifest_sha256
        result_path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, "manifest changed during build"):
            compare_builds(self.a, self.b)

    def test_same_builder_instance_is_not_independent(self) -> None:
        result_path = self.b / "build-result.json"
        result = json.loads(result_path.read_text())
        result["builder_instance_id_sha256"] = json.loads(
            (self.a / "build-result.json").read_text()
        )["builder_instance_id_sha256"]
        result_path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, "distinct builder instances"):
            compare_builds(self.a, self.b)

    def test_frozen_input_start_end_mismatch_is_refused(self) -> None:
        result_path = self.b / "build-result.json"
        result = json.loads(result_path.read_text())
        result["frozen_inputs_end_sha256"] = "sha256:" + "d" * 64
        result_path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, "frozen inputs changed during build"):
            compare_builds(self.a, self.b)

    def test_tampered_evidence_report_is_refused(self) -> None:
        (self.b / "rootfs-metadata.tsv").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "evidence report digest mismatch"):
            compare_builds(self.a, self.b)

    def test_reports_squashfs_as_first_divergence(self) -> None:
        result_path = self.b / "build-result.json"
        result = json.loads(result_path.read_text())
        squashfs = self.b / "work/binary/live/filesystem.squashfs"
        squashfs.write_bytes(b"different squashfs")
        payload = self.b / "payload.iso"
        payload.write_bytes(b"different payload")
        result["squashfs_digest"] = "sha256:" + hashlib.sha256(squashfs.read_bytes()).hexdigest()
        result["payload_digest"] = "sha256:" + hashlib.sha256(payload.read_bytes()).hexdigest()
        components = self.b / "components.sha256"
        components.write_text(
            "a" * 64 + "  ./EFI/bootx64.efi\n"
            + hashlib.sha256((self.b / "vmlinuz").read_bytes()).hexdigest()
            + "  ./live/vmlinuz\n"
            + hashlib.sha256((self.b / "initrd.img").read_bytes()).hexdigest()
            + "  ./live/initrd.img\n"
            + hashlib.sha256(squashfs.read_bytes()).hexdigest()
            + "  ./live/filesystem.squashfs\n"
        )
        result["evidence_report_digests"]["components.sha256"] = (
            "sha256:" + hashlib.sha256(components.read_bytes()).hexdigest()
        )
        result_path.write_text(json.dumps(result))
        measured = compare_builds(self.a, self.b)
        self.assertEqual(measured["first_divergence"], "squashfs")
        self.assertFalse(measured["checks"]["squashfs"])

    def test_reports_initramfs_compression_header_drift(self) -> None:
        inspection_path = self.b / "initramfs-inspection.json"
        inspection = json.loads(inspection_path.read_text())
        inspection["segments"][0]["compression_header"]["mtime"] = 1
        inspection_path.write_text(json.dumps(inspection))
        result_path = self.b / "build-result.json"
        result = json.loads(result_path.read_text())
        result["evidence_report_digests"]["initramfs-inspection.json"] = (
            "sha256:" + hashlib.sha256(inspection_path.read_bytes()).hexdigest()
        )
        result_path.write_text(json.dumps(result))
        measured = compare_builds(self.a, self.b)
        self.assertEqual(measured["first_divergence"], "initramfs_archive_structure")
        change = measured["initramfs"]["newc_archive_comparison"]["segment_changes"][0]
        self.assertEqual(change["field"], "compression_header")


if __name__ == "__main__":
    unittest.main()
