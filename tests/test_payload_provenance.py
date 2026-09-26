from __future__ import annotations

import hashlib
import base64
import json
import tempfile
import unittest
from pathlib import Path

from tools.payload.prepare_inputs import freeze_file, is_immutable_snapshot
from tools.payload.verify_frozen_inputs import verify


class FrozenBuildInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        self.inputs_dir = self.bundle / "frozen-inputs"
        self.inputs_dir.mkdir(parents=True)
        self.environment_root = self.root / "builder"
        self.external_source = self.environment_root / "etc/apt/sources.list.d/debian.sources"
        self.external_source.parent.mkdir(parents=True)
        self.external_source.write_text(
            "URIs: https://snapshot.debian.org/archive/debian/20260914T120000Z/\n"
        )
        self.input_paths: dict[str, Path] = {}
        for name in (
            "recipe",
            "rootfs_normalizer",
            "builder_seed_generator",
            "apt_cache_policy",
            "reproducibility_comparator",
            "package_requests",
            "quarantine_policy",
            "toolchain_lock",
            "c5_inspector",
            "initramfs_inspector",
            "rootfs_extraction_inspector",
            "nexus_source_bundle",
            "nexus_bundle_manifest",
            "nexus_guest_installer",
            "nexus_deb_packager",
            "nexus_guest_e2e",
            "nexus_qemu_runner",
            "nexus_guest_service",
            "boot_runtime_service",
            "boot_runtime_runtime",
            "boot_runtime_session_mode",
            "boot_quarantine_module",
            "boot_quarantine_refusals",
            "boot_runtime_commissioning",
            "boot_runtime_inventory",
            "boot_runtime_version",
        ):
            path = self.inputs_dir / name
            path.write_text(name)
            self.input_paths[name] = path
        self.running_recipe = self.root / "running-recipe"
        self.running_recipe.write_bytes(self.input_paths["recipe"].read_bytes())
        lock = {
            "schema": "azazel-payload/debian-toolchain-lock@2",
            "architecture": "amd64",
            "snapshot": "https://snapshot.debian.org/archive/debian/20260914T120000Z/",
            "packages": [{"name": "live-build", "version": "1:20250505+deb13u1"}],
            "apt_sources": [
                {
                    "path": "/etc/apt/sources.list.d/debian.sources",
                    "sha256": self._hash(self.external_source),
                    "content_base64": base64.b64encode(self.external_source.read_bytes()).decode(),
                }
            ],
        }
        self.input_paths["toolchain_lock"].write_text(json.dumps(lock))
        nexus_identity = {
            "commit": "a" * 40,
            "worktree_state": "dirty",
            "worktree_status_sha256": "b" * 64,
        }
        bundle_bytes = b"offline nexus bundle"
        self.input_paths["nexus_source_bundle"].write_bytes(bundle_bytes)
        self.input_paths["nexus_bundle_manifest"].write_text(json.dumps({
            "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
            "repository_identity": nexus_identity,
        }))
        inputs = {
            name: {
                "path": path.relative_to(self.bundle).as_posix(),
                "sha256": self._hash(path),
            }
            for name, path in self.input_paths.items()
        }
        manifest = {
            "schema": "azazel-payload/build-inputs@4",
            "builder": {
                "selected_for_production": False,
                "packages": lock["packages"],
            },
            "target": {
                "architecture": "amd64",
                "repository": {"snapshot": lock["snapshot"]},
                "toolchain_lock": lock,
                "nexus_source_bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
            },
            "source": {"repositories": {"nexus": nexus_identity}},
            "inputs": inputs,
        }
        self.manifest = self.bundle / "build-input-manifest.json"
        self.manifest.write_text(json.dumps(manifest))
        self.expected = self._hash(self.manifest)
        self.sidecar = self.bundle / "build-input-manifest.sha256"
        self.sidecar.write_text(f"{self.expected}  build-input-manifest.json\n")

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _hash(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_unchanged_frozen_bundle_and_toolchain_are_accepted(self) -> None:
        verify(
            self.manifest, self.bundle, self.expected, self.running_recipe,
            builder_environment_root=self.environment_root,
        )

    def test_rootfs_extraction_inspector_is_required(self) -> None:
        document = json.loads(self.manifest.read_text())
        document["inputs"].pop("rootfs_extraction_inspector")
        self.manifest.write_text(json.dumps(document))
        self.expected = self._hash(self.manifest)
        self.sidecar.write_text(f"{self.expected}  build-input-manifest.json\n")
        with self.assertRaisesRegex(ValueError, "rootfs_extraction_inspector"):
            verify(self.manifest, self.bundle, self.expected, self.running_recipe)

    def test_mutated_frozen_input_is_refused(self) -> None:
        self.input_paths["quarantine_policy"].write_text("changed")
        with self.assertRaisesRegex(ValueError, "quarantine_policy"):
            verify(self.manifest, self.bundle, self.expected, self.running_recipe)

    def test_live_recipe_drift_is_refused(self) -> None:
        self.running_recipe.write_text("different recipe")
        with self.assertRaisesRegex(ValueError, "executed recipe"):
            verify(self.manifest, self.bundle, self.expected, self.running_recipe)

    def test_manifest_digest_drift_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            verify(self.manifest, self.bundle, "0" * 64, self.running_recipe)

    def test_manifest_sidecar_drift_is_refused(self) -> None:
        self.sidecar.write_text(f"{'0' * 64}  build-input-manifest.json\n")
        with self.assertRaisesRegex(ValueError, "sidecar"):
            verify(self.manifest, self.bundle, self.expected, self.running_recipe)

    def test_old_manifest_schema_is_refused(self) -> None:
        document = json.loads(self.manifest.read_text())
        document["schema"] = "azazel-payload/build-inputs@2"
        self.manifest.write_text(json.dumps(document))
        self.expected = self._hash(self.manifest)
        self.sidecar.write_text(f"{self.expected}  build-input-manifest.json\n")
        with self.assertRaisesRegex(ValueError, "unsupported"):
            verify(self.manifest, self.bundle, self.expected, self.running_recipe)

    def test_prepare_freeze_requires_a_stable_source_hash(self) -> None:
        source = self.root / "source"
        destination = self.bundle / "frozen-inputs/source"
        source.write_text("original")
        with self.assertRaisesRegex(RuntimeError, "source changed"):
            freeze_file(source, destination, self.bundle, "0" * 64)

    def test_symlinked_frozen_input_is_refused(self) -> None:
        source = self.input_paths["quarantine_policy"]
        replacement = self.root / "replacement"
        replacement.write_text("quarantine_policy")
        source.unlink()
        source.symlink_to(replacement)
        with self.assertRaisesRegex(ValueError, "regular file"):
            verify(self.manifest, self.bundle, self.expected, self.running_recipe)

    def test_changed_apt_source_is_refused(self) -> None:
        self.external_source.write_text("URIs: https://deb.debian.org/debian\n")
        with self.assertRaisesRegex(ValueError, "APT source changed"):
            verify(
                self.manifest, self.bundle, self.expected, self.running_recipe,
                builder_environment_root=self.environment_root,
            )

    def test_apt_source_content_is_closed_by_embedded_digest(self) -> None:
        lock = json.loads(self.input_paths["toolchain_lock"].read_text())
        lock["apt_sources"][0]["content_base64"] = base64.b64encode(b"tampered").decode()
        self.input_paths["toolchain_lock"].write_text(json.dumps(lock))
        document = json.loads(self.manifest.read_text())
        document["target"]["toolchain_lock"] = lock
        document["inputs"]["toolchain_lock"]["sha256"] = self._hash(
            self.input_paths["toolchain_lock"]
        )
        self.manifest.write_text(json.dumps(document))
        self.expected = self._hash(self.manifest)
        self.sidecar.write_text(f"{self.expected}  build-input-manifest.json\n")
        with self.assertRaisesRegex(ValueError, "embedded APT source digest"):
            verify(self.manifest, self.bundle, self.expected, self.running_recipe)

    def test_snapshot_requires_an_exact_immutable_timestamp(self) -> None:
        self.assertTrue(
            is_immutable_snapshot(
                "https://snapshot.debian.org/archive/debian/20260914T120000Z/"
            )
        )
        for invalid in (
            "https://snapshot.debian.org/archive/debian/",
            "https://snapshot.debian.org/archive/debian/20260914/",
            "https://snapshot.debian.org/archive/debian/20260914T120000Z/?x=1",
            "http://snapshot.debian.org/archive/debian/20260914T120000Z/",
            "https://deb.debian.org/archive/debian/20260914T120000Z/",
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(is_immutable_snapshot(invalid))


if __name__ == "__main__":
    unittest.main()
