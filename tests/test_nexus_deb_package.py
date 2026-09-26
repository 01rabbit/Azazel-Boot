from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools/payload/package_nexus_deb.py"
SPEC = importlib.util.spec_from_file_location("package_nexus_deb", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class NexusDebPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bundle = self.root / "nexus-source.tar.gz"
        self.manifest = self.root / "nexus-source.manifest.json"
        self.files = {
            "packaging/install.sh": (b"#!/bin/sh\nexit 0\n", 0o755),
            "packaging/azazel-nexus.preset": (b"disable *\n", 0o644),
            "packaging/systemd/azazel-activated.service": (b"[Unit]\n", 0o644),
            "pyproject.toml": (
                b"[project.scripts]\nazazel-nexus = 'azazel_nexus.cli:main'\n",
                0o644,
            ),
            "runtime/pyproject.toml": (
                b"[project.scripts]\naz-activated = 'azazel_nexus_runtime.activated:main'\n"
                b"az-core-reserve-probe = 'azazel_nexus_runtime.core_reserve_probe:main'\n",
                0o644,
            ),
            "src/azazel_nexus/__init__.py": (b"CORE = True\n", 0o644),
            "src/azazel_nexus/cli.py": (b"def main(): return 0\n", 0o644),
            "runtime/src/azazel_nexus_runtime/__init__.py": (b"RUNTIME = True\n", 0o644),
            "runtime/src/azazel_nexus_runtime/activated.py": (b"def main(): return 0\n", 0o644),
            "runtime/src/azazel_nexus_runtime/core_reserve_probe.py": (
                b"def main(): return 0\n",
                0o644,
            ),
        }
        self._write_bundle(self.files)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_bundle(self, files: dict[str, tuple[bytes, int]]) -> None:
        raw_tar = io.BytesIO()
        entries = []
        with tarfile.open(fileobj=raw_tar, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for path, (content, mode) in files.items():
                info = tarfile.TarInfo(path)
                info.mode = mode
                info.size = len(content)
                info.mtime = 1_700_000_000
                archive.addfile(info, io.BytesIO(content))
                entries.append({
                    "path": path,
                    "mode": f"{mode:04o}",
                    "size": len(content),
                    "sha256": sha256(content),
                })
        compressed = gzip.compress(raw_tar.getvalue(), mtime=0)
        self.bundle.write_bytes(compressed)
        manifest = {
            "schema": "azazel-nexus-offline-source-bundle@1",
            "archive": self.bundle.name,
            "archive_size": len(compressed),
            "bundle_sha256": sha256(compressed),
            "files": entries,
        }
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

    def _build(self, name: str = "out") -> dict:
        return MODULE.build_package(self.bundle, self.manifest, self.root / name)

    def test_stages_prototype_package_layout_entrypoints_and_deterministic_metadata(self) -> None:
        summary = self._build()
        package_root = self.root / "out/package-root"
        control = (package_root / "DEBIAN/control").read_text(encoding="utf-8")
        self.assertIn("Package: azazel-nexus-prototype\n", control)
        self.assertIn("Architecture: all\n", control)
        self.assertFalse((package_root / "DEBIAN/postinst").exists())
        self.assertFalse((package_root / "DEBIAN/prerm").exists())
        self.assertEqual(
            (package_root / "usr/lib/python3/dist-packages/azazel_nexus/cli.py").read_bytes(),
            self.files["src/azazel_nexus/cli.py"][0],
        )
        self.assertEqual(
            (package_root / "usr/lib/python3/dist-packages/azazel_nexus_runtime/activated.py").read_bytes(),
            self.files["runtime/src/azazel_nexus_runtime/activated.py"][0],
        )
        self.assertEqual(
            (package_root / "usr/lib/azazel-nexus/packaging/install.sh").read_bytes(),
            self.files["packaging/install.sh"][0],
        )
        self.assertEqual(
            (package_root / "usr/lib/azazel-nexus/packaging/install.sh").stat().st_mode & 0o777,
            0o755,
        )
        self.assertEqual(
            (package_root / "usr/bin/azazel-nexus").stat().st_mode & 0o777,
            0o755,
        )
        self.assertTrue((package_root / "usr/libexec/azazel/az-activated").is_file())
        self.assertTrue((package_root / "usr/libexec/azazel/az-core-reserve-probe").is_file())
        self.assertTrue(
            (package_root / "usr/lib/azazel-nexus/packaging/systemd/azazel-activated.service").is_file()
        )
        self.assertEqual(summary["maintainer_scripts"], [])
        self.assertEqual(summary["production_packaging_selection"], "open")
        self.assertEqual(summary["normalized_mtime_epoch"], 0)
        self.assertTrue(all(path.stat().st_mtime == 0 for path in package_root.rglob("*")))
        saved_summary = json.loads((self.root / "out/package-summary.json").read_text())
        self.assertEqual(saved_summary, summary)

    def test_rejects_path_traversal_before_staging(self) -> None:
        unsafe = dict(self.files)
        unsafe["../escaped"] = (b"bad", 0o644)
        self._write_bundle(unsafe)
        with self.assertRaisesRegex(ValueError, "unsafe bundle member path"):
            self._build("unsafe-out")
        self.assertFalse((self.root / "unsafe-out/package-root").exists())
        self.assertFalse((self.root / "escaped").exists())

    def test_rejects_bundle_digest_mismatch(self) -> None:
        changed = bytearray(self.bundle.read_bytes())
        changed[-1] ^= 1
        self.bundle.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, "bundle digest differs"):
            self._build("bad-digest-out")
        self.assertFalse((self.root / "bad-digest-out/package-root").exists())

    def test_rejects_member_byte_mismatch_even_when_bundle_digest_is_updated(self) -> None:
        changed_files = dict(self.files)
        original, mode = changed_files["src/azazel_nexus/cli.py"]
        changed_files["src/azazel_nexus/cli.py"] = (original + b"# changed\n", mode)
        self._write_bundle(changed_files)
        manifest = json.loads(self.manifest.read_text())
        entry = next(item for item in manifest["files"] if item["path"] == "src/azazel_nexus/cli.py")
        entry["sha256"] = sha256(original)
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "content digest differs"):
            self._build("bad-member-out")

    def test_rejects_archive_member_missing_from_manifest(self) -> None:
        manifest = json.loads(self.manifest.read_text())
        manifest["files"] = [
            entry for entry in manifest["files"] if entry["path"] != "src/azazel_nexus/cli.py"
        ]
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unmanifested tar member"):
            self._build("unmanifested-out")

    def test_rejects_mode_mismatch(self) -> None:
        changed_files = dict(self.files)
        content, _mode = changed_files["packaging/install.sh"]
        changed_files["packaging/install.sh"] = (content, 0o644)
        self._write_bundle(changed_files)
        manifest = json.loads(self.manifest.read_text())
        entry = next(item for item in manifest["files"] if item["path"] == "packaging/install.sh")
        entry["mode"] = "0755"
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "mode differs from manifest"):
            self._build("bad-mode-out")


if __name__ == "__main__":
    unittest.main()
