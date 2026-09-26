from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOTFS_NORMALIZER = Path(__file__).parents[1] / "tools/payload/normalize_rootfs.sh"
APT_CACHE_POLICY = Path(__file__).parents[1] / "tools/payload/apt-cache-policy.conf"


class RootfsNormalizationTests(unittest.TestCase):
    def test_apt_cache_policy_disables_generated_cache_paths(self) -> None:
        policy = APT_CACHE_POLICY.read_text()
        self.assertIn('Dir::Cache::pkgcache "";', policy)
        self.assertIn('Dir::Cache::srcpkgcache "";', policy)
        recipe = (Path(__file__).parents[1] / "tools/payload/build_candidate.sh").read_text()
        self.assertIn("99azazel-disable-generated-cache.conf", recipe)

    def test_only_measured_generated_apt_cache_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apt_cache = root / "var/cache/apt"
            apt_cache.mkdir(parents=True)
            generated_cache = apt_cache / "pkgcache.bin"
            generated_cache.write_bytes(b"generated and variable")
            retained_metadata = apt_cache / "srcpkgcache.bin"
            retained_metadata.write_bytes(b"not measured to vary")

            result = subprocess.run(
                ["sh", str(ROOTFS_NORMALIZER), str(root)],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(generated_cache.exists())
            self.assertEqual(retained_metadata.read_bytes(), b"not measured to vary")

    def test_relative_normalization_root_is_refused(self) -> None:
        result = subprocess.run(
            ["sh", str(ROOTFS_NORMALIZER), "relative-root"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
