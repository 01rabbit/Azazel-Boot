"""Negative cases for the static PoC mount allowlist."""

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("persistence_manifest", ROOT / "tools/persistence_manifest.py")
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.valid = (ROOT / "config/persistence-mounts.toml").read_bytes()

    def test_exact_manifest(self):
        entries = module.validate(self.valid)
        self.assertEqual(len(entries), 7)
        self.assertEqual({x["name"] for x in entries}, module.SOURCES)

    def test_rejects_expansion_and_missing_mount(self):
        for content in (
            self.valid.replace(b'version = 1', b'version = 2'),
            self.valid.replace(b'destination = "/var/lib/azazel/state"', b'destination = "/var"'),
            self.valid.replace(b'source = "state"', b'source = "../state"'),
            self.valid.replace(b'mode = "0700"', b'mode = "0777"', 1),
            self.valid.replace(b'name = "operator"', b'name = "config"'),
            self.valid.replace(b'required = true', b'required = false', 1),
            self.valid + b'\n[[mount]]\nname = "home"\nsource = "home"\ndestination = "/home"\nmode = "0700"\nrequired = false\n',
        ):
            with self.subTest(content=content[-80:]), self.assertRaises(ValueError):
                module.validate(content)


if __name__ == "__main__":
    unittest.main()
