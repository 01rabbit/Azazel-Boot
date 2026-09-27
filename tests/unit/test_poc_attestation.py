import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import MappingProxyType, SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("poc_attestation", ROOT / "tools/poc_attestation.py")
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def test_record(**updates):
    fields = {
        "image_version": "poc-r1",
        "git_revision": "a" * 40,
        "builder_version": "local-prototype",
        "debian_snapshot": "pinned-test-snapshot",
        "package_manifest_ref": "manifests/packages.json",
        "package_manifest_digest": "sha256:" + "1" * 64,
        "firmware_manifest_ref": "manifests/firmware.json",
        "firmware_manifest_digest": "sha256:" + "2" * 64,
        "sbom_ref": "manifests/sbom.json",
        "sbom_digest": "sha256:" + "3" * 64,
        "source_date_epoch": 1,
        "build_input_digest": "sha256:" + "4" * 64,
        "partition_layout_digest": "sha256:" + "5" * 64,
        "root_filesystem_digest": "sha256:" + "6" * 64,
        "boot_chain_identity": "unsigned-prototype",
        "unsigned_payload_digest": "sha256:" + "7" * 64,
        "signed_artifact_digest": None,
        "signature": None,
        "build_time": "test-only",
        "compatibility_claim": "candidate",
        "quarantine_policy_version": "test-v1",
    }
    fields.update(updates)
    return SimpleNamespace(fields=MappingProxyType(fields))


class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.private = self.directory / "private.pem"
        self.public = self.directory / "public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.chmod(self.private, 0o600)
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        key = self.public.read_bytes()
        self.pin = module.public_key_fingerprint(key)

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_local_attestation_and_modified_payload(self):
        record = test_record()
        signature = module.sign_prototype(record, self.private)
        self.assertTrue(
            module.verify_prototype(
                record,
                signature,
                public_key_path=self.public,
                expected_public_key_fingerprint=self.pin,
            )
        )
        changed = test_record(unsigned_payload_digest="sha256:" + "8" * 64)
        self.assertFalse(
            module.verify_prototype(
                changed,
                signature,
                public_key_path=self.public,
                expected_public_key_fingerprint=self.pin,
            )
        )

    def test_refuses_wrong_pin_release_claim_and_modified_layout(self):
        record = test_record()
        signature = module.sign_prototype(record, self.private)
        args = {"public_key_path": self.public, "expected_public_key_fingerprint": self.pin}
        self.assertFalse(module.verify_prototype(record, signature, **{**args, "expected_public_key_fingerprint": "sha256:" + "0" * 64}))
        self.assertFalse(module.verify_prototype(test_record(partition_layout_digest="sha256:" + "9" * 64), signature, **args))
        with self.assertRaises(module.AttestationRefused):
            module.sign_prototype(test_record(image_version="release-1"), self.private)
        with self.assertRaises(module.AttestationRefused):
            module.sign_prototype(test_record(compatibility_claim="hardware_verified"), self.private)


if __name__ == "__main__":
    unittest.main()
