#!/usr/bin/env python3
"""Verify the PREPARE bundle and the exact BUILD recipe before/after use."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


SCHEMA = "azazel-payload/build-inputs@4"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(
    manifest_path: Path,
    bundle_root: Path,
    expected: str,
    running_recipe: Path,
    *,
    builder_environment_root: Path | None = None,
) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("expected manifest digest must be lowercase SHA-256")
    bundle_root = bundle_root.resolve(strict=True)
    if manifest_path.resolve(strict=True) != bundle_root / "build-input-manifest.json":
        raise ValueError("manifest path is not the PREPARE bundle manifest")
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("manifest digest differs from PREPARE output")
    sidecar = bundle_root / "build-input-manifest.sha256"
    if not sidecar.is_file():
        raise ValueError("PREPARE manifest digest sidecar is missing")
    sidecar_fields = sidecar.read_text().split()
    if sidecar_fields != [expected, "build-input-manifest.json"]:
        raise ValueError("manifest digest sidecar differs from PREPARE output")
    document = json.loads(raw)
    if document.get("schema") != SCHEMA:
        raise ValueError("unsupported build input manifest")
    if document.get("builder", {}).get("selected_for_production") is not False:
        raise ValueError("evaluation candidate cannot claim production selection")
    inputs = document.get("inputs")
    if not isinstance(inputs, dict):
        raise ValueError("manifest inputs must be an object")
    for required in (
        "recipe",
        "rootfs_normalizer",
        "reproducibility_comparator",
        "package_requests",
        "quarantine_policy",
        "toolchain_lock",
        "c5_inspector",
        "initramfs_inspector",
        "rootfs_extraction_inspector",
        "builder_seed_generator",
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
        if required not in inputs:
            raise ValueError(f"required frozen input missing: {required}")
    expected_files = set()
    for name, record in inputs.items():
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise ValueError(f"input record is malformed: {name}")
        relative = Path(record["path"])
        if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("frozen-inputs",):
            raise ValueError(f"input path escapes frozen bundle: {name}")
        path = bundle_root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"frozen input is not a regular file: {name}")
        resolved_path = path.resolve(strict=True)
        if bundle_root not in resolved_path.parents:
            raise ValueError(f"input path escapes frozen bundle after resolution: {name}")
        expected_files.add(relative.as_posix())
        if sha256(path) != record["sha256"]:
            raise ValueError(f"frozen input changed or missing: {name}")
    actual_files = {
        path.relative_to(bundle_root).as_posix()
        for path in (bundle_root / "frozen-inputs").rglob("*")
        if path.is_file()
    }
    if actual_files != expected_files:
        raise ValueError("frozen bundle contains unmanifested or missing files")
    recipe_hash = sha256(running_recipe)
    if recipe_hash != inputs["recipe"]["sha256"]:
        raise ValueError("executed recipe differs from the frozen recipe")

    lock_path = bundle_root / inputs["toolchain_lock"]["path"]
    lock = json.loads(lock_path.read_text())
    target = document["target"]
    builder = document.get("builder")
    repository = target.get("repository", {})
    snapshot = repository.get("snapshot")
    parsed_snapshot = urlsplit(snapshot or "")
    if (
        parsed_snapshot.scheme != "https"
        or parsed_snapshot.netloc != "snapshot.debian.org"
        or not re.fullmatch(r"/archive/[a-z0-9-]+/\d{8}T\d{6}Z/?", parsed_snapshot.path)
        or parsed_snapshot.query
        or parsed_snapshot.fragment
    ):
        raise ValueError("target repository is not an immutable Debian snapshot")
    if lock != target.get("toolchain_lock"):
        raise ValueError("manifest toolchain lock differs from frozen lock input")
    if not isinstance(builder, dict) or builder.get("packages") != lock.get("packages"):
        raise ValueError("builder package versions differ from frozen toolchain lock")
    if lock.get("architecture") != target["architecture"]:
        raise ValueError("toolchain architecture differs from target")
    if lock.get("snapshot") != snapshot:
        raise ValueError("toolchain snapshot differs from target")
    nexus_manifest = json.loads(
        (bundle_root / inputs["nexus_bundle_manifest"]["path"]).read_text()
    )
    if nexus_manifest.get("bundle_sha256") != inputs["nexus_source_bundle"]["sha256"]:
        raise ValueError("Nexus source bundle digest differs from its frozen manifest")
    if document.get("target", {}).get("nexus_source_bundle_sha256") != inputs["nexus_source_bundle"]["sha256"]:
        raise ValueError("Nexus source bundle digest differs from build target")
    if nexus_manifest.get("repository_identity") != document.get("source", {}).get("repositories", {}).get("nexus"):
        raise ValueError("Nexus source bundle checkout identity differs from PREPARE")
    apt_sources = lock.get("apt_sources")
    if lock.get("schema") != "azazel-payload/debian-toolchain-lock@2" or not isinstance(apt_sources, list) or not apt_sources:
        raise ValueError("toolchain lock must contain self-contained APT source records")
    for record in apt_sources:
        if not isinstance(record, dict):
            raise ValueError("APT source lock record is malformed")
        path = Path(record.get("path", ""))
        if path.is_absolute() is False or path.parts[:3] not in (
            ("/", "etc", "apt"),
        ):
            raise ValueError("APT source path is not an absolute /etc/apt path")
        allowed = path == Path("/etc/apt/sources.list") or (
            path.parent == Path("/etc/apt/sources.list.d")
            and path.name not in ("", ".", "..")
        )
        if not allowed:
            raise ValueError(f"APT source path is outside supported source locations: {path}")
        try:
            content = base64.b64decode(record["content_base64"], validate=True)
        except (KeyError, binascii.Error, TypeError) as exc:
            raise ValueError("APT source content is missing or invalid base64") from exc
        if hashlib.sha256(content).hexdigest() != record.get("sha256"):
            raise ValueError(f"embedded APT source digest mismatch: {path}")
        if builder_environment_root is not None:
            active = builder_environment_root / path.relative_to("/")
            if active.is_symlink() or not active.is_file():
                raise ValueError(f"APT source lock path is not a regular file: {active}")
            if active.read_bytes() != content:
                raise ValueError(f"APT source changed since lock capture: {active}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--running-recipe", required=True, type=Path)
    parser.add_argument("--verify-builder-environment", action="store_true")
    args = parser.parse_args()
    try:
        verify(
            args.manifest,
            args.bundle_root,
            args.expected_sha256,
            args.running_recipe,
            builder_environment_root=Path("/") if args.verify_builder_environment else None,
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"frozen build input verification failed: {exc}", file=sys.stderr)
        return 42
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
