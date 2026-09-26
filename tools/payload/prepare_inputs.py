#!/usr/bin/env python3
"""Freeze the exact files and declared inputs consumed by a candidate build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


SCHEMA = "azazel-payload/build-inputs@4"
SNAPSHOT_PATH = re.compile(r"/archive/[a-z0-9-]+/\d{8}T\d{6}Z/?")


def is_immutable_snapshot(value: str) -> bool:
    parsed = urlsplit(value)
    return (
        parsed.scheme == "https"
        and parsed.netloc == "snapshot.debian.org"
        and SNAPSHOT_PATH.fullmatch(parsed.path) is not None
        and not parsed.query
        and not parsed.fragment
    )


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def repository_identity(root: Path) -> dict[str, str]:
    status = git(root, "status", "--porcelain=v2", "--untracked-files=all")
    identity = {
        "commit": git(root, "rev-parse", "HEAD"),
        "worktree_state": "dirty" if status else "clean",
        "worktree_status_sha256": hashlib.sha256(status.encode()).hexdigest(),
    }
    if root.name == "Azazel-Nexus":
        selected = []
        fixed = (
            (root / "pyproject.toml", "pyproject.toml"),
            (root / "runtime/pyproject.toml", "runtime/pyproject.toml"),
            (root / "packaging/install.sh", "packaging/install.sh"),
            (root / "packaging/azazel-nexus.preset", "packaging/azazel-nexus.preset"),
        )
        selected.extend(fixed)
        for directory, python_only in (
            (root / "src/azazel_nexus", True),
            (root / "runtime/src/azazel_nexus_runtime", True),
            (root / "packaging/systemd", False),
        ):
            for path in sorted(directory.rglob("*")):
                if not path.is_file() or path.is_symlink():
                    continue
                relative = path.relative_to(root)
                if any(part in {".git", "tests", "__pycache__", "build", "dist"} for part in relative.parts):
                    continue
                if any(part.endswith((".egg-info", ".pyc")) for part in relative.parts):
                    continue
                if python_only and path.suffix != ".py":
                    continue
                selected.append((path, relative.as_posix()))
        selected.sort(key=lambda item: item[1])
        content = hashlib.sha256()
        for path, archive_name in selected:
            raw = path.read_bytes()
            content.update(archive_name.encode("utf-8") + b"\0")
            content.update(hashlib.sha256(raw).hexdigest().encode("ascii") + b"\n")
        identity["selected_inputs_sha256"] = content.hexdigest()
    return identity


def freeze_file(
    source: Path,
    destination: Path,
    bundle_root: Path,
    expected_sha256: str,
) -> dict[str, str]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o444)
    actual_sha256 = digest(destination)
    if actual_sha256 != expected_sha256:
        raise RuntimeError(f"source changed while being frozen: {source}")
    return {
        "path": destination.relative_to(bundle_root).as_posix(),
        "sha256": actual_sha256,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--boot-root", required=True, type=Path)
    parser.add_argument("--base-image", required=True, type=Path)
    parser.add_argument("--builder-seed", required=True, type=Path)
    parser.add_argument("--release", default="13.7.0-trixie")
    parser.add_argument("--architecture", default="amd64")
    parser.add_argument(
        "--snapshot",
        default="https://snapshot.debian.org/archive/debian/20260914T120000Z/",
    )
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--toolchain-lock", required=True, type=Path)
    parser.add_argument("--nexus-source-bundle", required=True, type=Path)
    parser.add_argument("--nexus-bundle-manifest", required=True, type=Path)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    boot_root = args.boot_root.resolve()
    nexus_root = root.parent / "Azazel-Nexus"
    output = args.output.resolve()
    base_image = args.base_image.resolve()
    builder_seed = args.builder_seed.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error(f"output directory must be empty: {output}")
    if not base_image.is_file() or not builder_seed.is_file():
        parser.error("base image and builder seed must both be files")
    if not is_immutable_snapshot(args.snapshot):
        parser.error(
            "snapshot must use https://snapshot.debian.org/archive/<repo>/<YYYYMMDDTHHMMSSZ>/"
        )

    recipe = root / "tools/payload/build_candidate.sh"
    rootfs_normalizer = root / "tools/payload/normalize_rootfs.sh"
    apt_cache_policy = root / "tools/payload/apt-cache-policy.conf"
    package_inputs = root / "tools/payload/package-inputs.txt"
    builder_tools = root / "tools/payload/builder-tools.txt"
    builder_bootstrap = root / "tools/payload/bootstrap_builder_vm.sh"
    builder_seed_generator = root / "tools/payload/create_builder_seed.py"
    c5_inspector = root / "tools/payload/measure_initramfs_c5.py"
    c5_persistence_probe = root / "tools/payload/c5-persistence-probe.sh"
    c5_persistence_service = root / "tools/payload/c5-persistence-probe.service"
    c5_configurator = root / "tools/payload/configure_initramfs_c5.hook.chroot"
    quarantine_helper = root / "tools/payload/quarantine-block-device"
    quarantine_udev_rule = root / "tools/payload/quarantine-udev.rules"
    hotplug_probe_service = root / "tools/payload/c5-hotplug-write-probe@.service"
    initramfs_quarantine_hook = root / "tools/payload/initramfs-hooks/azazel-quarantine"
    qemu_c5_runner = root / "tools/payload/run_qemu_c5_fixture.py"
    initramfs_inspector = root / "tools/payload/inspect_initramfs.py"
    rootfs_extraction_inspector = root / "tools/payload/inspect_rootfs_extraction.py"
    reproducibility_comparator = root / "tools/payload/compare_builds.py"
    input_verifier = root / "tools/payload/verify_frozen_inputs.py"
    policy = boot_root / "config/quarantine/policy-v2.json"
    c5_evaluator = boot_root / "tools/builder/initramfs_c5.py"
    quarantine_module = boot_root / "src/azazel_boot/quarantine.py"
    quarantine_refusals = boot_root / "src/azazel_boot/refusals.py"
    quarantine_package_init = boot_root / "src/azazel_boot/__init__.py"
    boot_runtime_modules = {
        name: boot_root / "src/azazel_boot" / f"{name}.py"
        for name in (
            "version",
            "inventory",
            "commissioning",
            "session_mode",
            "runtime",
        )
    }
    boot_runtime_service = root / "tools/payload/azazel-boot-runtime.service"
    toolchain_capture = root / "tools/payload/capture_toolchain_lock.py"
    nexus_deb_packager = root / "tools/payload/package_nexus_deb.py"
    nexus_guest_installer = root / "tools/payload/install_nexus_deb.sh"
    nexus_guest_e2e = root / "tools/payload/run_nexus_guest_e2e.py"
    nexus_qemu_runner = root / "tools/payload/run_qemu_nexus_e2e.py"
    nexus_guest_service = root / "tools/payload/nexus_guest_e2e.service"
    for path in (
        recipe, rootfs_normalizer, apt_cache_policy, package_inputs, builder_tools, builder_bootstrap,
        builder_seed_generator,
        c5_inspector, c5_persistence_probe, c5_persistence_service, c5_configurator,
        quarantine_helper, quarantine_udev_rule, hotplug_probe_service,
        initramfs_quarantine_hook, qemu_c5_runner,
        initramfs_inspector, rootfs_extraction_inspector, reproducibility_comparator,
        input_verifier,
        policy, c5_evaluator, quarantine_module, quarantine_refusals,
        quarantine_package_init,
        *boot_runtime_modules.values(),
        boot_runtime_service,
        args.toolchain_lock,
        args.nexus_source_bundle.resolve(),
        args.nexus_bundle_manifest.resolve(),
        nexus_guest_installer,
        nexus_deb_packager,
        nexus_guest_e2e,
        nexus_qemu_runner,
        nexus_guest_service,
    ):
        if not path.is_file():
            parser.error(f"required input is missing: {path}")

    source_repositories = {
        "azazel": root,
        "boot": boot_root,
        "nexus": nexus_root,
    }
    for name, path in source_repositories.items():
        if not (path / ".git").exists():
            parser.error(f"required source repository is unavailable ({name}): {path}")
        if output == path or path in output.parents:
            parser.error(f"PREPARE output must be outside source repositories: {path}")
    repository_identities_before = {
        name: repository_identity(path) for name, path in source_repositories.items()
    }

    source_files = {
        "recipe": (recipe, output / "frozen-inputs/build_candidate.sh"),
        "rootfs_normalizer": (
            rootfs_normalizer,
            output / "frozen-inputs/normalize_rootfs.sh",
        ),
        "apt_cache_policy": (
            apt_cache_policy,
            output / "frozen-inputs/apt-cache-policy.conf",
        ),
        "package_requests": (package_inputs, output / "frozen-inputs/package-inputs.txt"),
        "builder_tool_requests": (builder_tools, output / "frozen-inputs/builder-tools.txt"),
        "builder_bootstrap": (builder_bootstrap, output / "frozen-inputs/bootstrap_builder_vm.sh"),
        "builder_seed_generator": (
            builder_seed_generator,
            output / "frozen-inputs/create_builder_seed.py",
        ),
        "c5_inspector": (c5_inspector, output / "frozen-inputs/measure_initramfs_c5.py"),
        "c5_persistence_probe": (
            c5_persistence_probe,
            output / "frozen-inputs/c5-persistence-probe.sh",
        ),
        "c5_persistence_service": (
            c5_persistence_service,
            output / "frozen-inputs/c5-persistence-probe.service",
        ),
        "c5_initramfs_configurator": (
            c5_configurator,
            output / "frozen-inputs/configure_initramfs_c5.hook.chroot",
        ),
        "quarantine_block_helper": (
            quarantine_helper,
            output / "frozen-inputs/quarantine-block-device",
        ),
        "quarantine_udev_rule": (
            quarantine_udev_rule,
            output / "frozen-inputs/quarantine-udev.rules",
        ),
        "hotplug_probe_service": (
            hotplug_probe_service,
            output / "frozen-inputs/c5-hotplug-write-probe@.service",
        ),
        "initramfs_quarantine_hook": (
            initramfs_quarantine_hook,
            output / "frozen-inputs/initramfs-hooks/azazel-quarantine",
        ),
        "qemu_c5_runner": (
            qemu_c5_runner,
            output / "frozen-inputs/run_qemu_c5_fixture.py",
        ),
        "initramfs_inspector": (
            initramfs_inspector,
            output / "frozen-inputs/inspect_initramfs.py",
        ),
        "rootfs_extraction_inspector": (
            rootfs_extraction_inspector,
            output / "frozen-inputs/inspect_rootfs_extraction.py",
        ),
        "reproducibility_comparator": (
            reproducibility_comparator,
            output / "frozen-inputs/compare_builds.py",
        ),
        "input_verifier": (input_verifier, output / "frozen-inputs/verify_frozen_inputs.py"),
        "quarantine_policy": (policy, output / "frozen-inputs/quarantine-policy-v2.json"),
        "c5_evaluator": (c5_evaluator, output / "frozen-inputs/initramfs_c5.py"),
        "boot_quarantine_module": (
            quarantine_module,
            output / "frozen-inputs/boot-src/azazel_boot/quarantine.py",
        ),
        "boot_package_init": (
            quarantine_package_init,
            output / "frozen-inputs/boot-src/azazel_boot/__init__.py",
        ),
        "boot_quarantine_refusals": (
            quarantine_refusals,
            output / "frozen-inputs/boot-src/azazel_boot/refusals.py",
        ),
        "boot_runtime_service": (
            boot_runtime_service,
            output / "frozen-inputs/azazel-boot-runtime.service",
        ),
        "toolchain_lock": (args.toolchain_lock.resolve(), output / "frozen-inputs/toolchain-lock.json"),
        "toolchain_capture": (toolchain_capture, output / "frozen-inputs/capture_toolchain_lock.py"),
        "prepare_tool": (Path(__file__).resolve(), output / "frozen-inputs/prepare_inputs.py"),
        "nexus_source_bundle": (
            args.nexus_source_bundle.resolve(),
            output / "frozen-inputs/azazel-nexus-source.tar",
        ),
        "nexus_bundle_manifest": (
            args.nexus_bundle_manifest.resolve(),
            output / "frozen-inputs/azazel-nexus-bundle-manifest.json",
        ),
        "nexus_guest_installer": (
            nexus_guest_installer,
            output / "frozen-inputs/install_nexus_deb.sh",
        ),
        "nexus_deb_packager": (
            nexus_deb_packager,
            output / "frozen-inputs/package_nexus_deb.py",
        ),
        "nexus_guest_e2e": (
            nexus_guest_e2e,
            output / "frozen-inputs/run_nexus_guest_e2e.py",
        ),
        "nexus_qemu_runner": (
            nexus_qemu_runner,
            output / "frozen-inputs/run_qemu_nexus_e2e.py",
        ),
        "nexus_guest_service": (
            nexus_guest_service,
            output / "frozen-inputs/nexus_guest_e2e.service",
        ),
    }
    for name, source in boot_runtime_modules.items():
        source_files[f"boot_runtime_{name}"] = (
            source,
            output / "frozen-inputs/boot-src/azazel_boot" / source.name,
        )
    frozen_destinations = [destination for _, destination in source_files.values()]
    if len(set(frozen_destinations)) != len(frozen_destinations):
        parser.error("two frozen input names target the same bundle path")
    policy_bytes_before = policy.read_bytes()
    policy_sha256_before = hashlib.sha256(policy_bytes_before).hexdigest()
    policy_document = json.loads(policy_bytes_before)
    hook_sources = {}
    for index, name in enumerate(policy_document["early_hooks"]):
        matches = sorted((root / "tools/payload/hooks").glob(f"*-{name}"))
        if len(matches) != 1:
            parser.error(f"expected exactly one source hook for {name}: {matches}")
        key = f"hook_{index:02d}"
        hook_sources[key] = (name, matches[0])
        source_files[key] = (
            matches[0],
            output / "frozen-inputs/hooks" / matches[0].name,
        )

    source_hashes_before = {
        name: digest(source) for name, (source, _) in source_files.items()
    }
    if source_hashes_before["quarantine_policy"] != policy_sha256_before:
        parser.error("quarantine policy changed while its hook set was being read")
    external_hashes_before = {
        "base_image": digest(base_image),
        "builder_seed": digest(builder_seed),
        "toolchain_lock": digest(args.toolchain_lock.resolve()),
    }
    output.mkdir(parents=True, exist_ok=True)
    frozen = output / "frozen-inputs"
    frozen.mkdir()
    frozen_inputs = {
        name: freeze_file(source, target, output, source_hashes_before[name])
        for name, (source, target) in source_files.items()
    }
    for name, (source, _) in source_files.items():
        if digest(source) != source_hashes_before[name]:
            parser.error(f"source changed during PREPARE: {source}")
    external_hashes_after = {
        "base_image": digest(base_image),
        "builder_seed": digest(builder_seed),
        "toolchain_lock": digest(args.toolchain_lock.resolve()),
    }
    if external_hashes_after != external_hashes_before:
        parser.error("base image, builder seed, or toolchain lock changed during PREPARE")
    repository_identities_after = {
        name: repository_identity(path) for name, path in source_repositories.items()
    }
    if repository_identities_after != repository_identities_before:
        parser.error("source repository state changed during PREPARE; discard and rerun")

    hook_inputs = []
    for key, (name, source) in hook_sources.items():
        hook_inputs.append({
            "name": name,
            "input_key": key,
            "filename": source.name,
            "path": frozen_inputs[key]["path"],
            "sha256": frozen_inputs[key]["sha256"],
        })
    toolchain = json.loads((frozen / "toolchain-lock.json").read_text())
    if (
        not isinstance(toolchain, dict)
        or toolchain.get("schema") != "azazel-payload/debian-toolchain-lock@2"
        or not toolchain.get("packages")
        or toolchain.get("snapshot") != args.snapshot
        or toolchain.get("architecture") != args.architecture
    ):
        parser.error("toolchain lock must be an object with a non-empty packages list")
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("name"), str)
        or not isinstance(item.get("version"), str)
        for item in toolchain["packages"]
    ):
        parser.error("toolchain lock package entries need exact name and version fields")
    nexus_manifest = json.loads(
        (frozen / "azazel-nexus-bundle-manifest.json").read_text()
    )
    if nexus_manifest.get("bundle_sha256") != frozen_inputs["nexus_source_bundle"]["sha256"]:
        parser.error("Nexus source bundle digest differs from its bundle manifest")
    if nexus_manifest.get("repository_identity") != repository_identities_before["nexus"]:
        parser.error("Nexus source bundle was not generated from the current checkout state")

    manifest = {
        "schema": SCHEMA,
        "source": {
            "repositories": repository_identities_before,
        },
        "target": {
            "distribution": "debian",
            "release": args.release,
            "architecture": args.architecture,
            "base_image": {
                "name": base_image.name,
                "sha256": external_hashes_before["base_image"],
            },
            "repository": {
                "snapshot": args.snapshot,
                "components": ["main"],
                "security_updates": False,
                "rolling_updates": False,
            },
            "package_requests": [
                line.strip()
                for line in (frozen / "package-inputs.txt").read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ],
            "toolchain_lock": toolchain,
            "nexus_source_bundle_sha256": frozen_inputs["nexus_source_bundle"]["sha256"],
        },
        "builder_environment": {
            "base_image": {
                "filename": base_image.name,
                "sha256": external_hashes_before["base_image"],
            },
            "builder_seed_iso": {
                "filename": builder_seed.name,
                "sha256": external_hashes_before["builder_seed"],
            },
            "independent_instances_required": 2,
            "same_base_image": True,
            "same_seed": True,
        },
        "builder": {
            "candidate": "live-build-evaluation-only",
            "selected_for_production": False,
            "packages": toolchain["packages"],
            "bootstrap_sha256": frozen_inputs["builder_bootstrap"]["sha256"],
            "tool_request_sha256": frozen_inputs["builder_tool_requests"]["sha256"],
        },
        "normalization": {
            "source_date_epoch": args.source_date_epoch,
            "timezone": "UTC",
            "locale": "C.UTF-8",
            "umask": "022",
            "network": "only the declared Debian snapshot during package resolution",
        },
        "c5": {
            "schema": "azazel-boot/c5-inspection@1",
            "evaluator_sha256": frozen_inputs["c5_evaluator"]["sha256"],
            "policy_sha256": frozen_inputs["quarantine_policy"]["sha256"],
        },
        "initramfs_hooks": hook_inputs,
        "inputs": frozen_inputs,
    }
    manifest_path = output / "build-input-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    manifest_path.chmod(0o444)
    bundle_hash = digest(manifest_path)
    (output / "build-input-manifest.sha256").write_text(
        f"{bundle_hash}  build-input-manifest.json\n"
    )
    (output / "build-input-manifest.sha256").chmod(0o444)
    for path in sorted(frozen.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    os.chmod(frozen, 0o555)
    print(json.dumps({"manifest": str(manifest_path), "sha256": bundle_hash}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
