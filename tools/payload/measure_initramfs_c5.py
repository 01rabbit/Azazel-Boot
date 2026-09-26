#!/usr/bin/env python3
"""Measure C5 hook bytes and ordering from an extracted initramfs tree."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import re
import secrets
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True

EXPECTED_PSEUDO_MOUNT_RULES_SOURCE_SHA256 = "d63ba2ea309aadf7794a5f84b0f394c2e48fe630640aa37e9963cd9d1b769d89"
EXPECTED_PSEUDO_MOUNT_RULES_CURATED_SHA256 = "2d7221d25ef5e04a6a076c407653b45f032b84413293f6964dc5e10a2911b1e8"
EXPECTED_PSEUDO_MOUNT_RULES = [
    'SUBSYSTEM=="module", KERNEL=="fuse", TAG+="systemd", ENV{SYSTEMD_WANTS}+="sys-fs-fuse-connections.mount"',
    'SUBSYSTEM=="module", KERNEL=="configfs", TAG+="systemd", ENV{SYSTEMD_WANTS}+="sys-kernel-config.mount"',
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_stage_order(lines: list[str], stage: str) -> list[tuple[str, str]]:
    """Return only fully recognized commands from one sourced ORDER file.

    initramfs-tools sources ORDER as shell, so accepting hook-looking substrings
    is insufficient: any other executable line could run before/after those
    hooks without appearing in the measured plan. Permit the Debian-generated
    optional param.conf preamble and exact stage script invocations only.
    """
    entries = []
    allowed_preamble = {
        "[ -e /conf/param.conf ] && . /conf/param.conf",
        '[ -e /conf/param.conf ] && . "/conf/param.conf"',
    }
    invocation = re.compile(
        rf"/scripts/{re.escape(stage)}/([A-Za-z0-9_.+-]+)(?:\s+\"\$@\")?"
    )
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped in allowed_preamble:
            continue
        match = invocation.fullmatch(stripped)
        if match:
            entries.append((match.group(1), stripped))
            continue
        raise ValueError(
            f"unrecognized executable content in scripts/{stage}/ORDER:{line_number}: {stripped}"
        )
    return entries


def inspect_stage_order(lines: list[str], stage: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Return parsed entries and fail-closed diagnostics for one ORDER file."""
    try:
        return parse_stage_order(lines, stage), []
    except ValueError as exc:
        return [], [str(exc)]


def inspect_other_stage_orders(scripts_dir: Path) -> list[dict]:
    """Inspect every non-primary sourced ORDER file, including all content."""
    records = []
    for order_path in sorted(scripts_dir.glob("*/ORDER")):
        stage = order_path.parent.name
        if stage in {"init-top", "init-bottom"}:
            continue
        entries, invalid_content = inspect_stage_order(
            order_path.read_text(errors="replace").splitlines(), stage
        )
        records.append({
            "stage": stage,
            "order_file_sha256": digest(order_path),
            "entries": entries,
            "invalid_executable_content": invalid_content,
        })
    return records


def load_evaluator(frozen: Path):
    package_path = frozen / "boot-src/azazel_boot"
    package = types.ModuleType("azazel_boot")
    package.__path__ = [str(package_path)]
    sys.modules["azazel_boot"] = package
    spec = importlib.util.spec_from_file_location(
        "azazel_frozen_initramfs_c5", frozen / "initramfs_c5.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load frozen Boot C5 evaluator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def evaluate_inspection(evaluator, manifest: dict):
    """Adapt measured initramfs evidence to Boot's pinned evaluator API."""
    hooks = tuple(
        evaluator.HookEntry(
            name=item["name"],
            digest=item["digest"],
            provenance=evaluator.Provenance[item["provenance"].upper()],
            arguments=tuple(item["arguments"]),
        )
        for item in manifest["hooks"]
    )
    inspection = evaluator.InitramfsInspection(
        candidate=manifest["candidate"],
        build_host_id=manifest["build_host_id"],
        hooks=hooks,
        order_established=manifest["order_established"],
    )
    return evaluator.evaluate(inspection)


def summarize_faults(evaluator_faults: list[str], boot_policy_faults: list[dict]) -> list[str]:
    """Retain evaluator findings and surface every measured image-policy fault.

    The two evaluators use partly different vocabularies.  The top-level list
    is an inclusive machine-readable summary; original evaluator faults and
    detailed Boot policy findings remain available in separate fields.
    """
    codes = set(evaluator_faults)
    codes.update(
        item["code"]
        for item in boot_policy_faults
        if isinstance(item, dict) and isinstance(item.get("code"), str)
    )
    return sorted(codes)


def has_automount_activation_rule(text: str) -> bool:
    """Return whether udev rules actively request mount/automount handling.

    Properties such as SYSTEMD_MOUNT_DEVICE_BOUND in Debian's
    60-cdrom_id.rules describe device relationships and cleanup behavior; they
    do not activate a mount.  C5 should flag explicit unit requests or program
    execution instead of matching the word ``mount`` inside any token.
    """
    activation_patterns = (
        r'\bENV\{SYSTEMD_WANTS\}\s*\+?=\s*[^#\n]*(?:\.automount|\.mount)\b',
        r'\b(?:RUN|PROGRAM|IMPORT\{program\})\s*\+?=\s*[^#\n]*'
        r'\b(?:systemd-mount|mount|udisks|autofs)\b',
    )
    active_lines = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    return any(re.search(pattern, active_lines, re.IGNORECASE) for pattern in activation_patterns)


def find_forbidden_storage_commands(text: str) -> list[str]:
    """Find actual command words without mistaking shell case patterns for calls."""
    return re.findall(
        r"(?m)^\s*(?:/sbin/)?(?:modprobe|blockdev|fsck|mountroot|load_modules)(?=\s|$)[^\n]*",
        text,
    )


def inspect_pseudo_mount_curation(rootfs: Path) -> tuple[dict, bool]:
    """Validate the exact pinned Debian rules transformation, not a self-claim."""
    record_path = rootfs / "var/lib/azazel-c5/udev-pseudo-mount-curation.json"
    rules_path = rootfs / "usr/lib/udev/rules.d/99-systemd.rules"
    record = json.loads(record_path.read_text()) if record_path.is_file() else {}
    removed = record.get("removed_lines", [])
    removed_lines_valid = (
        isinstance(removed, list)
        and len(removed) == len(EXPECTED_PSEUDO_MOUNT_RULES)
        and all(isinstance(item, dict) for item in removed)
        and [item.get("line") for item in removed] == EXPECTED_PSEUDO_MOUNT_RULES
        and all(
            item.get("sha256") == hashlib.sha256(line.encode()).hexdigest()
            for item, line in zip(removed, EXPECTED_PSEUDO_MOUNT_RULES)
        )
    )
    file_digest = digest(rules_path) if rules_path.is_file() and not rules_path.is_symlink() else None
    matches_pinned_output = file_digest == EXPECTED_PSEUDO_MOUNT_RULES_CURATED_SHA256
    valid = (
        record.get("schema") == "azazel-payload/c5-udev-pseudo-mount-curation@1"
        and record.get("source_path") == "/usr/lib/udev/rules.d/99-systemd.rules"
        and record.get("source_sha256") == EXPECTED_PSEUDO_MOUNT_RULES_SOURCE_SHA256
        and record.get("curated_file_sha256") == EXPECTED_PSEUDO_MOUNT_RULES_CURATED_SHA256
        and removed_lines_valid
        and matches_pinned_output
        and all(line not in rules_path.read_text(errors="replace") for line in EXPECTED_PSEUDO_MOUNT_RULES)
    )
    return record, valid


def declares_fixture_enforcement(text: str) -> bool:
    return bool(
        "azazel.c5_fixture=QEMU-regular-file" in text
        and "quarantine-block" in text
        and "fixture-only" in text
        and "sysfs_ro" in text
        and "blockdev_ro" in text
    )


def inspect(
    frozen: Path,
    tree: Path,
    rootfs: Path,
    output: Path,
    payload: Path,
    initrd: Path,
) -> None:
    evaluator = load_evaluator(frozen)
    from azazel_boot.quarantine import ImageRefused, InitramfsManifest, verify_initramfs

    expected = tuple(evaluator.PINNED_HOOKS)
    build_manifest = json.loads((frozen.parent / "build-input-manifest.json").read_text())
    declared = {entry["name"]: entry for entry in build_manifest["initramfs_hooks"]}

    init = tree / "init"
    functions = tree / "scripts/functions"
    first_entry = tree / "scripts/azazel-quarantine-first"
    top_order = tree / "scripts/init-top/ORDER"
    bottom_order = tree / "scripts/init-bottom/ORDER"
    config_evidence_path = rootfs / "var/lib/azazel-c5/configuration.json"
    if not all(path.is_file() for path in (init, functions, first_entry, top_order, bottom_order)):
        raise RuntimeError("built initramfs is missing its entry quarantine, /init or ordered hook stages")
    if not config_evidence_path.is_file():
        raise RuntimeError("rootfs is missing the pinned C5 initramfs configuration record")

    init_text = init.read_text(errors="replace")
    init_source_path = rootfs / "var/lib/azazel-c5/init.source"
    if not init_source_path.is_file():
        raise RuntimeError("rootfs is missing the retained pristine Debian /init template")
    init_source_text = init_source_path.read_text(errors="replace")
    functions_text = functions.read_text(errors="replace")
    call = "/scripts/azazel-quarantine-first start"
    executable_call_lines = [
        line.strip() for line in init_text.splitlines()
        if line.strip() == call
    ]
    call_positions = [match.start() for match in re.finditer(
        r"(?m)^/scripts/azazel-quarantine-first start$", init_text
    )]
    call_before_break = bool(call_positions) and "maybe_break top" in init_text and call_positions[0] < init_text.index("maybe_break top")
    run_calls = re.findall(r"(?m)^\s*run_scripts\s+([^\s;]+)", init_text)
    run_scripts_function = re.search(
        r"(?ms)^run_scripts\s*\(\s*\).*?^\}", functions_text
    )
    runner = run_scripts_function.group(0) if run_scripts_function else ""
    sources_order_file = '. "${initdir}/ORDER"' in runner
    first_run_script = next(
        (index for index, item in enumerate(run_calls) if item.strip("'\"") == "/scripts/init-top"),
        None,
    )
    load_modules_position = init_text.find("load_modules")
    call_precedes_storage_paths = bool(
        call_positions
        and first_run_script is not None
        and call_positions[0] < init_text.find("run_scripts /scripts/init-top")
        and load_modules_position > call_positions[0]
    )
    prefix = init_text[:call_positions[0]] if call_positions else init_text
    forbidden_before_quarantine = find_forbidden_storage_commands(prefix)
    non_pseudo_mounts = []
    for line in re.findall(r"(?m)^\s*mount\s+[^\n]*", prefix):
        if not re.search(r"\s(?:/sys|/proc|/dev|/dev/pts|/run)(?:\s|$)", line):
            non_pseudo_mounts.append(line.strip())

    top_entries, top_order_errors = inspect_stage_order(
        top_order.read_text(errors="replace").splitlines(), "init-top"
    )
    bottom_entries, bottom_order_errors = inspect_stage_order(
        bottom_order.read_text(errors="replace").splitlines(), "init-bottom"
    )
    top_paths = [tree / "scripts/init-top" / name for name, _ in top_entries]
    bottom_paths = [tree / "scripts/init-bottom" / name for name, _ in bottom_entries]
    other_stage_orders = inspect_other_stage_orders(tree / "scripts")

    expected_top = [declared[name]["filename"] for name in expected[1:-1]]
    expected_bottom = [declared[name]["filename"] for name in expected[-1:]]
    actual_top = [name for name, _ in top_entries]
    actual_bottom = [name for name, _ in bottom_entries]
    no_unknown_stage_hooks = all(
        not item["entries"] and not item["invalid_executable_content"]
        for item in other_stage_orders
    )
    all_order_content_valid = not top_order_errors and not bottom_order_errors
    order_exact = (
        actual_top == expected_top
        and actual_bottom == expected_bottom
        and no_unknown_stage_hooks
        and all_order_content_valid
    )

    hooks = []
    execution_paths = [(expected[0], first_entry, call)]
    execution_paths.extend(
        (expected[1 + index] if index < len(expected[1:-1]) else path.name, path, order_line)
        for index, (path, (_, order_line)) in enumerate(zip(top_paths, top_entries, strict=True))
    )
    execution_paths.extend(
        (expected[-1] if index == 0 else path.name, path, order_line)
        for index, (path, (_, order_line)) in enumerate(zip(bottom_paths, bottom_entries, strict=True))
    )
    for index, (pinned_name, path, call_line) in enumerate(execution_paths):
        actual_digest = digest(path) if path.is_file() else None
        source_digest = declared.get(pinned_name, {}).get("sha256")
        is_pinned = bool(actual_digest and actual_digest == source_digest)
        hooks.append({
            "name": pinned_name if is_pinned else path.name,
            "digest": f"sha256:{actual_digest}" if actual_digest else None,
            "provenance": "pinned_by_boot" if is_pinned else "builder_default",
            "arguments": [],
            "inspected_path": str(path.relative_to(tree)) if path.is_relative_to(tree) else str(path),
            "execution_index": index,
            "invocation": call_line,
        })

    first_is_quarantine = bool(hooks and hooks[0]["name"] == expected[0] and hooks[0]["provenance"] == "pinned_by_boot")
    policy = json.loads((frozen / "quarantine-policy-v2.json").read_text())

    config_evidence = json.loads(config_evidence_path.read_text())
    udev_curation, udev_curation_valid = inspect_pseudo_mount_curation(rootfs)
    udev_rules_path = rootfs / "usr/lib/udev/rules.d/99-systemd.rules"
    udev_curated_file_matches = (
        udev_rules_path.is_file()
        and not udev_rules_path.is_symlink()
        and digest(udev_rules_path) == EXPECTED_PSEUDO_MOUNT_RULES_CURATED_SHA256
    )
    curation_hashes = {
        "all_generic_ide": "59697cff80663c30132578d3fc6128692ff15826b4e32df3468e85db03ba3b93",
        "blacklist": "e3fd2f67b92756f053ee3045c45f4d40ba957bf310f2ca64c11f80f6f25604a1",
        "keymap": "2d04d7d7705d1c06cb9fff4c5290c02e719120e43ac65c387f00d8ef37b2d4cf",
        "udev": "5893d2c4c9426b2d6166586cb5bd1852be8fa22ba2984b9e1b2ca15f8b9cca5f",
    }
    curation_bottom_hashes = {
        "udev": "5a7595d79328000420c9f641362af1ef15aa5b1bf6ce0114588b49e13f7949a6",
    }
    removed_top_path = rootfs / "var/lib/azazel-c5/removed-init-top-hooks.sha256"
    removed_bottom_path = rootfs / "var/lib/azazel-c5/removed-init-bottom-hooks.sha256"
    removed_resume_path = rootfs / "var/lib/azazel-c5/removed-local-premount-hook.sha256"
    removed_top = {}
    if removed_top_path.is_file():
        for line in removed_top_path.read_text().splitlines():
            fields = line.split()
            if len(fields) == 2:
                removed_top[fields[0]] = fields[1]
    removed_bottom = {}
    if removed_bottom_path.is_file():
        for line in removed_bottom_path.read_text().splitlines():
            fields = line.split()
            if len(fields) == 2:
                removed_bottom[fields[0]] = fields[1]
    removed_resume = removed_resume_path.read_text().strip() if removed_resume_path.is_file() else ""
    resume_hook_absent = not (tree / "scripts/local-premount/resume").exists()
    init_source_pinned = config_evidence.get("source_init_sha256") == "0a9bb34973c78987922b57f010e99c36ddf102e8a5a2fd198385566539f5d6d5"
    source_init_digest_matches = digest(init_source_path) == config_evidence.get("source_init_sha256")
    anchor = "maybe_break top\n"
    expected_patched_init = init_source_text.replace(
        anchor,
        "# AZAZEL_C5_FIRST_STORAGE_ACTION\n/scripts/azazel-quarantine-first start\n" + anchor,
        1,
    ) if init_source_text.count(anchor) == 1 else ""
    patched_init_is_single_insertion = bool(expected_patched_init) and init.read_text(errors="replace") == expected_patched_init
    patched_init_matches = (
        config_evidence.get("patched_init_sha256") == digest(init)
        and len(executable_call_lines) == 1
        and patched_init_is_single_insertion
    )
    curation_evidence_valid = (
        removed_top == curation_hashes
        and removed_bottom == curation_bottom_hashes
        and removed_resume == "resume e8b4ec9ba6e78965e9c054cd296291b3ed1441b3eef25c9c94b8a37afee53b3a"
        and resume_hook_absent
        and init_source_pinned
        and source_init_digest_matches
        and patched_init_matches
        and udev_curation_valid
        and config_evidence.get("init_entry_call") == call
    )
    measured_order = bool(
        call_before_break
        and call_precedes_storage_paths
        and sources_order_file
        and order_exact
        and not forbidden_before_quarantine
        and not non_pseudo_mounts
        and first_is_quarantine
        and tuple(item["name"] for item in hooks) == expected
        and curation_evidence_valid
    )
    expected_config_hashes = {
        "pinned_udev_start_hook_sha256": declared[expected[-2]]["sha256"],
        "pinned_udev_handoff_hook_sha256": declared[expected[-1]]["sha256"],
        "persistent_udev_rule_sha256": build_manifest["inputs"]["quarantine_udev_rule"]["sha256"],
        "quarantine_helper_sha256": build_manifest["inputs"]["quarantine_block_helper"]["sha256"],
    }
    config_hashes_match = all(config_evidence.get(key) == value for key, value in expected_config_hashes.items())
    initramfs_rule = tree / "etc/udev/rules.d/00-azazel-quarantine.rules"
    rootfs_rule = rootfs / "etc/udev/rules.d/00-azazel-quarantine.rules"
    initramfs_helper = tree / "usr/libexec/azazel-quarantine-block"
    rootfs_helper = rootfs / "usr/libexec/azazel-quarantine-block"
    persistent_rule_present = all(
        path.is_file() and digest(path) == build_manifest["inputs"]["quarantine_udev_rule"]["sha256"]
        for path in (initramfs_rule, rootfs_rule)
    )
    helper_present = all(
        path.is_file() and digest(path) == build_manifest["inputs"]["quarantine_block_helper"]["sha256"]
        for path in (initramfs_helper, rootfs_helper)
    )
    quarantine_persistence_declared = config_hashes_match and persistent_rule_present and helper_present
    first_hook_text = first_entry.read_text(errors="replace")
    persistence_marker_declared = "/run/azazel/host-storage-quarantined" in first_hook_text
    fixture_enforcement_declared = declares_fixture_enforcement(first_hook_text)
    resume_configs = sorted((tree / "conf/conf.d").glob("*"))
    resume_disabled = any(
        path.is_file()
        and re.search(r"(?m)^\s*RESUME\s*=\s*none\s*$", path.read_text(errors="replace"))
        for path in resume_configs
    )
    resume_enabled = not resume_disabled
    automount_rules = []
    for root, rules_dirs in ((tree, ("etc/udev/rules.d", "lib/udev/rules.d", "usr/lib/udev/rules.d")),
                             (rootfs, ("etc/udev/rules.d", "lib/udev/rules.d", "usr/lib/udev/rules.d"))):
      for rule_path in rules_dirs:
        rules_dir = root / rule_path
        if rules_dir.is_dir():
            for rule in sorted(rules_dir.glob("*.rules")):
                if has_automount_activation_rule(rule.read_text(errors="replace")):
                    automount_rules.append(str(rule.relative_to(root)))

    manifest = {
        "schema": "azazel-boot/c5-inspection@1",
        "candidate": "live-build-evaluation-only",
        "build_host_id": secrets.token_hex(8),
        "architecture": build_manifest["target"]["architecture"],
        "payload_digest": f"sha256:{digest(payload)}",
        "initramfs_digest": f"sha256:{digest(initrd)}",
        "build_input_manifest_digest": f"sha256:{digest(frozen.parent / 'build-input-manifest.json')}",
        "order_established": measured_order,
        "execution_plan": {
            "earliest_stage": "direct /init entry after pseudo-filesystem setup and before maybe_break",
            "quarantine_entry_call": call,
            "quarantine_entry_call_count": len(call_positions),
            "quarantine_entry_before_maybe_break": call_before_break,
            "quarantine_entry_before_init_top_and_module_loading": call_precedes_storage_paths,
            "forbidden_storage_commands_before_quarantine": forbidden_before_quarantine,
            "non_pseudo_mounts_before_quarantine": non_pseudo_mounts,
            "runner_sources_stage_order_file": sources_order_file,
            "init_top_order_file_sha256": digest(top_order),
            "init_bottom_order_file_sha256": digest(bottom_order),
            "init_top_order_invalid_executable_content": top_order_errors,
            "init_bottom_order_invalid_executable_content": bottom_order_errors,
            "init_sha256": digest(init),
            "runner_sha256": digest(functions),
            "curation": {
                "removed_init_top_hooks_sha256": removed_top,
                "expected_removed_init_top_hooks_sha256": curation_hashes,
                "removed_init_bottom_hooks_sha256": removed_bottom,
                "expected_removed_init_bottom_hooks_sha256": curation_bottom_hashes,
                "removed_resume_hook": removed_resume,
                "resume_hook_absent_from_initramfs": resume_hook_absent,
                "source_init_matches_pinned_debian_template": init_source_pinned,
                "source_init_digest_matches_retained_template": source_init_digest_matches,
                "patch_is_exact_single_insertion_before_maybe_break": patched_init_is_single_insertion,
                "executable_quarantine_call_count": len(executable_call_lines),
                "patched_init_matches_configuration_record": patched_init_matches,
                "udev_pseudo_mount_rule_curation": {
                    "evidence": udev_curation,
                    "curated_file_matches_evidence": udev_curated_file_matches,
                    "valid": udev_curation_valid,
                },
                "valid": curation_evidence_valid,
            },
            "init_top_entries": [
                {"path": str(path.relative_to(tree)), "sha256": digest(path), "order_line": line}
                for path, (_, line) in zip(top_paths, top_entries, strict=True) if path.is_file()
            ],
            "init_bottom_entries": [
                {"path": str(path.relative_to(tree)), "sha256": digest(path), "order_line": line}
                for path, (_, line) in zip(bottom_paths, bottom_entries, strict=True) if path.is_file()
            ],
            "other_ordered_stages": other_stage_orders,
            "configuration_evidence": config_evidence,
        },
        # Static inspection confirms that the exact quarantine udev rule and
        # helper exist in both initramfs and rootfs. Runtime persistence remains
        # None until QEMU verifies the live state after switch_root.
        "quarantine_persists_into_userspace": None,
        "quarantine_persistence_declared_in_initramfs_and_rootfs": quarantine_persistence_declared,
        "runtime_persistence_evidence_required": True,
        "persistence_marker_declared_by_hook": persistence_marker_declared,
        "qemu_regular_file_fixture_enforcement_declared": fixture_enforcement_declared,
        "persistence_marker": "/run/azazel/host-storage-quarantined",
        "resume_enabled": resume_enabled,
        "automount_rules": automount_rules,
        "policy_version": policy["version"],
        "hooks": hooks,
    }
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    result = evaluate_inspection(evaluator, manifest)
    c5_result = dataclasses.asdict(result)
    c5_result["verdict"] = result.verdict.value
    c5_result["evidence_type"] = result.evidence_type.value
    c5_result["faults"] = [fault.value for fault in result.faults]
    boot_policy_result = {"verdict": "pass", "faults": []}
    try:
        verify_initramfs(
            InitramfsManifest(
                policy_version=policy["version"],
                hooks=tuple(item["name"] for item in hooks),
                resume_enabled=resume_enabled,
                automount_rules=tuple(automount_rules),
                quarantine_persists_into_userspace=None,
            )
        )
    except ImageRefused as exc:
        boot_policy_result = {
            "verdict": "fail",
            "faults": [{"code": fault.value, "detail": detail} for fault, detail in exc.faults],
        }
    manifest["boot_image_policy_result"] = boot_policy_result
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    c5_result["evaluator_faults"] = c5_result["faults"]
    c5_result["faults"] = summarize_faults(
        c5_result["evaluator_faults"], boot_policy_result["faults"]
    )
    c5_result["boot_image_policy_result"] = boot_policy_result
    (output.parent / "c5-result.json").write_text(
        json.dumps(c5_result, indent=2, sort_keys=True) + "\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen-inputs", required=True, type=Path)
    parser.add_argument("--initramfs-tree", required=True, type=Path)
    parser.add_argument("--rootfs-tree", required=True, type=Path)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--initramfs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    inspect(
        args.frozen_inputs,
        args.initramfs_tree,
        args.rootfs_tree,
        args.output,
        args.payload,
        args.initramfs,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
