#!/usr/bin/env python3
"""Compare two successful payload builds from one byte-pinned input manifest."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
from typing import Any


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def result(build: Path) -> dict[str, Any]:
    document = json.loads((build / "build-result.json").read_text())
    if document.get("schema") != "azazel-payload/build-result@4":
        raise ValueError(f"unsupported or incomplete build result: {build}")
    manifest_path = build / "build-input-manifest.json"
    manifest_sha256 = file_sha256(manifest_path)
    expected_manifest_sha256 = document.get("build_input_manifest_digest", "").removeprefix("sha256:")
    if manifest_sha256 != expected_manifest_sha256:
        raise ValueError(f"build result is not bound to its input manifest: {build}")
    sidecar = (build / "build-input-manifest.sha256").read_text().split()
    if sidecar != [manifest_sha256, "build-input-manifest.json"]:
        raise ValueError(f"manifest digest sidecar mismatch: {build}")
    manifest = json.loads(manifest_path.read_text())
    if (
        document.get("recipe_sha256") != manifest["inputs"]["recipe"]["sha256"]
        or document.get("rootfs_normalizer_sha256") != manifest["inputs"]["rootfs_normalizer"]["sha256"]
        or document.get("reproducibility_comparator_sha256") != manifest["inputs"]["reproducibility_comparator"]["sha256"]
        or document.get("toolchain_lock_sha256") != manifest["inputs"]["toolchain_lock"]["sha256"]
        or document.get("source_date_epoch") != manifest["normalization"]["source_date_epoch"]
        or document.get("architecture") != manifest["target"]["architecture"]
        or document.get("builder_environment") != manifest["builder_environment"]
        or document.get("builder_tool_versions") != manifest["builder"]["packages"]
        or document.get("c5_inspector_sha256") != manifest["inputs"]["c5_inspector"]["sha256"]
        or document.get("qemu_c5_runner_sha256") != manifest["inputs"]["qemu_c5_runner"]["sha256"]
        or document.get("nexus_deb_packager_sha256") != manifest["inputs"]["nexus_deb_packager"]["sha256"]
        or document.get("nexus_qemu_runner_sha256") != manifest["inputs"]["nexus_qemu_runner"]["sha256"]
        or document.get("initramfs_inspector_sha256") != manifest["inputs"]["initramfs_inspector"]["sha256"]
        or document.get("c5_evaluator_sha256") != manifest["c5"]["evaluator_sha256"]
        or document.get("c5_policy_sha256") != manifest["c5"]["policy_sha256"]
        or document.get("source_repositories") != manifest["source"]["repositories"]
    ):
        raise ValueError(f"build result provenance fields disagree with input manifest: {build}")
    for field in (
        "input_manifest_start_sha256",
        "input_manifest_end_sha256",
        "frozen_inputs_start_sha256",
        "frozen_inputs_end_sha256",
    ):
        if document.get(field) != f"sha256:{manifest_sha256}" and field.startswith("input_manifest"):
            raise ValueError(f"build input manifest changed during build: {build}")
        value = document.get(field, "")
        if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
            raise ValueError(f"missing or invalid build input closure measurement {field}: {build}")
    if document["frozen_inputs_start_sha256"] != document["frozen_inputs_end_sha256"]:
        raise ValueError(f"frozen inputs changed during build: {build}")
    instance_id = document.get("builder_instance_id_sha256", "")
    if not isinstance(instance_id, str) or len(instance_id) != 71 or not instance_id.startswith("sha256:"):
        raise ValueError(f"missing builder instance identity: {build}")
    actual_artifacts = {
        "kernel_digest": build / "vmlinuz",
        "initramfs_digest": build / "initrd.img",
        "squashfs_digest": build / "work/binary/live/filesystem.squashfs",
        "payload_digest": build / "payload.iso",
        "nexus_package_digest": build / "azazel-nexus-prototype.deb",
        "nexus_package_in_iso_rootfs_digest": build / "rootfs-extracted/usr/share/azazel-nexus/azazel-nexus-prototype.deb",
        "iso_embedded_squashfs_digest": build / "iso-extracted/filesystem.squashfs",
    }
    for field, path in actual_artifacts.items():
        if document.get(field) != f"sha256:{file_sha256(path)}":
            raise ValueError(f"build result digest mismatch for {path}: {build}")
    package_sidecar = (build / "azazel-nexus-prototype.deb.sha256").read_text().split()
    if package_sidecar != [
        document["nexus_package_digest"].removeprefix("sha256:"),
        "azazel-nexus-prototype.deb",
    ]:
        raise ValueError(f"Nexus package checksum sidecar mismatch: {build}")
    if document.get("nexus_package_sha256_sidecar_digest") != f"sha256:{file_sha256(build / 'azazel-nexus-prototype.deb.sha256')}":
        raise ValueError(f"Nexus package checksum sidecar digest mismatch: {build}")
    if document.get("nexus_package_summary_digest") != f"sha256:{file_sha256(build / 'nexus-package-summary.json')}":
        raise ValueError(f"Nexus package summary is not bound to build result: {build}")
    if document.get("c5_manifest_digest") != f"sha256:{file_sha256(build / 'c5-manifest.json')}":
        raise ValueError(f"C5 manifest digest is not bound into build result: {build}")
    if document.get("c5_result_digest") != f"sha256:{file_sha256(build / 'c5-result.json')}":
        raise ValueError(f"C5 result digest is not bound into build result: {build}")
    report_digests = document.get("evidence_report_digests")
    if not isinstance(report_digests, dict) or not report_digests:
        raise ValueError(f"build result does not bind its evidence reports: {build}")
    for name, expected in report_digests.items():
        report = build / name
        if not report.is_file() or expected != f"sha256:{file_sha256(report)}":
            raise ValueError(f"evidence report digest mismatch for {report}: {build}")
    components = hash_manifest(build / document["component_digest_manifest"])
    expected_component_by_name = {
        "vmlinuz": document["kernel_digest"].removeprefix("sha256:"),
        "initrd.img": document["initramfs_digest"].removeprefix("sha256:"),
        "filesystem.squashfs": document["squashfs_digest"].removeprefix("sha256:"),
    }
    for filename, expected in expected_component_by_name.items():
        matches = [digest for path, digest in components.items() if Path(path).name == filename]
        if matches != [expected]:
            raise ValueError(f"component manifest does not bind {filename}: {build}")
    return document


def hash_manifest(path: Path, *, strip_dot: bool = False) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        digest, name = line.split("  ", 1)
        if strip_dot and name.startswith("./"):
            name = name[2:]
        values[name] = digest
    return values


def tsv_rows(path: Path) -> dict[str, str]:
    rows = {}
    for line in path.read_text(errors="replace").splitlines():
        if not line:
            continue
        key = line.split("\t", 1)[0]
        rows[key] = line
    return rows


def compare_extracted_metadata(
    left: Path,
    right: Path,
    *,
    transient_directory_mtime: bool = False,
    ignore_extracted_directory_size: bool = False,
) -> dict[str, Any]:
    """Compare extracted metadata without treating host extraction artifacts as payload drift.

    The TSV inode column is the inode assigned by the builder VM's extraction filesystem,
    not the inode stored in the SquashFS or newc image. Directory mtimes in the initramfs
    extraction are also rewritten as children are unpacked; the archived entry mtimes are
    independently compared from the newc inspection report.
    """
    raw_a = tsv_rows(left)
    raw_b = tsv_rows(right)
    normalized_a: dict[str, str] = {}
    normalized_b: dict[str, str] = {}
    ignored: dict[str, set[str]] = {
        "host_inode": set(),
        "extracted_directory_mtime": set(),
        "extracted_directory_size": set(),
    }
    ignored_paths: set[str] = set()

    def normalize(rows: dict[str, str], other: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for path, row in rows.items():
            fields = row.split("\t")
            metadata = fields[1:]
            if len(metadata) < 6:
                normalized[path] = row
                continue
            peer_fields = other.get(path, "").split("\t")[1:]
            if len(peer_fields) >= 6 and metadata[3] != peer_fields[3]:
                ignored["host_inode"].add(path)
                ignored_paths.add(path)
            # metadata[3] is host inode. Preserve type, mode, owner, size, mtime and target.
            semantic = [*metadata[:3], *metadata[4:]]
            if (
                ignore_extracted_directory_size
                and metadata[0] == "d"
                and len(peer_fields) >= 6
                and metadata[4] != peer_fields[4]
            ):
                ignored["extracted_directory_size"].add(path)
                ignored_paths.add(path)
                # The size is observed on the host extraction filesystem, not in the payload.
                # After removing inode, size is at index 3. Keep all other fields strict.
                semantic.pop(3)
            if (
                transient_directory_mtime
                and metadata[0] == "d"
                and len(peer_fields) >= 6
                and metadata[5] != peer_fields[5]
            ):
                ignored["extracted_directory_mtime"].add(path)
                ignored_paths.add(path)
                # After removing inode, mtime is at index 4.
                semantic.pop(4)
            normalized[path] = "\t".join(semantic)
        return normalized

    normalized_a = normalize(raw_a, raw_b)
    normalized_b = normalize(raw_b, raw_a)
    comparison = compare_maps(normalized_a, normalized_b)
    return {
        **comparison,
        "ignored_extraction_observations": {
            "counts": {name: len(paths) for name, paths in ignored.items()},
            "details": {
                "extracted_directory_size": (
                    "host extraction filesystem stat size; not payload directory metadata"
                ),
                "extracted_directory_mtime": (
                    "host extraction timestamp after child extraction; archived entry mtimes are compared separately"
                ),
                "host_inode": "inode assigned by the host extraction filesystem",
            },
            "path_count": len(ignored_paths),
            "paths_sample": sorted(ignored_paths)[:100],
            "paths_truncated": len(ignored_paths) > 100,
        },
    }


def compare_maps(left: dict[str, str], right: dict[str, str]) -> dict[str, Any]:
    keys = sorted(set(left) | set(right))
    changed = [key for key in keys if left.get(key) != right.get(key)]
    return {
        "equal": not changed,
        "left_count": len(left),
        "right_count": len(right),
        "changed_paths": changed,
        "changed_values": [
            {"path": key, "a": left.get(key), "b": right.get(key)}
            for key in changed
        ],
    }


def compare_text_files(left: Path, right: Path, *, sample_limit: int = 100) -> dict[str, Any]:
    left_text = left.read_text(errors="replace")
    right_text = right.read_text(errors="replace")
    diff = list(difflib.unified_diff(
        left_text.splitlines(), right_text.splitlines(),
        fromfile="build-a", tofile="build-b", lineterm="",
    ))
    return {
        "equal": left_text == right_text,
        "sha256": {"a": file_sha256(left), "b": file_sha256(right)},
        "diff_lines": len(diff),
        "diff_sample": diff[:sample_limit],
        "diff_truncated": len(diff) > sample_limit,
    }


def compare_initramfs_archives(left: Path, right: Path, *, sample_limit: int = 100) -> dict[str, Any]:
    a = json.loads(left.read_text())
    b = json.loads(right.read_text())
    segment_changes = []
    entry_changes = []
    max_segments = max(len(a["segments"]), len(b["segments"]))
    for segment_index in range(max_segments):
        segment_a = a["segments"][segment_index] if segment_index < len(a["segments"]) else None
        segment_b = b["segments"][segment_index] if segment_index < len(b["segments"]) else None
        if segment_a is None or segment_b is None:
            segment_changes.append({"segment": segment_index, "a": segment_a, "b": segment_b})
            continue
        for field in (
            "compression", "offset", "compressed_size", "compressed_sha256",
            "uncompressed_cpio_size", "uncompressed_cpio_sha256", "compression_header",
        ):
            if segment_a.get(field) != segment_b.get(field):
                segment_changes.append({
                    "segment": segment_index,
                    "field": field,
                    "a": segment_a.get(field),
                    "b": segment_b.get(field),
                })
        entries_a = segment_a["entries"]
        entries_b = segment_b["entries"]
        for entry_index in range(max(len(entries_a), len(entries_b))):
            entry_a = entries_a[entry_index] if entry_index < len(entries_a) else None
            entry_b = entries_b[entry_index] if entry_index < len(entries_b) else None
            if entry_a != entry_b:
                entry_changes.append({
                    "segment": segment_index,
                    "entry_order": entry_index + 1,
                    "a": entry_a,
                    "b": entry_b,
                })
    return {
        "equal": not segment_changes and not entry_changes,
        "segment_count": {"a": len(a["segments"]), "b": len(b["segments"])},
        "entry_count": {"a": a["entry_count"], "b": b["entry_count"]},
        "segment_changes": segment_changes[:sample_limit],
        "segment_change_count": len(segment_changes),
        "entry_changes": entry_changes[:sample_limit],
        "entry_change_count": len(entry_changes),
        "diff_truncated": len(segment_changes) > sample_limit or len(entry_changes) > sample_limit,
    }


def compare_builds(build_a: Path, build_b: Path) -> dict[str, Any]:
    a = result(build_a)
    b = result(build_b)
    binding_fields = (
        "build_input_manifest_digest",
        "recipe_sha256",
        "toolchain_lock_sha256",
        "architecture",
        "source_date_epoch",
    )
    binding = {field: {"a": a.get(field), "b": b.get(field)} for field in binding_fields}
    mismatched_binding = [field for field in binding_fields if a.get(field) != b.get(field)]
    if mismatched_binding:
        raise ValueError(f"builds do not share pinned inputs: {mismatched_binding}")
    if a["builder_instance_id_sha256"] == b["builder_instance_id_sha256"]:
        raise ValueError("builds do not come from distinct builder instances")

    component_a = hash_manifest(build_a / a["component_digest_manifest"])
    component_b = hash_manifest(build_b / b["component_digest_manifest"])
    content_a = hash_manifest(build_a / a["rootfs_file_content_manifest"], strip_dot=True)
    content_b = hash_manifest(build_b / b["rootfs_file_content_manifest"], strip_dot=True)
    rootfs_content = compare_maps(content_a, content_b)
    component_diff = compare_maps(component_a, component_b)
    changed_components = component_diff["changed_paths"]
    boot_component_paths = sorted(
        path for path in changed_components
        if "/EFI/" in path or "/boot/" in path or "/isolinux/" in path
    )
    core_components = {"vmlinuz", "initrd.img", "filesystem.squashfs"}
    other_component_values = [
        item for item in component_diff["changed_values"]
        if Path(item["path"]).name not in core_components
        and item["path"] not in boot_component_paths
    ]

    rootfs_meta = compare_extracted_metadata(
        build_a / a["rootfs_metadata"],
        build_b / b["rootfs_metadata"],
        ignore_extracted_directory_size=True,
    )
    initramfs_meta = compare_extracted_metadata(
        build_a / a["initramfs_extracted_metadata"],
        build_b / b["initramfs_extracted_metadata"],
        transient_directory_mtime=True,
    )
    initramfs_archive = compare_initramfs_archives(
        build_a / a["initramfs_inspection"], build_b / b["initramfs_inspection"]
    )
    initramfs_listing = compare_text_files(
        build_a / a["initramfs_entry_listing"],
        build_b / b["initramfs_entry_listing"],
    )
    iso_boot = compare_text_files(
        build_a / a["iso_boot_metadata"], build_b / b["iso_boot_metadata"]
    )
    iso_files = compare_text_files(
        build_a / a["iso_file_metadata"], build_b / b["iso_file_metadata"]
    )

    checks = {
        "kernel": a["kernel_digest"] == b["kernel_digest"],
        "initramfs": a["initramfs_digest"] == b["initramfs_digest"],
        "nexus_package": a["nexus_package_digest"] == b["nexus_package_digest"],
        "nexus_package_in_iso_rootfs": a["nexus_package_in_iso_rootfs_digest"] == b["nexus_package_in_iso_rootfs_digest"],
        "iso_embedded_squashfs": a["iso_embedded_squashfs_digest"] == b["iso_embedded_squashfs_digest"],
        "initramfs_entry_order_and_metadata": initramfs_listing["equal"],
        "initramfs_extracted_metadata": initramfs_meta["equal"],
        "initramfs_archive_structure": initramfs_archive["equal"],
        "rootfs_file_contents": rootfs_content["equal"],
        "rootfs_metadata": rootfs_meta["equal"],
        "squashfs": a["squashfs_digest"] == b["squashfs_digest"],
        "efi_and_boot_components": not boot_component_paths,
        "other_iso_file_components": not other_component_values,
        "iso_boot_metadata": iso_boot["equal"],
        "iso_filesystem_metadata": iso_files["equal"],
        "final_payload": a["payload_digest"] == b["payload_digest"],
    }
    ordered_layers = (
        "kernel",
        "initramfs",
        "nexus_package",
        "nexus_package_in_iso_rootfs",
        "iso_embedded_squashfs",
        "initramfs_entry_order_and_metadata",
        "initramfs_extracted_metadata",
        "initramfs_archive_structure",
        "rootfs_file_contents",
        "rootfs_metadata",
        "squashfs",
        "efi_and_boot_components",
        "other_iso_file_components",
        "iso_boot_metadata",
        "iso_filesystem_metadata",
        "final_payload",
    )
    first_divergence = next((layer for layer in ordered_layers if not checks[layer]), None)
    reproduced = all(checks.values())
    return {
        "schema": "azazel-payload/reproducibility-result@2",
        "result": "reproduced" if reproduced else "not_reproduced",
        "same_pinned_inputs": True,
        "binding": binding,
        "analyzer": {
            "tool": Path(__file__).name,
            "sha256": f"sha256:{file_sha256(Path(__file__))}",
            "post_build_analyzer_sha256": f"sha256:{file_sha256(Path(__file__))}",
            "digest_scope": "post_build_analyzer_source; not bound by the frozen build input manifest",
            "post_build_reanalysis": True,
            "normalizes_host_extraction_noise": [
                "host filesystem inode numbers",
                "initramfs extraction-time directory mtimes",
                "rootfs host-extraction directory sizes (rootfs metadata comparison only)",
            ],
            "pinned_build_comparator_sha256": a["reproducibility_comparator_sha256"],
            "frozen_build_comparator_sha256": a["reproducibility_comparator_sha256"],
            "pinned_build_comparator_digest_scope": "frozen build input; distinct from this post-build analyzer digest",
        },
        "checks": checks,
        "first_divergence": first_divergence,
        "artifacts": {
            "kernel_sha256": {"a": a["kernel_digest"], "b": b["kernel_digest"]},
            "initramfs_sha256": {"a": a["initramfs_digest"], "b": b["initramfs_digest"]},
            "squashfs_sha256": {"a": a["squashfs_digest"], "b": b["squashfs_digest"]},
            "payload_sha256": {"a": a["payload_digest"], "b": b["payload_digest"]},
            "nexus_package_sha256": {
                "a": a["nexus_package_digest"],
                "b": b["nexus_package_digest"],
            },
        },
        "initramfs": {
            "entry_listing_comparison": initramfs_listing,
            "newc_archive_comparison": initramfs_archive,
            "container_type": {
                "a": (build_a / a["initramfs_container_type"]).read_text().strip(),
                "b": (build_b / b["initramfs_container_type"]).read_text().strip(),
            },
            "metadata_comparison": initramfs_meta,
        },
        "rootfs": {
            "content_comparison": rootfs_content,
            "metadata_comparison": rootfs_meta,
        },
        "boot_components": {
            "changed_paths": boot_component_paths,
            "all_component_changes": component_diff["changed_values"],
        },
        "other_iso_file_components": other_component_values,
        "iso_metadata": {
            "boot_metadata": iso_boot,
            "filesystem_metadata": iso_files,
        },
        "production_builder_selected": False,
        "hardware_verified": False,
        "secure_boot_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-a", required=True, type=Path)
    parser.add_argument("--build-b", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    measurement = compare_builds(args.build_a, args.build_b)
    args.output.write_text(json.dumps(measurement, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": measurement["result"], "first_divergence": measurement["first_divergence"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
