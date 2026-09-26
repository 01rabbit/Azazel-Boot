#!/usr/bin/env python3
"""Strictly compare unnormalized rootfs extraction diagnostic JSON files.

This is an offline evidence tool. It does not rewrite, normalize, or otherwise
modify either diagnostics file or either optional build-result input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

DIAGNOSTICS_SCHEMA = "azazel-payload/rootfs-extraction-diagnostics@1"
BUILD_DIGEST_FIELDS = {
    "payload_sha256": "payload_digest",
    "kernel_sha256": "kernel_digest",
    "initramfs_sha256": "initramfs_digest",
    "squashfs_sha256": "squashfs_digest",
}


def _read_json(
    path: Path, expected_schema: str | None = None
) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise TypeError(f"{path}: JSON root must be an object")
    if expected_schema is not None and document.get("schema") != expected_schema:
        raise ValueError(
            f"{path}: expected schema {expected_schema!r}, got {document.get('schema')!r}"
        )
    return document, hashlib.sha256(raw).hexdigest()


def _sample_value(value: Any, limit: int = 512) -> Any:
    """Keep report examples bounded without changing comparison semantics."""
    if isinstance(value, str) and len(value) > limit:
        return {
            "prefix": value[:limit],
            "truncated": True,
            "original_characters": len(value),
        }
    if isinstance(value, list) and len(value) > 20:
        return {"prefix": value[:20], "truncated": True, "original_items": len(value)}
    if isinstance(value, dict) and len(value) > 30:
        keys = sorted(value)[:30]
        return {
            "prefix": {key: value[key] for key in keys},
            "truncated": True,
            "original_items": len(value),
        }
    return value


class _Differences:
    def __init__(self, sample_limit: int) -> None:
        self.sample_limit = sample_limit
        self.counts: Counter[tuple[str, str]] = Counter()
        self.samples: list[dict[str, Any]] = []

    def add(self, category: str, field: str, path: str, a: Any, b: Any) -> None:
        self.counts[(category, field)] += 1
        if len(self.samples) < self.sample_limit:
            self.samples.append(
                {
                    "category": category,
                    "field": field,
                    "path": path,
                    "a": _sample_value(a),
                    "b": _sample_value(b),
                }
            )

    def report(self) -> dict[str, Any]:
        by_category: dict[str, dict[str, Any]] = {}
        for (category, field), count in sorted(self.counts.items()):
            item = by_category.setdefault(category, {"mismatch_count": 0, "fields": {}})
            item["mismatch_count"] += count
            item["fields"][field] = count
        return {
            "mismatch_count": sum(self.counts.values()),
            "categories": by_category,
            "samples_limit": self.sample_limit,
            "samples": self.samples,
        }


def _compare_value(
    differences: _Differences,
    category: str,
    field: str,
    path: str,
    a: Any,
    b: Any,
) -> None:
    """Recursively compare exact JSON values and count differing leaves."""
    if type(a) is not type(b):
        differences.add(category, field, path, a, b)
    elif isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            child = f"{field}.{key}" if field else str(key)
            if key not in a or key not in b:
                differences.add(
                    category,
                    child,
                    path,
                    a.get(key, "<missing>"),
                    b.get(key, "<missing>"),
                )
            else:
                _compare_value(differences, category, child, path, a[key], b[key])
    elif isinstance(a, list):
        if a != b:
            differences.add(category, field, path, a, b)
    elif a != b:
        differences.add(category, field, path, a, b)


def _compare_entire_document(a: Any, b: Any, sample_limit: int) -> dict[str, Any]:
    """Count all differing JSON leaves, including fields unknown to this schema reader."""
    differences = _Differences(sample_limit)

    def walk(left: Any, right: Any, location: str) -> None:
        if type(left) is not type(right):
            differences.add("exact_json", location or "$", location or "$", left, right)
        elif isinstance(left, dict):
            for key in sorted(set(left) | set(right)):
                child = f"{location}.{key}" if location else str(key)
                if key not in left or key not in right:
                    differences.add(
                        "exact_json",
                        child,
                        child,
                        left.get(key, "<missing>"),
                        right.get(key, "<missing>"),
                    )
                else:
                    walk(left[key], right[key], child)
        elif isinstance(left, list):
            if left != right:
                # Keep each changed index measurable; an array insertion therefore
                # cannot be hidden by sorting or by treating it as a set.
                for index in range(max(len(left), len(right))):
                    lv = left[index] if index < len(left) else "<missing>"
                    rv = right[index] if index < len(right) else "<missing>"
                    if lv != rv or type(lv) is not type(rv):
                        walk(lv, rv, f"{location}[{index}]")
        elif left != right:
            differences.add("exact_json", location or "$", location or "$", left, right)

    walk(a, b, "")
    return differences.report()


def _by_path(items: Any, path_field: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if isinstance(item, dict) and isinstance(item.get(path_field), str):
            result[item[path_field]] = item
    return result


def _path_identity_set(nodes: Any) -> set[tuple[str, str | None]]:
    if not isinstance(nodes, list):
        return set()
    return {
        (node["path"], node.get("path_bytes_base64"))
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("path"), str)
    }


def _order_paths(items: Any, path_field: str = "path") -> list[Any]:
    if not isinstance(items, list):
        return ["<not-a-list>", type(items).__name__]
    return [item.get(path_field) if isinstance(item, dict) else item for item in items]


def compare_documents(
    a: dict[str, Any], b: dict[str, Any], sample_limit: int = 20
) -> dict[str, Any]:
    """Compare the required unnormalized extraction evidence in two documents."""
    if sample_limit < 0:
        raise ValueError("sample_limit must be non-negative")
    differences = _Differences(sample_limit)
    observation_a = (
        a.get("observation") if isinstance(a.get("observation"), dict) else {}
    )
    observation_b = (
        b.get("observation") if isinstance(b.get("observation"), dict) else {}
    )

    # Readdir order is compared as the exact ordered JSON sequence, independently
    # for every directory path. Directory traversal order is also retained below.
    dirs_a = _by_path(a.get("directories_in_observation_order"), "path")
    dirs_b = _by_path(b.get("directories_in_observation_order"), "path")
    for path in sorted(set(dirs_a) | set(dirs_b)):
        left, right = dirs_a.get(path), dirs_b.get(path)
        if left is None or right is None:
            differences.add(
                "directory_readdir_order",
                "directory_presence",
                path,
                left if left is not None else "<missing>",
                right if right is not None else "<missing>",
            )
        else:
            _compare_value(
                differences,
                "directory_readdir_order",
                "raw_readdir_order",
                path,
                left.get("raw_readdir_order"),
                right.get("raw_readdir_order"),
            )
            _compare_value(
                differences,
                "directory_readdir_order",
                "entry_count",
                path,
                left.get("entry_count"),
                right.get("entry_count"),
            )
            _compare_value(
                differences,
                "directory_readdir_order",
                "status",
                path,
                left.get("status"),
                right.get("status"),
            )

    directory_order_a = _order_paths(a.get("directories_in_observation_order"))
    directory_order_b = _order_paths(b.get("directories_in_observation_order"))
    _compare_value(
        differences,
        "directory_observation_order",
        "directories_in_observation_order",
        ".",
        directory_order_a,
        directory_order_b,
    )

    nodes_a = a.get("nodes_in_observation_order")
    nodes_b = b.get("nodes_in_observation_order")
    node_order_a = _order_paths(nodes_a)
    node_order_b = _order_paths(nodes_b)
    _compare_value(
        differences,
        "recursive_node_observation_order",
        "nodes_in_observation_order",
        ".",
        node_order_a,
        node_order_b,
    )

    paths_a, paths_b = _path_identity_set(nodes_a), _path_identity_set(nodes_b)
    if paths_a != paths_b:
        differences.add(
            "exact_path_set",
            "node_path_identities",
            ".",
            sorted(paths_a - paths_b),
            sorted(paths_b - paths_a),
        )

    node_map_a, node_map_b = _by_path(nodes_a, "path"), _by_path(nodes_b, "path")
    for path in sorted(set(node_map_a) | set(node_map_b)):
        left, right = node_map_a.get(path), node_map_b.get(path)
        if left is None or right is None:
            differences.add(
                "node_observation",
                "node_presence",
                path,
                left if left is not None else "<missing>",
                right if right is not None else "<missing>",
            )
            continue
        for field in (
            "status",
            "error",
            "name",
            "name_bytes_base64",
            "path_bytes_base64",
        ):
            if left.get(field) != right.get(field):
                differences.add(
                    "node_observation",
                    field,
                    path,
                    left.get(field, "<missing>"),
                    right.get(field, "<missing>"),
                )
        _compare_value(
            differences, "stat", "stat", path, left.get("stat"), right.get("stat")
        )
        _compare_value(
            differences,
            "xattrs_acl",
            "xattrs",
            path,
            left.get("xattrs"),
            right.get("xattrs"),
        )

    _compare_value(
        differences,
        "stat",
        "root_stat",
        ".",
        observation_a.get("root_stat"),
        observation_b.get("root_stat"),
    )
    _compare_value(
        differences,
        "xattrs_acl",
        "root_xattrs",
        ".",
        observation_a.get("root_xattrs"),
        observation_b.get("root_xattrs"),
    )

    filesystem_a = (
        observation_a.get("filesystem")
        if isinstance(observation_a.get("filesystem"), dict)
        else {}
    )
    filesystem_b = (
        observation_b.get("filesystem")
        if isinstance(observation_b.get("filesystem"), dict)
        else {}
    )
    _compare_value(
        differences,
        "mount",
        "mount",
        ".",
        filesystem_a.get("mount"),
        filesystem_b.get("mount"),
    )
    _compare_value(
        differences,
        "statvfs",
        "statvfs",
        ".",
        filesystem_a.get("statvfs"),
        filesystem_b.get("statvfs"),
    )
    _compare_value(
        differences,
        "creation_order",
        "creation_order",
        ".",
        observation_a.get("creation_order"),
        observation_b.get("creation_order"),
    )
    _compare_value(
        differences,
        "creation_order",
        "creation_order_status",
        ".",
        observation_a.get("creation_order_status"),
        observation_b.get("creation_order_status"),
    )

    mismatch_report = differences.report()
    exact_json_report = _compare_entire_document(a, b, sample_limit)
    return {
        "schema": "azazel-payload/rootfs-extraction-comparison@1",
        "comparison_mode": "strict_unormalized_exact_json_values",
        "diagnostics": {
            "a": {"schema": a.get("schema")},
            "b": {"schema": b.get("schema")},
            "semantic_json_identical": a == b,
            "mismatch_count": mismatch_report["mismatch_count"],
            "mismatches": mismatch_report,
            "exact_json_mismatches": exact_json_report,
        },
        "strict_identical": a == b,
    }


def compare_files(
    diagnostics_a: Path,
    diagnostics_b: Path,
    *,
    build_result_a: Path | None = None,
    build_result_b: Path | None = None,
    sample_limit: int = 20,
) -> dict[str, Any]:
    a, digest_a = _read_json(diagnostics_a, DIAGNOSTICS_SCHEMA)
    b, digest_b = _read_json(diagnostics_b, DIAGNOSTICS_SCHEMA)
    report = compare_documents(a, b, sample_limit)
    report["comparator"] = {
        "path": str(Path(__file__).resolve()),
        "sha256": f"sha256:{hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}",
    }
    report["diagnostics"]["a"].update(
        {"path": str(diagnostics_a), "sha256": f"sha256:{digest_a}"}
    )
    report["diagnostics"]["b"].update(
        {"path": str(diagnostics_b), "sha256": f"sha256:{digest_b}"}
    )
    report["diagnostics"]["raw_files_identical"] = digest_a == digest_b
    # Strict identity includes byte identity as well as exact parsed-value equality.
    report["strict_identical"] = digest_a == digest_b and a == b
    if (build_result_a is None) != (build_result_b is None):
        raise ValueError(
            "--build-result-a and --build-result-b must be provided together"
        )
    if build_result_a is not None and build_result_b is not None:
        build_a, _ = _read_json(build_result_a, "azazel-payload/build-result@4")
        build_b, _ = _read_json(build_result_b, "azazel-payload/build-result@4")
        fields = {}
        for label, key in BUILD_DIGEST_FIELDS.items():
            value_a, value_b = build_a.get(key), build_b.get(key)
            fields[label] = {
                "a": value_a,
                "b": value_b,
                "equal": value_a == value_b
                and value_a is not None
                and value_b is not None,
            }
        report["build_artifact_digests"] = {
            "build_result_a": str(build_result_a),
            "build_result_b": str(build_result_b),
            "fields": fields,
        }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diagnostics-a", required=True, type=Path)
    parser.add_argument("--diagnostics-b", required=True, type=Path)
    parser.add_argument("--build-result-a", type=Path)
    parser.add_argument("--build-result-b", type=Path)
    parser.add_argument("--sample-limit", type=int, default=20)
    parser.add_argument(
        "--output", type=Path, help="write report JSON here (default: stdout)"
    )
    args = parser.parse_args(argv)
    try:
        report = compare_files(
            args.diagnostics_a,
            args.diagnostics_b,
            build_result_a=args.build_result_a,
            build_result_b=args.build_result_b,
            sample_limit=args.sample_limit,
        )
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        input_paths = [
            args.diagnostics_a,
            args.diagnostics_b,
            args.build_result_a,
            args.build_result_b,
        ]
        if any(
            path is not None and args.output.resolve() == path.resolve()
            for path in input_paths
        ):
            parser.error("--output must not overwrite an input file")
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if report["strict_identical"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
