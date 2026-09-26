#!/usr/bin/env python3
"""Stage a prototype-only Debian package from a verified offline Nexus bundle.

This creates a dpkg-deb package root; it does not install the package, run the
Nexus installer, contact a network, or start services.  Production packaging
selection remains open.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tarfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any


PACKAGE_NAME = "azazel-nexus-prototype"
PACKAGE_VERSION = "0.0.1~prototype1"
PACKAGE_ARCHITECTURE = "all"
NORMALIZED_MTIME = 0
MAX_BUNDLE_BYTES = 64 * 1024 * 1024


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_member_path(raw: Any) -> str:
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise ValueError(f"invalid bundle member path: {raw!r}")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in ("", ".", "..") for part in raw.split("/")):
        raise ValueError(f"unsafe bundle member path: {raw!r}")
    if path.as_posix() != raw:
        raise ValueError(f"non-canonical bundle member path: {raw!r}")
    return raw


def _load_verified_bundle(bundle_path: Path, manifest_path: Path) -> tuple[dict[str, bytes], bytes, bytes]:
    bundle_bytes = bundle_path.read_bytes()
    manifest_bytes = manifest_path.read_bytes()
    if len(bundle_bytes) > MAX_BUNDLE_BYTES:
        raise ValueError(f"bundle exceeds prototype size limit ({MAX_BUNDLE_BYTES} bytes)")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("bundle manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != "azazel-nexus-offline-source-bundle@1":
        raise ValueError("unsupported Nexus bundle manifest schema")
    if manifest.get("archive_size") != len(bundle_bytes):
        raise ValueError("bundle size differs from its manifest")
    actual_bundle_sha = _sha256(bundle_bytes)
    if manifest.get("bundle_sha256") != actual_bundle_sha:
        raise ValueError("bundle digest differs from its manifest")

    declared = manifest.get("files")
    if not isinstance(declared, list) or not declared:
        raise ValueError("bundle manifest must declare at least one file")
    expected: dict[str, dict[str, Any]] = {}
    for item in declared:
        if not isinstance(item, dict):
            raise ValueError("bundle manifest file entry must be an object")
        name = _safe_member_path(item.get("path"))
        if name in expected:
            raise ValueError(f"duplicate path in bundle manifest: {name}")
        mode_text = item.get("mode")
        if not isinstance(mode_text, str) or not re.fullmatch(r"0[0-7]{3}", mode_text):
            raise ValueError(f"invalid mode for bundle member: {name}")
        mode = int(mode_text, 8)
        if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX) or mode & ~0o777:
            raise ValueError(f"unsafe permission bits for bundle member: {name}")
        size = item.get("size")
        digest = item.get("sha256")
        if not isinstance(size, int) or size < 0:
            raise ValueError(f"invalid size for bundle member: {name}")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"invalid SHA-256 for bundle member: {name}")
        expected[name] = {"mode": mode, "size": size, "sha256": digest}

    members: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=__import__("io").BytesIO(bundle_bytes), mode="r:*") as archive:
            for member in archive.getmembers():
                name = _safe_member_path(member.name)
                if name in members:
                    raise ValueError(f"duplicate path in source archive: {name}")
                if not member.isfile():
                    raise ValueError(f"non-regular tar member is not allowed: {name}")
                if name not in expected:
                    raise ValueError(f"unmanifested tar member: {name}")
                details = expected[name]
                if member.mode != details["mode"]:
                    raise ValueError(f"mode differs from manifest: {name}")
                if member.size != details["size"]:
                    raise ValueError(f"size differs from manifest: {name}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"tar member cannot be read: {name}")
                content = stream.read(details["size"] + 1)
                if len(content) != details["size"]:
                    raise ValueError(f"content size differs from manifest: {name}")
                if _sha256(content) != details["sha256"]:
                    raise ValueError(f"content digest differs from manifest: {name}")
                members[name] = content
    except tarfile.TarError as exc:
        raise ValueError(f"invalid source tar archive: {exc}") from exc
    if set(members) != set(expected):
        missing = sorted(set(expected) - set(members))
        raise ValueError(f"archive is missing manifest-declared members: {missing}")
    return members, bundle_bytes, manifest_bytes


def _entry_points(members: dict[str, bytes]) -> dict[str, str]:
    entry_points: dict[str, str] = {}
    for project_file in ("pyproject.toml", "runtime/pyproject.toml"):
        try:
            project = tomllib.loads(members[project_file].decode("utf-8"))
        except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ValueError(f"cannot read console scripts from {project_file}") from exc
        scripts = project.get("project", {}).get("scripts", {})
        if not isinstance(scripts, dict):
            raise ValueError(f"invalid console script table in {project_file}")
        for name, target in scripts.items():
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name)
                or not isinstance(target, str)
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*", target)
            ):
                raise ValueError(f"unsupported console entry point: {name!r} = {target!r}")
            if name in entry_points:
                raise ValueError(f"duplicate console entry point: {name}")
            module, _function = target.split(":", 1)
            allowed_root = "azazel_nexus_runtime." if project_file.startswith("runtime/") else "azazel_nexus."
            if not module.startswith(allowed_root):
                raise ValueError(f"console entry point escapes its source package: {name}")
            entry_points[name] = target
    if "azazel-nexus" not in entry_points:
        raise ValueError("operator console entry point azazel-nexus is required")
    return entry_points


def _write_file(root: Path, relative: str, content: bytes, mode: int) -> None:
    destination = root.joinpath(*PurePosixPath(relative).parts)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    destination.write_bytes(content)
    destination.chmod(mode)
    os.utime(destination, (NORMALIZED_MTIME, NORMALIZED_MTIME), follow_symlinks=False)


def _package_relative_files(members: dict[str, bytes], entry_points: dict[str, str]) -> dict[str, tuple[bytes, int]]:
    package_files: dict[str, tuple[bytes, int]] = {}
    for name, content in members.items():
        if name.startswith("src/azazel_nexus/"):
            package_files[f"usr/lib/python3/dist-packages/{name[len('src/'): ]}"] = (content, 0o644)
        elif name.startswith("runtime/src/azazel_nexus_runtime/"):
            relative = name[len("runtime/src/") :]
            package_files[f"usr/lib/python3/dist-packages/{relative}"] = (content, 0o644)
        elif name == "packaging/install.sh":
            package_files["usr/lib/azazel-nexus/packaging/install.sh"] = (content, 0o755)
        elif name.startswith("packaging/systemd/") or name == "packaging/azazel-nexus.preset":
            package_files[f"usr/lib/azazel-nexus/{name}"] = (content, 0o644)

    required = (
        "usr/lib/python3/dist-packages/azazel_nexus/__init__.py",
        "usr/lib/python3/dist-packages/azazel_nexus_runtime/__init__.py",
        "usr/lib/azazel-nexus/packaging/install.sh",
        "usr/lib/azazel-nexus/packaging/azazel-nexus.preset",
    )
    missing = [path for path in required if path not in package_files]
    if missing:
        raise ValueError(f"bundle is missing required package inputs: {missing}")
    if not any(path.startswith("usr/lib/azazel-nexus/packaging/systemd/") for path in package_files):
        raise ValueError("bundle has no Nexus systemd units")

    for name, target in entry_points.items():
        module, function = target.split(":", 1)
        script = (
            "#!/usr/bin/python3\n"
            "import sys\n"
            f"from {module} import {function}\n"
            "if __name__ == '__main__':\n"
            f"    sys.exit({function}())\n"
        ).encode("utf-8")
        destination = f"usr/bin/{name}" if name == "azazel-nexus" else f"usr/libexec/azazel/{name}"
        package_files[destination] = (script, 0o755)
    return package_files


def _normalize_directory_times(root: Path) -> None:
    for directory, child_dirs, _files in os.walk(root, topdown=False):
        for child in child_dirs:
            path = Path(directory) / child
            os.chmod(path, 0o755)
            os.utime(path, (NORMALIZED_MTIME, NORMALIZED_MTIME), follow_symlinks=False)
    os.chmod(root, 0o755)
    os.utime(root, (NORMALIZED_MTIME, NORMALIZED_MTIME), follow_symlinks=False)


def build_package(bundle_path: Path, manifest_path: Path, output_dir: Path) -> dict[str, Any]:
    members, bundle_bytes, manifest_bytes = _load_verified_bundle(bundle_path, manifest_path)
    entry_points = _entry_points(members)
    package_files = _package_relative_files(members, entry_points)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir = output_dir.resolve(strict=True)
    package_root = output_dir / "package-root"
    summary_path = output_dir / "package-summary.json"
    if package_root.exists() or summary_path.exists():
        raise FileExistsError("output already contains package-root or package-summary.json")
    package_root.mkdir(mode=0o755)
    control = (
        f"Package: {PACKAGE_NAME}\n"
        f"Version: {PACKAGE_VERSION}\n"
        f"Architecture: {PACKAGE_ARCHITECTURE}\n"
        "Maintainer: Azazel Prototype <noreply@example.invalid>\n"
        "Depends: python3 (>= 3.11)\n"
        "Section: misc\n"
        "Priority: optional\n"
        "Description: Prototype-only offline Azazel-Nexus package\n"
        " For payload construction and integration evaluation only.\n"
        " This package does not establish production packaging selection.\n"
    ).encode("utf-8")
    _write_file(package_root, "DEBIAN/control", control, 0o644)
    for relative, (content, mode) in sorted(package_files.items()):
        _write_file(package_root, relative, content, mode)
    _normalize_directory_times(package_root)

    staged = []
    for path in sorted(p for p in package_root.rglob("*") if p.is_file()):
        raw = path.read_bytes()
        staged.append({
            "path": path.relative_to(package_root).as_posix(),
            "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
            "size": len(raw),
            "sha256": _sha256(raw),
        })
    summary: dict[str, Any] = {
        "schema": "azazel-nexus-prototype-deb-staging@1",
        "package": PACKAGE_NAME,
        "version": PACKAGE_VERSION,
        "architecture": PACKAGE_ARCHITECTURE,
        "bundle_sha256": _sha256(bundle_bytes),
        "bundle_manifest_sha256": _sha256(manifest_bytes),
        "normalized_mtime_epoch": NORMALIZED_MTIME,
        "maintainer_scripts": [],
        "network_access": False,
        "services_started": False,
        "production_packaging_selection": "open",
        "entry_points": dict(sorted(entry_points.items())),
        "files": staged,
    }
    encoded = (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode("utf-8")
    summary_path.write_bytes(encoded)
    os.utime(summary_path, (NORMALIZED_MTIME, NORMALIZED_MTIME), follow_symlinks=False)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path, help="offline Nexus source tar.gz")
    parser.add_argument("--manifest", required=True, type=Path, help="JSON manifest for the source bundle")
    parser.add_argument("--output-dir", required=True, type=Path, help="caller-owned staging/output directory")
    args = parser.parse_args(argv)
    result = build_package(args.bundle, args.manifest, args.output_dir)
    print(json.dumps({
        "package_root": str(args.output_dir.resolve() / "package-root"),
        "summary": str(args.output_dir.resolve() / "package-summary.json"),
        "bundle_sha256": result["bundle_sha256"],
        "package_file_count": len(result["files"]),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
