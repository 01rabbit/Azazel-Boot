#!/usr/bin/env python3
"""Capture a Debian builder VM's installed package and APT source lock."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--snapshot", required=True)
    args = parser.parse_args()

    raw = subprocess.check_output(
        [
            "dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
        ],
        text=True,
    )
    packages = []
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and fields[2].startswith("ii"):
            packages.append({"name": fields[0], "version": fields[1]})
    packages.sort(key=lambda item: item["name"])

    source_paths = [Path("/etc/apt/sources.list")]
    source_paths.extend(sorted(Path("/etc/apt/sources.list.d").glob("*")))
    apt_sources = []
    for path in source_paths:
        if not path.is_file():
            continue
        text = path.read_text()
        if not text.strip():
            continue
        if "deb.debian.org" in text or "security.debian.org" in text:
            parser.error(f"mutable Debian repository remains configured in {path}")
        if args.snapshot not in text:
            parser.error(f"pinned snapshot is absent from active source file {path}")
        content = path.read_bytes()
        apt_sources.append({
            "path": str(path),
            "sha256": hashlib.sha256(content).hexdigest(),
            "content_base64": base64.b64encode(content).decode("ascii"),
        })
    if not apt_sources:
        parser.error("no active APT source file was captured")

    lock = {
        "schema": "azazel-payload/debian-toolchain-lock@2",
        "architecture": subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip(),
        "snapshot": args.snapshot,
        "packages": packages,
        "apt_sources": apt_sources,
    }
    args.output.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"packages": len(packages), "apt_sources": apt_sources}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
