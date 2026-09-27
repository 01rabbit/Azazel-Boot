"""Validate the PoC selective-persistence declaration without mounting anything.

This is a build-time check. The future initramfs mounter must independently
verify real paths with no-follow filesystem operations immediately before use.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


SOURCES = frozenset(
    {"config", "state", "evidence", "logs", "knowledge", "snapshots", "operator"}
)
REQUIRED = frozenset({"config", "state"})
BASE = "/var/lib/azazel/"


def validate(raw: bytes) -> tuple[dict[str, object], ...]:
    """Return fixed entries or fail closed on an unknown/expanded declaration."""

    document = tomllib.loads(raw.decode("utf-8"))
    if set(document) != {"version", "mount"} or type(document["version"]) is not int:
        raise ValueError("unknown manifest structure")
    if document["version"] != 1 or type(document["mount"]) is not list:
        raise ValueError("unsupported manifest version or mount list")
    mounts = document["mount"]
    if len(mounts) != len(SOURCES):
        raise ValueError("mount set must match the PoC allowlist")
    names: set[str] = set()
    for entry in mounts:
        if type(entry) is not dict or set(entry) != {
            "name", "source", "destination", "mode", "required"
        }:
            raise ValueError("unknown mount field")
        name = entry["name"]
        if type(name) is not str or name not in SOURCES or name in names:
            raise ValueError("invalid or duplicate mount name")
        names.add(name)
        # Exact strings are intentional: no traversal, symlink, overlapping
        # destination, /home, /var, or rootfs blanket persistence is expressible.
        if type(entry["source"]) is not str or entry["source"] != name:
            raise ValueError("source is outside the fixed allowlist")
        if type(entry["destination"]) is not str or entry["destination"] != BASE + name:
            raise ValueError("destination is outside the fixed allowlist")
        if type(entry["mode"]) is not str or entry["mode"] != "0700":
            raise ValueError("mount permissions must be private")
        if type(entry["required"]) is not bool or entry["required"] != (name in REQUIRED):
            raise ValueError("required mount policy changed")
    if names != SOURCES:
        raise ValueError("missing allowlisted mount")
    return tuple(mounts)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: persistence_manifest.py MANIFEST", file=sys.stderr)
        return 2
    try:
        entries = validate(Path(argv[1]).read_bytes())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValueError) as error:
        # No attacker-controlled manifest content is echoed to logs.
        print(f"manifest refused: {type(error).__name__}", file=sys.stderr)
        return 1
    print(f"manifest accepted: {len(entries)} fixed entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
