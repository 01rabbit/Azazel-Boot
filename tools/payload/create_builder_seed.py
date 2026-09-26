#!/usr/bin/env python3
"""Create a small cloud-init NoCloud seed ISO for one disposable builder VM."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def create(output: Path, public_key: str, instance_id: str) -> dict[str, object]:
    fields = public_key.strip().split()
    if len(fields) < 2 or fields[0] not in {"ssh-ed25519", "ssh-rsa"}:
        raise ValueError("builder access key must be one OpenSSH public-key line")
    if "\n" in public_key.strip() or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", instance_id):
        raise ValueError("builder seed metadata is malformed")
    output = output.resolve()
    if output.exists():
        raise ValueError(f"refusing to replace existing seed: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="azazel-builder-seed-") as temporary:
        root = Path(temporary)
        (root / "user-data").write_text(
            "#cloud-config\n"
            "manage_etc_hosts: true\n"
            "users:\n"
            "  - name: azazel\n"
            "    gecos: Azazel Prototype Builder\n"
            "    groups: [sudo]\n"
            "    shell: /bin/bash\n"
            "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
            "    ssh_authorized_keys:\n"
            f"      - {public_key.strip()}\n"
            "ssh_pwauth: false\n",
            encoding="utf-8",
        )
        (root / "meta-data").write_text(
            f"instance-id: {instance_id}\nlocal-hostname: {instance_id}\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "hdiutil",
                "makehybrid",
                "-quiet",
                "-iso",
                "-joliet",
                "-default-volume-name",
                "CIDATA",
                "-o",
                str(output),
                str(root),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    descriptor = subprocess.run(
        ["isoinfo", "-d", "-i", str(output)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    listing = subprocess.run(
        ["isoinfo", "-f", "-i", str(output)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if "Volume id: CIDATA" not in descriptor or not {"/USER-DATA", "/META-DATA"}.issubset(listing):
        raise ValueError("generated seed is not a complete NoCloud CIDATA ISO")
    embedded_user_data = subprocess.run(
        ["isoinfo", "-i", str(output), "-x", "/USER-DATA"],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    if public_key.strip() not in embedded_user_data:
        raise ValueError("generated seed does not contain the requested access key")
    version = subprocess.run(
        ["isoinfo", "-version"], check=False, capture_output=True, text=True
    ).stdout.splitlines()
    return {
        "schema": "azazel-payload/builder-seed-evidence@1",
        "seed_sha256": sha256(output),
        "seed_size_bytes": output.stat().st_size,
        "cloud_init_instance_id": instance_id,
        "public_key_type": fields[0],
        "hdiutil_command": "hdiutil makehybrid -iso -joliet -default-volume-name CIDATA",
        "isoinfo_content_check": "pass",
        "host_tool": version[0] if version else "isoinfo version unavailable",
        "private_key_included": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--instance-id", required=True)
    args = parser.parse_args()
    try:
        record = create(args.output, args.public_key.read_text(encoding="utf-8"), args.instance_id)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
