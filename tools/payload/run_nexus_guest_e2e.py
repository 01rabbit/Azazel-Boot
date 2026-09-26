#!/usr/bin/env python3
"""Disposable-guest Nexus installer and model-generation/rollback probe."""

from __future__ import annotations

import hashlib
import base64
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from azazel_nexus.model_catalog import ModelEntry

# /run is deliberately small tmpfs in this live guest; the real importer
# correctly refuses to consume its 2 GiB safety reserve. Keep the disposable
# generation fixture on the larger writable live root overlay instead.
ROOT = Path("/var/tmp/azazel-nexus-prototype-e2e")
COMMISSIONING = "sha256:" + "c" * 64
NOW = "2026-09-25T00:00:00Z"
ACTOR = "prototype-qemu-operator"
REPORT_PREFIX = "AZAZEL_NEXUS_E2E_REPORT"
REPORT_CHUNK_BYTES = 768


def command(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, capture_output=True, text=True)


def format_report_frame(report: dict[str, object]) -> tuple[str, ...]:
    """Encode a byte-counted, digest-bound frame with bounded sequenced chunks."""
    payload = json.dumps(report, sort_keys=True, separators=(",", ":"))
    payload_bytes = payload.encode("utf-8")
    digest = hashlib.sha256(payload_bytes).hexdigest()
    chunks = [
        payload_bytes[offset : offset + REPORT_CHUNK_BYTES]
        for offset in range(0, len(payload_bytes), REPORT_CHUNK_BYTES)
    ]
    metadata = f"length={len(payload_bytes)} sha256={digest} chunks={len(chunks)}"
    lines = [f"{REPORT_PREFIX}_BEGIN {metadata}"]
    lines.extend(
        f"{REPORT_PREFIX}_CHUNK seq={sequence} data={base64.b64encode(chunk).decode('ascii')}"
        for sequence, chunk in enumerate(chunks)
    )
    lines.append(f"{REPORT_PREFIX}_END {metadata}")
    return tuple(lines)


def signed_catalog(root: Path, entries: list[ModelEntry]) -> bytes:
    from azazel_nexus.model_catalog import CATALOG_DOMAIN, catalog_payload

    key = root / "fixture-key.pem"
    public_der = root / "fixture-public.der"
    message = root / "catalog-signing-input.bin"
    signature = root / "catalog-signature.bin"
    command(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)])
    command(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER", "-out", str(public_der)])
    public_bytes = public_der.read_bytes()
    if len(public_bytes) != 44 or not public_bytes.startswith(bytes.fromhex("302a300506032b6570032100")):
        raise RuntimeError("OpenSSL returned an unexpected Ed25519 SubjectPublicKeyInfo")
    payload = catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=entries)
    message.write_bytes(CATALOG_DOMAIN + payload)
    command(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(message), "-out", str(signature)])
    return signature.read_bytes() + payload


def entry(model_id: str, content: bytes, lineage: tuple[str, ...]) -> ModelEntry:
    from azazel_nexus.model_catalog import ModelEntry
    from azazel_nexus.resource_profile import ResourceProfile

    return ModelEntry(
        model_id=model_id,
        format="gguf",
        digest="sha256:" + hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        provenance="prototype-e2e-fixture",
        license_acknowledgement_required=False,
        runtime_abi="llama.cpp/1",
        purpose="exercise verified import and rollback only",
        context_limit=1024,
        declared_min_ram_mib=1024,
        declared_min_disk_mib=1,
        declared_profile=ResourceProfile.LITE,
        rollback_lineage=lineage,
        source_id=None,
    )


def main() -> int:
    if os.geteuid() != 0:
        raise RuntimeError("guest E2E requires root")
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    report_path = ROOT / "result.json"
    report: dict[str, object] = {
        "schema": "azazel-nexus/disposable-guest-e2e@1",
        "evidence_type": "qemu_disposable_guest_only",
        "lifecycle_scope": "package-install-and-status-plus-disposable-import-fixture",
        "hardware_verified": False,
        "secure_boot_verified": False,
        "network_fetch_performed": False,
        "provider_admission_performed": False,
        "edge_activation_performed": False,
        "installer": {},
        "status": {},
        "generation": {},
        "rollback": {},
    }
    try:
        install = subprocess.run(
            ["/usr/libexec/azazel-nexus-prototype-install"],
            check=True,
            capture_output=True,
            text=True,
        )
        package_path = Path("/usr/share/azazel-nexus/azazel-nexus-prototype.deb")
        package_digest = hashlib.sha256(package_path.read_bytes()).hexdigest()
        package = {
            "name": command(["dpkg-query", "-W", "-f=${Package}", "azazel-nexus-prototype"]).stdout.strip(),
            "version": command(["dpkg-query", "-W", "-f=${Version}", "azazel-nexus-prototype"]).stdout.strip(),
            "architecture": command(["dpkg-query", "-W", "-f=${Architecture}", "azazel-nexus-prototype"]).stdout.strip(),
            "install_source": "/usr/share/azazel-nexus/azazel-nexus-prototype.deb in the live-image root filesystem",
            "package_sha256": package_digest,
        }
        if package != {
            "name": "azazel-nexus-prototype",
            "version": "0.0.1~prototype1",
            "architecture": "all",
            "package_sha256": package_digest,
            "install_source": "/usr/share/azazel-nexus/azazel-nexus-prototype.deb in the live-image root filesystem",
        }:
            raise RuntimeError(f"installed Nexus package identity mismatch: {package}")
        # The package is deliberately installed by the real installer above.
        # Import only after that boundary; importing at module load time would
        # make a clean guest fail before it can exercise the installer.
        from azazel_nexus.model_catalog import (
            CATALOG_FILENAME,
        )
        from azazel_nexus.model_import import CommissionedModels, ModelImport

        operational_units = (
            "azazel-commissiond.service",
            "azazel-auditd.service",
            "azazel-watchdog.service",
            "azazel-edge-probed.service",
            "azazel-model-fetchd.service",
            "azazel-mio-locald.service",
            "azazel-mio-remoted.service",
        )
        unit_states = {
            unit: subprocess.run(["systemctl", "is-enabled", unit], capture_output=True, text=True).stdout.strip()
            for unit in operational_units
        }
        activation_state = subprocess.run(
            ["systemctl", "is-enabled", "azazel-activated.service"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if any(state != "masked" for state in unit_states.values()) or activation_state != "enabled":
            raise RuntimeError(f"Nexus unit boundary mismatch: {unit_states}; activation={activation_state}")
        if subprocess.run(["systemctl", "is-active", "azazel-activated.service"], capture_output=True, text=True).stdout.strip() == "active":
            raise RuntimeError("installer started activation controller instead of only enabling it")
        report["installer"] = {
            "exit_code": install.returncode,
            "operational_units_masked": unit_states,
            "activation_controller_enabled_not_started": True,
            "output": install.stdout.splitlines(),
        }
        report["package"] = package

        status = subprocess.run(
            ["/usr/bin/azazel-nexus", "status"],
            capture_output=True,
            text=True,
        )
        if status.returncode != 0:
            raise RuntimeError(f"azazel-nexus status failed ({status.returncode}): {status.stderr}")
        report["status"] = {"exit_code": status.returncode, "output": status.stdout.splitlines()}

        with tempfile.TemporaryDirectory(prefix="node-", dir=ROOT) as temporary:
            node_root = Path(temporary)
            for name in ("inbox", "trust"):
                (node_root / name).mkdir()
            first = b"prototype weights one -- " + b"a" * 4096
            second = b"prototype weights two -- " + b"b" * 4096
            first_entry = entry("prototype-one", first, ())
            second_entry = entry("prototype-two", second, (first_entry.digest,))
            public_der = node_root / "fixture-public.der"
            catalog_path = node_root / "trust" / CATALOG_FILENAME
            catalog_path.write_bytes(signed_catalog(node_root, [first_entry, second_entry]))
            # SubjectPublicKeyInfo is re-derived from the ephemeral signing key,
            # then only its raw 32-byte public key enters the test trust map.
            raw_public = public_der.read_bytes()[-32:]
            node = CommissionedModels(
                root=node_root,
                trusted_keys={"disposable-e2e-catalog": raw_public},
                commissioning_digest=COMMISSIONING,
            )
            service = ModelImport(node)
            outcomes = []
            verified_before_rollback = []
            for model, content in ((first_entry, first), (second_entry, second)):
                filename = model.model_id + ".gguf"
                (node.inbox / filename).write_bytes(content)
                listed = service.list_inbox()
                selected = next(item for item in listed if item.display_name == filename)
                outcome = service.import_entry(
                    selected.entry_id,
                    model.model_id,
                    now=NOW,
                    actor=ACTOR,
                )
                if not outcome.promoted:
                    raise RuntimeError(f"fixture import did not promote {model.model_id}: {outcome}")
                outcomes.append({"model_id": model.model_id, "generation": outcome.generation.number})
                reading = service.reading_for(model.model_id)
                if reading.state.value != "present":
                    raise RuntimeError(f"artifact verification failed for {model.model_id}: {reading}")
                verified_before_rollback.append({"model_id": model.model_id, "state": reading.state.value})
            before_rollback = service.current_generation()
            restored = service.rollback(
                reason="verify disposable prototype rollback",
                actor=ACTOR,
                now=NOW,
            )
            current = service.current_generation()
            if before_rollback is None or restored.number != 1 or current is None or current.number != 1:
                raise RuntimeError("model import rollback did not restore generation 1")
            if service.reading_for("prototype-one").state.value != "present":
                raise RuntimeError("previous generation artifact is not present after rollback")
            if service.reading_for("prototype-two").state.value != "declared":
                raise RuntimeError("rolled-back artifact is still present in current generation")
            report["generation"] = {
                "evidence_scope": "disposable_fixture_direct_ModelImport_API",
                "fixture_root": str(node_root),
                "commissioned_product_trust_store_used": False,
                "product_cli_import_path_used": False,
                "operation": "signed offline model import; generation 1 then generation 2",
                "imports": outcomes,
                "verified_before_rollback": verified_before_rollback,
                "current_before_rollback": before_rollback.number,
                "reading_one_after_rollback": service.reading_for("prototype-one").state.value,
                "reading_two_after_rollback": service.reading_for("prototype-two").state.value,
            }
            report["rollback"] = {
                "operation": "ModelImport.rollback",
                "restored_generation": restored.number,
                "current_generation": current.number,
                "reason_required": True,
            }
        report["verdict"] = "pass"
    except Exception as exc:  # noqa: BLE001 - serialize failed guest evidence
        report["verdict"] = "fail"
        report["failure"] = f"{type(exc).__name__}: {exc}"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("AZAZEL_NEXUS_E2E_" + str(report["verdict"]).upper(), flush=True)
    for frame_line in format_report_frame(report):
        print(frame_line, flush=True)
    return 0 if report["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
