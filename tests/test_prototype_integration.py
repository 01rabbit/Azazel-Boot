from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
BOOT_ROOT = ROOT.parent / "Azazel-Boot-audit-worktree"
NEXUS_ROOT = ROOT.parent / "Azazel-Nexus-harness"


def _load_harness():
    spec = importlib.util.spec_from_file_location(
        "azazel_prototype_integration",
        ROOT / "tools/prototype_integration.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_c5_fixture(path: Path) -> None:
    import sys

    sys.path.insert(0, str(BOOT_ROOT / "src"))
    from azazel_boot.quarantine import EARLY_HOOKS

    path.write_text(
        json.dumps(
            {
                "candidate": "fixture-payload",
                "build_host_id": "fixture-host",
                "order_established": True,
                "quarantine_persists_into_userspace": True,
                "hooks": [
                    {
                        "name": name,
                        "digest": "sha256:" + "b" * 64,
                        "provenance": "pinned_by_boot",
                        "arguments": [],
                    }
                    for name in EARLY_HOOKS
                ],
            }
        ),
        encoding="utf-8",
    )


def test_boot_and_nexus_fixture_lifecycle_is_one_qemu_only_scenario(tmp_path):
    harness = _load_harness()
    manifest = tmp_path / "c5-manifest.json"
    _write_c5_fixture(manifest)
    result = harness.run_prototype(
        boot_root=BOOT_ROOT,
        nexus_root=NEXUS_ROOT,
        c5_manifest=manifest,
        nexus_fixture_root=tmp_path / "nexus-root",
        payload_digest="sha256:" + "a" * 64,
    )

    assert result.c5_verdict == "pass"
    assert result.c5_evidence_type == "measured_on_a_built_initramfs"
    assert result.c5_source == "inspection_fixture"
    assert result.c5_faults == ()
    assert result.run["passed"] is True
    assert result.run["hardware_verified"] is False
    assert result.plan["evidence_class"] == "qemu_fixture_only"
    assert result.plan["builder_selected"] is False
    assert result.generation == 3
    assert result.rolled_back_from == 2


def test_cli_writes_machine_readable_fixture_result(tmp_path, capsys):
    harness = _load_harness()
    manifest = tmp_path / "c5-manifest.json"
    _write_c5_fixture(manifest)
    result_path = tmp_path / "result.json"
    assert harness.main(
        [
            "--boot-root",
            str(BOOT_ROOT),
            "--nexus-root",
            str(NEXUS_ROOT),
            "--c5-manifest",
            str(manifest),
            "--nexus-fixture-root",
            str(tmp_path / "nexus-root"),
            "--result",
            str(result_path),
        ]
    ) == 0
    assert json.loads(result_path.read_text(encoding="utf-8"))["run"]["passed"] is True
    assert json.loads(capsys.readouterr().out)["plan"]["hardware_verified"] is False
