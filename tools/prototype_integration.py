"""Run the Boot/Nexus prototype seam without claiming real-machine evidence.

This module is intentionally an umbrella-level adapter.  Boot and Nexus keep
their own boundaries; this file loads their fixture-facing APIs and exercises
the smallest end-to-end scenario that can be proven before an image builder,
QEMU, or hardware has been selected.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from types import ModuleType


class IntegrationRefused(ValueError):
    """The prototype inputs were malformed or crossed an evidence boundary."""


@dataclass(frozen=True)
class IntegrationResult:
    c5_verdict: str
    c5_evidence_type: str
    c5_source: str
    c5_faults: tuple[str, ...]
    plan: dict[str, object]
    run: dict[str, object]
    generation: int | None
    rolled_back_from: int | None

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2) + "\n"


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise IntegrationRefused(f"cannot load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_boot(boot_root: Path) -> tuple[ModuleType, ModuleType]:
    src = boot_root / "src"
    if not src.is_dir():
        raise IntegrationRefused(f"Boot src directory does not exist: {src}")
    sys.path.insert(0, str(src))
    c5 = _load_module(
        "azazel_prototype_boot_c5",
        boot_root / "tools/builder/initramfs_c5.py",
    )
    qemu = _load_module(
        "azazel_prototype_boot_qemu",
        boot_root / "tools/builder/qemu_prototype.py",
    )
    return c5, qemu


def _load_nexus(nexus_root: Path) -> ModuleType:
    src = nexus_root / "src"
    if not src.is_dir():
        raise IntegrationRefused(f"Nexus src directory does not exist: {src}")
    sys.path.insert(0, str(src))
    return __import__("azazel_nexus.installer_lifecycle", fromlist=["InstallerLifecycle"])


def run_prototype(
    *,
    boot_root: Path,
    nexus_root: Path,
    c5_manifest: Path,
    nexus_fixture_root: Path,
    payload_digest: str,
) -> IntegrationResult:
    """Run C5 plus all declared Boot/Nexus fixture stages.

    The callback state is deliberately local to this invocation.  A failed
    stage stops the runner, and no result from this function can report
    hardware verification or builder selection.
    """

    c5, qemu = _load_boot(boot_root)
    lifecycle_module = _load_nexus(nexus_root)
    inspection = c5.read_inspection_fixture(c5_manifest)
    c5_result = c5.evaluate(inspection)
    if c5_result.verdict is not c5.Verdict.PASS:
        raise IntegrationRefused(
            f"C5 fixture did not pass: {tuple(f.value for f in c5_result.faults)}"
        )

    lifecycle = lifecycle_module.InstallerLifecycle(nexus_fixture_root)
    files_one = {"etc/azazel/config.toml": b"generation = 1\n"}
    files_two = {"etc/azazel/config.toml": b"generation = 2\n"}
    gates = {
        "authenticity": True,
        "compatibility": True,
        "semantic_policy": True,
        "resource_topology": True,
        "operator_approval": True,
    }
    plan = qemu.make_plan(
        payload_digest,
        c5_manifest=c5_manifest,
        nexus_fixture_root=nexus_fixture_root,
    )

    def execute(stage: object) -> bool:
        if stage is qemu.Stage.UEFI:
            return True
        if stage is qemu.Stage.INITRAMFS_QUARANTINE:
            return c5_result.verdict is c5.Verdict.PASS
        if stage in (
            qemu.Stage.IMMUTABLE_ROOT,
            qemu.Stage.BOOT_USERSPACE,
        ):
            return True
        if stage is qemu.Stage.NEXUS_INSTALL:
            receipt = lifecycle.install()
            return receipt.installed and not receipt.services_started
        if stage is qemu.Stage.NEXUS_STATUS:
            status = lifecycle.status()
            return status.installed and not status.services_started and status.current_generation is None
        if stage is qemu.Stage.GENERATION_CHANGE:
            first = lifecycle.import_bundle(
                files_one, now="2026-09-24T00:00:00Z", actor="fixture", **gates
            )
            second = lifecycle.import_bundle(
                files_two, now="2026-09-24T00:01:00Z", actor="fixture", **gates
            )
            return first.number == 1 and second.number == 2 and not lifecycle.status().services_started
        if stage is qemu.Stage.ROLLBACK:
            rolled = lifecycle.rollback(
                now="2026-09-24T00:02:00Z",
                actor="fixture",
                reason="prototype rollback",
            )
            return (
                rolled.number == 3
                and rolled.rolled_back_from == 2
                and lifecycle.status().current_generation == 3
                and not lifecycle.status().services_started
            )
        return False

    run = qemu.run_fixture_plan(plan, execute)
    if not run.passed:
        raise IntegrationRefused(
            f"prototype stage failed: {run.failed_stage} ({run.failure_kind})"
        )
    current = lifecycle.status().current_generation
    rolled_back_from = lifecycle.generations.current().rolled_back_from
    return IntegrationResult(
        c5_verdict=c5_result.verdict.value,
        c5_evidence_type=c5_result.evidence_type.value,
        c5_source="inspection_fixture",
        c5_faults=tuple(fault.value for fault in c5_result.faults),
        plan=plan.as_dict(),
        run=asdict(run),
        generation=current,
        rolled_back_from=rolled_back_from,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boot-root", type=Path, required=True)
    parser.add_argument("--nexus-root", type=Path, required=True)
    parser.add_argument("--c5-manifest", type=Path, required=True)
    parser.add_argument("--nexus-fixture-root", type=Path, required=True)
    parser.add_argument(
        "--payload-digest",
        default="sha256:" + "a" * 64,
    )
    parser.add_argument("--result", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = run_prototype(
        boot_root=args.boot_root,
        nexus_root=args.nexus_root,
        c5_manifest=args.c5_manifest,
        nexus_fixture_root=args.nexus_fixture_root,
        payload_digest=args.payload_digest,
    )
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(result.to_json(), encoding="utf-8")
    print(result.to_json(), end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
