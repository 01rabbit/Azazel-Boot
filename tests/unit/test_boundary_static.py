"""Static scans that keep the bootstrap's boundaries mechanical, not aspirational.

Both properties below are stated in `docs/architecture.md` and `CONTRIBUTING.md`.
A rule that lives only in prose is one review away from being gone, so each is
also enforced here against the source itself.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src" / "azazel_boot"

#: The one module allowed to import Fabric. Containing it is what makes
#: Fabric's absence a bounded condition instead of an import error wherever
#: the interpreter happens to reach first.
FABRIC_BOUNDARY = "fabric_projection.py"


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_only_the_boundary_module_imports_fabric():
    offenders = [
        path.name
        for path in sorted(PACKAGE_ROOT.rglob("*.py"))
        if path.name != FABRIC_BOUNDARY and "azazel_fabric" in _imported_roots(path)
    ]
    assert offenders == [], (
        f"{offenders} import azazel_fabric; only {FABRIC_BOUNDARY} may, so that a "
        f"missing Fabric fails in one known place instead of anywhere"
    )


#: Names whose presence would mean the bootstrap had grown an operational
#: surface. Issue #1's last acceptance criterion forbids exactly this, and it
#: is the criterion most likely to erode one convenience at a time.
OPERATIONAL_MODULES = {
    "socket", "ssl", "http", "urllib", "ftplib", "telnetlib", "smtplib",
    "subprocess", "shutil", "ctypes", "multiprocessing", "asyncio",
    "requests", "httpx", "docker", "paramiko",
}


def test_the_bootstrap_contains_no_operational_code():
    """No network, no enforcement, no installer, no model fetch, no containers."""
    offenders: dict[str, list[str]] = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        found = sorted(_imported_roots(path) & OPERATIONAL_MODULES)
        if found:
            offenders[path.name] = found
    assert offenders == {}, (
        f"operational imports found: {offenders}. The bootstrap may not reach the "
        f"network, run a process, or touch host storage"
    )
