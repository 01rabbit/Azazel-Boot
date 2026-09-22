"""The builder tooling must not be able to reach outside its inputs.

`ADR-0009` D4 says nothing an operator types becomes a source, and the contract
puts the build inside an isolated environment. Both are easy to erode one
convenience at a time — an environment variable read "just for the cache
directory", a subprocess call "just to ask git for the revision".

This scans the syntax tree rather than the prose, so a module that grows such a
call fails here before it reaches a build host.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "tools" / "builder"

#: Modules that would let a build read something nobody pinned.
FORBIDDEN_IMPORTS = {
    "subprocess",
    "socket",
    "urllib",
    "urllib.request",
    "http",
    "http.client",
    "ftplib",
    "random",
    "os",
}

#: Names that reach the environment even without importing `os` directly.
FORBIDDEN_ATTRIBUTES = {"environ", "getenv", "putenv", "system", "popen"}


def _modules() -> list[Path]:
    found = sorted(PACKAGE.glob("*.py"))
    assert found, f"no modules found under {PACKAGE}"
    return found


@pytest.mark.parametrize("module", _modules(), ids=lambda path: path.name)
def test_no_module_imports_a_way_out_of_its_inputs(module: Path) -> None:
    tree = ast.parse(module.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module)
    offending = sorted(imported & FORBIDDEN_IMPORTS)
    assert not offending, (
        f"{module.name} imports {offending}; a build input comes from versioned "
        "configuration, never from the environment, a subprocess or the network"
    )


@pytest.mark.parametrize("module", _modules(), ids=lambda path: path.name)
def test_no_module_reads_the_environment(module: Path) -> None:
    tree = ast.parse(module.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert node.attr not in FORBIDDEN_ATTRIBUTES, (
                f"{module.name} touches {node.attr!r}"
            )
        if isinstance(node, ast.Name):
            assert node.id not in FORBIDDEN_ATTRIBUTES, f"{module.name} touches {node.id!r}"
