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
        elif isinstance(node, ast.ImportFrom) and node.module:
            # No `level == 0` condition. With it, `from .sibling import x` was
            # invisible to every check built on this function.
            roots.add(node.module.split(".")[0])
    return roots


def _called_builtins(path: Path) -> set[str]:
    """Bare-name calls, so a dynamic import cannot walk past the module scan.

    An adversarial review appended a function to a module under `src/` that ran
    `dd` against a raw block device and sent the bytes over TCP, with every
    module name assembled from fragments: `__import__("sub" + "process")`,
    `__import__("soc" + "ket")`, `__import__("io")`. Nothing in this file
    collected it, because it collects *imports*, and that code contains none.
    A denylist of module names answers "is this one of the names I thought of",
    which is not the question; the escape hatch has to be closed by name too.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }


#: The ways a module reaches something whose name it never has to write down.
DYNAMIC_IMPORT = {"__import__", "eval", "exec", "compile"}


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
    # Added after a review reached a block device through `io.FileIO` and none
    # of the names above. These are the file- and device-facing ones the
    # original set happened not to think of.
    "io", "fcntl", "mmap", "glob", "tempfile", "importlib", "pty", "termios",
}

#: The narrowly scoped exceptions, named per file rather than dropped from
#: the set above.
#:
#: The Fabric boundary asks `importlib.util.find_spec` whether the optional
#: extra is installed. Linux media is the separately scoped read-only host
#: inventory boundary; `lsblk` is its only subprocess and never opens a device.
#: Keep exemptions per-file so neither capability spreads across the package.
ALLOWED_IN: dict[str, frozenset[str]] = {
    FABRIC_BOUNDARY: frozenset({"importlib"}),
    "linux_media.py": frozenset({"subprocess"}),
    # The isolated Linux writer snapshots the verified artifact to an unlinked
    # temporary file before its first block write, closing source mutation.
    "linux_writer.py": frozenset({"tempfile"}),
}


def test_the_bootstrap_contains_no_operational_code():
    """No network, no enforcement, no installer, no model fetch, no containers."""
    offenders: dict[str, list[str]] = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        forbidden = OPERATIONAL_MODULES - ALLOWED_IN.get(path.name, frozenset())
        found = sorted(_imported_roots(path) & forbidden)
        if found:
            offenders[path.name] = found
    assert offenders == {}, (
        f"operational imports found: {offenders}. The bootstrap may not reach the "
        f"network, run a process, or touch host storage"
    )


def test_the_bootstrap_cannot_import_something_without_naming_it():
    """The hole the set above cannot close on its own.

    `__import__("sub" + "process")` imports a module this file's denylist never
    sees, because no `ast.Import` node exists to collect. A module under `src/`
    that calls it can reach anything at all, and every guard here would stay
    green. So the call itself is refused, by name, everywhere in the package.
    """

    offenders: dict[str, list[str]] = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        found = sorted(_called_builtins(path) & DYNAMIC_IMPORT)
        if found:
            offenders[path.name] = found
    assert offenders == {}, (
        f"dynamic import or evaluation found: {offenders}. A module that can name "
        f"an import at runtime is not bounded by any list of module names"
    )


def test_only_the_r11_poc_adapter_can_issue_poc_verifier_results():
    tooling_root = Path(__file__).resolve().parents[2] / "tools"
    issuers = []
    for path in sorted(tooling_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "azazel_boot.artifact":
                if any(alias.name == "_issue_r11_poc_verification" for alias in node.names):
                    issuers.append(path.relative_to(tooling_root).as_posix())
    assert issuers == ["poc_r11_attestation.py"]


def test_direct_block_io_apis_are_confined_to_linux_writer_backend():
    allowed = {
        "linux_writer.py": {"open", "pread", "pwrite", "write", "fsync"},
        "linux_media.py": {"open", "pread"},
    }
    forbidden = set().union(*allowed.values())
    offenders = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        used = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr in forbidden
        }
        excess = used - allowed.get(path.name, set())
        if excess:
            offenders[path.name] = sorted(excess)
    assert offenders == {}
