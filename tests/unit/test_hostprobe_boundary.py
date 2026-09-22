"""The adapter reads the host, and a test says what "reads" is allowed to mean.

`tools/hostprobe/` is the one place permitted to run a command or look at the
environment. `tests/unit/test_builder_tooling_boundary.py` keeps all of that out
of `tools/builder/`, and that guard was **not** relaxed to make room for this —
the probe was put outside the package instead.

A docstring saying "read-only" is worth nothing on its own, so the property is
checked three ways: every executable it may run is declared and every command
tuple is drawn from that list; nothing that writes, removes or elevates appears
anywhere in it; and the class implements exactly the one method the port has.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from tools.builder.hostports import HostProbe
from tools.hostprobe.system_probe import (
    BACKEND_EXECUTABLES,
    BACKEND_LIST_COMMANDS,
    PROBE_TIMEOUT_SECONDS,
    READ_ONLY_COMMANDS,
    SystemProbe,
)

MODULE = Path(__file__).resolve().parents[2] / "tools" / "hostprobe" / "system_probe.py"
TREE = ast.parse(MODULE.read_text(encoding="utf-8"))


def test_it_satisfies_the_port_and_adds_no_public_method_of_its_own() -> None:
    """One method, because the Protocol has one.

    A second would be the moment to ask whether it reads or acts, and this is
    the test that forces the question to be asked out loud.
    """

    assert isinstance(SystemProbe(), HostProbe)
    assert {n for n in vars(SystemProbe) if not n.startswith("_")} == {"facts"}


def test_every_command_it_may_run_is_declared() -> None:
    """`READ_ONLY_COMMANDS` is the whole list, and the tuples obey it.

    A command tuple whose first element is not declared would be a new
    capability arriving without anyone noticing.
    """

    assert set(READ_ONLY_COMMANDS) == {"virsh", "limactl", "utmctl", "curl"}
    for command in BACKEND_LIST_COMMANDS.values():
        assert command[0] in READ_ONLY_COMMANDS

    for node in ast.walk(TREE):
        if isinstance(node, ast.Tuple) and node.elts:
            first = node.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                looks_like_argv = all(
                    isinstance(item, ast.Constant | ast.Call | ast.Name | ast.Attribute)
                    for item in node.elts
                )
                if looks_like_argv and first.value.islower() and " " not in first.value:
                    if first.value in ("virsh", "limactl", "utmctl", "curl", "apt-get", "lb"):
                        assert first.value in READ_ONLY_COMMANDS


def _argv_literals() -> set[str]:
    """Every string that could reach a command line, and not the ones that cannot.

    The first version searched every string constant in the file and failed on
    `shutil.which("sudo")` — which is a **lookup**, the thing that answers
    "could this host escalate", and never an execution. Searching for a word
    cannot tell a question about a program from a use of it, so this collects
    the tuples and `run(...)` arguments that actually become argv.
    """

    found: set[str] = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Tuple):
            found.update(
                item.value
                for item in node.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            )
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and node.args
        ):
            for item in ast.walk(node.args[0]):
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    found.add(item.value)
    return found


def test_no_subcommand_it_runs_changes_anything() -> None:
    """The verbs are `list` and a HEAD request. Nothing else reaches argv."""

    argv = _argv_literals()
    for changing in (
        "create",
        "start",
        "destroy",
        "delete",
        "undefine",
        "install",
        "rm",
        "mkfs",
        "dd",
        "sudo",
        "--force",
        "-O",
        "--output",
    ):
        assert changing not in argv, f"the probe would run {changing!r}"


def test_sudo_is_looked_up_and_never_run() -> None:
    """"Could this host escalate" is a question. This module never answers it by doing.

    The distinction is the whole of `can_escalate_privilege`: it is reported so
    that `doctor` can say what is missing, and nothing in this package acts on
    it.
    """

    source = MODULE.read_text(encoding="utf-8")
    assert 'shutil.which("sudo")' in source
    assert "sudo" not in _argv_literals()


def test_it_writes_nothing_and_removes_nothing() -> None:
    """Reading a file is permitted; opening one for writing is not."""

    for node in ast.walk(TREE):
        if isinstance(node, ast.Attribute):
            assert node.attr not in {
                "write_text",
                "write_bytes",
                "mkdir",
                "unlink",
                "rmtree",
                "remove",
                "rename",
                "chmod",
                "setuid",
                "seteuid",
            }, f"the probe calls {node.attr!r}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "open"


def test_every_probe_command_has_a_timeout_and_no_shell() -> None:
    """A doctor that hangs on a hypervisor socket is a doctor nobody runs.

    `shell=True` would also turn a fixed argument vector into a string the
    operator's environment can influence, which is the thing ADR-0009 D4 is
    about even here, where nothing becomes a build input.
    """

    assert PROBE_TIMEOUT_SECONDS > 0
    runs = [
        node
        for node in ast.walk(TREE)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
    ]
    assert runs, "the probe runs no command at all; this test is stale"
    for call in runs:
        keywords = {kw.arg for kw in call.keywords}
        assert "timeout" in keywords
        assert "shell" not in keywords
        assert "check" in keywords


def test_a_backend_is_detected_by_presence_and_never_by_platform() -> None:
    """A Mac does not imply UTM and a Linux host does not imply libvirt."""

    assert set(BACKEND_EXECUTABLES.values()) == {
        "virsh",
        "qemu-system-x86_64",
        "limactl",
        "utmctl",
    }
    source = " ".join(MODULE.read_text(encoding="utf-8").split())
    for inference in ("platform.system", "sys.platform", "darwin"):
        assert inference not in source


@pytest.mark.parametrize("name", ["environ", "getenv"])
def test_the_environment_is_read_only_where_it_answers_a_container_question(
    name: str,
) -> None:
    """It may look, and only for the one fact it is looking for.

    `os.environ["container"]` is how systemd-nspawn announces itself. Reading it
    is a read; setting one would not be, and `putenv` does not appear.
    """

    source = MODULE.read_text(encoding="utf-8")
    assert "putenv" not in source
    if name in source:
        assert 'environ.get("container")' in source
