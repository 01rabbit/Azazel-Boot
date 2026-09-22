"""B4 reuses the existing identity and policy, and introduces no second one.

The failure this file exists against is the one the repository has already had
once: `test_commissioning.py` records three products holding three different
role vocabularies, two of them near-misses that read as agreement. A second
identity, a second binding or a second persistence policy would be the same
mistake in a new place.

So the checks here are about **absence**: what the new module does not define,
does not import, and does not decide.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from azazel_boot import commissioning, persistence

MODULE = Path(persistence.__file__)


def _names_defined(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    defined: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef | ast.FunctionDef):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            defined.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
    return defined


def test_the_session_binding_is_the_commissioning_one() -> None:
    """One binding, or two answers waiting to disagree."""

    from azazel_boot.persistence import SessionBinding

    assert SessionBinding is commissioning.SessionBinding


def test_the_medium_is_decided_by_the_quarantine_not_re_decided_here() -> None:
    """Sharing an enum type is not sharing a decision.

    The first version took a `Disposition` as an argument and this test asserted
    only that the type was shared. A review pointed out that
    `Disposition.BOOT_MEDIUM` is a process-global constant, so the "check" was a
    value the caller chose. The session now holds the quarantine and asks it.
    """

    import inspect

    from azazel_boot.persistence import PersistenceSession

    assert "quarantine" in {f.name for f in dataclasses.fields(PersistenceSession)}
    source = inspect.getsource(PersistenceSession._require_the_medium)
    assert "self.quarantine.disposition(device)" in source
    for name in ("create", "unlock"):
        assert "disposition" not in inspect.signature(
            getattr(PersistenceSession, name)
        ).parameters


@pytest.mark.parametrize(
    "name",
    [
        "SessionBinding",
        "CommissioningState",
        "Assessment",
        "InterfaceObservation",
        "Device",
        "DeviceClass",
        "Quarantine",
        "Disposition",
        "host_fingerprint",
        "bind_session",
        "assess",
    ],
)
def test_persistence_defines_no_second_version_of_an_existing_concept(name: str) -> None:
    assert name not in _names_defined(MODULE)


def test_persistence_holds_no_interface_role_vocabulary() -> None:
    """Roles belong to commissioning, and an operator confirms them per host.

    The partition roles are checked against the interface roles explicitly: a
    review noted the earlier assertion would have fired on the coincidence of a
    partition role named `management`, and would have missed anything else.
    """

    from azazel_boot.persistence import PARTITION_ROLES

    assert not set(PARTITION_ROLES) & set(commissioning.INTERFACE_ROLES)

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in commissioning.INTERFACE_ROLES:
                assert node.value in PARTITION_ROLES, (
                    f"persistence names the interface role {node.value!r}; storage "
                    "decisions do not assign or infer network roles"
                )


def test_persistence_infers_nothing_about_interfaces() -> None:
    """It imports the inventory nowhere: a storage decision is not a NIC decision."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "azazel_boot.inventory" not in imported
    assert ".inventory" not in imported


def test_a_commissioning_refusal_does_not_block_persistence_and_the_reverse() -> None:
    """Both degrade safely, and neither becomes the other's precondition.

    A responder whose laptop has one NIC still gets persistence; a medium with
    no persistence still lets an operator confirm a role. Coupling them would
    turn two independent degradations into one compound failure.
    """

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    referenced = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    } | {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert "CommissioningState" not in referenced
    assert "Assessment" not in referenced


def test_persistence_opens_nothing_itself() -> None:
    """Creating, unlocking and repairing are acts; this module only decides."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    assert not imported & {"os", "subprocess", "pathlib", "shutil", "ctypes", "fcntl"}
    assert "open" not in calls


def test_persistence_names_no_device_path() -> None:
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert "/dev" not in node.value
