"""The status scaffold must not be able to claim more than the repository holds."""

from __future__ import annotations

import azazel_boot.status as status_mod
from azazel_boot.status import (
    CAPABILITY_DIMENSIONS,
    CAPABILITY_STATES,
    BootStatus,
    current_status,
)

#: Handoff §7. `implemented` and `verified` are deliberately absent: no
#: component of Azazel-Boot is either, and a test that allowed them would let
#: the first false claim through silently.
ALLOWED_COMPONENT_STATUSES = {"absent", "target_contract"}


def test_no_component_claims_to_be_implemented_or_verified():
    for component in current_status().components:
        assert component.status in ALLOWED_COMPONENT_STATUSES, (
            f"{component.name} claims status {component.status!r}; nothing in this "
            f"repository is implemented or verified, so a status outside "
            f"{sorted(ALLOWED_COMPONENT_STATUSES)} is a false claim"
        )


def test_boot_asserts_no_authority_and_is_not_operational():
    """The one property that must survive every future change to this file.

    Azazel-Edge's deterministic arbiter is the only decision and enforcement
    authority in any configuration of Azazel-Boot.
    """
    status = current_status()
    assert status.authority == ()
    assert status.is_operational() is False


def test_capability_is_unassessed_and_every_dimension_says_why():
    """An unassessed dimension must be stated, not omitted.

    Effective capability is the intersection of resource, topology, verified
    assets and trust/health. Leaving a dimension out of the reasons map would
    read as "assessed and fine" -- the exact inference this reports against.
    """
    status = current_status()
    assert status.capability == "UNASSESSED"
    assert set(status.capability_reasons) == set(CAPABILITY_DIMENSIONS)
    assert all(reason for reason in status.capability_reasons.values())


def test_unassessed_is_weaker_than_every_real_capability_state():
    """`UNASSESSED` must sort below CORE, so a consumer ordering these states
    can never read Boot's silence as a capability."""
    assert CAPABILITY_STATES[0] == "UNASSESSED"
    assert set(CAPABILITY_STATES[1:]) == {"CORE", "LITE", "FULL"}


def test_the_scaffold_imports_nothing_outside_the_standard_library():
    """It has to stand where nothing optional is installed.

    Parsed rather than grepped: `status.py` names `azazel_fabric` in prose to
    say it does not import it, and a text scan would read that sentence as the
    violation it denies.
    """
    import ast
    import sys
    from pathlib import Path

    tree = ast.parse(Path(status_mod.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])

    allowed = set(sys.stdlib_module_names) | {"__future__"}
    assert imported <= allowed, (
        f"status.py imports {sorted(imported - allowed)}; the scaffold must work "
        f"with no optional dependency installed"
    )


def test_status_is_deterministic():
    assert current_status() == current_status()
    assert BootStatus() == BootStatus()
