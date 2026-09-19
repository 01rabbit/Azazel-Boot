"""Issue #1: Fabric absence or projection failure must not gain authority or crash.

Those are two promises, tested separately, because passing one says nothing
about the other: a projection that swallows every error still fails the first
if it lets Fabric's presence change what Boot claims to be.
"""

from __future__ import annotations

import builtins

import pytest

from azazel_boot.fabric_projection import (
    FABRIC_PIN,
    PLANNED_FABRIC_MODULES,
    project_status,
)
from azazel_boot.status import current_status


@pytest.fixture
def fabric_absent(monkeypatch):
    """Make every `azazel_fabric` import fail, as on a machine without it."""
    real_import = builtins.__import__

    def _blocked(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "azazel_fabric" or name.startswith("azazel_fabric."):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _blocked)


def test_absent_fabric_is_reported_not_raised(fabric_absent):
    projection = project_status()

    assert projection.available is False
    assert "azazel_fabric" in projection.reason
    assert projection.view is None


def test_absent_fabric_does_not_change_what_boot_claims_to_be(fabric_absent):
    """The promise that matters: presence of a dependency cannot grant anything.

    A projection renders the status; it never feeds back into it. If this ever
    fails, an optional package has become load-bearing for what Boot says it
    is -- which is how a dependency quietly acquires authority.
    """
    with_fabric_blocked = current_status()
    project_status(with_fabric_blocked)

    assert with_fabric_blocked.authority == ()
    assert with_fabric_blocked.capability == "UNASSESSED"
    assert with_fabric_blocked.is_operational() is False
    assert with_fabric_blocked == current_status()


def test_a_projection_that_raises_is_contained(monkeypatch):
    """Fabric's model may tighten between tags. That is a presentation problem.

    Needs Fabric installed: it is about the path taken when the import
    succeeds. The CI job that installs the `fabric` extra is what keeps this
    from being a test that never runs.
    """
    pytest.importorskip("azazel_fabric", reason="needs the optional fabric extra")
    import azazel_fabric.view as fabric_view

    class _Exploding:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("model tightened")

    monkeypatch.setattr(fabric_view, "StatusView", _Exploding)

    projection = project_status()

    assert projection.available is False
    assert "projection failed" in projection.reason
    assert projection.view is None


def test_the_planned_provisioning_module_is_reported_absent_not_fatal():
    """Today's real state, not an invented condition.

    The program plan assigns Boot's provisioning records to
    `azazel_fabric.provisioning_contracts`; the pinned tag has no such module.
    The scaffold must say so and keep working.

    Needs Fabric installed: with Fabric absent the projection stops at the
    first failure and never gets far enough to survey the planned modules,
    which is correct and is covered by the absence tests above.
    """
    pytest.importorskip("azazel_fabric", reason="needs the optional fabric extra")
    projection = project_status()

    assert "azazel_fabric.provisioning_contracts" in PLANNED_FABRIC_MODULES
    assert "azazel_fabric.provisioning_contracts" in projection.missing_planned


def test_the_pin_is_an_exact_tag():
    """No branch pin, no submodule, no copied source (issue #1)."""
    import tomllib
    from pathlib import Path

    manifest = tomllib.loads(
        (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text("utf-8")
    )
    fabric_requirements = manifest["project"]["optional-dependencies"]["fabric"]

    assert len(fabric_requirements) == 1
    requirement = fabric_requirements[0]
    assert requirement.endswith(f"@{FABRIC_PIN}"), (
        f"fabric extra is {requirement!r}; it must end at the exact tag {FABRIC_PIN}"
    )
    assert "@main" not in requirement and "@develop" not in requirement
