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


def test_the_planned_modules_are_present_at_the_pinned_tag():
    """Today's real state, not an invented condition.

    The program plan assigns Boot's provisioning records to
    `azazel_fabric.provisioning_contracts`. That module did not exist at the
    previously pinned `v0.8.0` and this test asserted its absence; it exists at
    `v0.9.0rc1` (ADR-0007), so the assertion is inverted rather than deleted.
    The survey mechanism is unchanged — what changed is what it finds.

    Needs Fabric installed: with Fabric absent the projection stops at the
    first failure and never gets far enough to survey the planned modules,
    which is correct and is covered by the absence tests above.
    """
    pytest.importorskip("azazel_fabric", reason="needs the optional fabric extra")
    projection = project_status()

    assert "azazel_fabric.provisioning_contracts" in PLANNED_FABRIC_MODULES
    assert projection.missing_planned == (), (
        f"the pinned tag {FABRIC_PIN} is missing {projection.missing_planned}; "
        "a planned module that vanished is a re-pin problem, not a scaffold one"
    )


def test_every_planned_module_is_importable_at_the_pinned_tag():
    """The survey reports on import-ability, so check it directly too.

    `missing_planned` being empty and the modules actually importing are two
    claims. A survey that silently stopped finding anything would satisfy the
    first without the second.
    """
    pytest.importorskip("azazel_fabric", reason="needs the optional fabric extra")
    import importlib

    for name in PLANNED_FABRIC_MODULES:
        assert importlib.import_module(name) is not None


def test_the_pin_is_the_first_tag_carrying_the_provisioning_contracts():
    """Guard the reason for the pin, not only its value.

    ADR-0007 re-pinned to reach `provisioning_contracts`. If a later change
    moves the pin back to a tag without it, the commissioning work this pin
    exists for breaks — and it should break here, loudly, rather than at the
    point where a consumer silently loses a contract.
    """
    pytest.importorskip("azazel_fabric", reason="needs the optional fabric extra")
    from azazel_fabric.provisioning_contracts import InterfaceIdentity, InterfaceIdentitySelector

    assert InterfaceIdentity is not None and InterfaceIdentitySelector is not None


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
