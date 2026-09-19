"""The only place Azazel-Boot imports `azazel_fabric` (ADR-0004).

Fabric is pinned to exactly one verified tag and consumed through this module
alone. Containing the import in one file is what makes its absence a bounded,
testable condition instead of an import error somewhere unpredictable:
`tests/unit/test_boundary_static.py` scans the package and fails if a second
import site appears.

**Fabric's absence must never gain authority and must never crash the
scaffold.** Those are two separate promises:

*No authority.* A projection is a rendering of `status.BootStatus`. It cannot
add a component, raise a capability, or grant an authority the scaffold does
not already report, and this module never writes back into the status it was
given. Whether Fabric is present changes how the status can be presented and
nothing about what is true. Azazel-Edge's deterministic arbiter remains the
only decision and enforcement authority in every case.

*No crash.* Every failure mode returns a `Projection` marked unavailable with
a reason: Fabric not installed, the needed submodule missing, or the
projection itself raising. Nothing here propagates an exception to a caller
that only wanted to know what this repository is.

The missing submodule is not hypothetical. The program plan assigns Boot's
provisioning records -- `HardwareInventory`, `ResourceProfile`,
`TopologyProfile`, `CommissioningRecord` -- to `azazel_fabric.
provisioning_contracts`, **which does not exist in the pinned tag**. That is
today's real state, and it is what the guard is tested against rather than a
condition invented to exercise it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from azazel_boot.status import BootStatus, current_status

#: The exact tag this module is written against (ADR-0004). No branch pin, no
#: submodule, no copied source.
FABRIC_PIN = "v0.8.0"

#: Fabric submodules Boot would consume. `provisioning_contracts` is absent
#: from the pinned tag; it is listed because an unmet requirement that is
#: written down can be tracked, and one that is omitted cannot.
REQUIRED_FABRIC_MODULES = ("azazel_fabric.view",)
PLANNED_FABRIC_MODULES = ("azazel_fabric.provisioning_contracts",)


@dataclass(frozen=True)
class Projection:
    """The outcome of projecting Boot's status through Fabric."""

    available: bool
    #: Why a projection could not be produced. Empty exactly when available.
    reason: str
    #: Fabric's own version string when it could be read, else None.
    fabric_version: str | None = None
    #: The projected view, when one was produced. Deliberately typed `Any`:
    #: this module must import cleanly with Fabric absent, so it cannot name
    #: Fabric's type in an annotation that is evaluated at import time.
    view: Any = None
    #: Planned modules that the pinned tag does not provide. Reported, never
    #: treated as an error: the scaffold does not need them to be correct.
    missing_planned: tuple[str, ...] = ()


def _import_fabric() -> tuple[Any | None, str]:
    try:
        import azazel_fabric  # noqa: PLC0415 -- deliberately deferred
    except ImportError as exc:
        return None, f"azazel_fabric is not installed ({exc})"
    return azazel_fabric, ""


def _missing_planned() -> tuple[str, ...]:
    import importlib.util  # noqa: PLC0415

    missing = []
    for name in PLANNED_FABRIC_MODULES:
        try:
            if importlib.util.find_spec(name) is None:
                missing.append(name)
        except (ImportError, ValueError):
            missing.append(name)
    return tuple(missing)


def project_status(status: BootStatus | None = None) -> Projection:
    """Render Boot's status through Fabric's shared view-model, if it is there.

    Returns a `Projection` in every case. A caller that needs the truth about
    this repository reads `status`; this is only how that truth can be shown
    alongside other Azazel products.
    """
    status = current_status() if status is None else status

    fabric, failure = _import_fabric()
    if fabric is None:
        return Projection(available=False, reason=failure)

    version = getattr(fabric, "__version__", None)

    try:
        from azazel_fabric.schema.mode import ModeState  # noqa: PLC0415
        from azazel_fabric.view import StatusView  # noqa: PLC0415
    except ImportError as exc:
        return Projection(
            available=False,
            reason=f"azazel_fabric.view is unavailable at the pinned tag ({exc})",
            fabric_version=version,
            missing_planned=_missing_planned(),
        )

    try:
        view = StatusView(
            schema_version="1.0",
            product=status.product,
            generated_at="1970-01-01T00:00:00Z",
            # A fixed, content-free mode: Boot has nothing that could enter a
            # real one. `since` is a constant for the same reason `generated_at`
            # is -- this module reads no clock, so its output is reproducible.
            mode=ModeState(
                name="not_operational",
                since="1970-01-01T00:00:00Z",
                reason="Azazel-Boot has no operational code",
            ),
            posture="unknown",
            headline="Azazel-Boot is target contract; nothing is implemented",
            reasons=[f"{c.name}: {c.status}" for c in status.components],
            health=[],
            next_actions=[],
            evidence_ids=[],
            product_view={
                "product_code": status.product_code,
                "capability": status.capability,
                "authority": list(status.authority),
                "capability_reasons": dict(status.capability_reasons),
            },
        )
    except Exception as exc:  # noqa: BLE001 -- a projection must not crash a caller
        # Fabric's model may tighten between tags. A view Boot cannot build is
        # a presentation problem, never a correctness one: the scaffold's own
        # status is unchanged and is what a caller should read.
        return Projection(
            available=False,
            reason=f"projection failed against the pinned tag ({type(exc).__name__}: {exc})",
            fabric_version=version,
            missing_planned=_missing_planned(),
        )

    return Projection(
        available=True,
        reason="",
        fabric_version=version,
        view=view,
        missing_planned=_missing_planned(),
    )
