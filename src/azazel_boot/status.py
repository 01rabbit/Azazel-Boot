"""The deterministic status scaffold: what Azazel-Boot is, and is not.

This module is the whole of Boot's non-operational surface. It reports what
exists in this repository and what does not, and it **never reports a
capability**. Boot has no hardware inventory, no commissioning, no network and
no enforcement code, so every capability dimension reads as *not assessed* —
which is not the same as "absent" and is emphatically not "available".

Three properties matter more than anything this module computes:

1.  **Stdlib only.** Nothing here imports `azazel_fabric`, and nothing here
    imports a third-party package. The scaffold must stand with no optional
    dependency installed, because that is the state a responder's machine is
    most likely to be in.
2.  **Deterministic.** The same inputs produce the same `BootStatus`. No
    wall-clock read, no randomness, no environment lookup, no filesystem
    enumeration. A caller that wants a timestamp passes one in.
3.  **No authority.** Azazel-Edge's deterministic arbiter is the only decision
    and enforcement authority in any configuration of Azazel-Boot. Nothing
    here decides anything; it describes.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

#: Capability states, weakest first. These are **capability** states, never
#: authority levels: a `FULL` Boot has exactly the authority a `CORE` Boot has,
#: which is none. Boot cannot assess any of them yet, hence `UNASSESSED`.
CAPABILITY_STATES = ("UNASSESSED", "CORE", "LITE", "FULL")

#: The dimensions whose intersection would give effective capability. Boot
#: measures none of them today; the tuple exists so the absence is enumerated
#: rather than implied.
CAPABILITY_DIMENSIONS = ("resource", "topology", "verified_assets", "trust_health")


@dataclass(frozen=True)
class Component:
    """One thing Boot will need, and whether this repository has it."""

    name: str
    #: Series status vocabulary (handoff §7). Everything here is
    #: `target_contract` or `absent`; nothing is `implemented` or `verified`.
    status: str
    detail: str


#: Every component issue #1 scopes, with its real state. Adding a row that
#: claims more than the repository holds is the failure this table exists to
#: prevent, so `tests/unit/test_status.py` pins the vocabulary.
COMPONENTS: tuple[Component, ...] = (
    Component("image_builder", "absent", "no image is built; no builder is chosen"),
    Component("initramfs_quarantine", "absent", "the no-host-write property has no implementation"),
    Component(
        "media_writer",
        "absent",
        "decision logic only: it opens no device, and no medium has been written",
    ),
    Component("persistence", "absent", "no encrypted USB persistence"),
    Component("commissioning", "absent", "no hardware inventory and no operator confirmation flow"),
    Component("networking", "absent", "no NIC roles, no capture, no enforcement"),
    Component("deception", "absent", "no Deception isolation"),
    Component("architecture_contract", "target_contract", "docs/architecture.md"),
    Component("threat_model", "target_contract", "docs/threat-model.md"),
    Component(
        "compatibility_envelope",
        "target_contract",
        "docs/compatibility.md; the table is empty",
    ),
)


@dataclass(frozen=True)
class BootStatus:
    """What this repository is, stated so it cannot be mistaken for a product."""

    product: str = "Azazel-Boot Responder"
    product_code: str = "AZ-03"
    #: Always `UNASSESSED`: Boot has no code that could assess a dimension.
    capability: str = "UNASSESSED"
    #: Always empty. Boot asserts no authority in any configuration; the field
    #: exists so that "none" is stated rather than left to inference.
    authority: tuple[str, ...] = ()
    components: tuple[Component, ...] = COMPONENTS
    #: Why the capability is unassessed, one entry per dimension, always
    #: complete -- a dimension missing from this map would read as assessed.
    capability_reasons: Mapping[str, str] = field(
        default_factory=lambda: {
            "resource": "no resource probe exists",
            "topology": "no interface inventory exists",
            "verified_assets": "no asset verification exists",
            "trust_health": "no media or platform trust classification exists",
        }
    )

    def is_operational(self) -> bool:
        """Always False. Kept as a method so a caller must ask, not assume."""
        return False


def current_status() -> BootStatus:
    """The repository's status. Takes no input because nothing varies yet."""
    return BootStatus()
