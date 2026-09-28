"""Non-operational statement of Boot's current implementation scope."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BootStatus:
    """The package records no host capability or installation success."""

    product: str = "Azazel-Boot Responder"
    product_code: str = "AZ-03"
    operational: bool = False
    installer: str = "not implemented"
    supported_host_environments: tuple[str, ...] = ()
    authority: tuple[str, ...] = ()


def current_status() -> BootStatus:
    return BootStatus()
