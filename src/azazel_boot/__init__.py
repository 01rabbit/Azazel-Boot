"""Azazel-Boot Responder (AZ-03) -- target contract, nothing implemented.

This package is the non-operational scaffold issue #1 asks for: a status
surface and a guarded Azazel-Fabric boundary, and nothing else. It contains no
network, enforcement, installer, model-fetch or container activation code, and
`status.BootStatus.is_operational()` returns False by construction.
"""

from azazel_boot.version import __version__

__all__ = ["__version__"]
