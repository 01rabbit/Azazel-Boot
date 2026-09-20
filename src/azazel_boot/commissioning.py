"""What an inventory permits, and what it requires an operator to settle.

Azazel-Boot#9. This module turns a read-only inventory
(:mod:`azazel_boot.inventory`) into one of three states. It **assigns no role**,
confirms nothing on an operator's behalf, and grants no authority: it reports
what would have to be true before a role could be confirmed at all.

Every path that cannot establish a single unambiguous identity resolves to
``COMMISSIONING_REQUIRED``. Zero matches and multiple matches are the same
answer, because an ambiguous NIC is never guessed — that is the rule the
program plan states and the one Fabric's own resolver enforces at the contract
level.

Commissioning does **not** carry across sessions. Boot has no "the network",
only "this host, this session". A record binds to both, and a different laptop
starts from nothing: the binding is checked, not assumed, so a record carried
on the same USB SSD to another machine is refused rather than reused.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from azazel_boot.inventory import InterfaceObservation

#: Azazel-Fabric's registered interface roles, mirrored locally.
#:
#: Named here rather than imported because commissioning is a CORE path and
#: `azazel_fabric` reaches this repository only through one boundary module
#: (ADR-0004 D3). `tests/unit/test_commissioning.py` pins this tuple against
#: `azazel_fabric.provisioning_contracts.INTERFACE_ROLES`, so the mirror cannot
#: drift from what it mirrors without going red.
#:
#: **This list replaced a Boot-local one**, and the correction is recorded
#: rather than quietly applied. Boot held
#: ``("observe", "internal", "external", "management", "capture", "decoy")``
#: while Fabric registered the five below and Azazel-Nexus documented a third
#: set. `management` was the only value all three shared, and two pairs were
#: near-misses that read as agreement -- `observe`/`observation`,
#: `decoy`/`deception_bridge`. A near-miss survives review; a clean difference
#: does not.
#:
#: The old list mixed two questions:
#:
#: *What does the node do on this interface?* -- observation, management,
#: deception bridging, asset acquisition. That is the **role**, it is what
#: another product needs to know, and it is what Fabric registers.
#:
#: *Which side of the boundary does this interface face?* -- `internal`,
#: `external`. That is **topology**, it is Boot's own, and it never crosses a
#: product boundary as a role. It is not represented here at all: Boot assigns
#: no zone today, and inventing a second local vocabulary to hold one would
#: repeat the mistake this change is correcting.
#:
#: One distinction was **lost, deliberately**: `observe` and `capture` both map
#: onto `observation`. Boot never said how they differed, and an interface
#: commissioned to watch a segment without transmitting is the same interface
#: either way. Keeping two words for one function is how a vocabulary starts
#: meaning different things to different readers.
INTERFACE_ROLES = (
    "asset_acquisition",
    "deception_bridge",
    "management",
    "observation",
    "unassigned",
)

#: Of those, the ones an operator may actually confirm against an interface.
#:
#: `unassigned` is not offered because it is not a confirmation: it is what an
#: interface is when no operator has confirmed anything, which is Boot's
#: starting state and needs no one's agreement.
ROLES = tuple(role for role in INTERFACE_ROLES if role != "unassigned")


class CommissioningState(str, Enum):
    """The three outcomes. Two of them are "not yet"."""

    #: An operator must settle something. The default, and the fail-closed one.
    COMMISSIONING_REQUIRED = "COMMISSIONING_REQUIRED"
    #: One usable interface, so no independent management path exists. This is
    #: the intended outcome for a single-NIC laptop, not a defect.
    OBSERVE_ONLY = "OBSERVE_ONLY"
    #: Enough distinct, unambiguous interfaces for an operator to be *asked*.
    #: Still no role assigned — the confirmation itself is not in this module.
    AWAITING_OPERATOR_CONFIRMATION = "AWAITING_OPERATOR_CONFIRMATION"


@dataclass(frozen=True)
class Assessment:
    """What the inventory permits. Descriptive; it authorizes nothing."""

    state: CommissioningState
    #: Plain-language reasons, in a stable order. Always non-empty.
    reasons: tuple[str, ...]
    #: Identity keys an operator could be asked about. Empty unless the state
    #: is AWAITING_OPERATOR_CONFIRMATION or OBSERVE_ONLY.
    commissionable_keys: tuple[str, ...] = ()
    #: Roles this assessment permits an operator to be offered. Never assigned
    #: here; `OBSERVE_ONLY` narrows the offer to observation alone.
    offerable_roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class SessionBinding:
    """The host and session a commissioning record is valid for.

    `host_fingerprint` is derived from inventory, so a different machine
    produces a different value and a carried record stops matching. It is an
    identifier, not a secret, and not a trust claim about the platform.
    """

    host_fingerprint: str
    session_id: str


def host_fingerprint(observations: tuple[InterfaceObservation, ...]) -> str:
    """A stable digest of the composite identities this host presents.

    Built only from commissionable identities, in sorted order, so it does not
    move when an unidentifiable interface appears or an interface is renamed by
    the kernel. It changes when the machine's real ports change, which is
    exactly when a commissioning record should stop applying.
    """

    keys = sorted(o.interface_key for o in observations if o.is_commissionable)
    digest = hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def bind_session(
    observations: tuple[InterfaceObservation, ...], *, session_id: str
) -> SessionBinding:
    """Bind to this host and this session. The caller supplies the session id.

    The session id is an input rather than something generated here: this
    module reads no clock and no randomness, so the same inventory and session
    id always produce the same binding and a record is reproducible.
    """

    if not session_id.strip():
        raise ValueError("session_id is required; a record must bind to one session")
    return SessionBinding(
        host_fingerprint=host_fingerprint(observations), session_id=session_id
    )


def binding_applies(
    binding: SessionBinding,
    observations: tuple[InterfaceObservation, ...],
    *,
    session_id: str,
) -> bool:
    """True only for the same host **and** the same session.

    A different laptop starts from nothing, and so does a later session on the
    same laptop. Both are refusals, not degradations.
    """

    return (
        binding.host_fingerprint == host_fingerprint(observations)
        and binding.session_id == session_id
    )


def assess(observations: tuple[InterfaceObservation, ...]) -> Assessment:
    """Report what this inventory permits, failing closed on any ambiguity."""

    from azazel_boot.inventory import duplicate_identity_keys  # noqa: PLC0415

    reasons: list[str] = []

    if not observations:
        return Assessment(
            state=CommissioningState.COMMISSIONING_REQUIRED,
            reasons=("no interfaces were observed",),
        )

    duplicates = duplicate_identity_keys(observations)
    if duplicates:
        return Assessment(
            state=CommissioningState.COMMISSIONING_REQUIRED,
            reasons=tuple(
                f"composite identity {key} is claimed by more than one interface; "
                "an ambiguous identity fails closed"
                for key in duplicates
            ),
        )

    commissionable = tuple(o for o in observations if o.is_commissionable)
    incomplete = tuple(o for o in observations if not o.is_commissionable)

    for observation in incomplete:
        reasons.append(
            f"{observation.interface_key}: "
            + ", ".join(observation.incomplete_reasons)
        )

    if not commissionable:
        reasons.append(
            "no interface carries a composite identity an operator could confirm "
            "against"
        )
        return Assessment(
            state=CommissioningState.COMMISSIONING_REQUIRED, reasons=tuple(reasons)
        )

    keys = tuple(sorted(o.interface_key for o in commissionable))

    if len(commissionable) == 1:
        reasons.append(
            "one commissionable interface, so there is no independent management "
            "path for a two-stage commit: this host is observe-only. That is the "
            "intended outcome, not a defect"
        )
        return Assessment(
            state=CommissioningState.OBSERVE_ONLY,
            reasons=tuple(reasons),
            commissionable_keys=keys,
            offerable_roles=("observation",),
        )

    reasons.append(
        f"{len(commissionable)} interfaces carry distinct composite identities; "
        "roles stay unassigned until an operator confirms each one"
    )
    return Assessment(
        state=CommissioningState.AWAITING_OPERATOR_CONFIRMATION,
        reasons=tuple(reasons),
        commissionable_keys=keys,
        offerable_roles=ROLES,
    )


def describe_for_operator(observation: InterfaceObservation) -> dict[str, str]:
    """What an operator may be shown about one interface.

    The kernel name is **never** included. An operator confirms "the port with
    the blue tag", not `enp3s0`: a name they cannot check against the machine in
    front of them invites a confirmation that means nothing, and the name is not
    stable enough to mean anything anyway.

    Only physically checkable facts are offered — a label, a bus position, a
    connector kind — which is what the threat model requires of the confirmation
    interface. It raises the bar on the interface; it never lowers the bar to
    inference.
    """

    described = {
        "identity": observation.interface_key,
        "physical_label": observation.physical_label or "unlabelled",
        "bus_position": observation.bus_path or "unknown",
        "connection": "wireless" if observation.wireless_phy else "wired",
    }
    if not observation.is_commissionable:
        described["unavailable_because"] = ", ".join(observation.incomplete_reasons)
    return described
