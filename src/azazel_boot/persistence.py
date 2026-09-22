"""Encrypted persistence on the Boot medium: what may be created, opened, or refused.

Azazel-Boot#7, and the storage half of B4. This module decides. It creates no
partition, opens no volume, derives no key and touches no device: the acts are
injected ports, and what is here is the judgement about whether an act is
permitted and what the session may claim afterwards.

Four properties shape it, and each comes from a rule written down elsewhere.

**Persistence exists on the removable medium and nowhere else.** A target that
is not the booted medium — by the quarantine's own disposition, not by a name —
is refused before anything else is considered. Host storage is never created on,
mounted, repaired, swapped to or written back to, which is
`docs/threat-model.md` §3 restated where the storage decisions are made.

**The layout is the simple one.** GPT, an ESP, the signed read-only root, and an
optional LUKS2 partition with a filesystem formatted **directly** on it. No
volume manager is assembled, imported or activated — on the host or on the
medium ([ADR-0008](../../docs/adr/0008-debian-13-live-baseline.md) D4.1). LUKS2's
`dm-crypt` mapping is the one exception, and it exists to open persistence.

**Every failure is a capability, never an authority.** An unlock that fails, a
volume that cannot be verified, a rollback, a medium pulled mid-session — each
narrows what this node can do and moves exactly nothing about who decides.
Azazel-Edge's deterministic arbiter is the only decision and enforcement
authority in every state below, including the ones that look like an emergency.

**Nothing here can hold a secret.** There is no passphrase field, no key field,
no recovery-key field, no operator field and no raw device identity. A value the
model cannot carry is a value no rendering, log, audit line or report can leak.

Nothing here has run. No persistence volume has been created, unlocked,
repaired or quarantined on any hardware.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum

from .commissioning import SessionBinding
from .quarantine import Disposition

#: The capability this node degrades to when persistence is unavailable.
#: A capability state, never an authority level: `CORE` removes optional
#: capacity and moves, transfers and expands exactly zero decision rights.
DEGRADED_CAPABILITY = "CORE"

#: Partition roles the medium may carry, in the order ADR-0008 D4.1 fixes them.
#: There is no fourth role: an extra partition is refused rather than ignored,
#: because "ignored" is how a volume nobody reviewed ends up on the medium.
PARTITION_ROLES = ("esp", "boot_root", "persistence")

#: Filesystem stacks that assemble something. Refused on the medium as well as
#: on the host: assembly is not per-device, and a volume group scanned from the
#: medium can pull in physical volumes living on host disks.
VOLUME_MANAGERS = ("lvm", "lvm2", "mdraid", "md", "zfs", "bcache", "dm-raid")

#: The one mapping permitted, and only to open persistence.
PERMITTED_MAPPING = "dm-crypt"


class PersistenceState(Enum):
    """What persistence is right now. Every value is a capability statement."""

    #: The medium carries no persistence partition. A normal configuration for
    #: media handed out in an emergency, not a failure to report as one.
    ABSENT = "absent"
    #: Present and not opened. The session runs from RAM.
    LOCKED = "locked"
    #: Opened and usable.
    OPEN = "open"
    #: Present, and not trustworthy. Detected, never repaired into use.
    QUARANTINED = "quarantined"
    #: The medium went away mid-session. New actions are fenced immediately.
    FENCED = "fenced"


class Refusal(Enum):
    NOT_THE_BOOT_MEDIUM = "not_the_boot_medium"
    HOST_STORAGE_TARGET = "host_storage_target"
    UNOBSERVED_TARGET = "unobserved_target"
    MISSING_PARTITION_ROLE = "missing_partition_role"
    UNKNOWN_PARTITION_ROLE = "unknown_partition_role"
    ROOT_NOT_READ_ONLY = "root_not_read_only"
    VOLUME_MANAGER_PRESENT = "volume_manager_present"
    PERSISTENCE_NOT_DIRECTLY_FORMATTED = "persistence_not_directly_formatted"
    NOT_LUKS2 = "not_luks2"
    NOT_THIS_SESSION = "not_this_session"
    NOT_THIS_HOST = "not_this_host"


class UnlockOutcome(Enum):
    """Why persistence is not open, when it is not.

    There is no `OPENED_WITH_WARNINGS` and no `REPAIRED`: a volume is usable or
    it is quarantined, and the space between those was where "repaired into a
    state an attacker chose" used to live (`docs/threat-model.md` §5).
    """

    OPENED = "opened"
    UNLOCK_FAILED = "unlock_failed"
    INTEGRITY_UNVERIFIED = "integrity_unverified"
    ROLLBACK_DETECTED = "rollback_detected"
    UNRECOVERABLE_DIRTY_VOLUME = "unrecoverable_dirty_volume"


class PersistenceRefused(Exception):
    """The act did not happen, and the detail names no device and no secret."""

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclass(frozen=True)
class Partition:
    """One partition as the medium presents it."""

    role: str
    filesystem: str
    read_only: bool = False
    #: The mapping stack between the partition and its filesystem. Empty means
    #: the filesystem sits directly on the partition, which is what D4.1 wants.
    mappings: tuple[str, ...] = ()


@dataclass(frozen=True)
class MediumLayout:
    """The medium's partitions, in the order it presents them."""

    partition_table: str
    partitions: tuple[Partition, ...]


@dataclass(frozen=True)
class PersistenceTarget:
    """Where persistence would live.

    `disposition` is the quarantine's own conclusion about the device. Passing
    it in rather than re-deciding here is deliberate: two modules deciding what
    the medium is would be two answers waiting to disagree.
    """

    disposition: Disposition | None
    layout: MediumLayout


@dataclass(frozen=True)
class PersistenceStatus:
    """What the session may claim about persistence, and what it may do.

    There is no `passphrase`, `key`, `recovery_key`, `operator` or `identity`
    field. `tests/unit/test_persistence.py` asserts their absence, so a value
    the model cannot carry cannot reach a screen, a log or an audit line.
    """

    state: PersistenceState
    outcome: UnlockOutcome | None
    reasons: tuple[str, ...]
    #: The capability this state leaves the node in. Never an authority.
    capability: str

    @property
    def authority(self) -> tuple[()]:
        """Empty in every state. Azazel-Edge's arbiter decides; Boot does not."""

        return ()

    @property
    def writable(self) -> bool:
        return self.state is PersistenceState.OPEN


def check_layout(layout: MediumLayout) -> None:
    """Refuse a medium whose block layout is not the one ADR-0008 D4.1 fixes."""

    if layout.partition_table.lower() != "gpt":
        raise PersistenceRefused(
            Refusal.UNKNOWN_PARTITION_ROLE, "the medium is not GPT"
        )

    roles = [partition.role for partition in layout.partitions]
    for role in roles:
        if role not in PARTITION_ROLES:
            raise PersistenceRefused(
                Refusal.UNKNOWN_PARTITION_ROLE,
                f"{role!r} is not one of {PARTITION_ROLES}; an extra partition is "
                "refused rather than ignored",
            )
    for required in ("esp", "boot_root"):
        if required not in roles:
            raise PersistenceRefused(Refusal.MISSING_PARTITION_ROLE, required)

    for partition in layout.partitions:
        for mapping in partition.mappings:
            if mapping.lower() in VOLUME_MANAGERS:
                raise PersistenceRefused(
                    Refusal.VOLUME_MANAGER_PRESENT,
                    f"{mapping!r} assembles something; assembly is refused on the "
                    "medium as well as on the host",
                )
        if partition.role == "boot_root" and not partition.read_only:
            raise PersistenceRefused(
                Refusal.ROOT_NOT_READ_ONLY, "the boot root is mounted read-only or not at all"
            )
        if partition.role == "persistence":
            if PERMITTED_MAPPING not in partition.mappings:
                raise PersistenceRefused(
                    Refusal.NOT_LUKS2,
                    "persistence is a LUKS2 volume opened through dm-crypt",
                )
            extra = [m for m in partition.mappings if m.lower() != PERMITTED_MAPPING]
            if extra:
                raise PersistenceRefused(
                    Refusal.PERSISTENCE_NOT_DIRECTLY_FORMATTED,
                    "the filesystem sits directly on the encrypted partition",
                )


def check_target(target: PersistenceTarget) -> None:
    """Persistence lives on the booted medium. Everything else is refused."""

    if target.disposition is None:
        raise PersistenceRefused(
            Refusal.UNOBSERVED_TARGET,
            "the target has not appeared; a device with no disposition is not a "
            "device with no rule",
        )
    if target.disposition is not Disposition.BOOT_MEDIUM:
        raise PersistenceRefused(
            Refusal.HOST_STORAGE_TARGET,
            "persistence exists on the removable medium; host storage is never "
            "created on, mounted, repaired or written back to",
        )
    check_layout(target.layout)


def create(
    target: PersistenceTarget, binding: SessionBinding, *, session_id: str, host_fingerprint: str
) -> PersistenceStatus:
    """Decide whether persistence may be created here, now, on this medium.

    Creation is a separate explicit act. Nothing implies it: not a boot, not a
    successful write, not an operator confirming a NIC role.
    """

    check_target(target)
    _require_binding(binding, session_id=session_id, host_fingerprint=host_fingerprint)
    return PersistenceStatus(
        state=PersistenceState.LOCKED,
        outcome=None,
        reasons=("persistence may be created on this medium; it is not open yet",),
        capability=DEGRADED_CAPABILITY,
    )


def unlock(
    target: PersistenceTarget,
    *,
    unlocked: bool,
    integrity_verified: bool,
    stored_generation: int,
    last_seen_generation: int,
    dirty: bool,
    repairable: bool,
) -> PersistenceStatus:
    """Open persistence, or say why not — and never repair into use.

    The order is deliberate. A volume that did not unlock cannot have its
    integrity judged; one that failed integrity is not asked about its
    generation; and a dirty volume is repaired only within bounds, with
    anything else quarantined rather than mounted.
    """

    check_target(target)

    if not unlocked:
        return _refused(UnlockOutcome.UNLOCK_FAILED, "the volume did not unlock")
    if not integrity_verified:
        return _refused(
            UnlockOutcome.INTEGRITY_UNVERIFIED,
            "a modification that is not authenticated is detected, not repaired",
        )
    if stored_generation < last_seen_generation:
        return _refused(
            UnlockOutcome.ROLLBACK_DETECTED,
            "an older generation is detected, never silently accepted",
        )
    if dirty and not repairable:
        return _refused(
            UnlockOutcome.UNRECOVERABLE_DIRTY_VOLUME,
            "a volume that cannot be repaired to a verified state is quarantined",
        )

    return PersistenceStatus(
        state=PersistenceState.OPEN,
        outcome=UnlockOutcome.OPENED,
        reasons=(
            "the volume was repaired within bounds and verified"
            if dirty
            else "the volume unlocked and verified",
        ),
        capability="LITE",
    )


def fence_after_removal() -> PersistenceStatus:
    """The medium was pulled. Fence new actions without reading the medium.

    `docs/threat-model.md` §4 requires the release supervisor to be RAM-resident
    and to withdraw what it owns without reading anything from the removed
    device. This decision takes no argument for the same reason: a fence that
    needed to consult the medium could not fire when the medium is the thing
    that left.
    """

    return PersistenceStatus(
        state=PersistenceState.FENCED,
        outcome=None,
        reasons=(
            "the medium was removed; new actions are fenced and the session "
            "requires a reboot rather than continuing ambiguously",
        ),
        capability=DEGRADED_CAPABILITY,
    )


def absent() -> PersistenceStatus:
    """No persistence partition. A configuration, not a failure."""

    return PersistenceStatus(
        state=PersistenceState.ABSENT,
        outcome=None,
        reasons=("the medium carries no persistence partition",),
        capability=DEGRADED_CAPABILITY,
    )


#: What an operator may do from each state. Every option acts on the medium or
#: on the session — none of them touches host storage, and none of them is a
#: repair of somebody else's laptop.
RECOVERY_OPTIONS: dict[PersistenceState, tuple[str, ...]] = {
    PersistenceState.ABSENT: (
        "continue without persistence, at CORE",
        "create persistence on this medium as a separate explicit act",
    ),
    PersistenceState.LOCKED: (
        "continue without persistence, at CORE",
        "attempt an unlock with the documented portable passphrase or recovery path",
    ),
    PersistenceState.OPEN: (),
    PersistenceState.QUARANTINED: (
        "continue without persistence, at CORE",
        "export the quarantined volume for offline examination, unmodified",
        "rewrite the medium from a verified image on another machine",
    ),
    PersistenceState.FENCED: (
        "reboot; the session cannot continue",
    ),
}


def recovery_options(status: PersistenceStatus) -> tuple[str, ...]:
    """What is offered next. Never a repair of the host, in any state."""

    return RECOVERY_OPTIONS[status.state]


def status_field_names() -> tuple[str, ...]:
    """The model's own field names, for the test that asserts what it cannot hold."""

    return tuple(field.name for field in fields(PersistenceStatus))


def _refused(outcome: UnlockOutcome, reason: str) -> PersistenceStatus:
    return PersistenceStatus(
        state=PersistenceState.QUARANTINED,
        outcome=outcome,
        reasons=(reason,),
        capability=DEGRADED_CAPABILITY,
    )


def _require_binding(
    binding: SessionBinding, *, session_id: str, host_fingerprint: str
) -> None:
    if binding.session_id != session_id:
        raise PersistenceRefused(
            Refusal.NOT_THIS_SESSION, "a binding does not outlive its session"
        )
    if binding.host_fingerprint != host_fingerprint:
        raise PersistenceRefused(
            Refusal.NOT_THIS_HOST,
            "this record was bound to another machine; a medium carried to a "
            "different laptop starts from nothing",
        )
