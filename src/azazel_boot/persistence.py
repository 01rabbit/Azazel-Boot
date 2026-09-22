"""Encrypted persistence on the Boot medium: what may be created, opened, or refused.

Azazel-Boot#7, and the storage half of B4. This module **decides**. It creates no
partition, opens no volume and derives no key: the caller performs those acts and
reports what happened, and what is here is the judgement about whether an act is
permitted and what the session may claim afterwards. That is a weaker statement
than "the acts are injected ports", and it is the true one — an adversarial
review caught the earlier wording claiming an isolation this module does not
have. It trusts the caller's reports completely; every input below named
`unlocked`, `integrity_verified` or `reverified_after_repair` is a conclusion
somebody else reached.

Four properties shape it, and each comes from a rule written down elsewhere.

**Persistence exists on the removable medium and nowhere else.** The session
asks the **quarantine** what a device is, by device; it does not accept a
disposition as an argument. The first version did, and a review showed what that
cost: `Disposition.BOOT_MEDIUM` is a process-global constant, so a disposition
obtained for the internal disk — or typed by hand, with no quarantine in
existence — opened persistence on anything. A value a caller can name is not a
check.

**The binding is re-derived, not re-compared.** The second version compared the
binding against the session's own constructor arguments — both operands supplied
by the same object, so a self-consistent session passed forever, on any laptop.
Every act now takes the live read-only inventory and calls
`commissioning.binding_applies`, which recomputes the host fingerprint from what
this machine actually presents. That one can fail on a different laptop; the
tautology could not.

**The session is not a value a caller can edit.** It is not a dataclass, its
fields are private, reassigning the quarantine or the binding raises, the fence
is one-way, and it refuses to be pickled. A review moved the round-one exploit
up one level by substituting a forged quarantine into a public field and by
clearing the fence flag with one assignment.

**The layout is the simple one.** GPT, an ESP, the signed read-only root, and an
optional LUKS2 partition with a filesystem formatted **directly** on it
([ADR-0008](../../docs/adr/0008-debian-13-live-baseline.md) D4.1). No volume
manager is assembled, imported or activated — on the host or on the medium — and
that is checked against the filesystem type as well as the mapping stack,
because a partition that *is* an LVM physical volume assembles something whether
or not anything is stacked on it today.

**Every failure is a capability, never an authority.** An unlock that fails, a
volume that cannot be verified, a rollback, a medium pulled mid-session — each
narrows what this node can do and moves exactly nothing about who decides.
Azazel-Edge's deterministic arbiter is the only decision and enforcement
authority in every state below, including the ones that look like an emergency.

**Nothing here can hold a secret.** No passphrase, key, recovery-key, operator or
device-identity field exists on any status, and no refusal message interpolates a
value the medium supplied — a partition table is attacker-supplied input on
borrowed hardware, and a refusal that echoes it puts that input on a console.

Nothing here has run. No persistence volume has been created, unlocked, repaired
or quarantined on any hardware.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum

from .commissioning import SessionBinding, binding_applies
from .inventory import InterfaceObservation
from .quarantine import Device, Disposition, Quarantine


class Capability(Enum):
    """What the node can do. Never what it may decide.

    An enum rather than a string: a review constructed a status claiming
    `"FULL"`, and `"ADMIN"`, because the field was a bare `str` and the
    invariant lived only in a test over the values the module happened to emit.
    """

    CORE = "CORE"
    LITE = "LITE"


#: The capability persistence degrades to when it is unavailable. A capability
#: state, never an authority level.
DEGRADED_CAPABILITY = Capability.CORE

#: Partition roles the medium may carry, in the order ADR-0008 D4.1 fixes them.
#: The order is checked, and so is uniqueness: two persistence partitions is not
#: the layout, and "ignored" is how a volume nobody reviewed reaches the medium.
PARTITION_ROLES = ("esp", "boot_root", "persistence")

#: Roles that must sit directly on their partition, with no mapping at all.
PLAIN_ROLES = ("esp", "boot_root")

#: Mapping stacks that assemble something. Refused on the medium as well as on
#: the host: assembly is not per-device, and a volume group scanned from the
#: medium can pull in physical volumes living on host disks.
VOLUME_MANAGERS = ("lvm", "lvm2", "mdraid", "md", "zfs", "bcache", "dm-raid", "dm-thin", "stratis")

#: Filesystem identifiers that *make a partition a member of* such a stack. A
#: partition that is an LVM physical volume assembles something even with no
#: mapping stacked on it, so the filesystem is checked too.
#:
#: This is defence in depth behind `PERMITTED_FILESYSTEMS`, which is the real
#: check. A review pointed out that a denylist here was the only thing standing
#: between the layout and an assembling partition, and listed a dozen ordinary
#: `blkid` types it missed; an allowlist of three roles' filesystems does not
#: have that failure mode.
VOLUME_MANAGER_MEMBERS = (
    "lvm1_member",
    "lvm2_member",
    "zfs_member",
    "linux_raid_member",
    "ddf_raid_member",
    "isw_raid_member",
    "promise_fasttrack_raid_member",
    "via_raid_member",
    "silicon_medley_raid_member",
    "adaptec_raid_member",
    "jmicron_raid_member",
    "bcache",
    "stratis",
    "vdo",
    "drbd",
)

#: What each role's filesystem may be. The medium carries exactly three
#: partitions, so naming what is allowed is tractable and is the honest shape:
#: a denylist of things that assemble is a list somebody has to keep complete.
PERMITTED_FILESYSTEMS = {
    "esp": ("vfat",),
    "boot_root": ("squashfs", "erofs"),
    "persistence": ("ext4", "xfs", "f2fs"),
}

#: The one mapping permitted, and only to open persistence.
PERMITTED_MAPPING = "dm-crypt"


class PersistenceState(Enum):
    """What persistence is right now. Every value is a capability statement."""

    #: No act has run, so nothing is known. Saying `absent` here would be a
    #: positive claim about hardware nobody has looked at — the same mistake
    #: `UNOBSERVED_TARGET` exists to prevent one layer down.
    UNEXAMINED = "unexamined"
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
    UNOBSERVED_TARGET = "unobserved_target"
    NOT_GPT = "not_gpt"
    MISSING_PARTITION_ROLE = "missing_partition_role"
    UNKNOWN_PARTITION_ROLE = "unknown_partition_role"
    DUPLICATE_PARTITION_ROLE = "duplicate_partition_role"
    PARTITION_ORDER_CHANGED = "partition_order_changed"
    ROOT_NOT_READ_ONLY = "root_not_read_only"
    VOLUME_MANAGER_PRESENT = "volume_manager_present"
    MAPPING_ON_A_PLAIN_PARTITION = "mapping_on_a_plain_partition"
    PERSISTENCE_NOT_DIRECTLY_FORMATTED = "persistence_not_directly_formatted"
    NOT_LUKS2 = "not_luks2"
    NO_PERSISTENCE_PARTITION = "no_persistence_partition"
    FILESYSTEM_NOT_PERMITTED = "filesystem_not_permitted"
    GENERATION_NOT_A_COUNT = "generation_not_a_count"
    QUARANTINE_FROM_ANOTHER_SESSION = "quarantine_from_another_session"
    NOT_THIS_HOST_OR_SESSION = "not_this_host_or_session"
    SESSION_FENCED = "session_fenced"


class UnlockOutcome(Enum):
    """Why persistence is, or is not, open.

    `OPENED_AFTER_REPAIR` exists because the first version returned
    plain `OPENED` for a repaired volume, identical to a clean open in
    everything but a free-text reason. A consumer reading `outcome` could not
    tell them apart, which is the distinction `docs/threat-model.md` §5 is about.
    """

    OPENED = "opened"
    OPENED_AFTER_REPAIR = "opened_after_repair"
    UNLOCK_FAILED = "unlock_failed"
    INTEGRITY_UNVERIFIED = "integrity_unverified"
    ROLLBACK_DETECTED = "rollback_detected"
    UNRECOVERABLE_DIRTY_VOLUME = "unrecoverable_dirty_volume"
    REPAIR_NOT_REVERIFIED = "repair_not_reverified"


class PersistenceRefused(Exception):
    """The act did not happen.

    The detail names the **rule**, never the value: a partition table is
    attacker-supplied input on borrowed hardware, and a refusal that echoes it
    puts a device path, a serial or a terminal escape on a console and in a log.
    """

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

    def __post_init__(self) -> None:
        # Normalised on construction: a review checked a layout and then
        # appended to the list it was built from, so the checked layout and the
        # acted-on layout were different objects' contents.
        object.__setattr__(self, "mappings", tuple(self.mappings))

    def __repr__(self) -> str:
        """Redacted: a partition table is attacker-supplied on borrowed hardware.

        A crafted role carried a device path, a serial and a terminal escape
        into every captured-locals traceback of every refusal raised downstream.
        Only recognised values are shown.
        """

        role = self.role if self.role in PARTITION_ROLES else "<unrecognised>"
        return f"Partition(role={role!r}, filesystem=<redacted>, mappings=<redacted>)"


@dataclass(frozen=True)
class MediumLayout:
    """The medium's partitions, in the order it presents them."""

    partition_table: str
    partitions: tuple[Partition, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "partitions", tuple(self.partitions))

    def __repr__(self) -> str:
        return (
            f"MediumLayout(partition_table=<redacted>, "
            f"partitions={self.partitions!r})"
        )


@dataclass(frozen=True)
class PersistenceStatus:
    """What the session may claim about persistence, and what it may do.

    There is no `passphrase`, `key`, `recovery_key`, `operator` or `identity`
    field. `tests/unit/test_persistence.py` asserts their absence, so a value
    the model cannot carry cannot reach a screen, a log or an audit line.

    It is a **snapshot**. A status obtained before a surprise removal keeps
    saying what was true then; `PersistenceSession.status()` is what says what is
    true now, and it is what a caller must consult before acting.
    """

    state: PersistenceState
    outcome: UnlockOutcome | None
    reasons: tuple[str, ...]
    capability: Capability

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
        raise PersistenceRefused(Refusal.NOT_GPT, "the medium is not GPT")

    # Sanitised on the way in: an unrecognised role becomes `None` rather than
    # being bound to a local. A captured-locals traceback renders every frame,
    # and a crafted role carried a device path and a serial into all of them.
    roles = [
        partition.role if partition.role in PARTITION_ROLES else None
        for partition in layout.partitions
    ]
    if None in roles:
        raise PersistenceRefused(
            Refusal.UNKNOWN_PARTITION_ROLE,
            "a partition outside the fixed layout is refused, not ignored",
        )
    if len(set(roles)) != len(roles):
        raise PersistenceRefused(
            Refusal.DUPLICATE_PARTITION_ROLE,
            "the layout carries one partition per role",
        )
    if roles != [role for role in PARTITION_ROLES if role in roles]:
        raise PersistenceRefused(
            Refusal.PARTITION_ORDER_CHANGED, "the roles are not in the fixed order"
        )
    for required in PLAIN_ROLES:
        if required not in roles:
            raise PersistenceRefused(Refusal.MISSING_PARTITION_ROLE, required)

    for partition in layout.partitions:
        mappings = tuple(mapping.lower() for mapping in partition.mappings)
        for mapping in mappings:
            if mapping in VOLUME_MANAGERS:
                raise PersistenceRefused(
                    Refusal.VOLUME_MANAGER_PRESENT,
                    "a mapping that assembles something is refused on the medium "
                    "as well as on the host",
                )
        if partition.filesystem.lower() in VOLUME_MANAGER_MEMBERS:
            raise PersistenceRefused(
                Refusal.VOLUME_MANAGER_PRESENT,
                "a partition that is a member of a volume manager assembles "
                "something even with nothing stacked on it",
            )
        if partition.filesystem.lower() not in PERMITTED_FILESYSTEMS[partition.role]:
            raise PersistenceRefused(
                Refusal.FILESYSTEM_NOT_PERMITTED,
                "this role carries one of a named set of filesystems; a denylist "
                "of things that assemble is a list somebody has to keep complete",
            )
        if partition.role in PLAIN_ROLES:
            if mappings:
                raise PersistenceRefused(
                    Refusal.MAPPING_ON_A_PLAIN_PARTITION,
                    "the ESP and the boot root sit directly on their partitions",
                )
            if partition.role == "boot_root" and not partition.read_only:
                raise PersistenceRefused(
                    Refusal.ROOT_NOT_READ_ONLY, "the boot root is read-only or not mounted"
                )
        if partition.role == "persistence":
            if PERMITTED_MAPPING not in mappings:
                raise PersistenceRefused(
                    Refusal.NOT_LUKS2,
                    "persistence is a LUKS2 volume opened through dm-crypt",
                )
            if tuple(mapping for mapping in mappings if mapping != PERMITTED_MAPPING):
                raise PersistenceRefused(
                    Refusal.PERSISTENCE_NOT_DIRECTLY_FORMATTED,
                    "the filesystem sits directly on the encrypted partition",
                )


def has_persistence(layout: MediumLayout) -> bool:
    return any(partition.role == "persistence" for partition in layout.partitions)


class PersistenceSession:
    """One sitting on one host, and the only thing that answers "may I".

    It is **not a dataclass and not a value**. Its fields are private, the
    quarantine and the binding cannot be reassigned, the fence is one-way, and
    it refuses to be pickled. A review took the previous version — a plain
    mutable dataclass — and substituted a forged quarantine into a public field,
    cleared the fence with one assignment, and read the host fingerprint out of
    `dataclasses.asdict`. `azazel_boot.quarantine.Quarantine` stopped being a
    dataclass for exactly these reasons, and says so; this follows it.

    It holds the quarantine, so "is this the medium" is asked rather than
    accepted, and it re-derives the binding from the **live inventory** on every
    act rather than comparing its own constructor arguments with each other.
    """

    __slots__ = ("_quarantine", "_binding", "_session_id", "_fenced", "_status", "_sealed")

    def __init__(
        self, quarantine: Quarantine, binding: SessionBinding, *, session_id: str
    ) -> None:
        object.__setattr__(self, "_sealed", False)
        self._quarantine = quarantine
        self._binding = binding
        self._session_id = session_id
        self._fenced = False
        self._status: PersistenceStatus | None = None
        if quarantine.session_id != session_id:
            raise PersistenceRefused(
                Refusal.QUARANTINE_FROM_ANOTHER_SESSION,
                "a quarantine belongs to one session, and so does this",
            )
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        """Sealed after construction, and the fence is one-way.

        `_fenced` may be set and never cleared: a fence an attacker can clear
        with one assignment is not the security property
        `docs/threat-model.md` §4 asks for.
        """

        if getattr(self, "_sealed", False):
            if name == "_status":
                object.__setattr__(self, name, value)
                return
            if name == "_fenced" and value is True:
                object.__setattr__(self, name, True)
                return
            raise AttributeError(
                "a PersistenceSession is sealed after construction; the fence "
                "is one-way and the quarantine and binding cannot be replaced"
            )
        object.__setattr__(self, name, value)

    def __reduce__(self):
        """Refuse to pickle rather than writing the binding into a file or queue."""

        raise TypeError("a PersistenceSession is not serialisable")

    def __repr__(self) -> str:
        """Redacted: a generated repr would print the binding into any traceback."""

        return f"PersistenceSession(fenced={self._fenced})"

    @property
    def quarantine(self) -> Quarantine:
        return self._quarantine

    @property
    def session_id(self) -> str:
        return self._session_id

    def status(self) -> PersistenceStatus:
        """What is true **now**. A status handed out earlier is a snapshot."""

        if self._fenced:
            return _fenced_status()
        return self._status if self._status is not None else _unexamined()

    def recovery_options(self) -> tuple[str, ...]:
        """What is offered next, read from the **current** state.

        A review held the status returned by `unlock`, pulled the medium, and
        got an empty option list — no reboot instruction — because the snapshot
        still said `open`. The safe call is now the only call.
        """

        return RECOVERY_OPTIONS[self.status().state]

    def create(
        self,
        device: Device,
        layout: MediumLayout,
        observations: tuple[InterfaceObservation, ...],
    ) -> PersistenceStatus:
        """Decide whether persistence may be created here, now, on this medium.

        Creation is a separate explicit act. Nothing implies it: not a boot, not
        a successful write, not an operator confirming a NIC role.
        """

        self._require_open_session(observations)
        self._require_the_medium(device)
        check_layout(layout)
        return self._settle(
            PersistenceState.LOCKED,
            None,
            "persistence may be created on this medium; it is not open yet",
            DEGRADED_CAPABILITY,
        )

    def unlock(
        self,
        device: Device,
        layout: MediumLayout,
        observations: tuple[InterfaceObservation, ...],
        *,
        unlocked: bool,
        integrity_verified: bool,
        stored_generation: int,
        last_seen_generation: int,
        dirty: bool,
        repairable: bool,
        reverified_after_repair: bool = False,
    ) -> PersistenceStatus:
        """Open persistence, or say why not — and never repair into use.

        The order is load-bearing and is tested with several faults present at
        once: a volume that did not unlock cannot have its integrity judged, one
        that failed integrity is not asked about its generation, and a repaired
        volume is opened only when the repair was re-verified afterwards.
        """

        self._require_open_session(observations)
        self._require_the_medium(device)
        check_layout(layout)
        if not has_persistence(layout):
            raise PersistenceRefused(
                Refusal.NO_PERSISTENCE_PARTITION,
                "this medium carries no persistence partition to open",
            )
        _require_generation(stored_generation)
        _require_generation(last_seen_generation)

        if not unlocked:
            return self._quarantine_volume(
                UnlockOutcome.UNLOCK_FAILED, "the volume did not unlock"
            )
        if not integrity_verified:
            return self._quarantine_volume(
                UnlockOutcome.INTEGRITY_UNVERIFIED,
                "a modification that is not authenticated is detected, not repaired",
            )
        if stored_generation < last_seen_generation:
            return self._quarantine_volume(
                UnlockOutcome.ROLLBACK_DETECTED,
                "an older generation is detected, never silently accepted",
            )
        if dirty:
            if not repairable:
                return self._quarantine_volume(
                    UnlockOutcome.UNRECOVERABLE_DIRTY_VOLUME,
                    "a volume that cannot be repaired to a verified state is quarantined",
                )
            if not reverified_after_repair:
                return self._quarantine_volume(
                    UnlockOutcome.REPAIR_NOT_REVERIFIED,
                    "a repair that was not verified afterwards is not an open volume",
                )

        return self._settle(
            PersistenceState.OPEN,
            UnlockOutcome.OPENED_AFTER_REPAIR if dirty else UnlockOutcome.OPENED,
            (
                "the volume was repaired and re-verified; the bound on the repair "
                "is the caller's to enforce, not this module's"
                if dirty
                else "the volume unlocked and verified"
            ),
            Capability.LITE,
        )

    def fence_after_removal(self) -> PersistenceStatus:
        """The medium was pulled. Fence new actions without reading the medium.

        `docs/threat-model.md` §4 requires the release supervisor to be
        RAM-resident and to withdraw what it owns without reading anything from
        the removed device. This takes no argument for that reason — and it
        **revokes**, one way: every later act is refused, `status()` reports the
        fence, and nothing can clear it.
        """

        self._fenced = True
        self._status = None
        return _fenced_status()

    # -- internals ---------------------------------------------------------

    def _require_open_session(
        self, observations: tuple[InterfaceObservation, ...]
    ) -> None:
        if self._fenced:
            raise PersistenceRefused(
                Refusal.SESSION_FENCED,
                "the medium was removed; this session cannot act again",
            )
        applies = binding_applies(
            self._binding, observations, session_id=self._session_id
        )
        _refuse_binding(applies=applies)

    def _require_the_medium(self, device: Device) -> None:
        disposition = self._quarantine.disposition(device)
        if disposition is None:
            raise PersistenceRefused(
                Refusal.UNOBSERVED_TARGET,
                "the target has not appeared; a device with no disposition is not "
                "a device with no rule",
            )
        if disposition is not Disposition.BOOT_MEDIUM:
            raise PersistenceRefused(
                Refusal.NOT_THE_BOOT_MEDIUM,
                "persistence exists on the removable medium; host storage is never "
                "created on, mounted, repaired or written back to",
            )

    def _settle(
        self,
        state: PersistenceState,
        outcome: UnlockOutcome | None,
        reason: str,
        capability: Capability,
    ) -> PersistenceStatus:
        self._status = PersistenceStatus(
            state=state, outcome=outcome, reasons=(reason,), capability=capability
        )
        return self._status

    def _quarantine_volume(
        self, outcome: UnlockOutcome, reason: str
    ) -> PersistenceStatus:
        return self._settle(
            PersistenceState.QUARANTINED, outcome, reason, DEGRADED_CAPABILITY
        )


#: What an operator may do from each state. Every option acts on the medium or
#: on the session — none of them touches host storage, and none of them is a
#: repair of somebody else's laptop. The tuples are asserted exactly, because a
#: review added "mount it read-write to salvage the session" and a denylist of
#: four nouns did not notice.
RECOVERY_OPTIONS: dict[PersistenceState, tuple[str, ...]] = {
    PersistenceState.UNEXAMINED: (
        "continue without persistence, at CORE",
        "examine the medium: no act has run in this session yet",
    ),
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
    PersistenceState.FENCED: ("reboot; the session cannot continue",),
}


def status_field_names() -> tuple[str, ...]:
    """The model's own field names, for the test that asserts what it cannot hold."""

    return tuple(field_.name for field_ in fields(PersistenceStatus))


def _unexamined() -> PersistenceStatus:
    """Nothing has been looked at, and saying `absent` would claim otherwise."""

    return PersistenceStatus(
        state=PersistenceState.UNEXAMINED,
        outcome=None,
        reasons=("no act has run in this session; nothing about the medium is known",),
        capability=DEGRADED_CAPABILITY,
    )


def _fenced_status() -> PersistenceStatus:
    return PersistenceStatus(
        state=PersistenceState.FENCED,
        outcome=None,
        reasons=(
            "the medium was removed; new actions are fenced and the session "
            "requires a reboot rather than continuing ambiguously",
        ),
        capability=DEGRADED_CAPABILITY,
    )


def _refuse_binding(*, applies: bool) -> None:
    """Raise from a frame that holds one boolean and nothing else.

    A traceback with captured locals is an ordinary thing for a crash reporter
    to build, and an earlier version raised from a frame holding the binding,
    the host fingerprint and the session id verbatim.

    One refusal rather than two: `binding_applies` answers the host and the
    session together, and distinguishing them here would mean re-deriving the
    fingerprint a second time in this frame.
    """

    if not applies:
        raise PersistenceRefused(
            Refusal.NOT_THIS_HOST_OR_SESSION,
            "this record was bound to another machine or another session; a "
            "medium carried to a different laptop starts from nothing",
        )


def _require_generation(value: object) -> None:
    """A generation is a count. NaN, a string and a fraction are not.

    A review passed `float("nan")`, whose every comparison is false, and the
    rollback check waved it through.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PersistenceRefused(
            Refusal.GENERATION_NOT_A_COUNT,
            "a generation is a non-negative integer",
        )
