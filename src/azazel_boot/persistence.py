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
Every act now takes the inventory and calls `commissioning.binding_applies`,
which recomputes the host fingerprint from it. The operand comes from outside
the session, so a different laptop's inventory refuses where the tautology could
not — but the inventory is **the caller's report**, like everything else here.
This module reads no sysfs and no machine, and a captured tuple replayed
elsewhere passes. The strength of the check is the strength of whoever collected
it; `azazel_boot.inventory` is where that reading happens.

**The session is hard to edit by accident, and not sealed.** It is not a
dataclass, its fields are private, plain assignment to the quarantine, the
binding or the fence raises, and it refuses to be pickled. That is defence
against a careless caller. It is **not** defence against code already running in
the process: `object.__setattr__` writes the slot regardless, `__new__` builds an
instance that never ran `__init__` and is therefore never sealed, and a subclass
can override the hook. An adversarial review used all three, and the third
opened persistence on the host's internal disk. `azazel_boot.quarantine` states
the same limit in the same words, and for the same reason — Python has no way to
close attribute assignment. The fence in particular does not rest on the seal:
it lives on the quarantine, which is the thing the removal happened to.

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

import hashlib
import hmac
from dataclasses import dataclass, fields
from enum import Enum
from types import MappingProxyType

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
#: Read-only, like `azazel_boot.artifact`'s field maps: the allowlist is the
#: whole of this module's structural authority, and `dict` hands a caller the
#: ability to widen it with one assignment. That is careless-caller defence, not
#: a seal — see the class docstring of `PersistenceSession`.
PERMITTED_FILESYSTEMS = MappingProxyType(
    {
        "esp": ("vfat",),
        "boot_root": ("squashfs", "erofs"),
        "persistence": ("ext4", "xfs", "f2fs"),
    }
)

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
    MEDIA_IDENTITY_UNAVAILABLE = "media_identity_unavailable"
    MEDIA_IDENTITY_NOT_STABLE = "media_identity_not_stable"
    MEDIA_BINDING_KEY_UNAVAILABLE = "media_binding_key_unavailable"
    MEDIA_BINDING_INCOMPLETE = "media_binding_incomplete"
    MEDIA_BINDING_MISMATCH = "media_binding_mismatch"


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


# ---------------------------------------------------------------------------
# The medium's own identity, and the binding that has to match before a volume
# is opened
#
# Added after an adversarial review showed what the host binding alone could
# not do. `commissioning.host_fingerprint` is taken over commissionable
# interfaces, so a laptop whose onboard NICs cannot be identified takes its
# whole identity from whatever identifiable NIC is present — and if that is a
# USB dongle, the adversary who supplies the dongle supplies the host identity.
# Three laptops sharing one dongle shared one fingerprint.
#
# The owner's decision (F32, option b) is that opening persistence requires a
# **hardware-provided stable media identity** as well, and that the binding
# covers four things at once under a key-protected HMAC: that identity, the
# LUKS persistence UUID, the signed Boot image digest, and the commissioning
# generation. Any of them changing is a refusal.
#
# Three properties follow, and each is a rule rather than a preference.
#
# *The identity is hardware-provided and topology-free.* A bus path, a device
# node, a port or an enumeration order says where a thing is plugged in, not
# what it is, and all four move when the operator uses a different socket.
# `MediaIdentitySource` has no value for any of them — the same discipline
# `azazel_boot.quarantine.Device` applies by having no `kernel_name` field.
#
# *The raw identity never leaves this process in the clear.* A serial, a WWN or
# an EUI-64 is the owner's hardware, and the standing rule is that it lives in
# the encrypted commissioning record and nowhere else: not in the audit, not in
# a journal, not on a terminal, not in an issue or a pull request, not in an
# external report. **No such encrypted record exists in this repository yet.**
# What exists here is the discipline that makes one possible: the value is
# wrapped in a type that will not render it, every refusal message names the
# rule rather than the value, and nothing stores it.
#
# *The key is never held by anything that persists.* It is supplied per act,
# derived by the caller from the TPM or the commissioning secret, and this
# module keeps no reference to it after the call returns.
#
# **What this does not claim.** It does not defeat a full byte-for-byte clone
# of the medium made together with its hardware identity, and it does not
# defeat an enclosure or bridge that reports an identity of the adversary's
# choosing. Those are hardware substitution, which
# [the threat model](../../docs/threat-model.md) §9 already says Boot does not
# defend against, and §2.1 now says so for this specific mechanism. What it
# does is make *the ordinary case* — a different medium, a re-created volume, a
# rolled-back generation, a different Boot image — refuse instead of open.


class MediaIdentitySource(Enum):
    """Where a stable media identity was read from. All hardware-provided.

    There is deliberately **no value** for a bus path, a device node, a port, a
    hub position or an enumeration order. A value the type cannot hold is a
    value a caller cannot smuggle in, which is the same reason
    `azazel_boot.quarantine.Device` has no `kernel_name` field and
    `azazel_boot.inventory.InterfaceObservation` keeps the kernel name out of
    identity.
    """

    USB_SERIAL_DESCRIPTOR = "usb_serial_descriptor"
    SCSI_VPD_WWN = "scsi_vpd_wwn"
    NVME_EUI64 = "nvme_eui64"
    NVME_NGUID = "nvme_nguid"
    ATA_SERIAL = "ata_serial"


#: The shortest identity that is allowed to count as one. A shorter value is
#: not rejected because it is weak; it is rejected because every device that
#: reports one reports the same one.
MINIMUM_IDENTITY_LENGTH = 8

#: Identities that are not identities. Cheap USB-SATA and USB-NVMe bridges ship
#: with these in the serial descriptor, so a whole production run presents one
#: value — the same failure as `inventory._NULL_MAC`, which is an absence a
#: driver reports rather than an address.
#:
#: This list is a floor and is not a guarantee: a bridge can report anything,
#: and one that reports a plausible unique string is indistinguishable from a
#: real one here. `docs/threat-model.md` §2.1 states that limit.
KNOWN_PLACEHOLDER_IDENTITIES = frozenset(
    {
        "0123456789abcdef",
        "123456789012",
        "000000000000",
        "0000000000000000",
        "deadbeef",
        "123456789abc",
        "012345678901",
        "aaaaaaaaaaaa",
        "20170101",
        "usb",
        "generic",
        "none",
        "null",
        "n/a",
        "unknown",
        "default",
        "serial",
        "noserial",
        "0",
    }
)


def identity_is_stable(raw: str | None) -> bool:
    """Whether a value may be used as a medium's identity at all.

    Not a judgement about how good it is. It rejects the three shapes that are
    certainly shared between devices: absent, uniform (all zeroes, all `F`s),
    and a known bridge placeholder. Everything else is accepted, and
    `docs/threat-model.md` §2.1 records that accepting it is not a claim that it
    is unique.
    """

    if raw is None:
        return False
    if not encodable(raw):
        # A lone surrogate reaches here by an ordinary route: Python decodes
        # OS-provided strings with `surrogateescape`, so a sysfs attribute whose
        # bytes are not valid UTF-8 produces one, and a USB string descriptor
        # (UTF-16LE by specification) decoded with `surrogatepass` does too.
        #
        # It used to pass every check here and then raise `UnicodeEncodeError`
        # out of the canonical encoding — from a frame holding the disclosed
        # identity, the volume UUID and the image digest. A review found all
        # three in that traceback. So it is refused here, as a value that cannot
        # be an identity, rather than escaping as an exception no caller is told
        # about.
        return False
    value = raw.strip().lower()
    if len(value) < MINIMUM_IDENTITY_LENGTH:
        return False
    if len(set(value)) == 1:
        return False
    return value not in KNOWN_PLACEHOLDER_IDENTITIES


def encodable(*values: str) -> bool:
    """Whether every value survives a strict UTF-8 encode.

    It returns rather than raising, and it returns **before** anything else can
    fail, so the values are locals of a frame that is gone by the time any
    refusal is raised. That is the same discipline `_digest` follows, and the
    reason both exist as separate functions.
    """

    try:
        for value in values:
            value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


class MediaIdentity:
    """A medium's hardware identity, in a wrapper that will not render it.

    The value is the owner's hardware. It reaches the encrypted commissioning
    record and nothing else, so this type has a redacting `__repr__`, refuses
    to be pickled or copied, and hands the value out only through
    :meth:`disclose` — a name a reader cannot mistake for a getter.

    `azazel_boot.media.DeviceIdentity` is the same shape for the same reason,
    and this follows it deliberately rather than inventing a second one.
    """

    __slots__ = ("_value", "_source", "_sealed")

    def __init__(self, value: str, source: MediaIdentitySource) -> None:
        object.__setattr__(self, "_sealed", False)
        self._value = value
        self._source = source
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError(
                "a MediaIdentity is fixed once read; a binding derived from one "
                "value must not be checked against another"
            )
        object.__setattr__(self, name, value)

    def __reduce__(self):
        raise TypeError(
            "a MediaIdentity is not serialisable; the raw value belongs in the "
            "encrypted commissioning record and nowhere else"
        )

    def __repr__(self) -> str:
        return f"MediaIdentity(source={self._source.value}, value=<redacted>)"

    @property
    def source(self) -> MediaIdentitySource:
        return self._source

    @property
    def is_stable(self) -> bool:
        return identity_is_stable(self._value)

    def disclose(self) -> str:
        """The raw value. Every caller of this is a disclosure decision."""

        return self._value


class BindingKey:
    """The HMAC key, derived by the caller from the TPM or the commissioning secret.

    A plain hash would let anyone who learns the four inputs recompute the
    binding, which is why the standing rule is a **key-protected** HMAC rather
    than a digest. The key material is never written to the audit, a journal, a
    terminal, an issue, a pull request or an external report, so this type
    cannot render itself and cannot be serialised.

    Nothing stores one. It is supplied per act and this module keeps no
    reference after the call returns.
    """

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        # `bytes(16)` is sixteen zero bytes, so a caller passing a *length*
        # where key material was meant used to get a usable, entirely
        # predictable key. An int is not key material.
        if not isinstance(key, bytes | bytearray | memoryview):
            raise TypeError(
                "a BindingKey is built from key material, not from a length "
                "or any other object"
            )
        object.__setattr__(self, "_key", bytes(key))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("a BindingKey is fixed at construction")

    def __reduce__(self):
        raise TypeError("a BindingKey is not serialisable")

    def __repr__(self) -> str:
        return "BindingKey(<redacted>)"

    @property
    def is_usable(self) -> bool:
        return len(self._key) >= MINIMUM_KEY_BYTES

    def disclose(self) -> bytes:
        return self._key


#: Below this, the key is not protecting anything. A caller with no TPM and no
#: commissioning secret has no key, and the refusal for that is the same one:
#: persistence does not open.
MINIMUM_KEY_BYTES = 16

#: Domain separation, so a digest computed here can never be confused with one
#: computed over the same fields for another purpose.
_BINDING_DOMAIN = b"azazel-boot/media-binding/v1"


@dataclass(frozen=True)
class MediaBinding:
    """The HMAC, and nothing else.

    There is no `media_identity`, `serial`, `wwn`, `key` or `key_material`
    field. The four inputs are not recoverable from it, which is what lets the
    caller store it beside the volume.
    """

    digest: str

    def __repr__(self) -> str:
        return "MediaBinding(digest=<redacted>)"


@dataclass(frozen=True)
class MediaClaim:
    """What the caller says this medium is, this boot.

    The identity is wrapped; the other three are not secret — a volume UUID, a
    signed image digest and a counter say nothing about the owner's hardware.
    """

    identity: MediaIdentity
    #: The identity of the device this claim is **about**, as
    #: `azazel_boot.quarantine.Device` carries it. Two identity systems meet
    #: here: the quarantine's, which this session assigned from what the
    #: initramfs marked, and the medium's own, which the hardware reports.
    #:
    #: A review checked them independently and showed the consequence: a valid
    #: binding for a medium the caller owns, presented alongside the booted
    #: medium as `device`, opened persistence. Each gate was satisfied by its
    #: own reference and nothing related the two. Binding the device identity
    #: into the HMAC — and checking the claim is about the device being acted
    #: on — makes them one binding rather than two coincidences.
    device_identity: str
    persistence_uuid: str
    boot_image_digest: str
    commissioning_generation: int

    def __repr__(self) -> str:
        return (
            f"MediaClaim(identity={self.identity!r}, device_identity=<redacted>, "
            f"persistence_uuid=<redacted>, boot_image_digest=<redacted>, "
            f"commissioning_generation={self.commissioning_generation!r})"
        )


@dataclass(frozen=True)
class MediaAssertion:
    """A claim and the binding it is checked against, for one act."""

    claim: MediaClaim
    binding: MediaBinding


def _canonical(*parts: str) -> bytes:
    """Length-prefixed, so no two different field sets share an encoding.

    Concatenating `a|b` and `ab|` would otherwise give one digest for two
    different media. The domain prefix keeps this digest distinct from any
    other HMAC the product computes over the same values.
    """

    # Every value reaching here has already passed `encodable`, so the strict
    # encode below cannot raise. That is what lets `_digest` promise to return
    # before anything can fail.
    encoded = [part.encode("utf-8") for part in parts]
    return _BINDING_DOMAIN + b"".join(
        str(len(item)).encode("ascii") + b":" + item for item in encoded
    )


def _digest(claim: MediaClaim, key: BindingKey) -> str:
    """Compute, and never raise.

    It returns before anything can fail, so no traceback taken later in the act
    holds this frame — which is where the disclosed identity and the disclosed
    key are locals. That is the lesson from the host binding, where making the
    check real put the values it was derived from into every refusal.
    """

    message = _canonical(
        claim.identity.source.value,
        claim.identity.disclose(),
        claim.device_identity,
        claim.persistence_uuid,
        claim.boot_image_digest,
        str(claim.commissioning_generation),
    )
    return hmac.new(key.disclose(), message, hashlib.sha256).hexdigest()


def bind_media(claim: MediaClaim, key: BindingKey) -> MediaBinding:
    """Mint the binding for this medium, this volume, this image, this generation.

    Refuses rather than minting a binding over an identity that is certainly
    shared, or with a key that is not one. A medium whose hardware identity
    cannot be read gets no binding, and therefore no persistence — the same
    discipline `commissioning.UnidentifiedHost` applies to the host.
    """

    _require_bindable(
        identity_present=claim.identity.disclose().strip() != "",
        identity_stable=claim.identity.is_stable,
        key_usable=key.is_usable,
        uuid_present=claim.persistence_uuid.strip() != "",
        image_digest_present=claim.boot_image_digest.strip() != "",
        fields_encodable=encodable(
            claim.device_identity, claim.persistence_uuid, claim.boot_image_digest
        ),
    )
    _require_generation(claim.commissioning_generation)
    return MediaBinding(digest=_digest(claim, key))


def media_binding_applies(
    binding: MediaBinding, claim: MediaClaim, key: BindingKey
) -> bool:
    """Re-derive and compare in constant time.

    Re-derived, not re-compared: the digest is recomputed from the claim the
    caller presents now, so a binding minted for another medium, another
    volume, another image or an earlier generation does not match. A changed
    identity and a forged binding are **the same refusal** — distinguishing
    them would make the refusal an oracle that tells an attacker which of the
    four inputs they got wrong.
    """

    try:
        recomputed = bind_media(claim, key)
    except PersistenceRefused:
        return False
    return hmac.compare_digest(recomputed.digest, binding.digest)


def _require_bindable(
    *,
    identity_present: bool,
    identity_stable: bool,
    key_usable: bool,
    uuid_present: bool,
    image_digest_present: bool,
    fields_encodable: bool,
) -> None:
    """Raise from a frame holding six booleans and nothing else.

    None of the values is in scope here, so a captured-locals traceback of any
    refusal below carries no hardware identity and no key material.
    """

    if not key_usable:
        raise PersistenceRefused(
            Refusal.MEDIA_BINDING_KEY_UNAVAILABLE,
            "a key-protected binding needs a key from the platform or the "
            "commissioning secret; without one persistence does not open",
        )
    if not identity_present:
        raise PersistenceRefused(
            Refusal.MEDIA_IDENTITY_UNAVAILABLE,
            "the medium reported no hardware identity; a medium that cannot say "
            "what it is does not carry persistence",
        )
    if not identity_stable:
        raise PersistenceRefused(
            Refusal.MEDIA_IDENTITY_NOT_STABLE,
            "the reported identity is one every device of its kind reports; it "
            "is an absence with a value, not an identity",
        )
    if not uuid_present:
        raise PersistenceRefused(
            Refusal.MEDIA_BINDING_INCOMPLETE,
            "the binding covers the persistence volume as well as the medium",
        )
    if not image_digest_present:
        raise PersistenceRefused(
            Refusal.MEDIA_BINDING_INCOMPLETE,
            "the binding covers the signed Boot image as well as the medium",
        )
    if not fields_encodable:
        raise PersistenceRefused(
            Refusal.MEDIA_BINDING_INCOMPLETE,
            "a value that cannot be encoded cannot be bound; it is refused here "
            "rather than raised out of the encoding, where it was a local",
        )


def has_persistence(layout: MediumLayout) -> bool:
    return any(partition.role == "persistence" for partition in layout.partitions)


class PersistenceSession:
    """One sitting on one host, and the only thing that answers "may I".

    It is **not a dataclass and not a value**. Its fields are private, plain
    assignment to the quarantine, the binding or the fence raises, and it
    refuses to be pickled. A review took the previous version — a plain mutable
    dataclass — and substituted a forged quarantine into a public field, cleared
    the fence with one assignment, and read the host fingerprint out of
    `dataclasses.asdict`. `azazel_boot.quarantine.Quarantine` stopped being a
    dataclass for exactly these reasons, and says so; this follows it.

    **The `__setattr__` guard is not a seal, and is not described as one.** It
    is a hook, and code in this process goes round it three ways, all of which a
    later review demonstrated: `object.__setattr__` writes the slot directly,
    `PersistenceSession.__new__` produces an instance that never ran `__init__`
    and so is never sealed at all — skipping the session check on the quarantine
    with it — and a subclass can override the hook. The third route opened
    persistence on the host's internal disk. Python has no way to close
    attribute assignment; `azazel_boot.quarantine` says exactly this, and the
    claim here is deliberately no stronger than the mechanism.
    `tests/unit/test_persistence.py` records the limit as an assertion, so a
    future seal that actually holds turns the test red and forces this paragraph
    to be rewritten rather than left standing as folklore.

    What does **not** rest on the guard is the fence. It lives on the
    quarantine, which is the object representing the medium that was removed, so
    rebuilding a session over that quarantine — no forgery, three ordinary
    arguments — does not get an unfenced one.

    It holds the quarantine, so "is this the medium" is asked rather than
    accepted, and it re-derives the binding on every act from the inventory the
    caller supplies, rather than comparing its own constructor arguments with
    each other. What it cannot do is read the machine itself; see the module
    docstring.
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

    @property
    def _is_fenced(self) -> bool:
        """Fenced here, or fenced on the medium this session is about.

        The second is what makes the fence survive a rebuilt session: the flag
        on the quarantine is one-way and shared by every session over it.
        """

        return self._fenced or self._quarantine.is_fenced

    def status(self) -> PersistenceStatus:
        """What is true **now**. A status handed out earlier is a snapshot."""

        if self._is_fenced:
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
        *,
        media: MediaAssertion,
        binding_key: BindingKey,
    ) -> PersistenceStatus:
        """Decide whether persistence may be created here, now, on this medium.

        Creation is a separate explicit act. Nothing implies it: not a boot, not
        a successful write, not an operator confirming a NIC role.

        The caller mints the binding with `bind_media` and passes it. It is
        checked rather than trusted: a binding minted for another medium,
        another volume, another image or another generation does not match the
        claim presented here.
        """

        self._require_open_session(observations)
        self._require_the_medium(device)
        self._require_the_media_binding(device, media, binding_key)
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
        media: MediaAssertion,
        binding_key: BindingKey,
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
        self._require_the_media_binding(device, media, binding_key)
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

        It fences the **quarantine** as well as this object. A review fenced one
        session and then built a second from the same quarantine, binding and
        session id — all three of which the legitimate caller already holds —
        and the new session opened persistence on the removed medium and offered
        no reboot. The removal happened to the medium, so the record of it
        belongs to the medium's rule.
        """

        self._fenced = True
        self._status = None
        self._quarantine.fence()
        return _fenced_status()

    # -- internals ---------------------------------------------------------

    def _require_open_session(
        self, observations: tuple[InterfaceObservation, ...]
    ) -> None:
        if self._is_fenced:
            raise PersistenceRefused(
                Refusal.SESSION_FENCED,
                "the medium was removed; no session over it acts again",
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

    def _require_the_media_binding(
        self, device: Device, media: MediaAssertion, binding_key: BindingKey
    ) -> None:
        """The medium's own identity, checked before the layout is even read.

        The quarantine answers "is this the booted medium" from the identity the
        initramfs marked, which is a value this session assigned. This answers a
        different question — "is this the medium the volume was bound to" — from
        a hardware-provided identity the medium reports, under a key the caller
        derives from the platform or the commissioning secret.

        Both are needed, and they are now **one** check rather than two. The
        host binding was defeated by a USB NIC supplying the host's whole
        identity; a medium binding that rested on the session's own labelling
        would be defeated the same way. A later review showed the third form of
        the same mistake: the two gates were satisfied independently, so a valid
        binding for a medium the caller owns, presented alongside the booted
        medium as `device`, opened persistence. The claim must now be *about*
        the device being acted on, and the device's identity is inside the HMAC
        so the pair cannot be swapped.

        `bind_media` raises the specific refusal for a missing key, an absent
        identity, a placeholder identity or an incomplete binding.
        `media_binding_applies` collapses everything else — a different medium, a
        re-created volume, a different image, a rolled-back generation, a forged
        binding — into one refusal on purpose: a refusal that says *which* input
        was wrong is an oracle.
        """

        recomputed = bind_media(media.claim, binding_key)
        _refuse_media_binding(
            matches=(
                media.claim.device_identity == device.identity
                and hmac.compare_digest(recomputed.digest, media.binding.digest)
            )
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
RECOVERY_OPTIONS = MappingProxyType({
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
})


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


def _refuse_media_binding(*, matches: bool) -> None:
    """Raise from a frame holding one boolean, for the reason `_refuse_binding` does."""

    if not matches:
        raise PersistenceRefused(
            Refusal.MEDIA_BINDING_MISMATCH,
            "this volume was bound to another medium, another device, another "
            "image or another generation; a medium whose identity changed is "
            "the same refusal",
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
