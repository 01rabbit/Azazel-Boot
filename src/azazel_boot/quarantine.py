"""The host-storage quarantine as a decision, and the initramfs contract it needs.

**This is the product's defining safety property** (`docs/threat-model.md`
section 3): zero content writes to internal host block devices from initramfs
entry through shutdown, until an operator explicitly selects and approves an
export target.

Three shapes in this module come straight from why a quarantine fails.

**It is a continuing rule, not a scan.** A device that appears after the
initramfs — a hotplug, a dock, a resume from suspend — is quarantined on
appearance. `docs/threat-model.md` section 3.2 calls this out as "explicitly a
place where a one-time implementation would be wrong", so there is no
enumeration step here at all: devices are observed as they arrive, and an
unobserved device has no disposition to inherit.

**A device is recognised by stable identity, never by name or order.** `sda` is
whatever enumerated first this boot. Basing the boot medium's identity on a
name, an order or a route is how a quarantine ends up protecting the USB stick
and writing to the laptop.

**An unknown device is quarantined.** Not reported, not deferred, not passed to
an operator to decide mid-boot: a device whose class could not be established
is treated as the thing it must not be allowed to be.

Export is the one path out, and it is per-target and per-session. An approval
names one device, carries a reason and a confirmation, is never persisted, and
covers nothing else (`docs/threat-model.md` section 3.2: "never a persisted
preference").

Nothing here has run. No initramfs has been built, no device has been
quarantined, and no write has been prevented on any machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

#: The version an artifact record carries as `quarantine_policy_version`.
#: `config/quarantine/policy-v1.json` is the pinned artifact a build consumes;
#: `tests/unit/test_quarantine_policy.py` asserts the two agree.
POLICY_VERSION = "quarantine.v1"

#: The order the early hooks must run in. The first one establishes the
#: quarantine; everything that could touch a disk comes after it, and a manifest
#: that reorders them is refused rather than warned about.
EARLY_HOOKS = (
    "az-quarantine-block-devices",
    "az-disable-resume",
    "az-disable-automount",
    "az-disable-volume-assembly",
    "az-mark-boot-medium",
)


class Action(Enum):
    """What something tried to do to a block device."""

    READ = "read"
    AUTOMOUNT = "automount"
    WRITABLE_MOUNT = "writable_mount"
    SWAP_ACTIVATION = "swap_activation"
    RESUME_FROM_HIBERNATION = "resume_from_hibernation"
    FSCK = "fsck"
    JOURNAL_REPLAY = "journal_replay"
    LVM_ASSEMBLY = "lvm_assembly"
    MD_ASSEMBLY = "md_assembly"
    ZFS_IMPORT = "zfs_import"
    INDEXING = "indexing"
    FIRMWARE_UPDATE = "firmware_update"
    EXPORT_WRITE = "export_write"


#: Actions that write, or that lead to a write before any Boot policy code runs.
#: `READ` is absent because reading is not a write; it is nonetheless refused on
#: a quarantined device unless an operator initiated it (see `evaluate`).
WRITING_ACTIONS = frozenset(
    {
        Action.AUTOMOUNT,
        Action.WRITABLE_MOUNT,
        Action.SWAP_ACTIVATION,
        Action.RESUME_FROM_HIBERNATION,
        Action.FSCK,
        Action.JOURNAL_REPLAY,
        Action.LVM_ASSEMBLY,
        Action.MD_ASSEMBLY,
        Action.ZFS_IMPORT,
        Action.INDEXING,
        Action.FIRMWARE_UPDATE,
        Action.EXPORT_WRITE,
    }
)

#: Changes the platform makes on its own. Reported, never claimed as prevented
#: (`docs/threat-model.md` section 3.2).
EXCLUDED_FROM_THE_ZERO_WRITE_CLAIM = (
    "firmware_nvram_boot_entry",
    "firmware_nvram_boot_order",
)


class DeviceClass(Enum):
    """What a device is.

    `HOST_STORAGE` rather than "internal": `internal` is a retired role word in
    this package (`tests/unit/test_commissioning.py`), it answered a different
    question — which side of a network boundary an interface faces — and the
    two must not be readable as the same vocabulary.
    """

    BOOT_MEDIUM = "boot_medium"
    HOST_STORAGE = "host_storage"
    UNKNOWN = "unknown"


class Disposition(Enum):
    QUARANTINED = "quarantined"
    BOOT_MEDIUM = "boot_medium"


class Verdict(Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


class Refusal(Enum):
    HOOK_ORDER_CHANGED = "hook_order_changed"
    HOOK_MISSING = "hook_missing"
    UNPINNED_HOOK = "unpinned_hook"
    QUARANTINE_NOT_FIRST = "quarantine_not_first"
    RESUME_ENABLED = "resume_enabled"
    AUTOMOUNT_RULE_PRESENT = "automount_rule_present"
    WRONG_POLICY_VERSION = "wrong_policy_version"

    UNOBSERVED_DEVICE = "unobserved_device"
    NOT_THIS_TARGET = "not_this_target"
    NOT_THIS_SESSION = "not_this_session"
    NO_REASON_GIVEN = "no_reason_given"
    NOT_CONFIRMED = "not_confirmed"
    BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET = "boot_medium_is_not_an_export_target"


class ImageRefused(Exception):
    """A built initramfs does not satisfy the contract, so it is not a Boot image."""

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


class ExportRefused(Exception):
    """An export was not approved in a way that authorises this write."""

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclass(frozen=True)
class InitramfsManifest:
    """What a build produced, as far as the quarantine is concerned."""

    policy_version: str
    hooks: tuple[str, ...]
    resume_enabled: bool
    automount_rules: tuple[str, ...]


@dataclass(frozen=True)
class Device:
    """A block device as the running system sees it.

    `identity` is stable across boots and enumeration order. There is no
    `kernel_name` field and no `device_path` field: a quarantine that can be
    written against `sda` is a quarantine that protects whatever happened to
    enumerate first.
    """

    identity: str
    device_class: DeviceClass


@dataclass(frozen=True)
class ExportApproval:
    """One operator approval: one target, one session, one reason.

    It is a value, not a setting. Nothing here is written anywhere, and nothing
    reconstructs it on the next boot.
    """

    session_id: str
    target_identity: str
    reason: str
    confirmed: bool


@dataclass(frozen=True)
class AuditEntry:
    """What the audit record keeps: classifications, never a device identity."""

    device_class: str
    action: str
    verdict: str


@dataclass
class Quarantine:
    """The running rule. Devices are observed as they arrive, never enumerated."""

    session_id: str
    boot_medium_identity: str
    _dispositions: dict[str, Disposition] = field(default_factory=dict)
    _approval: ExportApproval | None = None
    _audit: list[AuditEntry] = field(default_factory=list)

    def observe(self, device: Device) -> Disposition:
        """Classify a device on appearance.

        Anything that is not the booted medium, by stable identity, is
        quarantined — including a device that claims to be the boot medium.
        """

        is_boot_medium = (
            device.device_class is DeviceClass.BOOT_MEDIUM
            and device.identity == self.boot_medium_identity
        )
        disposition = Disposition.BOOT_MEDIUM if is_boot_medium else Disposition.QUARANTINED
        self._dispositions[device.identity] = disposition
        return disposition

    def disposition(self, device: Device) -> Disposition | None:
        return self._dispositions.get(device.identity)

    def approve_export(self, approval: ExportApproval) -> None:
        """Record one approval. It replaces any previous one; it never accumulates."""

        if approval.session_id != self.session_id:
            raise ExportRefused(Refusal.NOT_THIS_SESSION, "an approval does not outlive a session")
        if not approval.reason.strip():
            raise ExportRefused(Refusal.NO_REASON_GIVEN, approval.target_identity)
        if not approval.confirmed:
            raise ExportRefused(Refusal.NOT_CONFIRMED, approval.target_identity)
        if approval.target_identity == self.boot_medium_identity:
            raise ExportRefused(
                Refusal.BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET,
                "the export path exists for host storage; the medium is written "
                "through its own operations",
            )
        self._approval = approval

    def evaluate(self, device: Device, action: Action) -> Verdict:
        """Decide one attempt, and record its classification in the audit."""

        verdict = self._decide(device, action)
        self._audit.append(
            AuditEntry(
                device_class=self._class_of(device).value,
                action=action.value,
                verdict=verdict.value,
            )
        )
        return verdict

    def audit(self) -> tuple[AuditEntry, ...]:
        return tuple(self._audit)

    def _class_of(self, device: Device) -> DeviceClass:
        disposition = self._dispositions.get(device.identity)
        if disposition is None:
            return DeviceClass.UNKNOWN
        if disposition is Disposition.BOOT_MEDIUM:
            return DeviceClass.BOOT_MEDIUM
        if device.device_class is DeviceClass.HOST_STORAGE:
            return DeviceClass.HOST_STORAGE
        return DeviceClass.UNKNOWN

    def _decide(self, device: Device, action: Action) -> Verdict:
        disposition = self._dispositions.get(device.identity)
        if disposition is None:
            # An unobserved device is not a device with no rule. It is the one
            # case where guessing is most tempting and most expensive.
            return Verdict.BLOCKED
        if disposition is Disposition.BOOT_MEDIUM:
            return Verdict.ALLOWED
        if action is Action.EXPORT_WRITE:
            approval = self._approval
            if approval is not None and approval.target_identity == device.identity:
                return Verdict.ALLOWED
            return Verdict.BLOCKED
        return Verdict.BLOCKED


def verify_initramfs(manifest: InitramfsManifest) -> None:
    """Check a built initramfs against the contract, or refuse the image.

    This is `ADR-0002` C5 expressed as a check on the artifact rather than as a
    hope about the builder: a build whose initramfs does not satisfy it does not
    become a Boot image.
    """

    if manifest.policy_version != POLICY_VERSION:
        raise ImageRefused(Refusal.WRONG_POLICY_VERSION, manifest.policy_version)

    missing = [hook for hook in EARLY_HOOKS if hook not in manifest.hooks]
    if missing:
        raise ImageRefused(Refusal.HOOK_MISSING, str(missing))

    unpinned = [hook for hook in manifest.hooks if hook not in EARLY_HOOKS]
    if unpinned:
        raise ImageRefused(
            Refusal.UNPINNED_HOOK,
            f"{unpinned} entered the initramfs; an unpinned hook runs before "
            "Boot policy code and is exactly what C5 rules out",
        )

    if manifest.hooks[0] != EARLY_HOOKS[0]:
        raise ImageRefused(
            Refusal.QUARANTINE_NOT_FIRST,
            f"{manifest.hooks[0]} runs before the quarantine is established",
        )
    if manifest.hooks != EARLY_HOOKS:
        raise ImageRefused(Refusal.HOOK_ORDER_CHANGED, str(manifest.hooks))

    if manifest.resume_enabled:
        raise ImageRefused(
            Refusal.RESUME_ENABLED,
            "resume consumes a host hibernation image, which is a write to the "
            "owner's session",
        )
    if manifest.automount_rules:
        raise ImageRefused(Refusal.AUTOMOUNT_RULE_PRESENT, str(manifest.automount_rules))
