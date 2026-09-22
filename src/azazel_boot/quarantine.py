"""The host-storage quarantine as a decision, and the initramfs contract it needs.

**This is the product's defining safety property** (`docs/threat-model.md`
section 3): zero content writes to internal host block devices from initramfs
entry through shutdown, until an operator explicitly selects and approves an
export target.

Four shapes here come straight from why a quarantine fails. The last three were
added after an adversarial review defeated the first version of this module, and
each names what it defeated.

**It is a continuing rule, not a scan.** A device that appears after the
initramfs — a hotplug, a dock, a resume from suspend — is quarantined on
appearance. `docs/threat-model.md` section 3.2 calls this out as "explicitly a
place where a one-time implementation would be wrong", so there is no
enumeration step: devices are observed as they arrive, and an unobserved device
has no disposition to inherit.

**A disposition never improves, and an approval does not survive a
re-appearance.** The review's first finding: an approval was keyed on an
identity string and nothing invalidated it, so a dock could be pulled, another
disk could arrive reporting the same identity, and the write was still allowed.
Re-observing a device now withdraws any approval naming it, and a device once
quarantined is never re-promoted.

**An approval names a device that was actually seen.** The review's second
finding: `approve_export` checked neither, so an approval could be armed in
advance and fire the moment a matching device appeared.

**Some actions are refused everywhere, the medium included.** The review's third
finding: the boot medium was allowed every action, including running a firmware
updater — the one thing `docs/threat-model.md` section 3 forbids without
scoping it to host devices, and the most direct route to the firmware NVRAM
changes the same document declares unpreventable.

**What this cannot defend against.** Identity is the only thing that separates
the medium from a host disk. If an adversary with transient physical access can
present a device that reports the booted medium's stable identity *before the
medium itself is seen*, software here cannot tell them apart. What it can do,
and does, is refuse a second claimant once the medium is bound, and refuse to
re-promote anything it has quarantined.

Nothing here has run. No initramfs has been built, no device has been
quarantined, and no write has been prevented on any machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

#: The version an artifact record carries as `quarantine_policy_version`.
#: `config/quarantine/policy-v1.json` is the pinned artifact a build consumes;
#: `tests/unit/test_quarantine_policy.py` asserts every field of it against the
#: values below, so the two cannot drift.
POLICY_VERSION = "quarantine.v1"

#: The order the early hooks must run in. The first establishes the quarantine;
#: everything that could touch a disk comes after it, and a manifest that
#: reorders them is refused rather than warned about.
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
#: `READ` is absent because reading is not a write. It is nonetheless blocked on
#: a quarantined device: the operator-initiated read-only inspection that
#: `docs/threat-model.md` section 3 permits has **no implementation here**, and
#: this module does not pretend to offer one.
WRITING_ACTIONS = frozenset(set(Action) - {Action.READ})

#: Refused on every device, the boot medium included. A firmware updater is
#: forbidden by `docs/threat-model.md` section 3 without qualification, and
#: resume is disabled unconditionally by the initramfs contract — neither
#: becomes acceptable because the device is ours.
NEVER_ALLOWED_ANYWHERE = frozenset(
    {Action.FIRMWARE_UPDATE, Action.RESUME_FROM_HIBERNATION}
)

#: The only action an operator approval can unblock.
UNBLOCKABLE_BY_APPROVAL = frozenset({Action.EXPORT_WRITE})

#: Changes the platform makes on its own. Reported, never claimed as prevented
#: (`docs/threat-model.md` section 3.2).
EXCLUDED_FROM_THE_ZERO_WRITE_CLAIM = (
    "firmware_nvram_boot_entry",
    "firmware_nvram_boot_order",
)


class DeviceClass(Enum):
    """What a device says it is.

    This is an input, not a conclusion: an impostor sets it freely. The
    quarantine's own conclusion is a `Disposition`, and that is what the audit
    records.

    `HOST_STORAGE` rather than "internal": `internal` is a retired role word in
    this package (`tests/unit/test_commissioning.py`), it answered a different
    question — which side of a network boundary an interface faces — and the two
    must not be readable as the same vocabulary.
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
    QUARANTINE_NOT_PERSISTENT = "quarantine_not_persistent"
    RESUME_ENABLED = "resume_enabled"
    AUTOMOUNT_RULE_PRESENT = "automount_rule_present"
    WRONG_POLICY_VERSION = "wrong_policy_version"

    UNOBSERVED_DEVICE = "unobserved_device"
    NOT_THIS_SESSION = "not_this_session"
    NO_REASON_GIVEN = "no_reason_given"
    NOT_CONFIRMED = "not_confirmed"
    BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET = "boot_medium_is_not_an_export_target"


#: Refusal order for a built image: the most dangerous fault is named first,
#: so a version typo cannot mask resume being enabled.
IMAGE_REFUSAL_SEVERITY = (
    Refusal.RESUME_ENABLED,
    Refusal.AUTOMOUNT_RULE_PRESENT,
    Refusal.QUARANTINE_NOT_FIRST,
    Refusal.QUARANTINE_NOT_PERSISTENT,
    Refusal.UNPINNED_HOOK,
    Refusal.HOOK_MISSING,
    Refusal.HOOK_ORDER_CHANGED,
    Refusal.WRONG_POLICY_VERSION,
)


class ImageRefused(Exception):
    """A built initramfs does not satisfy the contract, so it is not a Boot image.

    It carries every fault found, not just the first: the refusal is the record,
    and a record that stops at a typo hides what was actually wrong.
    """

    def __init__(self, faults: tuple[tuple[Refusal, str], ...]) -> None:
        ordered = sorted(faults, key=lambda fault: IMAGE_REFUSAL_SEVERITY.index(fault[0]))
        self.faults = tuple(ordered)
        self.refusal = ordered[0][0]
        self.detail = ordered[0][1]
        super().__init__("; ".join(f"{name.value}: {detail}" for name, detail in ordered))


class ExportRefused(Exception):
    """An export was not approved in a way that authorises this write.

    The detail never names a device. The refusal is the same whichever disk it
    was, and the message lands on a console and in a log on media that travels
    through uncontrolled hands.
    """

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclass(frozen=True)
class InitramfsManifest:
    """What a build produced, as far as the quarantine is concerned.

    Nothing in this repository produces one from a real initramfs yet. It is the
    shape the eventual producer must fill, and `verify_initramfs` is what it
    will be checked against — not, today, a check performed on a built image.
    """

    policy_version: str
    hooks: tuple[str, ...]
    resume_enabled: bool
    automount_rules: tuple[str, ...]
    quarantine_persists_into_userspace: bool


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
    """What the audit keeps: the quarantine's own conclusion, never an identity.

    `disposition` is what this module decided, not what the device claimed. A
    host disk that misreports itself must not be able to choose how it appears
    in the record.
    """

    disposition: str
    action: str
    verdict: str


@dataclass
class Quarantine:
    """The running rule. Devices are observed as they arrive, never enumerated.

    The three pieces of state are `init=False`: an adversarial review built a
    `Quarantine` with a ready-made approval through the generated constructor
    and bypassed every check in `approve_export` at once.
    """

    session_id: str
    boot_medium_identity: str
    _dispositions: dict[str, Disposition] = field(default_factory=dict, init=False)
    _approval: ExportApproval | None = field(default=None, init=False)
    _audit: list[AuditEntry] = field(default_factory=list, init=False)
    _medium_bound: bool = field(default=False, init=False)

    def observe(self, device: Device) -> Disposition:
        """Classify a device on appearance.

        A disposition never improves: once quarantined, a device stays
        quarantined for the session, even if it later presents itself as the
        medium. Refusing the medium is a broken product; allowing a host write
        is a broken promise, and only one of those is recoverable.
        """

        previous = self._dispositions.get(device.identity)
        claims_medium = (
            device.device_class is DeviceClass.BOOT_MEDIUM
            and device.identity == self.boot_medium_identity
        )
        proposed = Disposition.BOOT_MEDIUM if claims_medium else Disposition.QUARANTINED

        if claims_medium and self._medium_bound and previous is not Disposition.BOOT_MEDIUM:
            # The medium is already bound; a second claimant is not it.
            proposed = Disposition.QUARANTINED

        if previous is Disposition.QUARANTINED or proposed is Disposition.QUARANTINED:
            disposition = Disposition.QUARANTINED
        else:
            disposition = Disposition.BOOT_MEDIUM

        if disposition is Disposition.BOOT_MEDIUM:
            self._medium_bound = True

        if previous is not None:
            self._withdraw_on_reappearance(device.identity, disposition)

        self._dispositions[device.identity] = disposition
        return disposition

    def disposition(self, device: Device) -> Disposition | None:
        return self._dispositions.get(device.identity)

    def approve_export(self, approval: ExportApproval) -> None:
        """Record one approval, and audit the attempt either way.

        It replaces any previous approval; it never accumulates.
        """

        try:
            self._check_approval(approval)
        except ExportRefused as refused:
            self._record(
                self._dispositions.get(approval.target_identity),
                "export_approval",
                refused.refusal.value,
            )
            raise
        self._approval = approval
        self._record(
            self._dispositions.get(approval.target_identity), "export_approval", "granted"
        )

    def withdraw_export(self) -> None:
        """An operator who changes their mind must not have to approve something else."""

        if self._approval is None:
            return
        target = self._approval.target_identity
        self._approval = None
        self._record(self._dispositions.get(target), "export_approval", "withdrawn")

    def evaluate(self, device: Device, action: Action) -> Verdict:
        """Decide one attempt, and record the decision in the audit."""

        verdict = self._decide(device, action)
        self._record(self._dispositions.get(device.identity), action.value, verdict.value)
        return verdict

    def audit(self) -> tuple[AuditEntry, ...]:
        return tuple(self._audit)

    # -- internals ---------------------------------------------------------

    def _check_approval(self, approval: ExportApproval) -> None:
        if approval.session_id != self.session_id:
            raise ExportRefused(
                Refusal.NOT_THIS_SESSION, "an approval does not outlive a session"
            )
        if not approval.reason.strip():
            raise ExportRefused(
                Refusal.NO_REASON_GIVEN, "an export is approved for a stated reason"
            )
        if not approval.confirmed:
            raise ExportRefused(
                Refusal.NOT_CONFIRMED, "the operator did not confirm this export"
            )
        disposition = self._dispositions.get(approval.target_identity)
        if disposition is None:
            raise ExportRefused(
                Refusal.UNOBSERVED_DEVICE,
                "the target has not appeared; an approval is not armed in advance",
            )
        if disposition is Disposition.BOOT_MEDIUM:
            raise ExportRefused(
                Refusal.BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET,
                "the export path exists for host storage; the medium is written "
                "through its own operations",
            )

    def _withdraw_on_reappearance(self, identity: str, disposition: Disposition) -> None:
        """A device that appeared again may not be the device that was approved."""

        if self._approval is not None and self._approval.target_identity == identity:
            self._approval = None
            self._record(disposition, "export_approval", "withdrawn_on_reappearance")

    def _record(self, disposition: Disposition | None, action: str, verdict: str) -> None:
        self._audit.append(
            AuditEntry(
                disposition=disposition.value if disposition is not None else "unobserved",
                action=action,
                verdict=verdict,
            )
        )

    def _decide(self, device: Device, action: Action) -> Verdict:
        if action in NEVER_ALLOWED_ANYWHERE:
            return Verdict.BLOCKED
        disposition = self._dispositions.get(device.identity)
        if disposition is None:
            # An unobserved device is not a device with no rule. It is the one
            # case where guessing is most tempting and most expensive.
            return Verdict.BLOCKED
        if disposition is Disposition.BOOT_MEDIUM:
            return Verdict.ALLOWED
        if action in UNBLOCKABLE_BY_APPROVAL:
            approval = self._approval
            if approval is not None and approval.target_identity == device.identity:
                return Verdict.ALLOWED
        return Verdict.BLOCKED


def verify_initramfs(manifest: InitramfsManifest) -> None:
    """Check a manifest against the contract, or refuse the image.

    This is `ADR-0002` C5 written as a condition an image either meets or does
    not. It is **not yet** a check performed on a built initramfs: nothing in
    this repository produces a manifest from one, so today a builder satisfies
    it by filling in a structure. Producing the manifest from the real artifact
    is what turns this from a contract into evidence.
    """

    faults: list[tuple[Refusal, str]] = []

    if manifest.resume_enabled:
        faults.append(
            (
                Refusal.RESUME_ENABLED,
                "resume consumes a host hibernation image, which is a write to "
                "the owner's session",
            )
        )
    if manifest.automount_rules:
        faults.append((Refusal.AUTOMOUNT_RULE_PRESENT, str(manifest.automount_rules)))
    if not manifest.quarantine_persists_into_userspace:
        faults.append(
            (
                Refusal.QUARANTINE_NOT_PERSISTENT,
                "a quarantine re-established in userspace starts after udev, LVM "
                "and the filesystem drivers have already written",
            )
        )

    missing = [hook for hook in EARLY_HOOKS if hook not in manifest.hooks]
    if missing:
        faults.append((Refusal.HOOK_MISSING, str(missing)))
    unpinned = [hook for hook in manifest.hooks if hook not in EARLY_HOOKS]
    if unpinned:
        faults.append(
            (
                Refusal.UNPINNED_HOOK,
                f"{unpinned} entered the initramfs; an unpinned hook runs before "
                "Boot policy code and is exactly what C5 rules out",
            )
        )
    if not manifest.hooks or manifest.hooks[0] != EARLY_HOOKS[0]:
        faults.append(
            (
                Refusal.QUARANTINE_NOT_FIRST,
                "the quarantine hook does not run first, so something else runs "
                "before the quarantine exists",
            )
        )
    elif manifest.hooks != EARLY_HOOKS:
        faults.append((Refusal.HOOK_ORDER_CHANGED, str(manifest.hooks)))

    if manifest.policy_version != POLICY_VERSION:
        faults.append((Refusal.WRONG_POLICY_VERSION, str(manifest.policy_version)))

    if faults:
        raise ImageRefused(tuple(faults))
