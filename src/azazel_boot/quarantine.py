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

**An approval does not survive a re-appearance.** The review's first finding: an
approval was keyed on an identity string and nothing invalidated it, so a dock
could be pulled, another disk could arrive reporting the same identity, and the
write was still allowed. Re-observing a device now withdraws any approval naming
it.

**A device's own claim about itself decides nothing.** A second review found the
opposite failure: because classification consulted the `device_class` a device
asserts, one hostile or garbled observation could demote the medium for the rest
of the session — an untrusted input could not promote anything, but it could
destroy the session's only writable volume, and the audit showed nothing to
distinguish that from an ordinary refusal. Classification is now identity
against identity, and nothing a device says about itself changes an outcome.

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
present a device reporting the booted medium's stable identity, software here
cannot tell it from the medium. An earlier version of this module claimed to
refuse "a second claimant once the medium is bound"; it did not, and could not —
nothing distinguishes a second device with one identity from the same device
appearing twice. The claim is gone rather than dressed up.

Nothing here has run. No initramfs has been built, no device has been
quarantined, and no write has been prevented on any machine.
"""

from __future__ import annotations

from dataclasses import dataclass
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

#: Refused on every device, the boot medium included.
#:
#: `docs/threat-model.md` section 3 scopes four of its bullets to the host
#: ("activate **host** swap", "automount any **non-Boot** device", "…on a
#: **host** filesystem") and leaves two unqualified: running a firmware updater,
#: and assembling LVM volume groups, md arrays or ZFS pools. Both unqualified
#: ones are here.
#:
#: Assembly earns its place for a second reason. It is the only operation in
#: that list that is not per-device: a volume group scanned from the medium can
#: pull in physical volumes that live on host disks, which is exactly the
#: mechanism section 3.2 names. This module's `evaluate(device, action)` shape
#: cannot express a cross-device write at all, so assembly is refused
#: everywhere rather than adjudicated per device.
NEVER_ALLOWED_ANYWHERE = frozenset(
    {
        Action.FIRMWARE_UPDATE,
        Action.RESUME_FROM_HIBERNATION,
        Action.LVM_ASSEMBLY,
        Action.MD_ASSEMBLY,
        Action.ZFS_IMPORT,
    }
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
    """What a device says it is. **Nothing consults it.**

    It is an input an impostor sets freely, so it decides no outcome: the
    quarantine classifies by identity alone, and `Disposition` is its own
    conclusion. `tests/unit/test_quarantine_harness.py` asserts that changing it
    changes nothing.

    It is not entirely ignored. When a device carrying the medium's identity
    says it is *not* the medium, the disagreement is written to the audit as
    `identity_claim_mismatch` — the classification is unaffected, and a
    collision that nobody notices is worse than one that is merely allowed.

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
    SESSION_FENCED = "session_fenced"
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
        if not faults:
            raise ValueError("an ImageRefused with no fault would say nothing")

        def severity(fault: tuple[Refusal, str]) -> int:
            # A refusal missing from the severity order sorts last rather than
            # raising: a build gate that crashes past every `except
            # ImageRefused` is worse than one that reports in the wrong order.
            if fault[0] in IMAGE_REFUSAL_SEVERITY:
                return IMAGE_REFUSAL_SEVERITY.index(fault[0])
            return len(IMAGE_REFUSAL_SEVERITY)

        ordered = sorted(faults, key=severity)
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

    def __repr__(self) -> str:
        """Redacted, for the reason `Quarantine.__repr__` is.

        A `Device` is an argument of nearly every call here and in
        `azazel_boot.persistence`, so a captured-locals traceback — which is
        what `pytest --showlocals` and most crash reporters build — carried the
        identity out of every refusal raised anywhere downstream.
        """

        return f"Device(identity=<redacted>, device_class={self.device_class})"


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


class Quarantine:
    """The running rule. Devices are observed as they arrive, never enumerated.

    The constructor takes the session and the medium's identity and nothing
    else. It was a dataclass once, and an adversarial review built one with a
    ready-made approval through the generated `__init__`, bypassing every check
    in `approve_export` at a stroke. A second review pointed out that
    identity-only classification makes `boot_medium_identity` the whole of this
    module's authority — assigning to it promotes any device — so it is read
    through a property now.

    A third mechanism arrived with the fence: `__setattr__` below refuses plain
    assignment to the session, the medium's identity, the dispositions and the
    audit, and makes `_fenced` one-way. `__slots__` closes the `__dict__` route
    that went round it — `vars(q)["_fenced"] = False` is what a serialisation
    helper or a fixture does routinely, and it cleared the fence — and
    `__reduce__` refuses to pickle or copy, which is why a snapshot taken before
    a fence can no longer be kept as an unfenced quarantine.

    **None of that is a seal, and Python has no way to make one.**
    `object.__setattr__` writes the attribute regardless, `Quarantine.__new__`
    yields an instance that never ran `__init__`, and a subclass can override
    the hook. This is defence against a careless caller, not against code
    already running in the process, and
    `azazel_boot.persistence.PersistenceSession` states the same limit in the
    same words for the same reason.

    **A fourth limit is the ordinary one, and it is named because the other
    three are not what a routine caller would reach for.** `__setattr__` stops
    an attribute being *rebound*; it does not stop the object it points at
    being *mutated*, and the authority lives in those objects.
    ``q._dispositions[identity] = Disposition.BOOT_MEDIUM`` promotes a host
    disk, and ``q._audit.clear()`` erases the record — an attribute read and a
    container write, no hook involved. That is more ordinary than the
    ``vars(q)`` route `__slots__` closes, and this repository's own test suite
    uses it to simulate a demotion, which is why it is documented as a limit
    rather than removed. `audit()` returns a copy and `disposition()` returns a
    value, so nothing reaches these containers through the public API.
    """

    __slots__ = (
        "_session_id",
        "_boot_medium_identity",
        "_dispositions",
        "_approval",
        "_audit",
        "_fenced",
        "_sealed",
    )

    def __init__(self, session_id: str, boot_medium_identity: str) -> None:
        object.__setattr__(self, "_sealed", False)
        self._session_id = session_id
        self._boot_medium_identity = boot_medium_identity
        self._dispositions: dict[str, Disposition] = {}
        self._approval: ExportApproval | None = None
        self._audit: list[AuditEntry] = []
        self._fenced = False
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        """Sealed after construction, and the fence is one-way.

        `azazel_boot.persistence.PersistenceSession` refused `_fenced = False`
        from the day the fence existed. Moving the fence here — the right home,
        because the removal happened to the medium — moved it from the one
        object in this design that resisted casual assignment to the one that
        did not, and a review cleared it with `q._fenced = False` and reopened
        persistence. The two fixes pointed opposite ways on the same flag.

        `_boot_medium_identity` is covered for the reason the class docstring
        already gives: assigning to it promotes any device, which is the whole
        of this module's authority. Reading it through a property stopped a
        dataclass from generating a setter; it never stopped an assignment.

        This is the same **careless-caller** defence stated above, on the same
        terms. `object.__setattr__` writes the attribute regardless and Python
        offers no way to prevent it.
        """

        if getattr(self, "_sealed", False):
            # Written out rather than read from a `_REASSIGNABLE` attribute. A
            # review replaced that attribute on the class — an instance
            # `__setattr__` does not intercept a class assignment — and the
            # allowlist defining the seal was itself outside the seal. A
            # literal in this frame has nothing to swap. `_approval` is here
            # because `approve_export` replaces it and `withdraw_export` clears
            # it; every other attribute is written once, in `__init__`.
            if name == "_approval":
                object.__setattr__(self, name, value)
                return
            if name == "_fenced" and value is True:
                object.__setattr__(self, name, True)
                return
            raise AttributeError(
                "a Quarantine is sealed after construction; the fence is "
                "one-way and the session, the medium's identity, the "
                "dispositions and the audit cannot be rebound — which is not "
                "the same as their contents being protected; see the class "
                "docstring"
            )
        object.__setattr__(self, name, value)

    def __reduce__(self):
        """Refuse to pickle or copy, rather than handing over the session.

        `__repr__` was written by hand so that every observed identity would not
        reach a traceback, a log line or a debugger frame. `pickle` walks the
        instance state instead and hands over `_dispositions` — every device
        seen this session — with `_boot_medium_identity`, `_session_id`, the
        approval and the whole audit. A review dumped one in 262 bytes with all
        three identities legible in it. This is the same defeat that made
        `PersistenceSession` refuse serialisation; the fix belongs on both.

        `copy.copy` and `copy.deepcopy` dispatch through here too, which closes
        the sharper case: a deep copy taken **before** a fence was an unfenced
        quarantine that still allowed a writable mount on the removed medium.
        """

        raise TypeError(
            "a Quarantine is not serialisable; it holds the session's observed "
            "identities and its fence"
        )

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def boot_medium_identity(self) -> str:
        return self._boot_medium_identity

    def observe(self, device: Device) -> Disposition:
        """Classify a device on appearance, by identity and nothing else.

        The medium is the identity the initramfs marked. Everything else is
        quarantined. What a device claims to be is not consulted: a first
        version did consult it, and one hostile or garbled observation could
        then demote the medium permanently — an input that cannot promote
        anything but can destroy the session's only writable volume.
        """

        previous = self._dispositions.get(device.identity)
        is_medium = device.identity == self._boot_medium_identity
        disposition = Disposition.BOOT_MEDIUM if is_medium else Disposition.QUARANTINED

        if is_medium != (device.device_class is DeviceClass.BOOT_MEDIUM):
            # The identity and the device's own claim disagree, in either
            # direction. Identity decides — the class is untrusted — but the
            # disagreement is information, and an unrecorded collision is an
            # invisible one.
            #
            # Both directions matter, and the first version recorded only one.
            # The medium's identity carried by a device saying it is host
            # storage is an accident: duplicate or blank serials on USB and NVMe
            # bridges are a known class of hardware, and nothing here yet
            # constrains how an identity is constructed. A device on another
            # identity *asserting* it is the medium is a deliberate claim, and
            # it is what the threat model's transient-physical-access adversary
            # would present.
            self._record(disposition, "identity_claim_mismatch", "recorded")

        if previous is not None:
            self._withdraw_on_reappearance(device.identity, disposition)

        self._dispositions[device.identity] = disposition
        return disposition

    def __repr__(self) -> str:
        """Deliberately says nothing about what has been observed.

        A dataclass-generated repr printed `_dispositions`, so every observed
        identity reached any traceback, log line or debugger frame holding a
        `Quarantine` — the property `AuditEntry` and `ExportRefused` are built to
        preserve. Dropping the dataclass fixed it incidentally; this makes it a
        decision.
        """

        return (
            f"Quarantine(session=<redacted>, observed={len(self._dispositions)}, "
            f"fenced={self._fenced})"
        )

    def medium_is_bound(self) -> bool:
        """Whether the medium has been seen this session.

        A caller — a trial boot, a status screen — must be able to ask. Without
        it, "the medium is not available" is indistinguishable from "a host disk
        was refused", which is what the audit shows either way.

        A fence answers it False. The question a caller asks through this is
        whether the medium is available, and a medium that was pulled is not —
        a device arriving afterwards on the same identity is the case the fence
        exists for, not evidence that the medium came back.
        """

        if self._fenced:
            return False
        # Identity equality decides classification, so "present in the map" and
        # "holds BOOT_MEDIUM" are the same question today. The stricter form is
        # written out so a future change to `observe` cannot quietly widen it.
        return self._dispositions.get(self._boot_medium_identity) is Disposition.BOOT_MEDIUM

    def disposition(self, device: Device) -> Disposition | None:
        return self._dispositions.get(device.identity)

    def fence(self) -> None:
        """The medium was removed. Record it here, where the medium's rule lives.

        The fence belongs to the **medium**, not to whoever noticed it go. An
        adversarial review fenced an `azazel_boot.persistence.PersistenceSession`
        after a surprise removal and then built a second one from the same three
        constructor arguments the legitimate caller already held -- same
        quarantine, same binding, same session id -- and the new object opened
        persistence on a device that was no longer there and offered no reboot.
        Nothing was forged; the fence was simply per-object, and the object that
        held it was not the one asked next.

        So it is one flag on the one thing that represents the removed medium,
        and it is one-way: a fence that can be lifted is a fence that an
        attacker who benefits from the removal can lift. Reappearance does not
        clear it either -- `_withdraw_on_reappearance` already treats a device
        coming back as a fresh, untrusted arrival, and a session that survived
        the gap is the thing being refused.

        Every consumer must consult :attr:`is_fenced` before acting;
        `azazel_boot.persistence` does. It is deliberately not folded into
        :meth:`disposition`, which answers "what is this device" -- a question
        whose answer did not change when the medium was pulled.
        """

        already = self._fenced
        self._fenced = True
        self._record(
            self._dispositions.get(self._boot_medium_identity),
            "medium_fenced",
            "already_fenced" if already else "fenced",
        )
        # A standing approval is withdrawn by the fence, and the withdrawal is
        # audited. Refusing to *grant* one after a removal while letting one
        # granted a second earlier stand was the same asymmetry from the other
        # side: "an authority the session can no longer exercise" describes
        # both. The record would otherwise keep asserting a live grant, and
        # `withdraw_export` would report `withdrawn` rather than
        # `nothing_to_withdraw`, which is how a review found it.
        if self._approval is not None:
            target = self._approval.target_identity
            self._approval = None
            self._record(
                self._dispositions.get(target), "export_approval", "withdrawn_on_fence"
            )

    @property
    def is_fenced(self) -> bool:
        """Whether the medium has been fenced this session. Never clears."""

        return self._fenced

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
        superseded = self._approval
        self._approval = approval
        if superseded is not None:
            self._record(
                self._dispositions.get(superseded.target_identity),
                "export_approval",
                "superseded",
            )
        self._record(
            self._dispositions.get(approval.target_identity), "export_approval", "granted"
        )

    def withdraw_export(self) -> None:
        """An operator who changes their mind must not have to approve something else."""

        if self._approval is None:
            self._record(None, "export_approval", "nothing_to_withdraw")
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
        """Structural faults first, operator-input faults second.

        An approval that is both unconfirmed and names the medium should report
        the medium: one is a slip at a prompt, the other is a mistake about what
        is being written to.

        **The fence pre-empts all of them, deliberately, and that costs a
        signal this docstring otherwise values.** After a removal every
        approval refuses as `session_fenced`, so an operator who aimed at the
        medium's own identity is audited as fenced rather than as having aimed
        at the medium. The trade is taken this way because the fence is the
        dominant fact and the finer refusals invite a retry that cannot
        succeed: an operator told `not_confirmed` would confirm and try again.
        A review raised the alternative — ordering the fence below the target
        and session checks to keep the audit's distinctions — and it is a real
        alternative; this records why it was not taken rather than leaving the
        ordering to look accidental.
        """

        if self._fenced:
            # The one combination that was neither policy: a review approved an
            # export on a fenced quarantine, the audit recorded it as granted,
            # and `evaluate` then blocked the write unconditionally. An audit
            # asserting an operator granted an authority nobody could exercise
            # is worse than either answer.
            #
            # This makes the refusal agree with what `_decide` already does. It
            # is the conservative direction and it widens nothing: the export
            # was already blocked. **It also has a cost**, and the cost is
            # stated rather than discovered later — an operator mid-export when
            # the medium is knocked out loses the product's one sanctioned host
            # write, which `docs/threat-model.md` section 3 exists to permit.
            # Sparing host-disk exports from the fence is the other coherent
            # answer, and it is a product decision rather than one taken here.
            raise ExportRefused(
                Refusal.SESSION_FENCED,
                "the medium was removed; the session cannot grant an authority "
                "it can no longer exercise",
            )
        if approval.session_id != self._session_id:
            raise ExportRefused(
                Refusal.NOT_THIS_SESSION, "an approval does not outlive a session"
            )
        # By identity **and** by disposition. A second review approved an export
        # to the medium's own identity after a demotion had changed its
        # disposition, which sent the incident record to the one identity this
        # module says it cannot adjudicate.
        if approval.target_identity == self._boot_medium_identity:
            raise ExportRefused(
                Refusal.BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET,
                "that is the medium's identity; the export path exists for host "
                "storage",
            )
        disposition = self._dispositions.get(approval.target_identity)
        if disposition is None:
            raise ExportRefused(
                Refusal.UNOBSERVED_DEVICE,
                "the target has not appeared; an approval is not armed in advance",
            )
        if disposition is Disposition.BOOT_MEDIUM:
            # Unreachable while classification is identity-only: the check above
            # has already refused every identity that can hold this disposition.
            # Kept as defence in depth against a future change to `observe`, and
            # labelled so it is not mistaken for a second independent check.
            raise ExportRefused(
                Refusal.BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET,
                "the export path exists for host storage; the medium is written "
                "through its own operations",
            )
        if not approval.reason.strip():
            raise ExportRefused(
                Refusal.NO_REASON_GIVEN, "an export is approved for a stated reason"
            )
        if not approval.confirmed:
            raise ExportRefused(
                Refusal.NOT_CONFIRMED, "the operator did not confirm this export"
            )

    def _withdraw_on_reappearance(self, identity: str, disposition: Disposition) -> None:
        """A device that appeared again may not be the device that was approved.

        No disposition test here: an approval can never name the medium, so
        every approval this could match belongs to a quarantined device.
        Restricting it would be a redundancy, not a check.
        """

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
        if self._fenced:
            # Ahead of the `BOOT_MEDIUM` short-circuit, which is what made this
            # necessary — second overall, after the actions refused everywhere.
            # A review fenced the medium and then evaluated a
            # writable mount, an fsck, a journal replay and a swap activation
            # against it: all four were allowed, and the audit recorded them as
            # permitted on `boot_medium`. The sharp case is a device presenting
            # the medium's identity **after** the removal — the
            # transient-physical-access adversary this module states it cannot
            # tell apart — which was classified as the medium and then allowed
            # to be mounted writable.
            #
            # `disposition()` deliberately does not consult the fence: "what is
            # this device" did not change when the medium was pulled. This
            # question is "may this happen **now**", and now is after the
            # removal.
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
