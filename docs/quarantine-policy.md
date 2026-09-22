# Host-storage quarantine policy `quarantine.v1`

Status: **decision logic and a pinned policy artifact. Nothing has run.** No
initramfs has been built, no device has been quarantined, no write has been
prevented, and no machine has booted anything. The no-host-write property is
**not** verified and may not be described as verified.

Related: [Threat model](threat-model.md) section 3 ·
[Builder and writer contract](builder-writer-contract.md) ·
[ADR-0002](adr/0002-image-builder.md) C5 ·
[ADR-0009](adr/0009-builder-and-writer-contract.md) · [Architecture](architecture.md)

## 1. What the policy is

`config/quarantine/policy-v1.json` is the versioned artifact a build pins, and
`quarantine.v1` is the value the artifact record carries as
`quarantine_policy_version`. `azazel_boot.quarantine` implements it, and a test
asserts **every field** of the file against the module: the version, the hook
list, the full action set, the actions refused everywhere, the one action an
approval can unblock, the NVRAM exclusions and the initramfs requirements. An
earlier version of that test checked three fields, and the file had already
drifted from the module on a fourth.

The policy has two halves: what a built initramfs must look like, and how the
running rule decides.

## 2. The initramfs contract

| Hook | Order |
| --- | --- |
| `az-quarantine-block-devices` | **first** |
| `az-disable-resume` | 2 |
| `az-disable-automount` | 3 |
| `az-disable-volume-assembly` | 4 |
| `az-mark-boot-medium` | 5 |

`verify_initramfs` refuses an image whose hooks are reordered, whose first hook
is not the quarantine, which is missing one, which carries a hook Boot did not
pin, which has resume enabled, or which ships an automount rule.

`verify_initramfs` reports **every** fault it finds, worst first, rather than
stopping at the first: a version-string typo must not mask resume being enabled.
A refusal the severity order does not name sorts last instead of raising — a
build gate that crashes past every `except` is worse than one that reports in an
odd order — and a refusal with no faults at all is refused outright.

This is [ADR-0002](adr/0002-image-builder.md) C5 written as a condition an image
either meets or does not. It is **not yet a check performed on a built
initramfs**: nothing in this repository produces a manifest from a real one, so
today a builder satisfies it by filling in a structure. Producing the manifest
from the artifact is what would turn this from a contract into evidence, and
that work has not been done. By the time a general-purpose
userspace is running, udev has automounted, LVM and md have scanned, systemd has
resumed and a filesystem driver has replayed a dirty journal — each of those is
a write, and each happens before any Boot policy code would run
([threat model](threat-model.md) section 3.1). A builder that cannot let Boot
pin these contents and their order cannot deliver the product's defining
property, which is why C5 is the criterion most likely to eliminate a tool.

## 3. The running rule

**It is continuing, not a scan.** Devices are classified on appearance, so a
hotplug, a dock or a resume from suspend is handled by the same rule as a device
present at boot. There is no enumeration step to be out of date.

**Identity decides, never a name or an order.** `sda` is whatever enumerated
first this boot. A device that *claims* to be the boot medium but whose stable
identity is not the booted medium's is quarantined.

**An unobserved device is blocked.** A device with no disposition is not a
device with no rule.

**The `Quarantine` is not a value, and is not sealed.** It stopped being a
dataclass because a review built one with a ready-made export approval through
the generated `__init__`, and `boot_medium_identity` is read through a property
because assigning to it promotes any device. Neither closes attribute
assignment, and **Python has no way to**: `object.__setattr__` writes the
attribute regardless, and an instance built with `__new__` never ran `__init__`.
This is defence against a careless caller, not against code already running in
the process, and it is stated that way in both this module and
[persistence](persistence.md) §1 so that neither page claims a seal that the
mechanism does not provide.

**What a device says about itself decides nothing.** Classification is identity
against identity. When a device carrying the medium's identity says it is *not*
the medium — **or a device on another identity claims that it is** — the
classification is unaffected and the disagreement is written to the audit as
`identity_claim_mismatch`. Both directions are recorded: duplicate or blank
serials on USB and NVMe bridges are a known class of hardware and nothing here
yet constrains how an identity is constructed, while a device *asserting* it is
the medium is a deliberate claim of the kind the threat model's
transient-physical-access adversary would present. A collision nobody notices is
worse than one that is merely allowed. An earlier version consulted the class a device asserts, and a
second review showed the consequence: one hostile or garbled observation could
demote the medium for the rest of the session — an untrusted input could not
promote anything, but it could destroy the session's only writable volume, and
the audit showed nothing to distinguish that from an ordinary refusal. A caller
can ask `medium_is_bound()` rather than inferring it from a refusal.

**Five actions are refused everywhere, the medium included**: running a firmware
updater, resuming from a hibernation image, and assembling LVM volume groups, md
arrays or ZFS pools. The threat model leaves exactly two of its bullets
unqualified — the firmware updater and assembly — and both are here. Assembly
earns it twice over: it is the only operation in that list that is not
per-device, because a volume group scanned from the medium can pull in physical
volumes living on host disks, and this module's per-device shape cannot express
a cross-device write at all.

| Device | What is allowed |
| --- | --- |
| the booted medium | its own operations, except the two refused everywhere |
| host storage | nothing, unless it is the currently approved export target |
| a device that could not be classified | nothing |
| a device never observed | nothing |

**Reading host storage is blocked too.** The operator-initiated read-only
inspection that [the threat model](threat-model.md) section 3 permits has **no
implementation here**, and this module does not pretend to offer one.

### What identity cannot defend against

Identity is the only thing separating the medium from a host disk. An adversary
with transient physical access who can present a device reporting the booted
medium's stable identity cannot be distinguished from the medium in software.

An earlier version of this document claimed the rule would "refuse a second
claimant once the medium is bound". It did not, and could not: nothing
distinguishes a second device carrying one identity from the same device
appearing twice. The claim is gone rather than dressed up, and the test that
made it look true — it manufactured a state the API cannot produce — is gone
with it.

## 4. The export path

Writing to host storage happens only through an export the operator explicitly
approved. An approval names **one** target that has **actually appeared**,
carries a reason and a confirmation, and belongs to **one** session. It
authorises an export write and nothing else — not a mount, not a repair, not a
read. A second approval replaces the first rather than accumulating, a new
session starts with none, and an operator who changes their mind can withdraw
one: [the threat model](threat-model.md) section 3.2 requires that it is "never
a persisted preference".

**An approval does not survive the device re-appearing.** A dock pulled and
replaced by another disk reporting the same identity is not the device that was
approved, so any re-observation withdraws the approval naming it. An approval
also cannot be armed in advance for a device that has never appeared, and the
medium's identity is never an approvable target — checked **by identity**, which
is the live check. The disposition check behind it is unreachable while
classification is identity-only and is kept, labelled, as defence in depth
against a future change to `observe`; a review found the two presented as
independent when they were two spellings of one.

**An approval covers its target for the rest of the session, not one write.** It
is not consumed by an export; an operator who wants it to end calls
`withdraw_export()`, and a re-appearance ends it automatically. A second
*accepted* approval replaces the first — **a refused one replaces nothing**, so
after a refusal the previous approval is still live even though the audit's last
approval entry reads as a refusal. The audit records the grant, any
supersession, the withdrawal, and a withdrawal that had nothing to withdraw.

**The audit is unbounded and RAM-resident.** Every evaluated attempt appends an
entry, and a flapping device appends one per re-appearance. Threat model
section 4 treats devices arriving and leaving as expected, so a long session with
a misbehaving bridge grows the record without limit. Nothing caps or summarises
it yet; a cap with a suppressed-count would keep the record's meaning and bound
the memory, and that is a design decision rather than a fix.

The audit keeps the **quarantine's own conclusion** — not the class the device
claimed, which an impostor sets freely — with the action and the verdict, and it
records approvals, their refusals and their withdrawals. It does not keep a
device identity, and neither does any refusal message: those strings reach a
console and a log on media that travels through uncontrolled hands.

### The fence

`fence()` records that the medium was removed, and `is_fenced` is what a
consumer asks. It belongs here rather than on whoever noticed the removal:
[persistence](persistence.md) §5 held the flag per session, and a review rebuilt
a session from the same quarantine, binding and session id — three arguments the
legitimate caller already holds — to get an unfenced one. It is one-way, and a
re-appearance does not clear it: `_withdraw_on_reappearance` already treats a
returning device as a fresh, untrusted arrival, and the session that survived
the gap is the thing being refused. The audit gets `medium_fenced`, once as
`fenced` and thereafter as `already_fenced`.

It does **not** change `disposition()`, which answers "what is this device" — a
question whose answer did not change when the medium was pulled. So the fence is
advisory to anything that does not ask: `azazel_boot.persistence` asks, and any
future consumer must, because nothing enforces it for them.

### What refusing assembly everywhere costs

`lvm_assembly`, `md_assembly` and `zfs_import` are refused before disposition is
consulted, and no approval unblocks them. LUKS2's `dm-crypt` mapping is the one
exception, and it exists to open persistence.

That is now recorded where it belongs:
[ADR-0008](adr/0008-debian-13-live-baseline.md) **D4.1** fixes the medium's
block layout — GPT, an ESP, the signed read-only root, and an optional LUKS2
partition holding a filesystem formatted directly on it — and states the cost in
the same place: LVM-on-LUKS is a common Debian layout, and under this constraint
Boot's own persistence may not use one. Relaxing it needs hardware-in-the-loop
evidence and its own ADR.

This module is the enforcement half of that record. Refusing assembly
**everywhere**, medium included, is what makes it enforceable at all: assembly is
the one operation in [the threat model](threat-model.md) section 3's list that is
not per-device, and `evaluate(device, action)` cannot express a volume group
that spans the medium and a host disk.

## 5. What is excluded from the zero-write claim

Firmware NVRAM changes the platform makes on its own — a boot entry, a boot
order — are **not preventable by Boot**. They are reported separately and are
explicitly outside the zero-content-writes claim. Reporting them is required;
preventing them is not promised.

## 6. How this is tested, and what that is not

The tests drive a synthetic block-device session: boot with host storage
present, a dock arriving mid-session, an unclassifiable bridge, a device that
never announced itself, and every writing action against each of them. The
assertion is that the set of allowed writes to anything that is not the medium
is **empty**.

That is simulation. It is deliberately kept apart from hardware evidence:

- **no QEMU run is part of this**, and none has been performed;
- no laptop's internal storage has been touched, observed, or measured;
- the program gate needs a hardware-in-the-loop record of zero content writes
  across a full session, including power loss, USB removal, persistence
  corruption and an internal disk present ([threat model](threat-model.md)
  section 3.3). **That record does not exist.**

Until it does, this document describes a design that behaves correctly in a
simulation, and nothing more.
