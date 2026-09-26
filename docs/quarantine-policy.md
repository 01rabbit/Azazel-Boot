# Host-storage quarantine policy `quarantine.v2`

Status: **decision logic, pinned `quarantine.v2` policy, and R11 prototype
measurement.** R11 statically inspected the required hook ordering/content and
reconciled the static persistence fault with measured QEMU userspace handoff.
Regular-file write probes were denied after device registration and backing
file digests remained unchanged. The initial scan still observed zero devices;
pre-registration quarantine and real-device/host-storage behavior remain
unverified. See the [R11 evidence](prototype-evidence-boot-runtime-r11.md).

Related: [Threat model](threat-model.md) section 3 ·
[Builder and writer contract](builder-writer-contract.md) ·
[ADR-0002](adr/0002-image-builder.md) C5 ·
[ADR-0009](adr/0009-builder-and-writer-contract.md) · [Architecture](architecture.md)

## 1. What the policy is

`config/quarantine/policy-v2.json` is the versioned artifact a build pins, and
`quarantine.v2` is the value the artifact record carries as
`quarantine_policy_version`. `azazel_boot.quarantine` implements it, and a test
asserts **every field** of the file: the closed JSON schema, artifact comment,
version, hook list, full action set, the all-actions quarantine rule, actions
refused everywhere, the one action an approval can unblock, NVRAM exclusions,
and initramfs requirements. Fields represented by the module are compared
against it; artifact-only fields are asserted as exact policy invariants. An
earlier version checked only selected fields, and the file had already drifted.
`policy-v1.json` is retained as the predecessor contract used by r10. R11
uses the v2-bound runtime hooks described in its report; its QEMU evidence must
not be attributed to physical host-storage enforcement.

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
| `az-start-udev` | 6 |
| `az-handoff-udev` (init-bottom) | 7 |

`verify_initramfs` refuses an image whose hooks are reordered, whose first hook
is not the quarantine, which is missing one, which carries a hook Boot did not
pin, which has resume enabled, or which ships an automount rule.

`verify_initramfs` reports **every** fault it finds, worst first, rather than
stopping at the first: a version-string typo must not mask resume being enabled.
A refusal the severity order does not name sorts last instead of raising — a
build gate that crashes past every `except` is worse than one that reports in an
odd order — and a refusal with no faults at all is refused outright.

This is [ADR-0002](adr/0002-image-builder.md) C5 written as a condition an image
either meets or does not. The following bytepin-next4 record is historical;
bytepin-next11-r8 is also superseded by the r10 measurement recorded below. Its frozen
[input manifest](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-a/output/build-input-manifest.json)
has SHA-256
`9f01979e8dd7e107cbaa88481bd7c96eb40ab13214bd4865f5cca51297d55c098`. The
[C5 manifest](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-a/output/c5-manifest.json)
records seven ordered, individually digested hooks, each with
`pinned_by_boot` provenance: quarantine, disable-resume, disable-automount,
disable-volume-assembly, mark-boot-medium, start-udev, and init-bottom
handoff-udev. The [static result](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-a/output/c5-result.json)
is **pass** with no faults. Static manifest persistence is null and explicitly
requires runtime persistence evidence.

The [r8 QEMU fixture result](../artifacts/prototype/2026-09-25/bytepin-next11-r8/qemu/c5-build-b/result.json)
is **fail**. The q35 TCG guest reached `multi-user.target`; initramfs `/dev/vda`
and userspace handoff probes observed read-only write denial, including the
userspace persistence marker. The hotplug `/dev/vdb` path reached read-only
state but has no write-probe result: the helper rejected origin/mode arguments
(`quarantine/probe origin and mode do not match`), and the runner timed out
waiting for the probe. The initial quarantine marker recorded `devices=0`, so
pre-registration quarantine was **NOT_OBSERVED**; quarantine was observed only
after kernel device registration. The source-level fail-closed fix rejecting
missing (`None`) persistence evidence was made after r8 inputs were frozen and
tested separately; it is not in the r8 payload. Runtime C5 therefore remains
failed; hardware and Secure Boot remain unverified.

The historical bytepin-next4 prototype inspector checked
a real initramfs and produced machine-readable evidence, but that evidence
**fails** the contract. The [input manifest](../artifacts/prototype/2026-09-25/bytepin-next4/input/prepared/build-input-manifest.json)
SHA-256 is
`75c72c1061507b6aca8f70a04e894cec79622340388bb26254de1d12a81ccef4`. The
[Build A C5 manifest](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/c5-manifest.json)
records initramfs SHA-256
`97f4f96021fe6cafd8c5922d79f30e005b8581913e76eac0aeba5bcfb3cb4469`. The
[static result](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/c5-result.json)
faults are `hook_order_changed`, `order_changed`,
`quarantine_not_persistent`, and `unpinned_hook`. The inspected init-top
sequence is `00-az-quarantine-block-devices` (pinned), `10-resume`,
`20-automount`, `30-volume assembly`, `40-mark-medium`, then builder-default
`all_generic_ide`, `blacklist`, `keymap`, and `udev`. The quarantine hook's
presence and position among pinned hooks do not establish that the full initrd
ordering is controlled, nor that quarantine persists into userspace.

The separate [QEMU fixture result](../artifacts/prototype/2026-09-25/bytepin-next4/qemu/c5-a/result.json)
is also `fail`. The q35 TCG guest reached `multi-user.target`, but the serial
log says “C5 fixture write failed for an unverified reason”. There is no
structured event or persistence marker, and read-only state/write denial were
not established in the report. The explicitly created 32 MiB regular-file
fixture was attached as `/dev/vda`; the fixture hook loads `virtio_blk` and
waits for that device before applying `blockdev --setro`, so pre-registration
quarantine is not established. Its unchanged digest does not prove writes
were denied. No host block device passthrough, USB, or NIC was used. This is
prototype evidence only: `hardware_verified` and `secure_boot_verified` are
false. The earlier bytepin-next3 evidence remains historical and unchanged.

By the time a general-purpose
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
because assigning to it promotes any device — neither of which closes attribute
assignment. Three mechanisms were added when the fence moved here, each after a
review used its absence:

- `__setattr__` refuses plain assignment to the session, the medium's identity,
  the dispositions and the audit, and makes `_fenced` one-way. The one
  permitted name is a literal inside the guard rather than a `_REASSIGNABLE`
  class attribute, because an instance hook does not intercept a class
  assignment and the allowlist defining the seal was itself outside it.
- `__slots__` closes the `__dict__` route that went round that guard.
  `vars(q)["_fenced"] = False` cleared the fence, and the same route renamed the
  medium so a host disk was classified as it. That is what a serialisation
  helper, a fixture or a debugger does routinely, not an exotic attack.
- `__reduce__` refuses pickling and copying. A redacted `__repr__` is not a
  redacted object: `pickle.dumps` handed over every observed identity, the
  medium's identity, the session id and the whole audit in 262 bytes, and a
  `deepcopy` taken before a fence was an unfenced quarantine that still allowed
  a writable mount on the removed medium.

A fourth limit is the **ordinary** one, and it is listed because the other
three are not what routine code would reach for: `__setattr__` stops an
attribute being *rebound*, not the object it points at being *mutated*, and the
authority lives in those objects. `q._dispositions[identity] =
Disposition.BOOT_MEDIUM` promotes a host disk and `q._audit.clear()` erases the
record — an attribute read and a container write, no hook involved. That is
more ordinary than the `vars(q)` route `__slots__` closes, and this
repository's own tests use it to simulate a demotion, so it is named as a limit
rather than removed. Nothing reaches those containers through the public API:
`audit()` hands out a copy and `disposition()` returns a value.

**None of that is a seal, and Python has no way to make one.**
`object.__setattr__` writes the attribute regardless, an instance built with
`__new__` never ran `__init__`, and a subclass can override the hook. This is
defence against a careless caller, not against code already running in the
process, and it is stated that way in both this module and
[persistence](persistence.md) §1 so that neither page claims a seal that the
mechanism does not provide. An earlier version of this paragraph enumerated two
mechanisms and said neither closed assignment, which stayed on the page after
one that does was added — while §5 of the other page correctly said it had.

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

When a volume is quarantined after a suspected torn write, the state belongs to
the sitting's `Quarantine` and takes precedence over every device disposition,
including the boot-medium allowance. `evaluate()` blocks every action submitted
to that same instance for every device, including read, export, repair, mount,
and activation actions. It withdraws a standing export approval and refuses a
new one. This all-device/all-action scope is the versioned `quarantine.v2`
contract. Exporting the quarantined volume for offline examination is not
implemented and is not an exception.
The caller must retain and reuse the canonical `Quarantine` instance for this
sitting. Constructing a fresh instance resets this in-memory flag; the current
API does not prevent that reset, so such replacement is an unresolved lifecycle
boundary, not a recovery mechanism.

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

**`evaluate()` consults it, ahead of the disposition.** Only the actions refused
on every device are checked before it; both answers are `BLOCKED`, so the order
between those two is not observable. That was not true when
the fence arrived: `_decide` short-circuited on `disposition is BOOT_MEDIUM` and
returned ALLOWED, so a fenced medium still permitted a writable mount, an fsck,
a journal replay and a swap activation — and the audit recorded them as
permitted, on `boot_medium`. The sharp case is a device presenting the medium's
identity *after* the removal, which is the transient-physical-access adversary
this policy says it cannot tell apart: it was classified as the medium and
allowed to be mounted writable. `medium_is_bound()` also answers False after a
fence, because the question a caller asks through it is availability.

**An export cannot be approved after a fence, and a standing approval is
withdrawn by it** — audited as `withdrawn_on_fence`. Refusing a new grant while
letting one made a second earlier stand was the same asymmetry from the other
side. This is a decision with a cost rather than a free safety win. Before, the approval succeeded and was
audited as `granted` while `evaluate` blocked the write unconditionally — an
audit asserting that an operator granted an authority nobody could exercise,
which is worse than either coherent answer. The refusal now agrees with the
verdict, and it widens nothing.

What it costs: [the threat model](threat-model.md) §3's operator-approved export
is the product's **one deliberate host write**, and an operator mid-export when
the medium is knocked out loses the sanctioned path off the machine. Sparing
host-disk exports from the fence is the other coherent answer — the removal
happened to the medium, not to the disk being written — and it is a product
decision that has not been taken. Until it is, the conservative direction holds
because it is the one that adds no capability after a removal.

The cost is smaller than it first reads, and the reason belongs here rather
than in an argument nobody wrote down: **the material an export would carry is
itself on the removed medium.** The evidence, the audit checkpoints and the
session state live in encrypted persistence, and Boot runs from that medium, so
an export path surviving the removal would in the common case have nothing left
to read. What does survive is RAM-resident — [the threat model](threat-model.md)
§4 requires the release supervisor to be — so a future design that wants an
in-memory audit tail written off the machine after a removal will need a path
that is not `approve_export`. §4's answer today is to reboot.

The fence also **pre-empts the finer approval refusals**: after a removal every
approval refuses as `session_fenced`, so an operator who aimed at the medium's
own identity is audited as fenced rather than as having aimed at the medium.
That trades away a distinction `_check_approval` otherwise values, and it is
taken deliberately — the fence is the dominant fact, and `not_confirmed` would
invite a retry that cannot succeed.

It does **not** change `disposition()`, which answers "what is this device" — a
question whose answer did not change when the medium was pulled. So the fence
remains advisory to a consumer that asks neither `evaluate()` nor `is_fenced`:
`azazel_boot.persistence` asks, and any future consumer must, because nothing
enforces it for them.

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

That is simulation. The current Azazel QEMU fixture is separately recorded at
[`qemu/c5-build-b/result.json`](../artifacts/prototype/2026-09-25/bytepin-next11-r8/qemu/c5-build-b/result.json): it used explicit regular-file backing targets and direct kernel/initramfs arguments, reached `multi-user.target`, and observed userspace persistence, but **failed** the runtime C5 gate because the hotplug write-probe was missing and pre-registration quarantine was not observed. This measured prototype result does not modify an ADR or the normative C5 criteria. It is not hardware evidence:

- no laptop's internal storage has been touched, observed, or measured;
- no physical writer target, Secure Boot path, or hardware quarantine has been verified;
- the program gate needs a hardware-in-the-loop record of zero content writes
  across a full session, including power loss, USB removal, persistence
  corruption and an internal disk present ([threat model](threat-model.md)
  section 3.3). **That record does not exist.**

Until it does, the policy remains a design/test contract. The current r8
prototype evidence records a passing static inspection and a failed QEMU
runtime gate. Quarantine must be the first initramfs action and persist through
userspace; initramfs presence alone is not success. Passing unit tests for the
policy logic do not override the missing runtime evidence or the open hardware
gate.
