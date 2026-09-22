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
asserts the two cannot drift apart.

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

This is [ADR-0002](adr/0002-image-builder.md) C5 expressed as a check on the
artifact rather than a hope about the builder. By the time a general-purpose
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

| Device | What is allowed |
| --- | --- |
| the booted medium | its own operations |
| host storage | nothing, unless it is the approved export target |
| a device that could not be classified | nothing |
| a device never observed | nothing |

## 4. The export path

Writing to host storage happens only through an export the operator explicitly
approved. An approval names **one** target, carries a reason and a confirmation,
and belongs to **one** session. It authorises an export write and nothing else —
not a mount, not a repair. A second approval replaces the first rather than
accumulating, and a new session starts with none:
[the threat model](threat-model.md) section 3.2 requires that it is "never a
persisted preference".

The audit keeps the device *class*, the action and the verdict. It does not keep
a device identity — audit is for traceability, not a place to accumulate
identifiers.

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
