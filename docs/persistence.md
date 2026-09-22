# Encrypted persistence, and safe degradation

Status: **decision logic only.** `azazel_boot.persistence` decides whether
persistence may be created, opened or refused, and what the session may claim
afterwards. It **creates no partition, opens no volume, derives no key and
touches no device**. No persistence volume has been created, unlocked, repaired
or quarantined on any hardware.

Related: [ADR-0008 D4.1](adr/0008-debian-13-live-baseline.md) ·
[Threat model](threat-model.md) §4–§5 · [Quarantine policy](quarantine-policy.md) ·
[Recovery](recovery.md) · [Architecture](architecture.md)

## 1. Where persistence may exist

On the **removable Boot medium**, and nowhere else. The target is checked
against the quarantine's own disposition, not against a device name, and a
target that is not the booted medium — or that has never been observed — is
refused before anything else is considered.

Host storage is never created on, mounted, repaired, swapped to, or written back
to. That is [the threat model](threat-model.md) §3 restated at the point where
storage decisions are made rather than assumed to hold from elsewhere.

## 2. The layout

[ADR-0008 D4.1](adr/0008-debian-13-live-baseline.md) fixes it, and this module
refuses anything else:

```
GPT
├─ UEFI System Partition
├─ signed read-only Boot root
└─ optional LUKS2 persistence partition
   └─ a filesystem formatted directly on it
```

| Refusal | Cause |
| --- | --- |
| `unknown_partition_role` | a fourth partition, or a table that is not GPT — an extra partition is refused, not ignored |
| `missing_partition_role` | no ESP, or no boot root |
| `root_not_read_only` | the boot root is writable |
| `not_luks2` | a persistence partition that is not opened through `dm-crypt` |
| `persistence_not_directly_formatted` | anything between the encrypted partition and its filesystem |
| `volume_manager_present` | LVM, mdraid, ZFS, bcache or dm-raid, **on the medium as well as on the host** |

Persistence is **optional**: a medium handed out in an emergency may simply not
carry it, and that is a configuration rather than a failure.

## 3. Every failure is a capability, never an authority

| State | What it means | Capability |
| --- | --- | --- |
| `absent` | the medium carries no persistence partition | `CORE` |
| `locked` | present, not opened; the session runs from RAM | `CORE` |
| `open` | unlocked and verified | `LITE` |
| `quarantined` | present and not trustworthy | `CORE` |
| `fenced` | the medium went away mid-session | `CORE` |

**Azazel-Edge's deterministic arbiter is the only decision and enforcement
authority in every one of those states**, including the ones that look like an
emergency. A test asserts `authority == ()` across all of them, because this is
exactly where a "temporary" exception would be argued for.

## 4. What unlocking refuses, and what it never does

The order is deliberate: a volume that did not unlock cannot have its integrity
judged, one that failed integrity is not asked about its generation, and a dirty
volume is repaired only within bounds.

| Outcome | Meaning |
| --- | --- |
| `unlock_failed` | the volume did not unlock |
| `integrity_unverified` | a modification that is not authenticated — **detected, not repaired** |
| `rollback_detected` | an older generation, detected and never silently accepted |
| `unrecoverable_dirty_volume` | a volume that cannot be repaired to a verified state is quarantined |

There is no `opened_with_warnings` and no `repaired`. The space between "usable"
and "quarantined" is where [the threat model](threat-model.md) §5's "repaired
into a state an attacker chose" lives, so the vocabulary does not have a word
for it.

## 5. Surprise removal

`fence_after_removal()` **takes no argument**. [The threat model](threat-model.md)
§4 requires the release supervisor to be RAM-resident and to withdraw what it
owns without reading anything from the removed device; a fence that needed to
consult the medium could not fire when the medium is the thing that left. After
a removal the session displays a reboot requirement rather than continuing in an
ambiguous state.

## 6. Recovery never repairs the host

Every option offered from every state acts on the medium or on the session:
continue at `CORE`, attempt an unlock with the documented portable passphrase or
recovery path, export a quarantined volume **unmodified** for offline
examination, rewrite the medium from a verified image on another machine, or
reboot. A test walks all five states and asserts that no option mentions the
host, an internal disk, a laptop or an `fsck`.

The first thing to recover on borrowed hardware is somebody else's laptop, and
it is recovered by not having been changed ([recovery](recovery.md) §1).

## 7. Nothing here can hold a secret

`PersistenceStatus` has no `passphrase`, `key`, `recovery_key`, `key_material`,
`operator`, `identity`, `serial` or `device_path` field, and a test asserts their
absence. No refusal message names a device, a host fingerprint or a session.
A value the model cannot carry is a value no rendering, log, audit line or
external report can leak.

## 8. What this does not establish

No medium has been written, no volume has been created or unlocked, no laptop
has booted anything, and **no-host-write is not verified**. The tests use
synthetic layouts and synthetic dispositions; they exercise the decisions in
full and say nothing whatsoever about hardware.
