# Encrypted persistence, and safe degradation

Status: **decision logic only.** `azazel_boot.persistence` decides whether
persistence may be created, opened or refused, and what the session may claim
afterwards. It **creates no partition, opens no volume, derives no key and
touches no device** — the caller performs those acts and reports what happened,
and this module trusts those reports completely. (An earlier version of this
page said "injected ports"; there are none, and the honest statement is the one
above.) No persistence volume has been created, unlocked, repaired or
quarantined on any hardware.

Related: [ADR-0008 D4.1](adr/0008-debian-13-live-baseline.md) ·
[Threat model](threat-model.md) §4–§5 · [Quarantine policy](quarantine-policy.md) ·
[Recovery](recovery.md) · [Architecture](architecture.md)

## 1. Where persistence may exist

On the **removable Boot medium**, and nowhere else. A `PersistenceSession`
holds the quarantine and **asks it** what a device is, by device. It does not
accept a disposition as an argument: an adversarial review showed that
`Disposition.BOOT_MEDIUM` is a process-global constant, so a disposition
obtained for the internal disk — or typed by hand with no quarantine in
existence — opened persistence on anything. A value a caller can name is not a
check.

A target that is not the booted medium, or that has never been observed, is
refused before anything else is considered. The binding to this host and this
session is re-checked on **every** act, not at creation only.

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
| `not_gpt` | the medium is not GPT |
| `unknown_partition_role` | a partition outside the fixed layout — refused, not ignored |
| `duplicate_partition_role` | two partitions claiming one role |
| `partition_order_changed` | the roles are not in the fixed order |
| `missing_partition_role` | no ESP, or no boot root |
| `root_not_read_only` | the boot root is writable |
| `mapping_on_a_plain_partition` | anything mapped under the ESP or the root |
| `not_luks2` | a persistence partition that is not opened through `dm-crypt` |
| `persistence_not_directly_formatted` | anything between the encrypted partition and its filesystem |
| `volume_manager_present` | a mapping that assembles, **or a partition that is a member of one** — a partition that *is* an LVM physical volume assembles something with nothing stacked on it |

Both acts apply this check. A review deleted the call from `create` and `unlock`
and every layout test stayed green, because they all called the checker
directly; two tests now assert the acts apply it.

Persistence is **optional**: a medium handed out in an emergency may simply not
carry it, and that is a configuration rather than a failure.

## 3. Every failure is a capability, never an authority

| State | What it means | Capability |
| --- | --- | --- |
| `absent` | the medium carries no persistence partition | `CORE` |
| `locked` | present, not opened; the session runs from RAM | `CORE` |
| `open` | unlocked and verified, or repaired within bounds and re-verified | `LITE` |
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
| `repair_not_reverified` | a repair nobody verified afterwards is not an open volume |
| `opened_after_bounded_repair` | opened, and **distinguishable from a clean open** |

There is no `opened_with_warnings`. A repaired volume gets its own outcome
rather than the clean one: the first version returned plain `opened`, identical
to a verified open in everything but a free-text string, so a consumer reading
`outcome` could not tell them apart — which is the distinction
[the threat model](threat-model.md) §5 is about.

A generation is a **non-negative integer**. `float("nan")` compares false
against everything, and a review used it to walk past the rollback check.

## 5. Surprise removal

`fence_after_removal()` **takes no argument**. [The threat model](threat-model.md)
§4 requires the release supervisor to be RAM-resident and to withdraw what it
owns without reading anything from the removed device; a fence that needed to
consult the medium could not fire when the medium is the thing that left.

It **revokes**. Every later act on the session is refused, and `status()`
reports the fence. A status handed out earlier is a snapshot and keeps saying
what was true then — that is why a caller consults the session rather than a
value it is holding. The first version returned a new value and left any holder
of the previous one reading `open`, which made fencing an announcement rather
than a fence.

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
absence.

Two leaks a review found are closed. A refusal detail names the **rule**, never
the value — a partition table is attacker-supplied input on borrowed hardware,
and the earlier version interpolated a partition's role, so a crafted role put a
device path, a serial and a terminal escape on the console. And the session
redacts its own `repr` and raises binding refusals from a frame holding
booleans, because `pytest --showlocals` and most crash reporters capture frame
locals; the earlier version put the host fingerprint and the session id in every
such traceback.

## 8. What this does not model

[The threat model](threat-model.md) §5 has seven rows; this module decides three
of them (offline modification, rollback, dirty-volume repair). Audit-chain
truncation, the `LOCAL_CONTINUITY_ONLY` anchor state, persistence migration and
passphrase loss are **not** represented here, and `unlock` grants `LITE` on
success without consulting an anchor. That is a scope statement, not a claim
that those rows are handled elsewhere.

## 9. What this does not establish

No medium has been written, no volume has been created or unlocked, no laptop
has booted anything, and **no-host-write is not verified**. The tests use
synthetic layouts and synthetic dispositions; they exercise the decisions in
full and say nothing whatsoever about hardware.
