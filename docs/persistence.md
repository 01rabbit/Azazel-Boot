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
refused before anything else is considered.

**The binding is re-derived, not re-compared.** Every act takes the inventory
and calls `commissioning.binding_applies`, which recomputes the host fingerprint
from it. The previous version compared the binding against the session's own
constructor arguments — both operands supplied by the same object — so a
self-consistent session passed forever, on any laptop. Making a tautology run
more often does not make it a check.

The operand now comes from outside the session, and a different laptop's
inventory refuses. It is still **the caller's report**: this module reads no
sysfs and no machine, so a captured tuple replayed elsewhere passes. The
strength of the check is the strength of whoever collected the inventory, and
[`azazel_boot.inventory`](../src/azazel_boot/inventory.py) is where that reading
happens. An earlier version of this page said "recomputes … from what this
machine presents", which claimed a reading that does not occur here.

**A host that presents no identity gets no binding at all.** The fingerprint is
taken over commissionable identities only, so a host with none used to hash the
empty string — `sha256:e3b0c442…`, one constant shared by every such machine —
and a binding made on one unidentifiable laptop applied to every other
unidentifiable laptop. Those are exactly the hosts Boot is lent. There is no
fingerprint for such a host now: `host_fingerprint` raises `UnidentifiedHost`,
`bind_session` refuses to mint a record, and `binding_applies` fails closed,
including for a record carried in already holding the empty digest. The
consequence is a safe degradation — no binding, so nothing that needs one runs,
which is the state `assess` already calls `COMMISSIONING_REQUIRED`.

**The session is hard to edit by accident, and is not sealed.** It is not a
dataclass, its fields are private, plain assignment to the quarantine, the
binding or the fence raises, and it refuses to be pickled. A review substituted
a forged quarantine into a public field, cleared the fence with one assignment,
and read the host fingerprint out of `dataclasses.asdict`. A session also
refuses a quarantine minted for a different session.

That guard is `__setattr__`, which is a hook rather than access control, and a
later review went round it three ways: `object.__setattr__` writes the slot,
`PersistenceSession.__new__` yields an instance that never ran `__init__` and is
therefore never sealed — skipping the quarantine's session check with it — and a
subclass can override the hook. The third route opened persistence on the host's
internal disk. **Python has no way to close attribute assignment**, so the claim
here is no stronger than the mechanism:
[the quarantine policy](quarantine-policy.md) states the same limit for the same
reason, and `tests/unit/test_persistence.py` records it as an assertion so a
future seal that actually holds turns the test red rather than leaving a stale
claim standing.

**The fence does not rest on that guard.** It lives on the `Quarantine`, which
is the object representing the medium that was removed, and it is one-way. A
review fenced a session after a surprise removal and then built a second one
from the same quarantine, binding and session id — three arguments the
legitimate caller already holds, nothing forged — and the new session opened
persistence on a medium that was no longer there and offered no reboot. Fencing
now fences every session over that medium, and clearing the session's own flag
with `object.__setattr__` does not restore it.

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
| `filesystem_not_permitted` | each role carries one of a named set: `vfat` for the ESP, `squashfs`/`erofs` for the root, `ext4`/`xfs`/`f2fs` for persistence |

The filesystem **allowlist** is the real check; the member denylist behind it is
defence in depth. A review listed a dozen ordinary `blkid` types the denylist
missed — an allowlist of three roles' filesystems does not have that failure
mode. The allowlist and both denylists are pinned literally rather than
parametrized over themselves: mutation testing found `VOLUME_MANAGERS` still
parametrized over itself, so a version keeping two of its nine entries passed
every test, and this page claimed it was pinned when it was not.

Both acts apply this check. A review deleted the call from `create` and `unlock`
and every layout test stayed green, because they all called the checker
directly; two tests now assert the acts apply it.

Persistence is **optional**: a medium handed out in an emergency may simply not
carry it, and that is a configuration rather than a failure.

## 3. Every failure is a capability, never an authority

| State | What it means | Capability |
| --- | --- | --- |
| `unexamined` | no act has run; nothing about the medium is known | `CORE` |
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
| `opened_after_repair` | opened, and **distinguishable from a clean open** |

The outcome is `opened_after_repair`, not `..._after_bounded_repair`: **nothing
in this module bounds the repair.** No extent, byte budget or transaction count
is expressed here, and `repairable` is a boolean the caller supplies. The bound
[the threat model](threat-model.md) §5 asks for is the caller's to enforce, and
saying otherwise was the last piece of an earlier claim doing work no code did.

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

It **revokes, one way**. Every later act is refused, `status()` reports the
fence, and nothing can clear it. A status handed out earlier is a snapshot and
keeps saying what was true then, which is why `recovery_options()` is a method
on the **session**: a caller holding `unlock`'s return value used to get an
empty option list after a removal — no reboot instruction — through the recovery
path itself.

The flag lives on the **`Quarantine`**, not on the session. Removal happened to
the medium, and the medium's rule is the thing that represents it, so
`Quarantine.fence()` is what `fence_after_removal()` calls and
`Quarantine.is_fenced` is what every session consults. Without that, the fence
was per-object: a review rebuilt a session from the same three constructor
arguments and got an unfenced one. It is deliberately **not** folded into
`Quarantine.disposition()`, which answers "what is this device" — a question
whose answer did not change when the medium was pulled. Any future consumer of a
quarantine must consult `is_fenced` for itself; nothing enforces that for it.

## 6. Recovery never repairs the host

Every option offered from every state acts on the medium or on the session:
continue at `CORE`, examine a medium nothing has looked at, attempt an unlock
with the documented portable passphrase or recovery path, export a quarantined
volume **unmodified** for offline examination, rewrite the medium from a
verified image on another machine, or reboot.

The test asserts the **exact tuple** for each state. It used to be a denylist of
four nouns, and a review added "mount it read-write to salvage the session" and
"copy the session to the machine's own storage first" — both offered to the
operator, both past the test that existed to prevent exactly that.

The first thing to recover on borrowed hardware is somebody else's laptop, and
it is recovered by not having been changed ([recovery](recovery.md) §1).

## 7. Nothing here can hold a secret

`PersistenceStatus` has no `passphrase`, `key`, `recovery_key`, `key_material`,
`operator`, `identity`, `serial` or `device_path` field, and a test asserts their
absence.

A refusal detail names the **rule**, never the value: a partition table is
attacker-supplied input on borrowed hardware, and an earlier version
interpolated a partition's role, so a crafted role put a device path, a serial
and a terminal escape on the console.

The same care is applied to **captured-locals tracebacks**, which is what
`pytest --showlocals` and most crash reporters build. The session redacts its
`repr` and refuses to be pickled; `Device`, `Partition` and `MediumLayout`
redact theirs; binding refusals are raised from a frame holding one boolean; and
`check_layout` sanitises an unrecognised role rather than binding it to a local.
An earlier version put the host fingerprint, the session id, the device identity
and the whole partition table into every such traceback.

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
