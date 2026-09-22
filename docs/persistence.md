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
[ADR-0010](adr/0010-persistence-key-and-migration.md) ·
[Session mode](session-mode.md) ·
[Snapshot and recovery](snapshot-and-recovery.md) ·
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

**The medium has an identity of its own, and it is checked before anything
else.** The host binding above is necessary and was not sufficient: a review
showed that a laptop whose onboard NICs cannot be identified takes its whole
fingerprint from whatever identifiable NIC is present, so an adversary
supplying a USB dongle supplied the host identity — three laptops sharing one
dongle shared one fingerprint. At the owner's decision
([ADR-0008 D4.1.1](adr/0008-debian-13-live-baseline.md)), opening persistence
now requires a **hardware-provided stable media identity** as well, bound under
a **key-protected HMAC** together with three other things:

```
stable media hardware identity   (USB serial descriptor, SCSI VPD WWN,
                                  NVMe EUI-64 / NGUID, ATA serial)
+ the device identity the quarantine holds
+ LUKS persistence UUID
+ signed Boot image digest
+ commissioning generation
```

| Refusal | Cause |
| --- | --- |
| `media_binding_key_unavailable` | no key from the platform or the commissioning secret; a plain digest anyone can recompute is not a binding |
| `media_identity_unavailable` | the medium reported no hardware identity |
| `media_identity_not_stable` | it reported one every device of its kind reports — blank, uniform, or a known bridge placeholder |
| `media_binding_incomplete` | the volume UUID or the image digest is missing |
| `media_binding_mismatch` | a different medium, a different device, a re-created volume, a different image, a mismatched generation, or a forged binding |

The last row is **one refusal for six causes, deliberately**. A refusal that
says which of the four inputs was wrong is an oracle: it tells an attacker
holding three of them which one to keep working on.

*Topology is never identity.* `MediaIdentitySource` has no value for a bus
path, a device node, a port, a hub position or an enumeration order. Those say
where a medium is plugged in, they move when the operator uses another socket,
and the medium does not report them. This is the same discipline that keeps the
kernel name out of an interface's identity.

*The raw identity and the key are never rendered.* `MediaIdentity` and
`BindingKey` hand their values out only through `disclose()`, redact their
`__repr__`, and refuse to be pickled or copied. `MediaBinding` carries the HMAC
and has no field that could hold an identity or a key. The digest is computed
in a frame that returns before anything can raise, so no traceback taken later
in the act holds the disclosed values — the lesson from the host binding, where
making the check real put the values it was derived from into every refusal.
The raw value belongs in the encrypted commissioning record and nowhere else;
**no such record exists in this repository yet**, and what exists is the
discipline that makes one possible.

*The two identity systems are one binding.* The quarantine answers "is this
the booted medium" from an identity this session assigned; the media binding
answers "is this the medium the volume was bound to" from one the hardware
reports. Checked independently, both were satisfiable at once — a review
presented a valid binding for a medium the caller owns alongside the booted
medium as the device, and persistence opened. The claim must now be about the
device being acted on, and that device identity is inside the HMAC, so the pair
cannot be swapped and the binding cannot be reused under another device
identity.

*"Changed" means checked at the next act.* Creating and unlocking each check
the binding; a volume already open stays open until something asks again. A
live substitution with no removal event is not modelled, and
[the threat model](threat-model.md) §5 says so.

*What this does not claim.* It does not defeat a byte-for-byte clone of the
medium made together with its hardware identity, nor a programmable enclosure
reporting an identity of the adversary's choosing. Both are hardware
substitution, which [the threat model](threat-model.md) §9 excludes and §2.1
now states for this mechanism. What it closes is the ordinary case.

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
mode. The allowlist and both denylists are asserted as **exact tuples**, not as
subsets and not by parametrizing over themselves. Two rounds of mutation testing
were needed for that sentence to become true: the first found `VOLUME_MANAGERS`
parametrized over itself, so a version keeping two of its nine entries passed
every test; the second found the members list asserted as a five-element subset
of fifteen, so ten entries — including every one added to close the earlier
finding — could be dropped unnoticed. This page claimed the pin both times
before it existed.

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
| `open` | unlocked and verified. **Nothing else reaches this state** | `LITE` |
| `quarantined` | present and not trustworthy | `CORE` |
| `fenced` | the medium went away mid-session | `CORE` |

**Azazel-Edge's deterministic arbiter is the only decision and enforcement
authority in every one of those states**, including the ones that look like an
emergency. A test asserts `authority == ()` across all of them, because this is
exactly where a "temporary" exception would be argued for.

## 4. What unlocking refuses, and what it never does

The order is deliberate: a volume that did not unlock cannot have its integrity
judged, one that failed integrity is not asked about its generation, and a
volume suspected of an interrupted write is not asked anything further at all.

| Outcome | Meaning |
| --- | --- |
| `unlock_failed` | the volume did not unlock |
| `integrity_unverified` | a modification that is not authenticated — **detected, not repaired** |
| `rollback_detected` | an older generation, detected and never silently accepted |
| `dirty_volume` | an interrupted write is suspected; the volume is quarantined |

There is no `opened_with_warnings`, and — since
[ADR-0010](adr/0010-persistence-key-and-migration.md) D4 — **no
`opened_after_repair` either.**

That member was real, and removing it is worth recording rather than quietly
dropping. An earlier version opened a dirty volume the caller reported as
repaired and re-verified, under a distinct outcome so a consumer could tell it
from a clean open. That was the right fix for the problem as it then stood: the
version before *it* returned plain `opened`, identical to a verified open in
everything but a free-text string.

**Naming the repaired case honestly is not a substitute for not having it.** A
caller who can report "repairable" and "re-verified" can open a torn volume by
saying so twice, and this module bounded neither claim — it had no extent, byte
budget or transaction count, and said as much. D4 removes the sentence rather
than improving its wording: there is no `repairable` parameter, no
`reverified_after_repair` parameter, and no branch from `dirty` to `open`. A
test asserts the absence on the **signature**, which is stronger than every
combination of arguments being refused.

## 4.1 A suspected torn write costs the whole volume

[ADR-0010](adr/0010-persistence-key-and-migration.md) D4 and D5, implemented in
[`azazel_boot.dirty_write`](../src/azazel_boot/dirty_write.py) and the session's
`report_write` / `require_ordinary`.

The caller performs the write and reports what it saw in three closed
vocabularies — the receipt, the medium's continuity, the verify step — and
**each is three-valued, not a boolean.** A `bool` has no room for "nobody
established this", so a caller facing an unknown would have to pick one of the
two answers it does have, and under time pressure that is the convenient one.

Of the twenty-seven possible observations, **one is a clean write.** The other
twenty-six quarantine the volume, and the test enumerates all of them rather
than sampling, so a widened condition is a red test.

**The three fields are checked where the observation is built, and the type is
checked again where it is read.** Six `is` comparisons followed by `return
None` means *anything unrecognised is a clean write* — the opposite of what
this page claims. An adversarial review passed a `SimpleNamespace` of three
`None`s and got a clean write, and built a `WriteObservation` whose three
fields were the *strings* naming the worst faults there are, which also
classified clean. An annotation is not a check, and the wrong import is enough
to produce the second one by accident.

The classification order is fixed and is part of the contract, because faults
arrive together and the audit records one word: continuity first, then whether
the verify step reached an answer, then the receipt. A pulled medium *causes* a
missing receipt, so recording `receipt_missing` there would name the symptom
instead of the event.

**Why the whole volume.** [Threat model](threat-model.md) §4 fixes the write
order — *prepare-and-sync, apply, verify, persist receipt* — so a missing
receipt is the signal. What it does not say is *how much* is affected, and
there is no way to find out from this side: the records already there are the
same bytes whether the interrupted write touched them or not, and the only
thing that could say otherwise is the volume being judged. Per-record salvage
would be a guess presented as a finding.

Ordinary `read`, `write` and `export` are then all refused, with the same
refusal. **The fence wins over all of it**: a medium that was pulled is refused
before its write is even classified, because classifying it would mean
reasoning about a device that is not there.

The quarantine is **one-way within the boot**. There is no clearing call — not
`clear`, not `reopen`, not `reset` — and a test asserts the absence over the
public surface rather than trying the obvious spellings one at a time. Leaving
quarantine is D8's explicit recovery workflow, which is
[#42](https://github.com/01rabbit/Azazel-Boot/issues/42) and does not exist; a
method here that ended the state would be that workflow with its four gates
removed.

### Nothing is called erased

The data is on the medium. Boot **will not use it in ordinary operation**, and
that is a different sentence from "the volume was wiped". What an operator may
later truthfully tell someone about the evidence depends on the distinction.

What is scanned for `wiped`, `cleared`, `erased`, `destroyed`, `shredded` and
`deleted`, and what is not, is worth stating exactly — an earlier version of
this paragraph claimed more than the test did:

- **`azazel_boot.dirty_write`: everything, including its class and function
  docstrings.** A docstring is where an operator-facing claim actually lives —
  `help()`, an IDE hover, generated documentation — and the first version
  excluded docstrings *as a category*, so a review put "the volume has been
  wiped and its contents erased and destroyed" into `classify`'s docstring and
  the suite stayed green. Only the module docstring is exempt, by node
  identity, because it names the six words in order to say the volume is none
  of them.
- **`azazel_boot.persistence`: every string it can render** — reason strings,
  refusal details, every `Refusal`, `UnlockOutcome` and `PersistenceState`
  value, and every line of `RECOVERY_OPTIONS`. The first version scanned none
  of them, and a review replaced the D4 unlock reason with "the dirty volume
  was shredded, erased and destroyed, not repaired" — a string that lands
  straight in `PersistenceStatus.reasons` — with the suite green.
- **Not `azazel_boot.persistence`'s docstrings.** They carry long historical
  narrative about reviews that "cleared the fence with one assignment" and an
  `_audit.clear()` that "erases the record": prose about *other objects*.
  Scanning it for six English words would fail on the history that exists to
  stop those bugs recurring, and a proximity heuristic would stop meaning
  anything. The boundary is stated here rather than left to be discovered.

The offline-examination export of [quarantine
policy](quarantine-policy.md) §4 is **unchanged**: an approved, unmodified copy
taken *because* the volume is not trustworthy. It is granted on the quarantine,
not here, and a test drives it on a quarantined volume rather than asserting
that it is a different path — "it is a different path" being the kind of claim
that stops being true quietly.

### The screen says the rule, the audit says which condition

`PersistenceStatus.reasons` carries **one sentence, the same one for every
detection**: an interrupted write is suspected, Boot will not use this volume
in ordinary operation, and does not repair it. The word naming *which*
condition was observed lives in the audit, where D4 puts it.

This was found undecided rather than designed: a mutation that interpolated the
signal into the operator-facing reason survived the whole suite, because the
refusal message was pinned and this surface was not. It is not a
confidentiality break — D4 records the classification deliberately, so it is
not a secret. It is a second place the same fact would live, with nothing
keeping the two in agreement and no decision about which one an operator reads.
It is now decided, and pinned, the same way the refusal is.

### What the audit may hold

Three classifications: the detection, the transition into quarantine, and the
refusal of each refused act. `VolumeAuditEntry` has three fields — `event`,
`signal`, `act` — and no field for content, an offset, a size, a record count,
a timestamp, a device identity, key material or an operator identifier. A test
asserts the rendered audit carries no digit at all, because a count is digits.

A generation is a **non-negative integer**. `float("nan")` compares false
against everything, and a review used it to walk past the rollback check.

## 5. Surprise removal

`fence_after_removal()` **takes no argument**. [The threat model](threat-model.md)
§4 requires the release supervisor to be RAM-resident and to withdraw what it
owns without reading anything from the removed device; a fence that needed to
consult the medium could not fire when the medium is the thing that left.

It **revokes, one way through the API**. Every later act is refused, `status()`
reports the fence, and no call clears it: `fence()` is idempotent, plain
assignment to the flag raises on the session *and* on the quarantine, and the
medium re-appearing does not lift it. It is not a seal, on the same terms as §1
— an earlier version of this sentence read "nothing can clear it", which
contradicted §1 of this page and was false in the plainest way: the flag had
moved to an object with no guard on it at all, and `q._fenced = False` reopened
persistence. A status handed out earlier is a snapshot and
keeps saying what was true then, which is why `recovery_options()` is a method
on the **session**: a caller holding `unlock`'s return value used to get an
empty option list after a removal — no reboot instruction — through the recovery
path itself.

The flag lives on the **`Quarantine`**, not on the session. Removal happened to
the medium, and the medium's rule is the thing that represents it, so
`Quarantine.fence()` is what `fence_after_removal()` calls and
`Quarantine.is_fenced` is what every session consults. Without that, the fence
was per-object: a review rebuilt a session from the same three constructor
arguments and got an unfenced one.

Moving it there was not enough on its own. `Quarantine.evaluate` — the call that
decides whether a write happens — did not consult the flag, so a fenced medium
still allowed a writable mount, an fsck, a journal replay and a swap activation,
and the audit recorded them as permitted. It does consult it now, ahead of the
disposition (only the actions refused on every device are checked first, and
both answers are `BLOCKED`), and `medium_is_bound()` answers False after a
fence. An export can no longer be approved once the medium is gone either; the
cost of that is recorded in [the quarantine policy](quarantine-policy.md) §4.
`disposition()` still does not: "what is this device" did not change when the
medium was pulled, and "may this happen now" did.

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
