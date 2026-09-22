# ADR-0010: Persistence key handling, dirty-write detection, and migration

Status: **proposed — decisions required, nothing implemented.** This record
exists to put four open questions in front of the owner with the options
narrowed and the consequences stated. Nothing in
[#7](https://github.com/01rabbit/Azazel-Boot/issues/7) is implemented against
it, and #7 stays open.

Related: [ADR-0008 D4.1 / D4.1.1](0008-debian-13-live-baseline.md) ·
[ADR-0003 D4](0003-immutable-ab-update.md) ·
[Threat model](../threat-model.md) §4–§5 ·
[Quarantine policy](../quarantine-policy.md) §4 ·
[Persistence](../persistence.md)

## Context

[ADR-0008](0008-debian-13-live-baseline.md) D4.1.1 fixed what persistence is
**bound to** — a hardware-provided media identity, the device identity, the
LUKS2 volume UUID, the signed image digest and the commissioning generation,
under a key-protected HMAC. It did not decide what opens the volume, what
happens when nothing can, how a write interrupted by a removal is detected, or
how a persistence format change is migrated.

Those four are what #7's acceptance criteria still lack, and three of them
interact, so deciding one at a time would be deciding the others by accident.

**No key material, passphrase, endpoint or device identity appears in this
record, in any issue, in any fixture or in any log.** The decisions below are
about shapes and failure modes; the values are not this document's business.

## D1 — What opens the LUKS2 volume

### D1.1 (proposed) — Three sources, in a fixed order, and none is required

| Source | When it is available |
| --- | --- |
| Platform-sealed key material | Only in `VERIFIED_FIRMWARE`. It is sealed to a platform Boot does not own, so on a borrowed laptop it is **absent by definition**. |
| An operator-carried passphrase | Whenever the operator has it. This is the ordinary case and the program plan already requires a *documented, portable* one. |
| A recovery credential | Held separately from the field passphrase, used when the passphrase is lost. |

The order is fixed so that "which one opened it" is recorded rather than
inferred, and so that a platform-sealed open on one laptop does not become an
expectation on the next.

**The recovery credential may not sign ordinary field checkpoints and may not
hide a discontinuity** — [threat model](../threat-model.md) §5 already requires
this, and it is restated here because a recovery path that could sign normally
would make the split pointless.

### D1.2 (proposed, and the one to argue about) — No key means no persistence, and the session runs ephemeral

**The base proposal the owner asked to be evaluated.** When none of the three
sources yields a key, Boot does **not** open persistence, does **not** create
one, and continues in an **ephemeral** session: RAM only, `CORE` capability, no
evidence retained across a reboot.

Why this is the right default:

- It is the same shape as every other refusal in this codebase.
  `UnidentifiedHost` removed the empty fingerprint rather than letting it match
  everything; the media binding refuses rather than opening on an unknown
  medium. "Could not establish X, so proceed without X's protection" is the
  failure mode all of them exist to prevent.
- The alternative — creating a fresh unencrypted or weakly-keyed volume so the
  responder has *somewhere* to write — puts evidence on a USB SSD that travels
  through uncontrolled hands with nothing protecting it. [Threat
  model](../threat-model.md) §2.1 names media theft as a threat whose mitigation
  is that theft "must not yield plaintext evidence". A fallback volume breaks
  exactly that.
- Ephemeral is a real degradation and not a disabled product: Edge's arbiter is
  unaffected, observation still works, and the operator is told what they lose.

What it costs, stated rather than discovered: **a responder who forgets the
passphrase loses everything gathered in that session at reboot.** That is a
real operational loss in a civil emergency, and the mitigation is the
documented portable passphrase, not a softer failure mode.

**The screen must say this before the session starts**, in the vocabulary
[`confirmation.py`](../../src/azazel_boot/confirmation.py) already enforces —
no "safe", no "protected", and no implication that ephemeral is equivalent.

### What is open for D1

1. **Is D1.2 accepted as written?** The alternative is a named emergency policy
   under which an operator explicitly accepts an unprotected volume, which
   [threat model](../threat-model.md) §5 already contemplates for audit
   assurance (`LOCAL_CONTINUITY_ONLY`) but not for encryption at rest.
2. **Is a passphrase attempt limit wanted, and what does exhausting it do?**
   Ephemeral, or refuse to continue at all. A limit that quarantines the volume
   would make a mistyped passphrase indistinguishable from an attack.
3. **May a session that started ephemeral later open persistence** if the
   operator finds the passphrase? Opening mid-session means the volume's binding
   is checked against a machine whose state has already moved.

## D2 — Detecting a write interrupted by removal

Today's fence refuses **new** actions
([quarantine policy](../quarantine-policy.md) §4). It says nothing about a
write that was in flight, which is the half of #7's criterion that is unmet.

### D2.1 (proposed) — The receipt is the evidence, and its absence is the detection

[Threat model](../threat-model.md) §4 already fixes the operation order:
*prepare-and-sync, apply, verify, persist receipt*, with a prepare or sync
failure producing zero changes. The proposal is to make the **receipt** the
thing that is read on the next open:

- every write records a receipt as its last step;
- on open, a record whose receipt is missing is a write that did not complete;
- an incomplete write is **reported and not repaired** — the same rule
  `UNRECOVERABLE_DIRTY_VOLUME` and `REPAIR_NOT_REVERIFIED` already follow.

This detects; it does not recover. Recovery of a partial write is a filesystem
and journalling question that hardware evidence has to inform, and claiming it
here would be claiming something untested.

### What is open for D2

1. **Is "detected and reported, never repaired" sufficient for #7's criterion**,
   or is recovery of the last record required?
2. **Does an incomplete write quarantine the whole volume, or only that
   record?** Quarantining everything on one torn write costs a responder every
   earlier record; quarantining one record leaves a volume whose contents are
   partly unverified.

## D3 — Migration snapshot format and restore path

[ADR-0003](0003-immutable-ab-update.md) D4 lists this as open, waiting on "the
persistence design, which does not exist". Part of it exists now.

### D3.1 (proposed) — The snapshot is a second encrypted volume on the same medium, and nowhere else

- **Format**: the same LUKS2 shape [ADR-0008](0008-debian-13-live-baseline.md)
  D4.1 fixes — a filesystem formatted directly on an encrypted partition, no
  volume manager. A snapshot in a different shape would be a second storage
  format to review.
- **Location**: the **same removable medium**. Not the host's disk, not a
  network target, not a second medium.
- **Authority to restore**: the same gates a normal open passes — the media
  binding, the quarantine's disposition, the fence, and the session binding. A
  restore is an open, not an exception to one.
- **What a restore may not do**: raise a capability, clear a fence, or
  re-open a session that required a reboot.

**Why not the host disk.** [Quarantine policy](../quarantine-policy.md) §4
refuses an export approval after a fence, and the owner's decision was that
host-disk exports are not spared. A migration path that wrote a snapshot to the
host's storage would reintroduce exactly the write that decision closed — with
the operator's attention on a version upgrade rather than on a host write. So
this record proposes no such path, and none should be proposed later without
overturning that decision explicitly.

### What is open for D3

1. **Does a snapshot fit?** A second encrypted partition of comparable size
   roughly doubles the persistence footprint on the medium, and
   [ADR-0008](0008-debian-13-live-baseline.md) D4.1's layout has exactly one
   persistence partition. Adding a second is a D4.1 revision.
2. **What happens when it does not fit?** Refuse the migration and keep the old
   format, or migrate without a snapshot under an explicit operator acceptance.
   The first is consistent with everything else here.
3. **Is a failed trial's restore automatic or operator-initiated?** Automatic
   restore is what [ADR-0003](0003-immutable-ab-update.md) does for the image;
   for persistence it means writing during a failure, which is when the state is
   least understood.

## D4 — What this record does not decide

- Any concrete key-derivation function, parameter set, slot layout or
  credential format. Those follow the decisions above, not the other way round.
- Anything about `azazel_boot.persistence`'s code. **Nothing is implemented
  against this record**, and #7 stays open until D1–D3 are decided and built.
- Anything requiring hardware. D2 in particular cannot be called demonstrated
  without the hardware-in-the-loop record [threat model](../threat-model.md)
  §3.3 requires, which does not exist.

## Consequences if accepted as proposed

- A responder with no passphrase gets an ephemeral session and is told so.
  Evidence from that session does not survive a reboot.
- A torn write is visible at the next open and is never repaired into use.
- A migration keeps its snapshot on the medium it came from, and a medium too
  small to hold one refuses the migration rather than proceeding without it.
- [ADR-0008](0008-debian-13-live-baseline.md) D4.1 needs a revision for the
  snapshot partition, and that revision is part of accepting D3.

## What this record does not establish

Nothing here has been implemented, and nothing has run on hardware. No volume
has been created, opened, torn or migrated on any device. The proposals are
shapes and failure modes; a decision on them is what turns them into work.
