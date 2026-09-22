# ADR-0010: Persistence key handling, dirty-write detection, and migration

Status: **accepted (2026-09-22). D1–D5 implemented in software and
hardware-unverified; D6–D10 not implemented.** The owner decided D1–D10 below.
`azazel_boot.session_mode` implements D1, D2 and D3 — see
[session mode](../session-mode.md) — and `azazel_boot.dirty_write` with
`azazel_boot.persistence` implements D4 and D5, see
[persistence](../persistence.md) §4.1. All of it on no hardware: no passphrase
has been attempted, no volume opened, and no USB SSD pulled mid-write on any
device.
[#7](https://github.com/01rabbit/Azazel-Boot/issues/7) stays open, and so do
the three children this record names.

Related: [ADR-0008 D4.1 / D4.1.1](0008-debian-13-live-baseline.md) ·
[ADR-0003 D4](0003-immutable-ab-update.md) ·
[Threat model](../threat-model.md) §4–§5 ·
[Quarantine policy](../quarantine-policy.md) §4 ·
[Persistence](../persistence.md) · [Recovery](../recovery.md) ·
[Session mode](../session-mode.md) — D1–D3 as implemented ·
[ADR-0011](0011-unlock-helper-boundary.md) — where the passphrase is typed

## Context

[ADR-0008](0008-debian-13-live-baseline.md) D4.1.1 fixed what persistence is
**bound to** — a hardware-provided media identity, the device identity, the
LUKS2 volume UUID, the signed image digest and the commissioning generation,
under a key-protected HMAC. It did not decide what opens the volume, what
happens when nothing can, how a write interrupted by a removal is detected, or
how a format change is migrated.

Those four are what #7's acceptance criteria still lack, and they interact, so
deciding one at a time would decide the others by accident.

**No key material, passphrase, endpoint, device identity or snapshot content
appears in this record, in any issue, in any pull request, in any fixture, on a
terminal, in a journal or in an audit** (D10). The decisions are about shapes
and failure modes; the values are not this document's business.

## D1 — No key, no persistence. No emergency exception.

When no key or passphrase can be obtained safely, Boot **never opens
persistence**, never creates one, and continues in an **ephemeral** session:
RAM only, `CORE` capability, nothing retained across a reboot.

**There is no emergency exception for an unprotected volume.** An operator
cannot accept one, a policy cannot name one, and no state permits one. This was
considered — [threat model](../threat-model.md) §5 already contemplates an
explicit operator acceptance for *audit assurance* (`LOCAL_CONTINUITY_ONLY`) —
and it is refused for encryption at rest, because the medium travels through
uncontrolled hands and §2.1's mitigation for theft is that it "must not yield
plaintext evidence". A fallback volume breaks exactly that, under exactly the
time pressure that makes it tempting.

Three sources may supply a key, in a fixed order, and **none is required**:

| Source | When it is available |
| --- | --- |
| Platform-sealed key material | Only in `VERIFIED_FIRMWARE`. Sealed to a platform Boot does not own, so on a borrowed laptop it is **absent by definition**. |
| An operator-carried passphrase | The ordinary case. The program plan requires a documented, portable one. |
| A recovery credential | Held separately from the field passphrase, for when that is lost. |

The order is fixed so that *which one opened it* is recorded rather than
inferred, and so a platform-sealed open on one laptop does not become an
expectation on the next. The recovery credential **may not sign ordinary field
checkpoints and may not hide a discontinuity** — [threat
model](../threat-model.md) §5 already requires this.

**The cost, stated rather than discovered:** a responder who cannot supply the
passphrase loses everything gathered in that session at reboot. The mitigation
is the documented portable passphrase, not a softer failure mode.

## D2 — Five attempts per boot, then sealed for that boot

A passphrase may be attempted at most **five times in the current boot**. After
the fifth failure persistence is **sealed for that boot** and the session is
**fixed in ephemeral mode**. There is no sixth attempt, no unlock later in the
same boot, and no operator override.

**The attempt count, the passphrase and any user identifier never reach a
journal, an audit entry or a screen.** The screen says persistence is sealed
for this boot; it does not say how many attempts were made or remain, because a
counter on a screen is a counter in a photograph of a screen.

**Rebooting permits a fresh five attempts, and this is not claimed as
brute-force resistance.** It is not one: an attacker with the medium and time
reboots as often as they like. What the limit buys is that a *running* session
cannot be ground down in place while an operator is elsewhere, and that a
mistyped passphrase degrades to ephemeral rather than quarantining the volume —
a mistyped passphrase and an attack are indistinguishable here, and treating
them the same way is the point. Resistance to offline attack is a property of
the key derivation, which this record does not decide.

## D3 — The session mode is decided once, at commissioning

A session that starts **ephemeral stays ephemeral**. It cannot open persistence
later, even if the operator finds the passphrase five minutes afterwards. The
mode is decided **once, during commissioning**, and changing it requires a
reboot.

Why: opening mid-session means checking a binding against a machine whose state
has already moved — the medium's identity, the commissioning generation and the
session's own record of what it has done are no longer the ones the decision
was made against. It also removes a whole class of question ("is this session
persistent right now?") that every later decision would otherwise have to ask.

The operator is told at commissioning which mode this sitting is in, in the
vocabulary [`confirmation.py`](../../src/azazel_boot/confirmation.py) enforces
— no "safe", no "protected", and no implication that ephemeral is equivalent.

## D4 — A suspected dirty write quarantines the whole volume, fail-closed

On surprise removal, or on any suspicion of a torn write, Boot **does not
repair**. The **entire volume** enters a fail-closed quarantine: ordinary read,
write and export are refused.

Detection **records a classification and nothing else** — which condition was
observed, from a fixed vocabulary. It does not record what was being written,
which record was in flight, or any content. The classification is the whole of
the audit payload.

[Threat model](../threat-model.md) §4 already fixes the write order —
*prepare-and-sync, apply, verify, persist receipt*, with a prepare or sync
failure producing zero changes — so a missing receipt is the signal. What this
decides is what happens next: quarantine, not repair, not partial use.

Leaving quarantine is possible **only** through the explicit recovery workflow
in D8.

## D5 — No record-level continuation, and nothing is called erased

Records written before the suspected fault are **not used in ordinary
operation**. There is no per-record salvage, no "the earlier ones are fine",
and no partial mount.

**This is not a claim that anything was erased.** The data is on the medium.
Boot refuses to use it in ordinary operation and says so in those words; it
does not say the volume was wiped, cleared or destroyed, because it was not.
The distinction matters for what an operator may later tell someone about what
happened to the evidence.

Whether a quarantined volume can be examined offline elsewhere is outside this
record: [quarantine policy](../quarantine-policy.md) already offers export of a
quarantined volume **unmodified** for offline examination, and that path is
unchanged.

## D6 — The migration snapshot lives inside the existing partition

**No second partition.** The snapshot is a **side-by-side snapshot inside the
single existing encrypted persistence partition**: encrypted with the volume,
versioned, and integrity-verifiable on its own.

This replaces the proposal's earlier second-volume shape, and the reason is
that a second partition would require revising
[ADR-0008](0008-debian-13-live-baseline.md) D4.1's fixed three-partition layout
— which exists so that "what can assemble something on this medium" stays
enumerable. Keeping the snapshot inside the partition leaves D4.1 untouched.

"Versioned" and "integrity-verifiable on its own" are both load-bearing: a
snapshot that cannot be told apart from the live data, or whose integrity can
only be judged by the thing it exists to restore, is not a snapshot.

## D7 — Preflight, and no migration without a snapshot

Before a migration runs, a preflight checks:

1. the space the snapshot requires,
2. the space actually available inside the partition,
3. the integrity of what is being snapshotted,
4. schema compatibility between the current and target formats.

Any of the four failing **refuses the migration and keeps the old schema**. The
old schema continuing to work is the safe outcome, not a degraded one.

**Migration without a snapshot is not permitted**, under any acceptance, by any
operator, in any state. An operator cannot consent to it, because the thing
they would be consenting to is the loss of the only path back.

## D8 — Recovery is explicit, never automatic

A failed trial is **never** restored automatically. Restoring happens only
through a recovery workflow the operator starts explicitly, and that workflow
passes, in order:

1. **target binding** — the media binding of
   [ADR-0008 D4.1.1](0008-debian-13-live-baseline.md), unchanged;
2. **key acquisition** — D1's sources, in D1's order, under D2's limit;
3. **integrity verification** of the snapshot being restored;
4. **operator confirmation** of what is being restored and over what.

Automatic restore was rejected because it means writing during a failure —
the moment the state is least understood — and because
[ADR-0003](0003-immutable-ab-update.md)'s automatic fallback is about the
*image*, which is signed, reproducible and replaceable. Persistence is none of
those: it is the only copy of what a responder gathered.

A recovery **may not** raise a capability, clear a fence, or re-open a session
that required a reboot.

## D9 — Nothing goes to the host's disk, and no version upgrade is a way round the fence

**No migration, export or snapshot targets host storage.** Not a temporary
file, not a staging directory, not a "just while the migration runs" copy.

And explicitly: **the fence that follows a medium's removal is not bypassed
under the name of a version upgrade.** [Quarantine policy](../quarantine-policy.md)
§4 refuses an export approval after a fence and does not spare host-disk
exports; a migration path that wrote to the host would reintroduce exactly that
write, with the operator's attention on an upgrade rather than on a host write.
Overturning this needs a new ADR that says so in those words.

## D10 — What never appears anywhere

Raw keys, passphrases, raw device identities and snapshot contents do not
appear in this ADR, an issue, a pull request, a fixture, a terminal, a journal
or an audit entry.

The audit may hold the classification of what happened and nothing more: which
condition was detected, which transition occurred, which refusal fired. An
audit is a place for traceability, not a guarantee of confidentiality, and
these values are not traceability.

## Consequences

- A responder with no passphrase gets an ephemeral session and is told so;
  evidence from it does not survive a reboot. There is no way to accept an
  unprotected volume instead.
- A fifth failed passphrase seals persistence for that boot. Rebooting gives
  five more, and that is not a brute-force defence.
- "Am I persistent?" is answered once per boot and never changes.
- A suspected torn write costs the whole volume in ordinary operation, and
  nothing is described as erased.
- [ADR-0008](0008-debian-13-live-baseline.md) D4.1 is **not** revised: the
  snapshot lives inside the existing partition.
- A medium too small for a snapshot refuses the migration and keeps working on
  the old schema.
- Restoring is something an operator does deliberately, through four gates.

## What this record does not decide

- Any concrete key-derivation function, parameter set, slot layout or
  credential format. Those follow these decisions rather than the reverse, and
  offline-attack resistance is a property of that choice, not of D2.
- The snapshot's on-disk container format, versioning scheme or integrity
  construction. D6 fixes the requirements; the construction is the third
  child's design work.
- Anything requiring hardware. D4 in particular cannot be called demonstrated
  without the hardware-in-the-loop record [threat model](../threat-model.md)
  §3.3 requires, which does not exist.

## What this record does not establish

**No volume has been created, opened, sealed, torn, quarantined, snapshotted,
migrated or restored on any device. No passphrase has been attempted, and no
medium has been pulled mid-write.** D1–D3 exist as decision logic in
`azazel_boot.session_mode`, and D4–D5 in `azazel_boot.dirty_write` and
`azazel_boot.persistence`. Both open nothing and read nothing: they decide what
an outcome reported by something else means. D6–D10 are decisions with no code
behind them at all. #7 and its three
children stay open, and every one of them carries `hardware-unverified` until a
real USB SSD and a real laptop say otherwise.
