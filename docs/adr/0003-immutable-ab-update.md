# ADR-0003: Immutable A/B update direction

Status: **recorded as decided at program level (2026-09-19)**. This ADR does not
choose the direction — the program plan already did. It records that decision,
states what it costs Boot, and is explicit that Boot has built none of it.

Scope item 3 of [Azazel-Boot #1](https://github.com/01rabbit/Azazel-Boot/issues/1).

Related: [ADR-0002](0002-image-builder.md) · [Threat model](../threat-model.md) ·
[Architecture](../architecture.md) · [Release policy](../release-policy.md)

## Context

An emergency environment on removable media has to be updatable, and an update
is the most dangerous routine operation such a product performs: it rewrites the
thing that boots, usually on a machine nobody is watching, often on battery.

This is not an open question for Boot. The program plan decided it, in two
places, in operative detail. Boot's job is to inherit it correctly rather than
to re-derive it.

## Decision

### D1 — The direction, as decided

> "signed immutable A/B boot image, read-only root, redundant signed boot
> metadata, one-shot trial boot, encrypted USB persistence with dirty-shutdown
> recovery, and an explicit no-host-storage-write rule"
> — program plan §5 R7, Boot deliverables (line 326)

> "Build a reproducible signed boot image with read-only root and encrypted
> persistence; use firmware verification where the supported hardware permits
> and provide a documented portable passphrase/recovery path when platform
> ownership is unavailable. **Install updates to the inactive slot, verify the
> full digest before selection, promote only after a health-confirmed trial
> boot, and automatically fall back on failure.** Persistence migrations are
> backward compatible or require a verified pre-trial snapshot and restore path."
> — program plan §6.7 item 2 (line 468), emphasis added

§6.7 item 9 (line 475) lists "immutable A/B slots" among the properties Boot
must enforce, and §12's cross-product table (line 626) records Boot's
update/recovery unit as "image/persistence" — the image and the persistence are
updated and recovered as separate things.

The mechanism, stated as obligations:

1. An update is written to the **inactive** slot. The running slot is never
   modified in place; "immutable" is what makes fallback possible at all.
2. The **full digest** of the installed payload is verified **before** that slot
   is selected. Not a manifest signature alone, and not a per-file check
   deferred to first use.
3. Selection is a **one-shot trial boot**. It is consumed by the attempt, so a
   machine that never completes the trial does not loop into it.
4. Promotion happens only after the trial boot is **health-confirmed**.
5. Failure **falls back automatically**, without an operator who may be a
   non-technical responder in the field having to diagnose anything.
6. The root filesystem is **read-only**, so the only writable state is the
   encrypted persistence created on first use outside the reproducible base
   image (§4.5, line 156).
7. Boot metadata is **signed and redundant** — there are at least two copies,
   and a torn write to one does not lose the ability to boot.

### D2 — The failure and power-loss obligations that come with it

> "a failed update returns to the prior verified generation without losing the
> last valid audit checkpoint" — §5 R7 exit gate (line 334)

> "power interruption after every inactive-slot, boot-metadata, checkpoint, and
> persistence-migration write leaves one verified bootable generation and the
> last valid audit checkpoint recoverable; a failed trial restores any required
> persistence snapshot" — §5 R7 exit gate (line 339)

The second is the harder requirement and the one that constrains the design:
the invariant must hold after a power cut at *every* write point, which means
write ordering and sync boundaries are part of the contract, not an
implementation detail. The program plan states the ordering for enforcement
state as "prepare + fsync -> apply -> verify -> persist receipt" (§4.3, line
138), and the [threat model](../threat-model.md) §4 already applies the same
shape to persistence.

### D3 — What A/B does *not* do

A/B slots, trial boots, and rollback are **integrity and availability**
mechanisms. They are not authority mechanisms and they do not interact with
authority at all.

- A successful promotion grants nothing. Azazel-Edge's deterministic arbiter is
  the only decision and enforcement authority in every capability state, on both
  slots, during the trial, and after a fallback.
- A fallback is not a degraded-authority mode. It may reduce capability; it
  changes authority by exactly zero.
- "Software rollback never restores obsolete trust state, policy, or hardware
  bindings" (§4.2, line 132). Falling back to a previous image must not resurrect
  a revoked key, an old security epoch, or a previous host's commissioning.
- Anti-rollback is not version comparison. Admission requires "an exact tested
  compatibility tuple, the correct signer role, and a minimum security epoch"
  ([threat model](../threat-model.md) §2.1), and a correctly signed but obsolete
  artifact is rejected (§4.1, line 112).

### D4 — What is *not* decided

None of the following is fixed by the program plan, and none is fixed here:

| Open | Waiting on |
| --- | --- |
| Slot layout on the media, number of retained generations, and how a slot is addressed | The image builder selection ([ADR-0002](0002-image-builder.md)); layout is a builder output before it is an updater input |
| Boot metadata format, how the two copies are placed, and how a torn write is detected | Same, plus the signing story ([release policy](../release-policy.md)) |
| Digest and signature algorithms, and the envelope a signature is carried in | [Release policy](../release-policy.md); currently open everywhere in the program |
| ~~**What "health-confirmed" measures**~~ | **Decided** by [ADR-0006](0006-trial-boot-health-confirmation.md) (2026-09-19). Six signals, ambiguity fails toward fallback |
| ~~Trial-boot timeout and how many failed attempts precede a permanent fallback~~ | **Decided** by [ADR-0006](0006-trial-boot-health-confirmation.md): a 300-second window and one attempt. Both are values, not principles, and are the first things to revisit against real hardware |
| Persistence migration snapshot format and restore path | The persistence design, which does not exist |

## Rationale

The rationale for the direction belongs to the program plan, not to this ADR.
What is worth recording is why Boot inherits it without adjustment.

Boot runs on borrowed hardware, in an emergency, operated by someone who may not
be technical, with no guarantee of a second machine or a network. Every
alternative to A/B — in-place update, package-level update, a writable root that
accumulates state — shares one property: a failure leaves a machine that needs
an expert and a working network to fix. That is exactly the situation Boot
exists to be usable in, so the failure mode is not acceptable at any frequency.

Read-only root is the same argument from the other direction. If the root cannot
be written, the update path cannot be a slow drift, a partial upgrade cannot
exist, and the reproducibility claim in [ADR-0002](0002-image-builder.md) stays
meaningful after deployment rather than only at build time.

## Consequences

- **Boot has built none of this.** There is no image, no slot, no boot metadata,
  no updater, no trial-boot health check, no fallback path, no persistence, and
  no test for any of it. This ADR is target contract in the
  [handoff §7](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
  sense, and citing it as evidence that Boot updates safely would be false.
- The image builder must produce a slot-installable immutable payload whose full
  digest is verifiable before selection — recorded as criterion C4 in
  [ADR-0002](0002-image-builder.md).
- Read-only root makes encrypted persistence the only writable state, which
  concentrates every tampering, rollback, and dirty-shutdown concern there. The
  [threat model](../threat-model.md) §5 already treats it that way.
- The power-loss obligation (D2) reaches the audit chain, not just the image: the
  last valid audit checkpoint must survive a cut at every write point. Checkpoint
  design and update design cannot be sequenced independently.
- "Health-confirmed" (D4) was a decision someone had to make before an updater
  could be written, and it must not be settled silently inside an
  implementation PR. It was not: [ADR-0006](0006-trial-boot-health-confirmation.md)
  makes it, in the open, with its own reasoning about why the two failure modes
  are not symmetric.

## What this ADR does not establish

- That Boot can update, roll back, or survive a power cut. Nothing has been
  implemented and nothing has been tested.
- That the R7 exit-gate conditions in D2 are met, or that they have been
  attempted.
- That the remaining mechanism details in D4 have a preferred answer. They are
  open. The two health-related rows are no longer among them — see
  [ADR-0006](0006-trial-boot-health-confirmation.md).
- That an A/B design alone preserves the host laptop. The no-host-storage-write
  property is a separate mechanism — the initramfs quarantine
  ([threat model](../threat-model.md) §3) — and A/B neither provides nor
  protects it.
