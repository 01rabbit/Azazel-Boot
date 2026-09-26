# ADR-0002: Image builder — reproducibility is decided, the tool is not

Status: **accepted in part, deferred in part (2026-09-19)**. The properties the
build must have are decided at program level and recorded here. **No build tool
is selected**, and this ADR does not select one.

Scope item 3 of [Azazel-Boot #1](https://github.com/01rabbit/Azazel-Boot/issues/1).

Related: [ADR-0003](0003-immutable-ab-update.md) · [Release policy](../release-policy.md) ·
[Threat model](../threat-model.md) · [Architecture](../architecture.md)

## Context

Azazel-Boot ships as removable media. Something has to produce that media. This
repository contains no selected production builder or release image
definition. An unsigned R11 prototype was constructed for evaluation with a
remaster workflow after a clean live-build attempt stalled; see the
[prototype evidence](../prototype-evidence-boot-runtime-r11.md). This does not
select a builder or implement the production build contract. No physical
medium was opened or written.

The program plan is unusually specific about what the build must *achieve* and
completely silent about what performs it. It contains no build-tool name at all
— not `mkosi`, `debootstrap`, `live-build`, `dracut`, `Buildroot`, `Yocto`,
`Nix`, `osbuild`, or any other. That silence is the substance of this ADR: the
property is settled, the mechanism is not, and pretending otherwise would fix a
supply-chain dependency by accident.

## Decision

### D1 — The reproducibility property is decided (program level, recorded here)

> "two independent builders reproduce the unsigned immutable payload digest from
> pinned toolchain and repository snapshots; signatures attest that subject
> digest separately"
> — program plan §5 R8 deliverables (line 348), repeated verbatim as a release
> eligibility condition in §9.5 (line 565)

Three things follow, and Boot does not get to negotiate them:

1. The reproduced subject is the **unsigned immutable payload**, not the signed
   artifact. Signing is a separate act over a digest that was already
   independently reproduced.
2. The inputs are **pinned toolchain and repository snapshots**. A build that
   resolves a floating dependency at build time cannot satisfy this, whatever
   its output digest happens to be on a given day.
3. **Two independent builders** must agree. One builder producing the same
   digest twice on the same machine is not the claim being made.

Supporting program-level requirements on the same build:

| Requirement | Source |
| --- | --- |
| Reproducible **signed** boot image with **read-only root** and encrypted persistence | §6.7 item 2 (line 468) |
| Signed immutable **A/B** boot image, redundant signed boot metadata, one-shot trial boot | §5 R7 Boot deliverables (line 326); see [ADR-0003](0003-immutable-ab-update.md) |
| Clean-room "Boot media build from released artifacts only"; "no test uses an unpublished branch or unpinned mutable artifact" | §5 R8 (lines 346, 354) |
| Every release records component versions, hashes, signatures, **SBOM references**, profile, hardware inventory, and applied overlay digest | §4 rule 6 (line 97); see [release policy](../release-policy.md) |
| "Nexus base installer and Boot image builder consume the same Fabric provisioning contracts" | §5 R2 (line 206) |
| Initramfs host-storage quarantine established before anything that could touch a disk starts | §5 R7 (line 327); [threat model](../threat-model.md) §3 |

### D2 — The tool is not decided

No candidate is named, evaluated, or preferred in this repository, and none is
named here. Selecting one is a dependency decision and a supply-chain decision
at once, and Boot currently has neither a dependency manifest nor a release
policy with a signing story (see [release policy](../release-policy.md)).
Choosing now would mean choosing on familiarity.

### D3 — Criteria a candidate must meet

These are derived from D1's sources. A candidate that fails any of them is not
a candidate; meeting all of them qualifies it for evaluation, not for
selection.

- **C1 — Bit-identical unsigned payload.** Two builders on independent
  infrastructure produce the same payload digest from the same pinned inputs.
  Demonstrated, not claimed by the tool's documentation.
- **C2 — Pins are inputs, and unpinned inputs are refused.** The toolchain and
  every repository snapshot are named by digest or immutable tag. A build that
  can silently resolve something mutable fails C1 eventually and fails it
  invisibly.
- **C3 — Signing is not part of the build.** The builder emits an unsigned
  payload and its digest. A tool that can only produce an already-signed
  artifact cannot express the program's separation between reproduction and
  attestation.
- **C4 — Immutable read-only root, installable to a slot.** The output is a
  whole-payload artifact whose full digest can be verified before a slot is
  selected ([ADR-0003](0003-immutable-ab-update.md)).
- **C5 — Deterministic control of the initramfs.** The host-storage quarantine
  must be the first thing the initramfs does and must survive into userspace
  ([threat model](../threat-model.md) §3.1). A builder that generates the
  initramfs from host state, from an opaque vendor hook, or from an ordering
  Boot cannot pin, cannot deliver the product's defining safety property. This
  criterion is the one most likely to eliminate an otherwise attractive tool.
- **C6 — SBOM and provenance emission.** The build emits an SBOM for the payload
  and the inputs needed for a provenance attestation, covering every released
  component embedded in the image.
- **C7 — No host-specific values.** Nothing about a particular laptop — an
  interface name, an address, a disk path — may be baked into the image.
  Interface roles come from per-host commissioning
  ([architecture](../architecture.md) §4), and an inherited fixed value would be
  a guess presented as a fact.
- **C8 — Offline, clean-room buildable.** The build runs from released artifacts
  only, without network access to anything unpinned (§5 R8, lines 346 and 354).
- **C9 — Consumes Fabric provisioning contracts.** Per §5 R2 (line 206), once
  those contracts exist. They do not exist at Boot's Fabric pin; see
  [ADR-0004](0004-exact-tag-fabric-consumption.md).

### D4 — What would settle it

Selection happens in a new ADR when **all** of the following hold:

1. a candidate has been evaluated against C1–C9 with a recorded result, including
   an **actual** two-builder reproduction of one payload digest — not a citation
   of the tool's reproducibility claims;
2. the Fabric provisioning contract candidate exists, which is the
   synchronization gate the program plan §7 (line 488) places on the Deployment
   lane that owns the image builder;
3. the dependency and supply-chain consequences of the tool itself are recorded,
   because the builder becomes part of what a Boot release attests to.

Until then the correct state of this question is "open", and an image-building
PR that arrives without a selection ADR is rejected on that ground.

## Rationale

The program fixed the property rather than the tool for a reason worth
preserving. The reproducibility requirement is what lets an independent party
disbelieve the builder and check anyway — the thing a civil responder's trust
ultimately rests on is not that we are honest but that dishonesty would be
detectable. A tool choice is replaceable; that property is not.

Recording a tool now would also invert the evidence order this repository is
built around. Every criterion above is a measurement or an artifact. None can be
produced by reasoning about a tool's documentation, and a tool adopted before
C1 and C5 were demonstrated would have to be un-adopted later, after image
definitions had accumulated around it.

## Consequences

- Boot cannot produce media, and will not be able to until a builder is selected
  and a signing story exists. Both are prerequisites for any release
  ([release policy](../release-policy.md)).
- C5 constrains the selection more than build-system preference does. A tool is
  disqualified by its initramfs behavior regardless of how well it does
  everything else.
- The reproducibility claim belongs to the payload, so the release record must
  carry the unsigned payload digest separately from the signed artifact digest.
  `docs/compatibility.md` §3.3 already requires both in a qualified entry, which
  is consistent with this and is the only place the distinction currently
  appears.
- The provisioning-contract gate (C9, D4.2) means the builder question cannot be
  fully closed before Fabric's R1 ships, even if a tool were otherwise ready.

## What this ADR does not establish

- That any tool is suitable. None has been evaluated.
- That a reproducible build of this image is achievable at all. No one has tried.
- That the program's reproducibility requirement has been met, or partially met,
  by anything in this repository. Nothing here builds anything.
- That signing exists. There is no key, no role, and no signed artifact
  ([release policy](../release-policy.md)).
