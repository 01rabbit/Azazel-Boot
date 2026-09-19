# ADR-0004: Consume Azazel-Fabric at exactly `v0.8.0`, behind one guarded boundary

Status: **accepted (2026-09-19)** — scope item 5 and acceptance criteria of
[Azazel-Boot #1](https://github.com/01rabbit/Azazel-Boot/issues/1): "Pin the
verified current stable Fabric tag and adopt its guarded projection pattern";
"Fabric uses one verified exact tag; no branch pin, submodule, or copied source."

Related: [Architecture](../architecture.md) · [ADR-0002](0002-image-builder.md) ·
[Release policy](../release-policy.md)

## Context

Azazel-Fabric owns every record that crosses a product boundary, together with
its canonical serialization, digests, validation, and fixtures. The program plan
§2 (line 24) gives consumers exactly one permitted move: "Pin a released tag and
implement adapters." §1 (line 13) adds that the program "does not copy source
trees into Nexus or Boot", and §7 (line 490) that "Development branches or
editable checkouts are allowed in local integration work but cannot satisfy a
release gate."

The R0 baseline is more specific still. Line 46: Fabric "`v0.8.0` is the current
reference candidate because its source package, Edge pin, and Deception pin
agree and a published release exists… No repository may silently float its
Fabric dependency." The R0 exit criteria (line 64) require that "Every consumer
has an explicit immutable Fabric pin or image lock."

Boot had none. This ADR gives it one.

> **D1 superseded by [ADR-0007](0007-repin-fabric-to-v0-9-0rc1.md)
> (2026-09-19).** The pin is now `v0.9.0rc1`, the first tag carrying
> `provisioning_contracts`. D1's *discipline* — an exact tag, no branch, no
> submodule, no copied source — is adopted there unchanged; only the value
> moves. **D2, D3 and D4 stand as written** and are why the re-pin was a
> one-line change. The record below is retained as the reasoning that produced
> that discipline.

## Decision

**D1 — The pin is exactly `v0.8.0`.** `azazel-fabric` is declared as
`azazel-fabric @ git+https://github.com/01rabbit/Azazel-Fabric.git@v0.8.0`. No
branch pin. No submodule. No vendored or copied source. No version range, and no
"or later".

**D2 — It is an optional extra, never a runtime requirement.** The Boot scaffold
is standard-library only. Fabric is installed by an extra; a machine without it
runs Boot with a reduced reported status and nothing else changes.

**D3 — Exactly one module may import it.** `src/azazel_boot/fabric_projection.py`
is the only permitted import site for `azazel_fabric`, and a static test fails
the build on a second one. This mirrors Azazel-Knowledge, whose
`api/contracts.py` documents itself as "the *only* place `azazel_fabric` is
imported" ([ADR-0010](https://github.com/01rabbit/Azazel-Knowledge/blob/main/docs/adr/0010-adopt-fabric-cti-contracts.md)).

**D4 — The boundary is guarded, and the guard fails downward.** A missing
`azazel-fabric`, an import that raises, or a contract that does not exist at the
pin must each produce the same class of outcome:

- the reported status degrades and says why;
- **no authority is granted** — not to Boot, not to a caller, not by default.
  Azazel-Edge's deterministic arbiter remains the only decision and enforcement
  authority whether Fabric is present, absent, or broken;
- **the deterministic scaffold does not crash.** An absent optional contract is
  an expected state, not an error path.

A guard that raised, or that fell back to a Boot-local shape of the record,
would violate the acceptance criterion directly. So would one that treated
"Fabric unavailable" as permission to proceed with an unvalidated payload.

**D5 — No Boot-local canonical form, at any point.** If a record Boot needs does
not exist at the pin, Boot reports that it does not exist. It does not define a
placeholder shape, a "temporary" dataclass mirroring the intended fields, or a
local serialization "until Fabric catches up". Those are the forms this decision
exists to prevent, and they are hardest to remove once tests depend on them.

## Evidence

Measured on 2026-09-19 against the local Azazel-Fabric checkout, not inferred:

- `v0.8.0` is the newest tag (`git tag --sort=-v:refname` → `v0.8.0`, `v0.6.0`,
  `v0.5.0`, …), pointing at commit `b2fd983` dated 2026-08-22.
- `src/azazel_fabric/version.py` at that tag reads `__version__ = "0.8.0"`. The
  R0 baseline (line 38) records the corresponding GitHub release as published.
- The three sibling consumers carry the identical pin string
  `azazel-fabric @ git+https://github.com/01rabbit/Azazel-Fabric.git@v0.8.0`:
  Azazel-Edge (`requirements/fabric.txt`), Azazel-Deception (`pyproject.toml`),
  and Azazel-Knowledge (`pyproject.toml`, moved to this tag by its
  [ADR-0016](https://github.com/01rabbit/Azazel-Knowledge/blob/main/docs/adr/0016-fabric-pin-v0-8-0.md)
  on 2026-09-19). Edge's file states the same pin policy in its own words: "an
  exact tagged release, never a branch and never a development commit, for field
  deployment."
- The package at `v0.8.0` contains exactly: `api`, `audit`, `cti_contracts`,
  `deception_contracts`, `deception_integrity`, `engagement_contracts`,
  `notify`, `paths`, `schema`, `testing`, `version`, `view`.
- **There is no `provisioning_contracts` module at `v0.8.0`**, and no
  `mio_contracts` either (`git ls-tree -r v0.8.0` matches neither name).

One correction worth keeping, because it is the failure mode this ADR guards
against: `outcome_contracts` is present in Fabric's working tree and on `main`,
but **not** at `v0.8.0` — it was added in commit `2ccb2e6`, after the tag. A
module observed by listing a checkout is not necessarily a module present at the
pin, and Boot must reason about the pin.

## The absent module is the point

> **Historical (2026-09-19).** This section described the state at `v0.8.0`.
> Fabric's `v0.9.0rc1` carries `provisioning_contracts`, so the guard in D4 now
> reports nothing missing. It is retained because it records *why* the guard
> was built and what it was first tested against — the mechanism did not become
> decorative, it changed what it finds. See
> [ADR-0007](0007-repin-fabric-to-v0-9-0rc1.md).

The program plan §5 R1 (line 183) assigns to `provisioning_contracts` precisely
the records Boot needs: `HardwareInventory`, `ResourceProfile`,
`TopologyProfile`, `ProductManifest`, `AssetManifest`, `ModelManifest`,
`InterfaceAssignment`, `CommissioningRecord`, `ProposedGenerationDescriptor`,
observation-only `ActivationReceipt`, and `CompatibilityManifest`.
[`docs/architecture.md`](../architecture.md) §2.2 lists the same set as Boot's
requirement and records that the module "**does not exist yet**".

R1 has not shipped. So Boot adopts a pin in full knowledge that the module it
most needs is absent from it. That is not a defect in the decision — it is the
current state of the program, and it means the guard in D4 is not a hypothetical
robustness feature written against an imagined future failure. It is exercised
by today's reality: the module is missing right now, and the test for the guard
asserts against that.

A guard tested only against a fabricated absence would be the weaker artifact.
This one has a real one to work with.

## Rationale

**Why an exact tag, rather than a branch or a floating range.** A branch pin
means the artifact that reproduces a given Boot image cannot be named, which
breaks the reproducibility requirement in
[ADR-0002](0002-image-builder.md) before the builder is even chosen, and fails
§5 R8's "no test uses an unpinned mutable artifact" (line 354). A range means the
version tested and the version installed can differ silently.

**Why `v0.8.0` specifically.** Not because it is newest for its own sake, but
because Edge, Deception and Knowledge are all on it, and a series where the
integrator sits on a different Fabric than the components it integrates is a
compatibility fiction. The R0 baseline names it the reference candidate on the
same grounds.

**Why one import site.** Containment has to be structural to be true. "We only
use Fabric at the boundary" is a claim about discipline; a single module plus a
static test that fails the build is a claim about the repository. The second
kind survives contributors, including future ones under time pressure.

**Why the guard fails downward rather than loudly.** Boot runs in a civil
emergency on borrowed hardware. An optional contract library that is not
installed must not be able to stop a responder's machine from starting, and must
equally not be able to become a reason to proceed without validation. Degrading
the reported status is the only outcome that is honest in both directions.

## Consequences

- **Documents that describe the pre-decision state must be revised in the change
  that lands this ADR.** [`docs/architecture.md`](../architecture.md) §2.2 states
  that Boot has "no Fabric pin at all today: no version, no branch, no submodule,
  no copied source", and §5 lists "Which Fabric version Boot will pin" as
  undecided. Both are superseded by D1. `CONTRIBUTING.md`'s contract rule — a
  document altered by a change is revised in the same commit — applies to them.
  This ADR flags them; it does not edit them.
- When Fabric releases `provisioning_contracts` (R1c stable tag, §5 R1 line 190),
  Boot re-pins in a **new ADR** with its own evidence, exactly as Knowledge did
  in its ADR-0016. The trigger is the stable tag plus a conformance result — not
  the module's first appearance on Fabric's `main`.
- Until then, every Boot record that would belong to `provisioning_contracts`
  stays unimplemented and unrepresented. Per D5, no placeholder exists to remove
  later.
- The pin becomes part of what a Boot release attests to. The release record must
  carry it as an exact component version ([release policy](../release-policy.md);
  program plan §4 rule 6, line 97).
- `azazel-fabric` is the only permitted non-stdlib runtime dependency, and only
  as an extra. Adding another is a separate decision with its own record.

## What this ADR does not establish

- That Fabric `v0.8.0` is *correct* or *better* — only that it is the tag the
  rest of the series is on, and the one Boot is pinned to.
- That the guard works. The boundary module and its tests belong to the bootstrap
  change landing alongside this ADR; this record decides the approach and does not
  report a passing result.
- That Boot can validate any provisioning record. It cannot: the module that
  would define them is absent at the pin.
- That features added to Fabric between earlier tags and `v0.8.0` are used here.
  None is. Adopting one is a separate change with its own evidence.
