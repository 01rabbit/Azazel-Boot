# ADR-0009: The builder and writer contract, and how the builder selection gets settled

Status: **accepted (2026-09-22)**, **revised (2026-09-22)** — D2 now separates
the artifact record from the manifests it references, at the owner's decision,
after an adversarial review showed that a record carrying structured documents
cannot be fingerprinted safely. Fixes the operator surface, the artifact
record, the build-host profile, the privilege boundary and the writer safety
model for a builder that does not exist. **No build tool is selected** —
[ADR-0002](0002-image-builder.md) D2, D3 and D4 stand unchanged. Nothing is
built, nothing is written, and no medium exists.

Opens the B0 step of the builder/writer program. Related:
[ADR-0002](0002-image-builder.md) · [ADR-0005](0005-uefi-secure-boot-posture.md) ·
[ADR-0008](0008-debian-13-live-baseline.md) ·
[Builder and writer contract](../builder-writer-contract.md) ·
[Threat model](../threat-model.md) · [Release policy](../release-policy.md)

## Context

The owner set a builder/writer program on 2026-09-22: an image builder and a
media writer for the Debian 13 Live USB SSD medium, drivable from a Linux or a
macOS console, in phases B0 (this contract) through B5 (hardware compatibility).

[ADR-0002](0002-image-builder.md) D4 closes with a rule that has to be honoured
before anything else in that program can start: "an image-building PR that
arrives without a selection ADR is rejected on that ground." Two readings of
that rule are possible, and they lead to opposite places.

The wrong reading is that nothing about the builder may be written down until a
tool is chosen. Under it, the tool would be chosen first and the contract
written around whatever the tool made easy — which is the inversion of evidence
order that [ADR-0002](0002-image-builder.md)'s rationale exists to prevent.

The right reading is narrower and is the one taken here. C1–C9 are all about
what a tool does with inputs and what it emits. Not one of them says how an
operator invokes a build, what a build records about itself, which process may
open a block device, or what a writer must refuse. Those questions are
answerable now, they **constrain** the selection rather than pre-empt it, and
answering them first is what gives the eventual C1–C9 evaluation a fixed target.

## Decision

### D1 — Seven verbs, and `build` and `write` are never one verb

`doctor`, `prepare-host`, `build`, `verify`, `list-media`, `write`, `inspect`.
No mode turns one verb into another: no `--write` on `build`, no `--build` on
`write`, no combined verb, and no configuration where one implies the other.
`prepare-host` is limited to the isolated build-host preparation boundary and
cannot select an image source or build an artifact. The two destructive domains
are separated by an artifact, not by a flag, so that the confirmation that
authorises a destructive act is adjacent to the act, and so that re-verifying
an artifact before writing it is the only path rather than the diligent one.

Details in [the contract](../builder-writer-contract.md) §2.

### D2 — The record holds scalars; the manifests are referenced sidecars

*Revised 2026-09-22. The first version of this section listed eighteen fields,
three of which — `package_manifest`, `firmware_manifest`, `sbom` — were described
in words that read like collections ("every package…", "every firmware blob…").
An adversarial review of the verification path showed what that costs: a
fingerprint over a record containing arbitrary nested documents is a
canonicalisation hazard, and a binding that cannot be computed identically twice
is not a binding. The owner decided the separation below rather than let the
record's shape be settled by an implementation's type constraint.*

**The artifact record contains JSON scalars only** — a string, an integer, or
absent. The structured package manifest, firmware manifest and SBOM are **not
embedded in it**. They are separate files inside the signed artifact, and the
record carries, for each:

| Field | What it holds |
| --- | --- |
| `package_manifest_ref` / `package_manifest_digest` | where the manifest is, and a digest binding its contents |
| `firmware_manifest_ref` / `firmware_manifest_digest` | the same, for firmware |
| `sbom_ref` / `sbom_digest` | the same, for the SBOM |

A `*_ref` is a **normalised relative reference inside the artifact**. An
arbitrary URL, an absolute path and a parent traversal are refused: a reference
that can leave the artifact turns a record into an instruction to fetch
something, which is the opposite of what a record is for.

The binding is two-layer and each layer does one job. A `*_digest` binds the
contents of its sidecar, so a manifest that changed is detectable against the
record. The signed artifact digest binds the record **and** the set of
sidecars, so a sidecar that was added, removed or swapped is detectable against
the signature.

This changes the wording of the claim these fields make. It was "every package,
every firmware blob and the SBOM are in the record". It is now:

> **every included item is represented by a verified, referenced manifest or
> SBOM.**

That is a weaker statement about the record and the same statement about the
artifact, which is the honest pair.

Unchanged from the original D2: *image digest* is carried as
`unsigned_payload_digest` and `signed_artifact_digest`, because
[ADR-0002](0002-image-builder.md) D1.1 makes the reproduced subject the unsigned
payload and signing a separate act over it; a single field would be ambiguous
precisely where the distinction matters, and
[`docs/compatibility.md`](../compatibility.md) §3.3 already requires both.
`compatibility_claim` takes `candidate` or `hardware_verified` and nothing else,
and a successful build never moves it.

### D3 — The build host is Debian 13 / amd64, and the build is isolated

v1 builds on Debian 13 / amd64 only. The build runs inside an isolated build
environment; no arbitrary host path is a build input or output; any root or
loop-mount requirement stays inside that environment and does not become a
privileged step on the operator's host. Another build-host distribution is a
change to [the contract](../builder-writer-contract.md) §4 and to
[ADR-0008](0008-debian-13-live-baseline.md), not a flag.

### D4 — Nothing an operator types becomes a source

No URL, apt repository, mirror, package name, overlay path or shell fragment
from operator input enters a build. Sources are named by symbolic ID resolved in
versioned configuration or a signed manifest
([contract](../builder-writer-contract.md) §5). An added driver or an extra
repository arrives as its own manifest with its own hardware evidence, which is
[ADR-0008](0008-debian-13-live-baseline.md) D1 item 3 applied to the build
rather than to the release record.

### D5 — macOS is a console frontend, never a native builder

It verifies a fixed Debian 13 build environment's digest and signature before
starting it, refuses when none is present locally rather than fetching one, and
never reports emulated performance on Apple Silicon as supported performance.
Identical inputs must produce an identical artifact record on either host, and
that equality is a harness test ([contract](../builder-writer-contract.md) §6).

### D6 — The writer names a target by code, never by device path

`write` accepts no `--device` and no `/dev/...` path. A target is named only by
a target code issued by `list-media` in the same session; the writer re-checks
removability, capacity, partition table and stable identity before writing, and
refuses a substitution rather than warning about it. It refuses internal disks,
the disk holding the running root, a disk whose removability cannot be
determined, a mounted volume, and an artifact that did not pass `verify`.
Unmount and raw write happen only in the write service, with least privilege
and a fixed allowlist, under an audit classification. After writing, the medium
is re-read and verified read-only, and a medium that fails is never labelled
valid. Persistence is a separate explicit act on the USB medium only. Model,
serial and raw device identity are never printed to a terminal, a journal, an
external report, or GitHub ([contract](../builder-writer-contract.md) §7).

### D7 — One privileged writer, one contained builder

The operator's CLI is unprivileged. The build environment is privileged only
inside itself. The write service is the only component that opens a block device
for writing, and it does nothing else ([contract](../builder-writer-contract.md)
§8).

### D8 — This ADR selects no builder, and here is what would

[ADR-0002](0002-image-builder.md) D4 requires three things. The plan that
produces them, in the order that fails fastest:

| Step | What it produces | Evidence class |
| --- | --- | --- |
| P1 | The candidate set. [ADR-0008](0008-debian-13-live-baseline.md) D2 makes Debian 13 Live media the constraint: a tool that cannot produce it is not a candidate, and a candidate other than `live-build` must say why the baseline still holds. | recorded |
| P2 | **C5 evaluated first.** The candidate must let Boot pin initramfs contents and early-hook ordering, and must fail a build into which an unpinned hook enters. [ADR-0002](0002-image-builder.md) D3 names C5 as the criterion most likely to eliminate a tool; evaluating it first is what stops effort accumulating around a tool that cannot carry the product's defining property. | measured, never read from documentation |
| P3 | C1–C9 in a table, one row per criterion per candidate, each row carrying how it was established. C1 and C5 rows may not be filled from a tool's reproducibility claims. | mixed, per row |
| P4 | **The two-builder reproduction.** Two build hosts on independent infrastructure — not two containers on one machine — the same pinned inputs, and the result reported as a measured digest pair whether or not they match. An unequal pair is a result, not a retry. A failure to reproduce is a build failure, not a warning. | measured |
| P5 | The Fabric provisioning-contract gate ([ADR-0002](0002-image-builder.md) D4.2). [ADR-0007](0007-repin-fabric-to-v0-9-0rc1.md) moved Boot's pin to `v0.9.0rc1`, the first tag carrying `provisioning_contracts`, so the *existence* condition now appears satisfiable. What is **not** established is that Nexus's installer and Boot's builder consume the *same* contract, which is what program plan §5 R2 requires. The evaluation shows shared consumption, not a successful import. | recorded |
| P6 | The supply-chain record ([ADR-0002](0002-image-builder.md) D4.3): what the tool adds to a release's trusted computing base, who maintains and signs it, what it fetches at build time, and what happens if it is abandoned. | recorded |
| P7 | A new ADR selecting the builder, superseding [ADR-0002](0002-image-builder.md)'s open question and closing [#4](https://github.com/01rabbit/Azazel-Boot/issues/4). | — |

Until P7 exists, the builder question stays open, and this ADR does not move it.

### D8.1 — An evaluation build is not a release, and is not the thing ADR-0002 rejects

P2 and P4 cannot be performed without running a candidate builder. Reading
[ADR-0002](0002-image-builder.md) D4's closing rule as forbidding that would
make D4 unreachable — the selection would require evidence that the selection
rule forbids producing.

So the rule is read as it was written: a PR that produces an image **as a
product artifact** is rejected without a selection ADR. A build performed as
evaluation evidence under P2–P4 is what the selection requires. Such a build:

- is marked non-releasable in its artifact record and is never signed;
- is never written to a medium by `write`, and never published;
- is never cited as a Boot image, a release, or evidence that Boot builds;
- exists to produce one number — a digest — and the record of how it was made.

This narrows nothing in [ADR-0002](0002-image-builder.md) and adds nothing to
it. It states which of two readings of one sentence is in force, because the
program's next three steps all depend on the answer.

## Rationale

Every decision above is a constraint on a tool nobody has chosen, and each one
is cheaper to state now than to retrofit. A contract written after a tool is
adopted tends to describe the tool. The writer's safety model in particular —
no device path, a per-session target code, re-verification after enumeration —
is the sort of property that is straightforward to build in and very awkward to
add to a writer whose interface already takes a path.

The `build`/`write` separation deserves its own line. The failure it prevents is
not a typo. It is an operator, hours into an unattended build, being asked at
the end whether to write to a device they selected before the build started, on
a machine whose enumeration has since changed. Every part of that sentence is
avoidable, and separating the verbs avoids all of it at once.

## Consequences

- B1, B2 and B3 can proceed in parallel against a fixed contract: B1 owns the
  build environment and the reproducibility harness, B2 the verifier and the
  writer, B3 the initramfs quarantine. They share this document and change
  different parts of it.
- [ADR-0002](0002-image-builder.md) is **constrained, not superseded**. Its
  D2/D3/D4 stand; D8 above says how D4 gets satisfied, not what it requires.
- [#4](https://github.com/01rabbit/Azazel-Boot/issues/4) is unblocked as a plan
  and unchanged as a decision. It closes on P7, not on this ADR.
- The release record gains the artifact-record field list as a contract; the
  release policy's open questions about signing and key roles are untouched and
  still open ([release policy](../release-policy.md) §6–§7).

## What this ADR does not establish

- That a builder exists, has been selected, or has been evaluated against any
  criterion. None of that is true.
- That `live-build` is selected, preferred, or evaluated. It is the constraint
  [ADR-0008](0008-debian-13-live-baseline.md) D2 recorded, and nothing more.
- That an image has been built, a medium written, or a laptop booted.
- That the host-storage quarantine works, or that any write was prevented.
  Nothing has run.
