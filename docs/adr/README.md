# Architecture Decision Records

Status: **target contract**. Every record in this directory describes intended
behavior. Azazel-Boot contains no product code, has never produced a release,
and has never been started on a laptop. An ADR here records what was decided —
not what was built, and never that something works.

Related: [Architecture](../architecture.md) · [Threat model](../threat-model.md) ·
[Compatibility](../compatibility.md) · [Release policy](../release-policy.md)

## Rules for this directory

1. **Most of Boot's design was decided above Boot.** The
   [program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
   and the
   [R0 baseline](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-r0-baseline.md)
   are authoritative over this repository. An ADR that records a program-level
   decision says so and cites the section it comes from. It does not re-decide
   it, restate it more strongly, or extend it quietly.
2. **An ADR may decide nothing.** If a heading needs a decision that no one has
   made, the ADR says it is not decided, says what it is waiting on, and names
   the trigger that would settle it. A deferral with a stated trigger is a
   complete ADR. Manufacturing a decision to fill a heading is the failure mode
   these records exist to prevent.
3. **Overturning an accepted ADR requires a new ADR**, in the same change as
   the document revisions it forces. This mirrors
   [Azazel-Knowledge's ADR discipline](https://github.com/01rabbit/Azazel-Knowledge/tree/main/docs/adr).
4. **An ADR never promotes status.** *target contract*, *implemented*,
   *verified*, *supported*, *experimental*, and *retired* mean what the
   [third-party development handoff](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
   §7 says they mean. Writing a decision down does not make it implemented, and
   implementing it does not make it verified.
5. **No ADR creates authority.** Azazel-Edge's deterministic arbiter is the only
   decision and enforcement authority in every configuration and failure mode of
   Azazel-Boot. `FULL`, `LITE`, and `CORE` are capability states, not authority
   levels.

## Records

| ADR | Question | Status |
| --- | --- | --- |
| [0001](0001-x86_64-uefi-compatibility.md) | On what evidence may a laptop enter the compatibility set, and who ratifies it? | **Accepted (2026-09-19), partly superseded by [0005](0005-uefi-secure-boot-posture.md)** — admission policy only, and that part is untouched: `x86_64` is fixed at program level; the qualified set is **empty** and no machine, candidate or otherwise, may be named. Its record that the firmware boot path is *not* fixed by the program plan was true when written and is now historical. |
| [0002](0002-image-builder.md) | What builds the boot image? | **Property accepted, tool deferred (2026-09-19)** — the program plan fixes reproducibility of the unsigned immutable payload digest from pinned inputs by two independent builders. It names no tool, and none is selected here. Candidate criteria and the selection trigger are recorded. |
| [0003](0003-immutable-ab-update.md) | Root filesystem and update direction | **Recorded as decided at program level (2026-09-19)** — signed immutable A/B boot image, read-only root, redundant signed boot metadata, one-shot trial boot, verified digest before selection, automatic fallback. Boot has built none of it, and the mechanism details are open. |
| [0004](0004-exact-tag-fabric-consumption.md) | How does Boot consume Azazel-Fabric? | **Accepted (2026-09-19)** — exactly `v0.8.0`; no branch pin, no submodule, no copied source. One boundary module imports it. `provisioning_contracts`, the module the program plan assigns Boot's provisioning records to, **does not exist at that tag**, and the guard is tested against that fact. |
| [0007](0007-repin-fabric-to-v0-9-0rc1.md) | Which Azazel-Fabric tag does Boot pin now? | **Accepted (2026-09-19)** — supersedes [0004](0004-exact-tag-fabric-consumption.md) **D1 only**: the pin becomes `v0.9.0rc1`, the first tag carrying `provisioning_contracts` (verified by installing the tag, not by reading a changelog). D1's discipline is unchanged — exact tag, no branch, no submodule, no copied source — and D2/D3/D4 stand, which is why this was a one-line change. A candidate is pinnable and promises no stability; Boot re-pins to `v0.9.0` when Fabric cuts it. Unblocks #9, #11 and #16; completes none of them. |
| [0008](0008-debian-13-live-baseline.md) | What platform does the medium carry? | **Accepted (2026-09-22), D4 revised twice (2026-09-22)** — adopts program plan §15 OF-07: Debian 13 Live / amd64, `main` plus `non-free-firmware`, UEFI with Secure Boot enabled required, USB-side persistence only. D4.1 fixes the medium's block layout (GPT, ESP, signed read-only root, optional LUKS2 partition formatted directly) and refuses LVM, mdraid and ZFS assembly on the host **and** on the medium; LUKS2's `dm-crypt` is the one mapping permitted. D4.1.1 requires a
**hardware-provided stable media identity**, bound under a key-protected HMAC with the LUKS
persistence UUID, the signed Boot image digest and the commissioning generation, before
persistence opens at all — topology is never identity, and the raw value lives only in the
encrypted commissioning record. It is explicitly **not** a claim to defeat cloning.
**No builder is selected**: `live-build` enters as a constraint on [0002](0002-image-builder.md)'s open selection, whose conditions are untouched. Nothing is built and nothing is measured. |
| [0006](0006-trial-boot-health-confirmation.md) | What must a trial boot prove before it is promoted? | **Accepted (2026-09-19)** — resolves the item [0003](0003-immutable-ab-update.md) D4 named as its most consequential gap. Six signals (running digest matches the verified one; quarantine established and still in force; zero attempted host writes; Core answered a probe with a durable audit record; the promotion record is writable; persistence, conditionally), a **300-second** window, **one** attempt, and fallback on any ambiguity. Operator confirmation, network reachability, external-module availability, and a clean log are explicitly *not* signals. Nothing is implemented. |
| [0005](0005-uefi-secure-boot-posture.md) | Which firmware boot path, and what is Secure Boot's status? | **Accepted (2026-09-19)** — records Boot's adoption of program finding OF-03. UEFI is the assumed boot path; booting with **Secure Boot enabled** through a signed shim chain is the target; disabling it is a fallback requiring the owner's agreement, a known recovery-key location, and restoration; **no key is enrolled into a host's firmware**. The per-machine state is measured, never declared, and the requirement constrains the still-unselected image builder ([0002](0002-image-builder.md)). |
| [0010](0010-persistence-key-and-migration.md) | What opens persistence, what happens when nothing can, how is a torn write detected, and how is a migration snapshotted? | **Accepted (2026-09-22). D1–D9 implemented in software ([session mode](../session-mode.md), [persistence](../persistence.md) §4.1, [snapshot and recovery](../snapshot-and-recovery.md)), hardware-unverified; D10 is a rule the others are held to.** D1 no key means no persistence and an ephemeral session, with **no emergency exception** for an unprotected volume. D2 five passphrase attempts per boot, then sealed for that boot and fixed ephemeral; the count, the passphrase and any user identifier reach no journal, audit or screen, and a reboot's fresh attempts are **not claimed as brute-force resistance**. D3 the session mode is decided once at commissioning and needs a reboot to change. D4 a suspected torn write quarantines the **whole volume**, fail-closed, never repaired; detection records a classification only. D5 no record-level continuation, and nothing is described as erased. D6 the migration snapshot lives **inside the existing partition** — [ADR-0008](0008-debian-13-live-baseline.md) D4.1 is not revised. D7 preflight on space, integrity and schema; **no migration without a snapshot**, under any acceptance. D8 recovery is explicit, through target binding, key acquisition, integrity verification and confirmation. D9 nothing targets host storage and **a version upgrade is not a way round the fence**. D10 keys, passphrases, raw device identities and snapshot contents appear nowhere. [#7](https://github.com/01rabbit/Azazel-Boot/issues/7) stays open and is decomposed into three children, each `hardware-unverified`. |
| [0009](0009-builder-and-writer-contract.md) | How is the builder driven, what must a build record, and what may touch a block device? | **Accepted (2026-09-22)** — fixes six verbs (`doctor`, `build`, `verify`, `list-media`, `write`, `inspect`) with **`build` and `write` never merged**, an artifact record of JSON scalars whose manifests and SBOM are referenced sidecars bound by digest (D2, revised 2026-09-22), a Debian 13 / amd64 isolated build host, an input closure where nothing an operator types becomes a source, macOS as a console frontend only, and a writer that names a target by per-session code and never by device path. **Selects no builder**: [0002](0002-image-builder.md) D2/D3/D4 stand, and D8 records the plan (P1–P7) that would satisfy D4 — C5 evaluated first, an actual two-builder digest pair, the Fabric contract gate, a supply-chain record. Nothing is built and nothing is written. |
| [0011](0011-unlock-helper-boundary.md) | Where is the passphrase typed, and what may cross back from the thing that holds it? | **Accepted (2026-09-22) — nothing implemented.** D1 the unlock helper is an **initramfs hook helper**, not part of `azazel_boot`: a boot-time-only component cannot be called later, which is the mid-session unlock [ADR-0010](0010-persistence-key-and-migration.md) D3 refuses. D2 one invocation is one prompt and one attempt; the helper holds **no counter** and the budget stays in `session_mode`, because two implementations of one limit disagree and the looser one runs. D3 exactly two inputs — a hidden local console prompt, and a binding the helper **re-derives** from the commissioning record on the medium; no argv, environment, configuration file, network, remote API, host disk or USB export. D4 the return channel is a **process exit status**, because an eight-bit channel cannot carry a passphrase and a pipe can. D5 no passphrase, key, slot, mapper path, raw identity, errno or `cryptsetup` output crosses back; its stderr is **discarded, not captured**. D6 the mapper name is a constant, not a reported identity. D7 the helper writes no log; the audit may hold `unlock-succeeded`, `unlock-unavailable`, `unlock-refused`, `attempt-budget-exhausted` and nothing else, and `unlock-refused` deliberately does not say *which* refusal it was. D8 all six failure paths are fail-closed to ephemeral, and a failed unlock does **not** quarantine the volume. D9 no secret is written into the initramfs; **no claim** of memory erasure, TPM protection or offline-attack resistance. D10 the acceptance criteria are static, integration and mutation tests that no secret crosses the boundary, plus an independent adversarial review. D11 no network, host disk, USB export, snapshot, migration, recovery, capability change or fence clearing. The concrete privilege and the hook position are **not decided**, pending the first built initramfs. |

## What this directory does not establish

- That a decision recorded here has been implemented. One partly has:
  [ADR-0010](0010-persistence-key-and-migration.md) D1–D3 exist as decision
  logic in `azazel_boot.session_mode` ([session mode](../session-mode.md)),
  and that row says so. Every other decision in this directory is a
  decision and nothing more.
- That anything recorded here has been **verified**. Nothing has: no image
  has been built, no medium written, no laptop started. Implemented is not
  verified, which is Rule 4.
- That Azazel-Boot boots, is safe on any laptop, or preserves host storage.
- That a program-level decision cited here has itself been verified. The
  program plan's own status is *proposed program baseline*.
