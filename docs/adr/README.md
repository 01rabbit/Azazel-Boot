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
| [0005](0005-uefi-secure-boot-posture.md) | Which firmware boot path, and what is Secure Boot's status? | **Accepted (2026-09-19)** — records Boot's adoption of program finding OF-03. UEFI is the assumed boot path; booting with **Secure Boot enabled** through a signed shim chain is the target; disabling it is a fallback requiring the owner's agreement, a known recovery-key location, and restoration; **no key is enrolled into a host's firmware**. The per-machine state is measured, never declared, and the requirement constrains the still-unselected image builder ([0002](0002-image-builder.md)). |

## What this directory does not establish

- That any decision recorded here has been implemented. None has.
- That Azazel-Boot boots, is safe on any laptop, or preserves host storage.
- That a program-level decision cited here has itself been verified. The
  program plan's own status is *proposed program baseline*.
