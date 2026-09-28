# Architecture Decision Records

Boot's current scope is recorded in [ADR-0012](0012-existing-environment-tooling.md).
It supersedes the former bootable-OS, image-builder, media-writer,
initramfs-quarantine, and Boot-owned-persistence direction. Those retired
records have been removed from the current tree; their prior versions remain
in Git history and must not be treated as current requirements.

## Rules

1. The [Azazel program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
   owns cross-repository scope and shared contracts.
2. A new implementation needs an explicit user problem, product owner,
   supported host contract, declared side effects, and verification plan.
3. No ADR creates decision or enforcement authority. Azazel-Edge remains the
   sole decision and enforcement authority.
4. Status words such as *implemented*, *verified*, and *supported* require the
   evidence rules in the current program handoff.

| ADR | Decision | Status |
| --- | --- | --- |
| [0012](0012-existing-environment-tooling.md) | Boot does not create or write OS images; it may help install a narrowly scoped toolset in a user-provided environment | Accepted by owner, 2026-09-28; implementation and toolset undecided |
