# ADR-0008: Boot adopts the Debian 13 Live / amd64 platform baseline

Status: **accepted (2026-09-22)**. Records a program-level decision; decides
nothing Boot was free to decide. **No builder is selected** — [ADR-0002](0002-image-builder.md)'s
selection conditions are untouched.

Related: [ADR-0002](0002-image-builder.md) · [ADR-0005](0005-uefi-secure-boot-posture.md) ·
[Compatibility](../compatibility.md) · [Support matrix](../support-matrix.md) ·
[Threat model](../threat-model.md) · [Update channel](../update-channel.md)

## Context

Boot named no distribution. `docs/support-matrix.md` said only that the image
would be built "on a distribution whose shim and kernel signatures are already
trusted", and `docs/adr/0002-image-builder.md` records that the repository
contains no build-tool name at all — "that silence is the substance of this
ADR".

Nexus was writing an installer preflight at the same time, and it needed a
distribution to refuse a host against. Two products were about to answer the
same question separately — the failure `docs/compatibility.md` §2.1 records
once already, where a Boot assumption reached a document as an inherited
decision by citing a plan that did not say it.

The owner decided the frame at program level on 2026-09-22, as finding OF-07.

## Decision

### D1 — Boot adopts the OF-07 frame unchanged

> 1. **The initial platform baseline is Debian 13 / amd64, for both products.**
>    Nexus installs Debian 13 minimal; Boot builds Debian 13 Live. No other
>    distribution is a co-equal v1 support target.
> 2. **Creation method.** Nexus: a signed netinst, or a verified offline install
>    bundle. Boot: a reproducible USB SSD image built with Debian `live-build`.
> 3. **Firmware.** `main` plus `non-free-firmware`. Any firmware added beyond
>    that is recorded in the release manifest and in the SBOM.
> 4. **Boot path.** UEFI, under the OF-03 frame. Nexus: Secure Boot enabled is
>    the default on machines that support it. Boot: **UEFI with Secure Boot
>    enabled is required**.
> 5. **Persistence.** […] Boot: the host's internal disk is **quarantined**;
>    persistence exists only on the USB side, and its LUKS2 is optional. This
>    restates Boot's existing property and **does not withdraw** the
>    operator-approved export target […]
> 6. **Updates.** […] Boot: a media rewrite or a new signed medium; **no
>    host-side update path exists**.
> 7. **Interface roles.** Read-only inventory plus explicit operator
>    confirmation, per host, in both products. No automatic inference […]

— program plan §15, finding OF-07, resolved 2026-09-22

Per [ADR index](README.md) rule 1, this ADR records that decision and does not
re-decide it, restate it more strongly, or extend it.

### D2 — `live-build` is a constraint on the builder selection, not the selection

[ADR-0002](0002-image-builder.md) D2 states that no candidate is named,
evaluated or preferred, and D4 fixes what a selection requires: an **actual**
two-builder reproduction of one payload digest, the existence of the Fabric
provisioning contract, and a recorded supply-chain assessment. **None of those
conditions is met, and this ADR does not pretend otherwise.**

So OF-07 item 2 enters this repository the way OF-03 entered it through
[ADR-0005](0005-uefi-secure-boot-posture.md) D6 — as a constraint the eventual
selection must satisfy:

- the image is Debian 13 Live, so a candidate that cannot produce Debian 13
  Live media is not a candidate;
- `live-build` is the builder the baseline is written against, and a selection
  ADR that chooses something else must say why the baseline still holds;
- C1–C9 are unchanged, and C5 (deterministic control of the initramfs, which
  carries the host-storage quarantine) remains the criterion most likely to
  eliminate a tool.

**An image-building change still arrives with a selection ADR or not at all.**

### D3 — Secure Boot enabled is required for Boot

OF-03 made Secure Boot the target and disabling it a conditional fallback.
OF-07 item 4 makes it **required for Boot**. The fallback ADR-0005 D2 describes
— disabling Secure Boot with the machine owner's explicit agreement, after the
recovery-key location is established, restored at the end of the session —
is a property of a session on a borrowed machine, not of the medium. A medium
that cannot boot with Secure Boot enabled does not satisfy the baseline.

### D4 — Persistence is USB-side, and the host's disk is untouched

The internal disk stays quarantined from initramfs entry, as
[the threat model](../threat-model.md) §3 already requires. Persistence, if it
exists at all, is on the USB medium and its LUKS2 is optional.

**The operator-approved export target is unchanged.** OF-07 item 5 restates
the default — nothing is written — and does not withdraw the path by which an
operator explicitly selects and approves a destination. Withdrawing it would
change the product's defining property and would need its own ADR.

### D5 — Nothing here is built, and nothing here is measured

No Debian 13 Live image exists. No medium has been written, no machine has
booted one, and no Secure Boot state, no host-storage behaviour and no
resource-class figure has been observed on any hardware.

## Rationale

A hardware campaign measures under one kernel, one allocator and one service
manager, and those belong to the distribution. Two distributions produce
evidence for neither, because nothing in either product can say by how much
they differ.

Recording the baseline as an adoption rather than a Boot decision is the point
of ADR index rule 1. Boot reached this question from the media side and Nexus
from the installer side; had each answered it, the two answers would have been
consistent only by luck, and the first document to cite the other would have
laundered one product's assumption into a shared decision.

## Consequences

- `docs/compatibility.md` §2 gains an OS baseline row and a media row, both
  citing program plan §15 OF-07 and this ADR; `docs/support-matrix.md` and
  `README.md` are revised in the same change.
- [ADR-0002](0002-image-builder.md) is **constrained, not superseded**. Its
  D2, D3 and D4 stand as written; this ADR adds what the payload must be.
- Ubuntu, Fedora and the RHEL family are recorded as a
  [future evaluation profile](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/future-platform-profiles.md)
  in the umbrella repository. No Boot document names them as a target.
- The Fabric pin does not move. The baseline is a platform fact recorded per
  entry, not a contract Boot consumes.

## What this ADR does not establish

- That Debian 13 Live media can be built reproducibly. Nobody has tried.
- That `live-build` satisfies C1–C9. It has not been evaluated against any of
  them.
- That any machine boots such a medium with Secure Boot enabled, or that any
  machine's internal storage stays untouched. No measurement exists.
- That Boot has a release, a signing key, or an image. It has none of them.
