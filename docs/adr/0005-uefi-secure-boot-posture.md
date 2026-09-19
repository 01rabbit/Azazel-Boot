# ADR-0005: UEFI is assumed, Secure Boot stays on, and disabling it is a conditional fallback

Status: **accepted (2026-09-19)** — records Boot's adoption of program finding
**OF-03**, resolved at program level the same day. It decides a *frame*. It
qualifies no machine, measures no Secure Boot state, and selects no image
builder.

Resolves the deferral [ADR-0001](0001-x86_64-uefi-compatibility.md) left open:
"waiting on either a program-level statement or the first ratified entry's
measured boot path — whichever comes first, in an ADR of its own." The
program-level statement came first.

Related: [ADR-0001](0001-x86_64-uefi-compatibility.md) ·
[ADR-0002](0002-image-builder.md) · [Compatibility](../compatibility.md) ·
[Support matrix](../support-matrix.md) · [Threat model](../threat-model.md) ·
[Release policy](../release-policy.md)

## Context

Until 2026-09-19 nothing in this program said anything about the firmware boot
path. The
[program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
contained no occurrence of `UEFI`, `Secure Boot`, `CSM`, or `legacy BIOS`;
ADR-0001 recorded that fact and disclaimed the whole area; `docs/compatibility.md`
§2 recorded the boot path as "not yet decided" after an earlier row had cited
the plan for something it did not say. Azazel-Nexus and Azazel-Boot reached the
same gap independently while writing their support matrices.

It was raised as program finding **OF-03** and resolved the same day by owner
decision (program plan §15, `### OF-03`; restated as a blockquote in §5 R2).
Four questions had been unanswered in both products: whether UEFI is required,
whether a non-UEFI path is excluded, what Secure Boot's status is, and whether
shim, key enrollment, or vendor signing are in scope.

### The frame, as decided above this repository

> 1. "**Booting with Secure Boot enabled is the target**, via the standard signed
>    chain: a Microsoft-UEFI-CA-signed `shim` as the first stage, which verifies
>    the next stage against a certificate embedded in the shim itself. This is how
>    mainstream Linux live media already boot on Secure Boot machines. UEFI is the
>    assumed boot path."
> 2. "**Disabling Secure Boot is a fallback, never the default**, and it is
>    permitted only with the machine owner's explicit agreement, only after the
>    location of the host's disk-encryption recovery key has been established, and
>    it must be restored at the end of the session."
> 3. "**Enrolling a product key into the host (MOK) is not adopted.** It writes a
>    key into someone else's firmware and survives the session."
> 4. "**A qualified hardware entry records the Secure Boot state that was
>    observed**, as `Azazel-Boot/docs/compatibility.md` §3.3 already requires. No
>    product declares Secure Boot support for a machine nobody has tested."
>
> — program plan §15, finding OF-03, resolved 2026-09-19

Per [ADR index](README.md) rule 1, this ADR records that decision and does not
re-decide it, restate it more strongly, or extend it. What follows is what it
obliges **Boot** to do, which is Boot's to state because Boot is the product
that runs on hardware it does not own.

## Decision

**D1. Boot adopts the OF-03 frame unchanged.** All four items above are binding
on this repository. Where a Boot document describes the boot path, it cites
program plan §15 OF-03 and this ADR, not a Boot-local restatement.

**D2. The target is a machine with Secure Boot left enabled.** Boot's media must
be bootable on such a machine *without a firmware change* — a signed `shim` as
first stage, verifying the next stage against the certificate embedded in it.
An operator procedure whose first instruction is "turn Secure Boot off" is not
the product's boot path; it is the fallback, and D3 governs it.

**D3. The fallback's conditions are conjunctive, and its reason travels with
it.** Disabling Secure Boot requires *all* of: the machine owner's explicit
agreement; the location of the host's disk-encryption recovery key established
beforehand; and restoration of the prior state at the end of the session. In
addition, and this part is Boot's own discipline rather than the frame's:
**wherever a Boot document or operator-facing procedure describes this
fallback, it states the recovery-key consequence and the distinction below it.**
A responder reading "put the USB first and turn Secure Boot off" as one
instruction with one risk profile is the specific failure this clause exists to
prevent. No operator-facing procedure exists yet; when one is written, this
applies to it.

**D4. Boot enrolls nothing into a host's firmware.** No MOK, no platform key, no
vendor certificate, at no point in the session and by no operator instruction.
This is the same line the initramfs quarantine already draws — Boot must not
"run a firmware updater or an enrollment tool"
([threat model](../threat-model.md) §3; program plan §5 R7 Boot deliverables) —
and D4 extends it from "during the session" to "at all, including in a written
procedure".

**D5. The per-machine state is measured, never declared.** A qualified entry
records the Secure Boot state observed, under
[compatibility](../compatibility.md) §3.3's existing "firmware settings required
to reach the media… including Secure Boot state". This ADR adds no field and
duplicates none. Absence of a row remains untested, not incompatible
([ADR-0001](0001-x86_64-uefi-compatibility.md) D6).

**D6. This constrains the image builder, which is still unselected.** D2 is a
build property before it is a boot property: the image must carry a signed shim
and a chain that shim will verify. In practice that means building on a
distribution whose shim and kernel signatures are already trusted, or completing
shim review for a self-signed chain. [ADR-0002](0002-image-builder.md) records
that no builder is selected and does not select one; this ADR does not select one
either. It records a requirement any candidate must satisfy, to be read
alongside ADR-0002's C1–C9 by whichever ADR eventually makes the selection.
**Deciding this before the builder is chosen is the point** — the reverse order
risks choosing a builder that cannot produce Secure Boot media.

## Rationale

D3 carries the weight, so it gets the argument.

Windows BitLocker with a TPM protector is, by default, sealed against a PCR that
measures the Secure Boot state. Turning Secure Boot off changes that
measurement, the TPM does not release the key, and the next Windows boot demands
the recovery key. A responder who does that to a clinic's laptop, on a day the
clinic is already in trouble, may have taken the owner's data away from them —
and will have done it with a firmware setting, in thirty seconds, believing it
was a reversible convenience.

**Booting from USB does not by itself do this. Only changing the Secure Boot
state does.** That is the whole reason the fallback is hedged and the default is
not, and it is why D3 requires the distinction to be restated wherever the
fallback appears rather than recorded once here. "Put the USB first in the boot
order" and "turn Secure Boot off" look like one instruction in a hurried
procedure. They are two actions with very different consequences for someone
else's computer, and the product's defining safety property — that the laptop is
returned as it was found — is the one they threaten.

The second reason is plainer. On managed clinic, municipal and corporate laptops
a firmware password is common and the responder does not have it. A plan that
requires firmware changes does not run on those machines at all, so a product
whose boot path depends on a firmware change has quietly excluded much of its
intended field.

D4 follows from the same premise from the other side. Enrolling a key is worse
than toggling a setting, because a toggle can be restored at the end of the
session and an enrolled key survives it: the machine goes home trusting a
certificate its owner never agreed to, and Boot would have modified a host
after promising not to.

D6 exists because the alternative order is expensive. Shim-verifiable media is
not a property that can be added to an image builder after image definitions
have accumulated around it; it constrains which distribution the payload is
built from. Recording it while ADR-0002 is still open costs nothing, and
recording it after would cost a re-selection.

## Consequences

- [`docs/compatibility.md`](../compatibility.md) §2's firmware row is replaced in
  the same change as this ADR, per `CONTRIBUTING.md`'s rule that a document a
  change falsifies is revised in that change. §2.1 carries the frame and the
  BitLocker distinction; §3.3 is unchanged and remains where the measurement goes.
- [`docs/support-matrix.md`](../support-matrix.md) §3 answers three of its four
  rows from OF-03 and leaves the fourth — whether a non-UEFI or legacy path is
  excluded — undeclared, because the frame states an assumption rather than an
  exclusion. §2, §8 and §9 are revised to match.
- [ADR-0001](0001-x86_64-uefi-compatibility.md) is partly superseded: its
  statement that the boot path is undecided is now historical. Its admission
  policy D1–D7 is untouched and remains in force. A superseding pointer is added
  to it and to the [ADR index](README.md), per rule 3.
- [`docs/threat-model.md`](../threat-model.md) §2's trust classes are **not**
  changed and are not a boot-path claim. `VERIFIED_FIRMWARE` is a decided
  concept about what a platform demonstrates; the boot path is about which
  firmware interface the image is started through, and one does not require the
  other. One consequence worth naming: under D4, the route by which Boot could
  ever be in a `VERIFIED_FIRMWARE` session is the platform *relying on*
  verification it already performs, never Boot enrolling anything to create it.
- The builder selection ADR contemplated by [ADR-0002](0002-image-builder.md) D4
  must record how its candidate satisfies D6, alongside C1–C9.
- No Boot document may instruct an operator to disable Secure Boot without the
  D3 conditions and the D3 warning attached. That includes a future quick-start
  guide, which the program plan §5 R2 exit gate requires a nontechnical operator
  to be able to follow.

## What this ADR does not establish

- That Azazel-Boot boots on anything, with Secure Boot enabled or disabled. No
  image has been built, no machine has been booted, and no Secure Boot state has
  been measured. This frame is a target, not a capability.
- That a non-UEFI or legacy path is excluded. The frame assumes UEFI; it states
  no exclusion, and this ADR does not add one.
- Anything about the industry transition away from the expiring Microsoft UEFI
  CA 2011 certificate. The program plan is explicit that it "must be checked
  against firmware in hand rather than assumed — a machine whose firmware never
  received the newer CA in a database update will not trust a shim signed under
  it" (§15 OF-03). No firmware has been in anyone's hand, and this ADR asserts
  nothing about which certificate any firmware trusts today.
- That an image builder is selected, or that any candidate can satisfy D6.
  [ADR-0002](0002-image-builder.md) remains open and nothing here narrows it to a
  named tool.
- That the fallback in D3 is ever appropriate on a particular machine. That is
  the machine owner's judgement, taken with their recovery key in front of them,
  and Boot's documents supply the consequence rather than the permission.
- That any of this is implemented. Nothing in this repository builds, signs, or
  boots anything ([ADR index](README.md), rule 4).
