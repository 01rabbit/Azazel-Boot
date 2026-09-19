# ADR-0006: What a trial boot must prove before it is promoted

Status: **accepted (2026-09-19)** — decides the health signal set, the trial
window, and the attempt count that [ADR-0003](0003-immutable-ab-update.md) D4
left open and named its most consequential gap. It decides what is *measured*.
It implements no updater, builds no image, and has never been run on a machine.

Related: [ADR-0003](0003-immutable-ab-update.md) ·
[ADR-0002](0002-image-builder.md) · [Threat model](../threat-model.md) ·
[Architecture](../architecture.md) · [Recovery](../recovery.md) ·
[Update channel](../update-channel.md)

## Context

ADR-0003 records the update direction as decided at program level: an inactive
slot, a full digest verified before selection, a one-shot trial boot, promotion
only after health confirmation, and automatic fallback. Its D4 table lists what
that leaves open and singles this one out:

> **What "health-confirmed" measures** — which checks must pass, in what time,
> before a trial is promoted. Nothing upstream defines it, and it is the single
> most consequential open item here: an over-eager health check promotes a
> broken image, an over-strict one strands a working responder on the previous
> generation.

Nothing upstream defines it, and nothing in this repository depends on the
image builder to settle it. It needs the argument finished before anyone writes
the check.

### The two failure modes are not symmetric

The framing that makes this decidable is that "over-eager" and "over-strict"
do not cost the same thing.

| | What the responder is left with | Recoverable in the field? |
| --- | --- | --- |
| **False promote** — a broken generation is made default | No working system. The A/B fallback already fired during the trial and was consumed; the next boot lands on the broken generation again. | **No.** It needs a second machine, a network, or an expert — the three things Boot assumes are absent. |
| **False fallback** — a working generation is not promoted | The previous generation, which was the running one and is therefore known to boot. An older Boot, not a dead laptop. | **Yes**, trivially: the responder is working. The update is re-offered later. |

A false fallback costs an update. A false promote costs the machine, in the
situation the machine exists for. The check is therefore built to **fail toward
fallback**, and the way to keep that from becoming flakiness is not to soften
it — it is to choose signals a working generation produces *every time*.

## Decision

### D1 — Promotion requires positive evidence; ambiguity is fallback

A trial is promoted only when **every** required signal has been evaluated and
returned a pass. No signal defaults to true, no signal is skipped, and a signal
that cannot be evaluated is a **failure**, not a pass. An unreachable check, a
timeout inside a check, a check that errors, and a check that has not run yet
are all the same outcome: not promoted.

This is the whole design in one line. Everything below is an application of it.

### D2 — The health signal set

All six are evaluated in the trial boot. H1–H5 are required. H6 is conditional
in the specific sense D2.1 defines — not in the sense of being optional.

| # | Signal | What a pass proves | What it does **not** prove |
| --- | --- | --- | --- |
| **H1** | The running generation's payload digest equals the digest that was verified when the slot was selected. | The trial is running the image that was verified. Without this, "verified before selection" says nothing about what is now executing. | That the image is *correct*. Only that it is the intended one. |
| **H2** | The initramfs host-storage quarantine was established before any host block device was exposed to a filesystem driver, and is still in force when the check runs. | The product's defining safety property ([threat model](../threat-model.md) §3) is active in **this** generation, not only in the previous one. | That it will hold for the rest of the session, or against a device that appears later. §3.2 makes the continuing rule a separate requirement. |
| **H3** | Zero content writes were attempted to non-Boot internal block devices between initramfs entry and the check. | The quarantine actually held so far, as opposed to merely being configured. H2 is the mechanism; H3 is the outcome. Both, because either can be true without the other. | That no write will occur later. It also says nothing about **firmware NVRAM changes**, which §3.2 excludes from the claim and requires to be reported separately. |
| **H4** | The deterministic Core answered a synthetic probe, and that answer's audit record is durable. | Core is serving and the audit path is writable — the two things that make a Boot session usable and accountable. | That Core's answer is *correct*, or that any external capability is present. A `CORE` session passes this. |
| **H5** | The boot medium is still present, and the promotion record can actually be written and read back. | The promotion can be recorded. A promotion that cannot be persisted is worse than no promotion: the next boot would find inconsistent metadata. | Anything about the medium's long-term health. |
| **H6** | Persistence: see D2.1. | Persistence is usable in this generation. | That its contents are correct or complete. |

### D2.1 — H6 and the difference between *not applicable* and *unknown*

If persistence is configured for this installation, it must have mounted and
passed its integrity check. If persistence is **not** configured, H6 is *not
applicable* and does not block promotion.

`not_applicable` requires a **positive determination** that persistence is
absent by configuration. "The check could not tell" is `unknown`, and `unknown`
is a failure under D1. This distinction is the seam where an over-eager check
would otherwise creep in: an implementation that treats "no persistence found"
as "no persistence configured" would promote a generation whose persistence is
broken.

### D2.2 — What is deliberately not a health signal

Each of these was considered and rejected. The reason matters more than the
verdict, because each would be defensible in a product Boot is not.

- **Operator confirmation.** Rejected. The [threat model](../threat-model.md)
  says the non-technical-operator problem is *reduced, not eliminated*; making
  promotion depend on a human judgement puts the most consequential decision in
  this ADR on the person least able to make it. An operator looking at a laptop
  cannot distinguish a healthy generation from a broken one, and a wrong answer
  is the unrecoverable direction. It also makes promotion depend on someone
  being present at the right moment: a machine left to finish an update alone
  would never promote.
- **Network reachability.** Rejected. Boot must be useful with no network at
  all. Requiring one would strand a responder in exactly the situation the
  product exists for.
- **Availability of external Knowledge, Deception, or remote cognition.**
  Rejected for the same reason, and because these are `LITE`/`FULL`
  capabilities. A `CORE` session is a fully successful session; a health check
  that demanded more would make capability a promotion condition, which it is
  not.
- **Absence of any error or warning in the logs.** Rejected as over-strict in
  the precise way D1 warns about: an unrelated driver warning on borrowed
  hardware would strand a working responder. The signals above are positive
  assertions about specific properties, not the absence of noise.
- **A timed "it stayed up for N minutes" soak.** Rejected. It proves less than
  H4 and costs the responder the whole N minutes in an emergency.

### D3 — Trial window: 300 seconds from initramfs entry

All required signals must have returned a pass within **300 seconds** of
initramfs entry. At 300 seconds the trial fails and the fallback runs.

The number is anchored, not guessed. The
[program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
§8 targets Core ready within **120 seconds** after encrypted-volume unlock
(assigned as SO-01 in
[service-objective-assignments.md](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/service-objective-assignments.md)).
300 seconds is 2.5× that, which leaves headroom for slow borrowed hardware and
a slow USB controller while still failing before a responder concludes the
machine is dead and pulls the power. A window shorter than the Core-ready
target would fail healthy generations by construction; a much longer one would
spend an emergency waiting.

**This is the one number here with no upstream anchor of its own.** It is a
decision, and it is the first thing to revisit when a real machine produces a
real distribution of boot times — with measurement, not with an opinion.

### D4 — One trial attempt, then permanent fallback for that generation

A generation gets **one** automatic trial. This is what ADR-0003's inherited
"one-shot trial boot" means, stated as a count.

On failure the previous generation is restored as default, the failed
generation is marked failed, and **no further automatic attempt is made**. The
generation is re-offered only when a new update is applied.

A second automatic attempt was considered. It buys the chance that a failure
was transient, and it costs the responder another 300-second window on their
next boot, in an emergency, with no working system during it. Boot's premise is
that the person in front of the machine can fix nothing, so the system must
stop spending their time and settle on the generation known to boot. A
transient failure is better handled by re-applying the update later, when they
are not relying on the machine.

### D5 — The failure is recorded, and the recording cannot be the thing that fails

A failed trial writes a record naming which signals passed, which failed, and
which were `unknown`, so a later operator or maintainer can tell a broken image
from a slow one. That record is written **during the fallback path**, which
must not itself depend on the generation under trial.

H5 exists partly for this: if the medium cannot be written, the trial fails
before it can reach a state where neither promotion nor a coherent failure
record is possible.

## Consequences

- An updater cannot be written against ADR-0003 alone; it now has a signal set,
  a window, and an attempt count to implement against.
- H2 and H3 make the quarantine a **promotion condition**, not only a runtime
  property. A generation that boots but does not quarantine is never promoted.
  This is stronger than the threat model alone requires and is deliberate: the
  quarantine is the product's defining property, and an update path that could
  silently drop it would be the worst available outcome — the borrowed laptop
  is damaged by the thing that was supposed to protect it.
- H4 ties promotion to the same "Core answered and the audit record is durable"
  event that program objective SO-01 measures. One definition of *Core is up*
  serves both, and a change to either has to face the other.
- 300 seconds and the one-attempt rule are the two values most likely to move
  once real hardware exists. Both are named here so a change is a visible
  revision rather than a quiet tuning.
- Nothing here is implemented. There is no image, no updater, no machine, and
  no measurement.

## What this ADR does not establish

- That Boot can update, promote, fall back, or survive a power cut. Nothing has
  been implemented and nothing has been tested.
- That 300 seconds is right. It is anchored to a program target that has itself
  never been measured.
- That the signals are cheap to implement, or that all six can be evaluated on
  every candidate laptop. That is exactly what the first hardware trial will
  say, and it may force a revision.
- That the quarantine works. H2 and H3 *check* it; [threat model](../threat-model.md)
  §3.3 still requires a hardware-in-the-loop record before the property is more
  than a claim.
- Any authority. A health check observes; it does not decide policy and grants
  nothing. Azazel-Edge's deterministic arbiter remains the only decision and
  enforcement authority in every configuration and failure mode of Azazel-Boot.
