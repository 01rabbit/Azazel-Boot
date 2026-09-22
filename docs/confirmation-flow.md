# The confirmation screen: what it says, and what it does not buy

Status: **decision and content only.** `azazel_boot.confirmation` produces the
lines a screen would show and enforces the rules about them. **Boot has no user
interface.** Nothing has been shown to an operator, no confirmation has been
made on hardware, and no real laptop or NIC is involved anywhere in this.

Related: [Threat model](threat-model.md) §2 and §6 ·
[Architecture](architecture.md) §4 ·
[#9](https://github.com/01rabbit/Azazel-Boot/issues/9)

## The one sentence this is built around

> A confirmation is treated as an authorization — the operator "approved" the
> interface, therefore the action is approved.
> — [threat model](threat-model.md) §6

An operator confirming a role is **confirming a fact about the hardware**: that
this adapter is the one plugged into that port. It is not permission. Edge's
deterministic arbiter holds the same and only authority before and after.

So `Confirmation` holds three strings — a per-session code, a role word, and
the session it belongs to — and nothing else. It has no device, no capability,
no lease, no expiry, and its `authority` property is `()` in every instance. No
module that acts imports it, no signature has a parameter it fits, and a test
drives the quarantine with a completed confirmation in hand to show every
verdict is the one it was before.

## Two stages

**First**, the choosing screen: what the platform trust class permits anyone to
say, what Boot will and will not do, what state the inventory is in, and one
row per port with a code.

**Second**, the restating screen: one port, one role, said back, and a phrase
built from both. `yes` does not work. The phrase for another port does not
work. The phrase for another role does not work.

The second screen must actually have been shown — `confirm` refuses with
`first_stage_not_shown` otherwise, because a stage a caller can skip is not a
stage. A code confirms one port once.

Two stages rather than one because the failure being defended against is a
stressed operator agreeing to something they did not read.

## What the screen may say about the platform

The three classes are [threat model](threat-model.md) §2's, mirrored in code
with a test pinning them against the document. Each maps to one fixed sentence,
and the renderer cannot compose its own.

For `UNVERIFIED_PLATFORM` — **the expected class on a borrowed laptop** — that
sentence is:

> nothing checked Boot on this machine, and nothing here can tell you whether
> the machine itself was already interfered with. what you see below is what
> Boot could read, not a finding about this laptop

**These words appear in no line of any screen, in any state:** `safe`,
`secure`, `verified`, `trusted`, `compatible`, `supported`, `certified`,
`guaranteed`, `protected`, `validated`, `approved`. A test renders every screen
in every trust class and scans for each of them. A stressed operator reading
"verified" takes it as a finding about the laptop, and there is no such
finding.

A class is **determined and displayed, never assumed and never silently
upgraded**. There is no setter, no upgrade function, and no path in this module
that returns a higher class than it was given.

## What the screen says Boot will and will not do

Both halves, on the screen, because "I approved it" is precisely the mistake:

| Boot will | Boot will not |
| --- | --- |
| record which port you pointed at, for this sitting only | write anything to this laptop's own disks |
| read what the hardware reports about that port, without sending anything | start capture, enforcement or deception |
| | decide or enforce anything — Azazel-Edge does that, before and after |
| | carry this confirmation to another laptop, or to a later sitting |

## What the screen may not contain

No permanent MAC, no serial, no asset tag, no TPM identifier, no filesystem
path, no operator name — in a line, a refusal message, an exception or a
`repr`. `interface_key` is `bus_path|permanent_mac`, so it is absent too, which
is why a port is chosen by a **per-session code** rather than by its identity —
the same shape `azazel_boot.media.MediaSession` uses for write targets.

`describe_for_operator` is used as it stands and two of its four fields are
then **dropped**.

### The one judgement, recorded rather than hidden

The **bus position is shown, and only when the port has no physical label.**

It is not a serial, a MAC or a filesystem path; it is the same for every
machine of that model. Showing it always would disclose more than the question
needs. Never showing it would leave an operator facing two unlabelled sockets
with no way to answer at all — and [threat model](threat-model.md) §6 requires
the interface to present *physically checkable facts*. A reviewer who disagrees
should say so; the alternative is a screen that cannot distinguish two bare
ports.

## Nothing is inferred, and nothing is re-decided

A role must be one `assess` offered. A code must be one this screen issued. A
code from an earlier screen does not resolve — it would otherwise name whatever
now occupies that position, which is the substitution happening upstream of
every check.

**Whether a row may be chosen is the assessment's answer, not the row's.** The
first version read `incomplete_reasons` alone, and a test caught what that
costs: two interfaces presenting one composite identity are each individually
complete, so both rows said "choose me" while `assess` had already returned
`COMMISSIONING_REQUIRED` and offered no role at all. Such a row now carries
`not_offered_by_the_assessment` and gets no code. Re-deciding what another
module decided is the mistake `azazel_boot.persistence` was rebuilt to stop
making.

## What this does not establish

- **No operator has seen this.** The program's own test of "physically
  checkable facts" — civil emergency exercises with non-technical operators —
  has not been run, and [threat model](threat-model.md) §6.1 item 2 still
  stands: nothing upstream says what a sufficient confirmation looks like to a
  non-technical responder.
- **No real laptop, no real NIC.** Every test uses captured sysfs fixtures with
  an injected MAC reader, and the permanent MAC is still not read at all — the
  default reader reads nothing and says so, which resolves to
  `COMMISSIONING_REQUIRED`.
- **There is no renderer, no terminal and no input loop.** This module produces
  lines and accepts a string; nothing in `azazel_boot` prints or reads one.
- **Boot still cannot represent a commissioning record** ([threat
  model](threat-model.md) §6.1 item 1): the record shapes live in
  `azazel_fabric.provisioning_contracts`, and a `Confirmation` is deliberately
  not a local stand-in for one — it holds a code and a word.
