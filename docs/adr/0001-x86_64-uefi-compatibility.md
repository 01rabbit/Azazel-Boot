# ADR-0001: Admission policy for the x86_64 compatibility set

Status: **accepted (2026-09-19)** — this ADR decides the *admission policy* for
the laptop compatibility set. It qualifies no hardware, names no candidate, and
does not decide the firmware boot path.

Scope item 3 of [Azazel-Boot #1](https://github.com/01rabbit/Azazel-Boot/issues/1).

Related: [Compatibility](../compatibility.md) · [Threat model](../threat-model.md) ·
[Architecture](../architecture.md) · [Release policy](../release-policy.md)

## Context

[`docs/compatibility.md`](../compatibility.md) §4 is deliberately empty.
Azazel-Boot has never been started on a laptop — not once, not in a lab. There
is no measurement of any machine, so there is nothing to qualify.

What the question actually needs is therefore not a list. It is a rule for how
a row is ever allowed to appear, written before anyone has a machine in front
of them and a reason to be optimistic about it.

### Already decided above this repository

| Fact | Source |
| --- | --- |
| The architecture is `x86_64`. | R0 baseline, product definitions table (line 18): AZ-03 runs on a "commissioned compatible x86_64 laptop". Repeated in the handoff §3. |
| Product claims refer to a *tested compatibility envelope*, not to laptops in general. | Program plan §6.7 item 8 (line 474): "Publish a laptop compatibility matrix and run civil emergency exercises with nontechnical operators; product claims refer to the tested compatibility envelope rather than arbitrary laptops." |
| Admission is deny-by-default against exactly tested tuples; a version *range* is descriptive and cannot authorize anything. | Program plan §4.1 (line 114): "Field releases use a deny-by-default set of tested tuples containing exact artifact and adapter/compiler digests, schema features, OS ABI, CPU features, architecture, profile, and overlay schema. Broad version ranges are descriptive compatibility claims and cannot authorize activation." |
| A qualifying test must produce hardware evidence, including the no-host-write record. | Program plan §5 R7 exit gate (lines 336–337): Boot "starts on every supported compatibility-class device and leaves internal storage unchanged in the verification test"; "Boot HIL records zero content writes to internal block devices until an operator explicitly selects an export target, and separately reports any unavoidable firmware NVRAM change." |
| Product-level boundaries are owner-ratified. | R0 exit criteria (line 62): "Product names, designations, audiences, and deployment boundaries are owner-ratified." |

### Not decided above this repository

**The program plan never says UEFI.** It does not contain the strings `UEFI`,
`Secure Boot`, `CSM`, or `legacy BIOS`. What it fixes about firmware is weaker
and different: §6.7 item 2 (line 468) says to "use firmware verification where
the supported hardware permits", and §5 R7 (line 328) defines the
`VERIFIED_FIRMWARE` / `EXTERNALLY_VERIFIED_MEDIA` / `UNVERIFIED_PLATFORM` trust
classes so that a platform that cannot verify anything is still usable with
reduced claims.

`docs/compatibility.md` §2 currently lists "Firmware | UEFI boot path" and
cites "program plan §6.7, R7" for it. That citation is not supported by the
plan's text. UEFI is a reasonable working assumption for commodity `x86_64`
laptops, and this ADR does not dispute it — but it is Boot's assumption, not an
inherited decision, and this ADR will not launder it into one.

## Decision

The following admission policy governs [`docs/compatibility.md`](../compatibility.md).

**D1. A row is a statement about one exact tuple, not about a machine.** A
qualified entry covers one composite identity (system, firmware version, CPU,
chipset, storage controller, and each interface by bus path and permanent MAC),
one image identity (unsigned payload digest and signed artifact digest), and the
measurements observed on that combination. `compatibility.md` §3 already defines
the fields; this ADR makes them the admission condition rather than a suggested
template. A partial entry is not a provisional qualification — it is not an
entry.

**D2. Qualification is per system *and* per firmware version.** A firmware
update, a driver change, or a hardware revision retires the row. Class-level or
family-level qualification is not available and may not be introduced without a
new ADR carrying evidence that it is sound.

**D3. Evidence, then ratification, in that order.** A row requires (a) a
hardware-in-the-loop record containing the §3.3 measurements, including the
zero-content-writes result and the separately reported firmware NVRAM changes
required by the R7 exit gate, and (b) a ratification record in which the
repository owner accepts the entry. Neither substitutes for the other. A
reviewer's confidence, a vendor specification sheet, and a successful boot
witnessed without instrumentation are none of them evidence.

**D4. The reviewing loop is the program's, unchanged.** Program plan §9.1 lists
"updated compatibility entry and known risks" among an author's deliverables,
and §9.2 requires independent specialist perspectives. Adding a row is such a
change. This ADR adds no review step beyond that and grants no local shortcut
around it.

**D5. A row never authorizes activation.** It is a descriptive compatibility
claim. Admission on a running host is product-local and separate: authenticity,
then the exact tested tuple, then semantic content policy, then resource and
topology admission, then approval, then staged activation (§4.1, line 112).
A machine appearing in the table does not make Boot run on it, and does not
grant Boot any authority: Azazel-Edge's arbiter remains the only decision and
enforcement authority in every capability state.

**D6. Absence of a row is not a claim of incompatibility.** It means untested.
Both statements — "nothing is supported" and "nothing has been tested" — are
currently true and equivalent.

**D7. No machine may be named anywhere in this repository until it has a
ratified row.** Not as a candidate, not as a target, not as an example, not in
an issue template, not in a commit message. This is the operative prohibition
of the policy and the one most likely to be violated by someone being helpful.

## Rationale

D7 carries the weight, so it deserves the argument.

A reader who sees their laptop model written down will try it. That is not a
hypothetical failure of comprehension; it is the normal way people read a list
in a document about a product whose purpose is to be booted on a borrowed
machine during an emergency. The reader will be a civil responder, the machine
will belong to a clinic, and the outcome the product exists to prevent —
modifying someone else's computer — will have been made more likely by a line
of text that was carefully labelled "candidate, untested".

`compatibility.md` §5 already reaches this conclusion for the candidate list.
This ADR generalizes it to the whole repository, because the expectation is
created by the model name appearing at all, not by the column it appears in.

The rest follows from the plan's own admission discipline. If a broad version
range cannot authorize activation (§4.1), then a hardware family cannot qualify
a machine either — the argument is identical, and the consequence of being
wrong is larger, because a compatibility claim is what a responder reads before
deciding to use a stranger's laptop.

## Consequences

- `docs/compatibility.md` §4 and §5 stay empty. That is now a decision with a
  record behind it, not an omission awaiting a volunteer.
- The first ratified row will require hardware, an instrumented no-host-write
  test, and an owner decision. None of the three exists, so the first row is
  far away, and the table honestly says so in the meantime.
- Issue templates, marketing text, and READMEs inherit D7. A PR that names a
  machine is rejected on that ground alone.
- `docs/compatibility.md` §2's "UEFI boot path" row needs either a corrected
  source (it is Boot's own envelope boundary, not a program-plan citation) or a
  program-level statement to cite. This ADR flags it; it does not edit it.

## What this ADR does not establish

- That any laptop works. None has been tested.
- That the firmware boot path is UEFI-only, that Secure Boot is required,
  permitted, or irrelevant, or that a non-UEFI path is excluded. None of that is
  decided, here or above. It is waiting on either a program-level statement or
  the first ratified entry's measured boot path — whichever comes first, in an
  ADR of its own.
- That the `x86_64` constraint is sufficient. It is necessary and inherited;
  everything else about a machine remains unqualified.
- That the compatibility set will ever be non-empty. That depends on a test
  program that does not exist yet.
