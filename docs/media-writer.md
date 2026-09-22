# Artifact verification and the media writer

Status: **decision logic only**. `azazel_boot.artifact`, `azazel_boot.media` and
`azazel_boot.writer` decide whether an artifact may be written, which devices
may be offered, and what happens at each step of a write. **They open no
device.** Unmounting, raw writing and reading back are injected ports; the real
ones belong to the write service, which does not exist. No medium has been
written, no device has been enumerated on real hardware, and nothing here has
run outside a test.

Related: [Builder and writer contract](builder-writer-contract.md) ·
[ADR-0009](adr/0009-builder-and-writer-contract.md) ·
[Threat model](threat-model.md) · [Release policy](release-policy.md)

## 1. Verification comes before everything

An artifact record is the eighteen fields of
[the contract](builder-writer-contract.md) section 3, exactly: a missing field
is refused because the fact it carried is gone, and an unknown field is refused
because it is a claim nobody agreed to carry. `compatibility_claim` is
`candidate` or `hardware_verified`; there is no third value and none is
inferred.

Verification produces one of three outcomes:

| Outcome | Meaning | May be written |
| --- | --- | --- |
| `signature_verified` | the digest matched and an injected verifier accepted the signature | **yes** |
| `digest_only` | the digest matched; the record is unsigned, or no verifier was wired | no |
| `refused` | the digest did not match, or the signature was rejected | no |

A verification also carries **what it is about** — the digest it was measured
over, and a digest over **every field** of the record it checked. The write
authority re-measures the artifact and refuses unless the verification is about
that record and those bytes.

Binding to the payload digest alone is not enough, and a review demonstrated
why: two records can share a payload digest, so an unsigned record claiming
`hardware_verified` and naming a different quarantine policy was attached to a
write whose bytes were honest. The record is what a later reader has.

A signature is a **non-empty string**. `""`, `false`, `0`, `[]` and `{}` are
refused rather than read as signed.

**Verification is injected and the default verifies nothing.** Boot has no
signing key, no signer role and no signed artifact
([release policy](release-policy.md) section 1), and Ed25519 is outside the
standard library this bootstrap is limited to. A build that forgot to wire
verification therefore cannot write, rather than writing something nobody
checked.

The practical consequence today is that **nothing can be written at all**: no
signed artifact exists. That is the state of the product, not a limitation to
work around, and it is why the writer's tests inject a verifier rather than
lowering the bar.

An evaluation build's record ([ADR-0009](adr/0009-builder-and-writer-contract.md)
D8.1) does not parse as an artifact record, so it cannot become writable by
being renamed.

## 2. A target is a code, never a path

`list-media` assesses each enumerated device and issues a code **only** to the
ones that may be written to:

| Refusal | Why |
| --- | --- |
| `internal_disk` | the product exists to not write to one |
| `holds_running_root` | the same, and it destroys the session that would report it |
| `removability_unknown` | unknown is not removable; treating it as removable is the writer deciding for the operator |
| `mounted` | something else is using it |

An ineligible device is listed with its refusal and **no code**, so there is
nothing to type for it. A refusal that can still be selected is a prompt, and a
prompt is something people click through.

Codes carry the enumeration that issued them (`m1-2-01` is the first eligible
device of the second listing), belong to one session, and are spent by one use.
A code from an earlier listing does not resolve, and a spent code stays spent
across a re-listing.

The first version of this module reissued the same positional code on every
listing, so a code an operator had written down for a blank stick resolved,
after they re-ran `list-media`, to an evidence disk — a substitution upstream of
every check the writer performs. That is why the enumeration is in the code.

`MediaCandidate` has **no model field and no serial field**: the model cannot
hold them, so no rendering can leak them. The stable identity *is* a field — the
writer needs it — and it is held in an opaque `DeviceIdentity`: `repr` and `str`
are redacted, the value is reachable only through `disclose()`, and pickling is
refused outright. A redacted `__repr__` alone was not enough, because
`dataclasses.asdict` — how a `--json` output or an audit line is actually built
— walked straight past it.

A `DeviceIdentity` is also **immutable**, and that is a safety property rather
than a confidentiality one. The writer hands the same identity to the unmounter
and then to the raw writer; when it was mutable, a port that assigned to it
between those two calls changed what was opened **after** every refusal had been
evaluated. A review used that to write the host's internal disk while the medium
was reported valid. A write target that can change under the checks is not a
target.

The operator screen carries capacity, bus path, physical label, eligibility and
the code.

## 3. The write

**Every step is issued by the authority.** `plan`, `confirm_target`,
`confirm_destruction` and `execute` are all methods on a `WriteAuthority` that
owns the enumeration session. Each accepts only the object it issued at the
previous step and retires that object as it goes, so a step cannot be
constructed, skipped, repeated, or retried after a refusal. There is no `force`
and no `yes`.

Three rounds of adversarial review produced that shape, and each round found the
same class of defect. The first version let `execute` trust any value it was
handed. The second minted a nonce — a bearer token, so one `dataclasses.replace`
carried it onto a plan naming a different artifact and a different device. The
third sealed the plan and left the two confirmations constructible, so a caller
could wrap a genuine plan and write with **neither the target code nor the
destructive phrase ever typed**. Securing the token was never the point;
securing the sequence is.

**Any refusal during the write ends the authorisation.** A device that
disappeared, a substitution, a device that became ineligible, an unmount that
failed — each means re-running `list-media`, re-typing the code and re-typing
the phrase. That is deliberate: a substitution is "refused, not a warning and
not a prompt", and an authorisation that survives its own refusal is a prompt.

**The record binding is re-asserted before the write**, not only at plan time.
The record's fingerprint is stored on the plan and recomputed in `execute`: a
review edited a record after the verification had been bound to it, and a
binding checked once is a ceremony.

At write time, before anything is touched, the writer re-reads the device and
compares identity, removability, capacity, partition table, **bus path and
physical label** against the enumeration the code was issued against. The last
two are there because they are what an operator physically identifies the object
by; comparing only machine attributes accepts a different stick of the same
model in a different port. Comparing the identity a probe was queried with
against the identity it returns is a check on the probe, not on the device, and
is documented as such.

Afterwards the medium is read back over the artifact's own measured length —
not over the number the writer reports about its own work — and digested against
the record. A short write fails on its own terms. There is no outcome meaning
"written but unchecked": `written_and_verified` requires both, and anything else
is `verification_failed`, whose medium is never described as valid. `inspect` on
such a medium reports the mismatch rather than the record, and takes a candidate
from a listing rather than a bare device name.

**A mounted device is refused with no remedy offered here.** `list-media` will
not offer a stick a desktop has automounted, and this version deliberately does
not unmount it on the operator's behalf. The operator unmounts it and re-runs
`list-media`. An explicit unmount-then-write step is a change to
[the contract](builder-writer-contract.md) section 7.4 and would need its own
revision; it is named here so nobody discovers the gap while holding a stick.

The artifact file is measured at plan time and re-read by the write service at
write time. A file swapped in between is written and then caught by the
read-back, so the medium is never called valid — but the destruction already
happened. The artifact must sit where the write service controls it between the
two, and that is a property of the deployment, not something these modules can
check.

Persistence is not part of this. Creating encrypted persistence is a separate
explicit operation on the USB medium only
([contract](builder-writer-contract.md) section 7.5), and nothing in these
modules can start it.

## 4. How this is tested, and what that does not prove

Every test uses a file as the device. **No test touches `/dev`, a real disk or a
loop device.** A syntax-tree scan asserts that none of the three modules carries
a device-path literal, that the writer imports none of the named modules that
could open a device, and that it calls no `open()`. That is a blacklist plus a
structural fact — every filesystem effect is behind a `Protocol` — rather than a
proof that nothing can be opened.

That gives a complete exercise of the decision logic and **no evidence at all**
about hardware. Nothing here shows that a medium can be written, that a written
medium boots, that a real device enumerates as expected, or that an internal
disk stays untouched. Those need real media and a real machine, and until that
evidence exists no document may say otherwise.
