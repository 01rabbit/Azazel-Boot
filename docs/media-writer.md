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

Codes are issued per enumeration, belong to one session, and are single-use. A
code from an earlier listing does not resolve: a device must not be selected
against a view of the world that has since changed.

`MediaCandidate` has **no model field and no serial field**. Not "does not print
them" — the model cannot hold them, so no rendering, log, report or export can
leak them. The operator screen carries capacity, bus path, physical label,
eligibility and the code; the stable identity never reaches it.

## 3. The write

The two confirmations are types, not flags: `plan` then `confirm_target` then
`confirm_destruction` then `execute`, and `execute` accepts only the value the
last of those produces. There is no `force` and no `yes`.

At write time, before anything is touched, the writer re-reads the device and
compares identity, removability, capacity and partition table against the
enumeration the code was issued against. Any difference is a refusal. So is a
device that disappeared, one that has become ineligible since the listing, and
one that could not be unmounted.

Afterwards the medium is read back and digested against the record. There is no
outcome meaning "written but unchecked": `written_and_verified` requires the
match, and anything else is `verification_failed`, whose medium is never
described as valid. `inspect` on such a medium reports the mismatch rather than
the record.

Persistence is not part of this. Creating encrypted persistence is a separate
explicit operation on the USB medium only
([contract](builder-writer-contract.md) section 7.5), and nothing in these
modules can start it.

## 4. How this is tested, and what that does not prove

Every test uses a file as the device. **No test touches `/dev`, a real disk or a
loop device**, and a syntax-tree scan asserts the writer module names no device
path and imports nothing that could open one.

That gives a complete exercise of the decision logic and **no evidence at all**
about hardware. Nothing here shows that a medium can be written, that a written
medium boots, that a real device enumerates as expected, or that an internal
disk stays untouched. Those need real media and a real machine, and until that
evidence exists no document may say otherwise.
