# P2 host bootstrap: the plan, shown before anything is created

Status: **a plan, and nothing more for the P2 host-bootstrap workflow.**
Separate disposable builder VMs were used for prototype evidence, but this
workflow's host bootstrap actions were not run. No image was downloaded by
this plan, and it installed no package or selected a builder.
This page and `tools/builder/host_bootstrap.py` are what `doctor` shows; they
perform nothing, and the module imports no means of performing anything.

**Superseded in part by the CLI.** These steps are now what
[`azazel-boot-builder`](p2-builder-cli.md) checks and asks about rather than a
runbook an operator follows by hand: `doctor` answers whether the host can
drive them, and `prepare-host` shows them and confirms each of the three risky
ones separately. This page stays as the statement of *what* the steps are and
why each is constrained; the CLI page is the statement of *how* the tool
refuses.

Related: [Builder CLI](p2-builder-cli.md) · [C5 evaluation](c5-evaluation.md) ·
[ADR-0002](adr/0002-image-builder.md) · [ADR-0009](adr/0009-builder-and-writer-contract.md) D3 ·
[Builder and writer contract](builder-writer-contract.md) §2

## Why this page exists

[ADR-0009](adr/0009-builder-and-writer-contract.md) D1 makes `doctor` the verb
that "reports whether this host can drive the other six verbs, and what is
missing. Changes nothing." The owner added a rule for P2 on top of it: **any
operation that creates a build host, downloads something external, or needs
privilege is shown as a `doctor` plan before it runs.**

So the plan is a value. `plan(host_kind)` returns a `BootstrapPlan` of steps,
each carrying its command, the reason it exists, and — on every step — what it
does *not* do, because a command line does not show the constraints being
honoured.

## Why not a chroot

A chroot was the cheaper option and it was rejected, by the owner, for a reason
worth writing down: **a chroot shares the kernel of the machine it runs on**.
An initramfs measured inside one is evidence about that kernel's environment,
not about an isolated Debian 13 host, and C5 is a question about a builder's
control over an initramfs. A result obtained that way would have to be labelled
with a qualification that makes it unusable for a builder selection, which is
the only thing it was wanted for.

The refusal is structural rather than remembered: `HostKind` has **no value**
for a chroot, a container, a namespace or the session's own machine. There is
nothing to record one with, and `require_isolated_host` refuses the string
spelling of a value that does exist, for the caller who tries anyway.

## The steps

| ID | Step | Kind | Needs the plan shown first |
| --- | --- | --- | --- |
| P2-B1 | Record what the operator's own machine is | inspect | no |
| P2-B2 | Fetch the Debian 13 / amd64 image and its signed checksums | **external download** | **yes** |
| P2-B3 | Verify the image against the Debian CD signing key | inspect | no |
| P2-B4 | Create the disposable VM | **create host** | **yes** |
| P2-B5 | Record the VM evidence | inspect | no |
| P2-B6 | Install the candidate builder inside the VM | **privilege escalation** | **yes** |
| P2-B7 | Confirm the VM is the build host the gate requires | inspect | no |
| P2-B8 | Run the evaluation build inside the VM | write inside the VM | no |
| P2-B9 | Destroy the VM once the measurement is recorded | inspect | no |

Three steps need permission, and they are named individually because "some
steps need approval" is not a plan. The classification is what decides:
`steps_needing_approval` is derived from each step's `kind`, so a step added
later with one of those kinds appears without anyone remembering to add it to a
second list.

## What each risky step does not do

**P2-B2 — the download.** The only fetch outside the VM. It writes to no block
device and touches no release channel or signed product artifact. Its companion
step P2-B3 verifies `SHA512SUMS.sign` against the Debian CD signing key before
anything uses the image: **only signed Debian inputs**. An image whose signature
nobody checked makes every later measurement evidence about a download.

**P2-B4 — the VM.** Created with no shared folder, no host passthrough and **no
USB passthrough**. USB passthrough would put a real device within reach of an
evaluation build, which is the B5 boundary the owner has not opened. A reused VM
is not disposable and the step says so.

**P2-B6 — the privilege escalation.** `apt-get install live-build`, **inside the
VM only**, never on the operator's machine. It adds no repository, mirror or URL
an operator typed: [ADR-0009](adr/0009-builder-and-writer-contract.md) D4 says
nothing an operator types becomes a source, and that applies to the evaluation
host as much as to a build.

## Build inputs and outputs stay inside the VM

Everything a build reads or writes lives under `/srv/azazel-evaluation/`, inside
the VM. `require_build_io_inside_the_vm` refuses anything else — and refuses by
construction, so an unannotated path refuses rather than being guessed at.

A shared folder is the ordinary way this constraint is broken. It is convenient,
it is how a build reads a file nobody pinned, and it is how an evaluation output
reaches a Git working tree, which
[`evaluation.py`](../tools/builder/evaluation.py) refuses for its own reasons.

## What is recorded about the VM

Every field is required; a missing one is refused rather than defaulted, because
a blank reads as "any machine" three months later.

| Field | Why |
| --- | --- |
| `image_source` | which image, and from where |
| `image_digest` | that this is that image |
| `signature_verification` | that **Debian published it** — separate from the digest, because a digest only says two files match. An enum, not a boolean: `not_attempted` is a real answer and a boolean would round it to the same value as a check that ran and failed |
| `digest_verification` | that the bytes are the bytes the signed checksum names |
| `created_at` | when the machine came into existence |
| `cpu_architecture` | `x86_64`, and recorded rather than assumed |
| `debian_version_id` | `13`, and recorded rather than assumed |
| `builder_tool_version` | which `live-build` produced the initramfs |
| `backend` | which hypervisor made the VM, measured on the host rather than assumed from the platform |
| `execution` | native, or amd64 emulated on arm64. Decided by the session from the measured architecture, never passed in — a record that took it as an argument would let an emulated run be written up as a native build |

It carries the stamp `NON-RELEASABLE / EVALUATION ONLY`, and it has no
`compatibility_claim`, `signature`, `signed_artifact_digest`, `release_channel`,
`supported`, `reproducible` or `selected_builder` field. A record that cannot
carry a claim cannot be read as making one.

The repr is redacted: `image_source` is a path or URL the operator typed and
`created_at` is a timestamp on their machine, and a traceback gets pasted into
an issue.

## One VM is not evidence

`BootstrapPlan` reports `reproducibility_established`, `supported` and
`selects_a_builder` as `False`, unconditionally, and none of the three is a
field anyone can set — the same shape `C5Result` uses.

Creating a machine that can run a measurement is not the measurement. C1's
reproducibility needs **two independent builders**
([ADR-0002](adr/0002-image-builder.md) D1.3); support is a claim this repository
has no evidence for anywhere; and a builder is selected by an ADR
([ADR-0009](adr/0009-builder-and-writer-contract.md) D8 P7), never by a result.

## What this does not establish

- That a VM can be created. Nobody has tried.
- That `live-build` installs, runs, or produces an initramfs Boot can pin. C5
  remains **`inconclusive` / `not_measured`**; see [the C5 page](c5-evaluation.md).
- That `live-build` is the builder. It is a candidate and
  [#4](https://github.com/01rabbit/Azazel-Boot/issues/4) stays open.
- Anything about a USB SSD, an internal disk, a release, a signed product
  artifact or a compatibility claim. P2 touches none of them.
