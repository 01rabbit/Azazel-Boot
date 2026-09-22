# `azazel-boot-builder` — what it checks, what it asks, and what it will not do

Status: **`doctor` works; `prepare-host` plans and refuses.** The two verbs
exist, the checks run, the refusal vocabulary is complete and the evidence
schema is enforced. The three acts — downloading, creating a VM, installing a
package inside one — have **no implementation in this repository**, so
`prepare-host` shows the plan and then refuses with `no_executor_available`
unless `--dry-run` is given. Nothing has been downloaded, created or installed.

Related: [P2 host bootstrap plan](p2-host-bootstrap-plan.md) ·
[C5 evaluation](c5-evaluation.md) ·
[ADR-0009](adr/0009-builder-and-writer-contract.md) D1, D3, D4

```
azazel-boot-builder doctor
azazel-boot-builder prepare-host [--dry-run]
```

## `doctor` — read-only, and read-only by construction

[ADR-0009](adr/0009-builder-and-writer-contract.md) D1 defines the verb:
"reports whether this host can drive the other five verbs, and what is missing.
Changes nothing."

That is enforced by the **type it depends on**, not by the code inside it.
`doctor` is handed a `HostProbe`, whose Protocol has exactly one method,
`facts()`. There is no `run`, `write`, `create`, `install`, `download` or
`remove` on it, and `tools/builder/` as a whole cannot import `subprocess`,
`os`, `socket` or `urllib` — a guard that predates this work and was **not**
relaxed to make room for it. The adapter that does read the machine lives
outside that package, in `tools/hostprobe/`.

| Check | `ready` | `missing` | `refused` |
| --- | --- | --- | --- |
| `shared_kernel` | no marker found | — | `shared_kernel_host` |
| `host_platform` | native amd64, or emulated and recorded as such | — | — |
| `virtualisation_backend` | one is installed | `host_backend_unavailable` | — |
| `free_space` | ≥ 48 GiB | `insufficient_free_space` | — |
| `network_reachability` | the Debian archive answers | `network_unreachable` | — |
| `existing_vm_collision` | the name is free | — | `vm_name_already_in_use` |
| `privilege` | escalation is available | `privilege_unavailable` | — |
| `no_shared_folder` | none configured | — | `shared_folder_configured` |
| `no_usb_passthrough` | none configured | — | `usb_passthrough_configured` |

**`missing` and `refused` are different answers.** `missing` is something an
operator can supply — install a backend, free some disk, connect a network.
`refused` is something they cannot: no amount of installing makes a container a
machine of its own, and an existing VM of this name is theirs to resolve
because **this tool does not delete a VM**.

### The report carries nothing from the machine

Every finding is three enum values — check, status, reason — and `Finding` has
no `detail`, `message`, `path` or `value` field to hold anything else. A VM
name is a name a person chose, a free-space figure is a fact about their disk,
and a `doctor` report is the thing an operator pastes into an issue when asking
for help. A test renders a report from a probe carrying private VM names and a
byte count and asserts that none of it appears.

### What the shared-kernel check can and cannot tell you

Four markers: `/.dockerenv`, the `container` environment variable, container
strings in `/proc/1/cgroup`, and a root device that differs from PID 1's. Any
one of them refuses.

**The absence of all four is not proof of a dedicated machine.** The check is
one-directional by design: a marker is evidence, and no marker is the absence
of evidence. A microVM with its own kernel and a bare laptop look identical
here, which is correct — both are eligible — but so would a container the four
markers do not recognise. The stronger guarantee is structural and comes from
elsewhere: **the machine running this CLI never becomes the build host.**
`prepare-host` always creates a VM, `HostKind` has no value for anything that
shares a kernel, and `check_build_host` runs Debian 13 / amd64 checks *inside*
the guest.

## `prepare-host` — the plan first, then one confirmation per act

Three acts, three separate confirmation phrases, in a fixed order:

| Order | Act | The operator types |
| --- | --- | --- |
| 1 | `external_download` | `download the debian image` |
| 2 | `create_vm` | `create the disposable vm` |
| 3 | `install_in_vm` | `install live-build inside the vm` |

The phrases differ so that **one answer cannot stand for all three**, which is
what a shared "yes" would allow.

### Nothing happens before approval, structurally

The object that could act — the `Executor` — is **not in scope** until a phase
actually runs. Building a session, showing the plan and collecting a
confirmation have nothing capable of reaching the network or creating a
machine.

And an approval is **issued, not asserted**. `Approval` is minted only by the
session, and `run` checks the one it is handed by identity. A constructed one,
a copy, a `deepcopy`, a pickle and an approval for another phase are all
refused — the shape that survived four rounds of adversarial review on
`azazel_boot.writer` and `azazel_boot.persistence`, where a token a caller could
build was defeated every time.

### What it will not do, and why those are absent rather than guarded

`Executor` has no `delete_vm`, no `install_on_host`, no `attach_usb` and no
`mount_host_disk`. A later contributor cannot call a method that does not
exist, which is a stronger statement than a check they might not read.

So: **no dependency is installed on the operator's machine, no privilege is
escalated on it, no VM is deleted, and no USB device is touched.**
`can_escalate_privilege` is *reported* so `doctor` can say what is missing;
`sudo` is looked up with `which` and never run, and a test asserts it never
reaches an argument vector.

### Refusals

| Refusal | Cause |
| --- | --- |
| `host_backend_unavailable` | no backend installed; one is never inferred from the platform and never installed by this tool |
| `host_not_eligible` | the host shares a kernel |
| `plan_not_shown` | an approval before the plan is a confirmation of nothing |
| `confirmation_did_not_match` | the phrase belongs to another phase, or to none |
| `not_an_issued_approval` | it is not the object this session minted |
| `approval_for_another_phase` | permission to download is not permission to create a machine |
| `approval_already_spent` | one approval permits one act |
| `phase_out_of_order` | a VM is created from a verified image; a package goes into a VM that exists |
| `signature_not_verified` | only signed Debian inputs are used |
| `digest_not_matched` | the bytes are not the bytes the signed checksum names |
| `vm_would_not_be_disposable` | a shared folder, a host disk mount or USB passthrough was requested |
| `no_executor_available` | the acts are not implemented here yet — see the status line above |

### The signature and the digest are checked independently

Two fields, two enums, both read. A digest says two files are the same file; a
signature says Debian published it. `not_attempted` is a real answer and it is
**not** a pass — a single boolean could not tell it from a check that ran and
failed, and the failure this separation prevents is exactly checking one and
reporting the other satisfied.

### Cleanup never removes a VM

A failure part-way removes only files this session created, and names any
half-created VM as **left for the operator**. Deleting one is something this
tool does not do, and a failure is not an exception to that rule — a
half-created machine on someone's laptop is theirs to inspect before it is
destroyed. Cleanup is idempotent: a second call removes nothing.

## macOS on Apple silicon is emulation, and is recorded as one

An amd64 Debian guest on an arm64 Mac runs under emulation. The evidence
carries `execution: emulated_amd64_on_arm64`, the plan prints it, and the line
it prints is explicit: *no timing, reproducibility or support conclusion
follows from it.*

The session decides this from the host's measured architecture and the caller
cannot pass it in — a record that took it as an argument would let an emulated
run be written up as a native build.

## The evidence a run must produce

Ten fields, all required; a missing one is refused rather than defaulted,
because a blank reads as "any machine" three months later.

`image_source` · `image_digest` · `signature_verification` ·
`digest_verification` · `created_at` · `cpu_architecture` ·
`debian_version_id` · `builder_tool_version` · `backend` · `execution`

It carries `NON-RELEASABLE / EVALUATION ONLY` and has no `compatibility_claim`,
`signature`, `signed_artifact_digest`, `release_channel`, `supported`,
`reproducible` or `selected_builder` field. A record that cannot carry a claim
cannot be read as making one.

## What this establishes, and what it does not

`doctor` has been run on this session's own machine. Its answer:

```
shared_kernel: ready (ok)
host_platform: ready (ok)
virtualisation_backend: missing (host_backend_unavailable)
free_space: missing (insufficient_free_space)
network_reachability: ready (ok)
existing_vm_collision: ready (ok)
privilege: ready (ok)
no_shared_folder: ready (ok)
no_usb_passthrough: ready (ok)
backend: none available
conclusion: prepare-host may not run
```

That is the whole of what has been established: **this machine cannot prepare a
build host**, for the two reasons named. No VM has been created, no image
downloaded, no package installed, and **C5 remains `inconclusive` /
`not_measured`** — see [the C5 page](c5-evaluation.md).

Creating one VM would establish that one VM exists. It would not establish
reproducibility ([ADR-0002](adr/0002-image-builder.md) D1.3 needs two
independent builders), support, or a builder selection
([ADR-0009](adr/0009-builder-and-writer-contract.md) D8 P7 is an ADR, never a
measurement). The plan reports all three as `False` and none of them is a field
anyone can set.
