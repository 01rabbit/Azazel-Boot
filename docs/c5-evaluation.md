# C5 evaluation — deterministic control of the initramfs

Status: **R11 prototype measured; static ordering/content inspection and
manifest-bound QEMU effective-policy reconciliation pass for regular-file
fixtures.** The original static policy result still records
`quarantine_not_persistent`; the separate QEMU evidence demonstrates the
userspace handoff for the measured fixture, not hardware. The initial scan
observed zero registered devices, so pre-registration quarantine remains
unobserved. See the [R11 report](prototype-evidence-boot-runtime-r11.md).
This is evidence about this prototype only: **no production builder is selected**, and
[ADR-0002](adr/0002-image-builder.md) D2/D3/D4 and [#4](https://github.com/01rabbit/Azazel-Boot/issues/4)
remain open.

The recorded evaluation used disposable Debian 13 / amd64 build environments
and QEMU amd64 emulation on an Apple Silicon host. This does not select a
production builder or establish hardware behavior. The P2 host bootstrap plan
and `doctor` describe a separate builder workflow; their earlier
`host_backend_unavailable` observation is not the current C5 evidence. See
[the CLI page](p2-builder-cli.md).

Related: [Builder CLI](p2-builder-cli.md) ·
[P2 host bootstrap plan](p2-host-bootstrap-plan.md) · [ADR-0002](adr/0002-image-builder.md) C5 and D4 ·
[ADR-0008](adr/0008-debian-13-live-baseline.md) D2 ·
[ADR-0009](adr/0009-builder-and-writer-contract.md) D8 P2 ·
[Build environment](build-environment.md) · [Quarantine policy](quarantine-policy.md)

## 1. What C5 asks, and why it goes first

> **C5 — Deterministic control of the initramfs.** The host-storage quarantine
> must be the first thing the initramfs does and must survive into userspace. A
> builder that generates the initramfs from host state, from an opaque vendor
> hook, or from an ordering Boot cannot pin, cannot deliver the product's
> defining safety property. This criterion is the one most likely to eliminate
> an otherwise attractive tool.
> — [ADR-0002](adr/0002-image-builder.md) D3

[ADR-0009](adr/0009-builder-and-writer-contract.md) D8 puts it first in the
evaluation order for that reason: it eliminates, and evaluating it first stops
effort accumulating around a tool that cannot carry the quarantine.

## 2. The candidate

`live-build`, on Debian 13 / amd64. It is listed because
[ADR-0008](adr/0008-debian-13-live-baseline.md) D2 records it as **the builder
the baseline is written against — a constraint on the open selection, not the
selection**. Nothing in this repository adopts it, and `Candidate` in
`tools/builder/candidates.py` has no field that could record adoption.

## 3. What a measurement must establish

C5 is decided from the **built image**, never from documentation
([ADR-0002](adr/0002-image-builder.md) D4.1). An inspector must read out:

- the ordered list of hooks that run in the initramfs;
- a digest for each hook's contents;
- where each hook came from — pinned by Boot, a builder default, or derived
  from the build host;
- every path and argument a hook carries.

`tools/builder/initramfs_c5.py` then refuses the build if any hook cannot be
pinned:

| Fault | What it means |
| --- | --- |
| `order_not_determined` | contents without order is not control, and C5 is about control |
| `quarantine_not_first` / `order_changed` | something runs before the quarantine exists, or the pinned order moved |
| `hook_missing` / `unpinned_hook` | Boot's set is not what is in the image |
| `provenance_unknown` | the builder cannot say where a hook came from, so Boot cannot pin it |
| `host_path_dependence` | the image is a function of the machine it was built on |
| `shell_fragment` | a hook carries an input nobody reviewed |
| `digest_missing` | there is nothing to pin the hook *to* |

## 4. Where an evaluation build may run

Inside a dedicated **Debian 13 / amd64** build environment, and nowhere else. An
evaluation is a build, so it inherits every constraint a build has: the output
goes to a temporary directory outside every Git working tree, the artifact
record carries `NON-RELEASABLE / EVALUATION ONLY`, and nothing is signed,
published, or written to any medium ([ADR-0009](adr/0009-builder-and-writer-contract.md)
D8.1, [build environment](build-environment.md) §4).

**No USB device, no internal disk, no release channel and no signed product
artifact is touched by an evaluation.**

## 5. The recorded result

```json
{
  "candidate": "live-build",
  "verdict": "pass",
  "evidence_type": "measured_on_a_built_initramfs",
  "faults": [],
  "boot_image_policy_result": {
    "faults": [],
    "verdict": "pass"
  },
  "build_host_count": 1,
  "detail": "one build host; C5 is a property of this build, and C1 is untouched",
  "reproducibility_established": null,
  "selects_a_builder": false
}
```

The R11 record is the retained prototype measurement. Its static C5 inspection
reported no ordering/content faults, while the nested boot-image policy result
retained `quarantine_not_persistent` pending runtime evidence. Manifest-bound
QEMU reconciliation then observed the userspace handoff, read-only state,
`EPERM` write denial, and unchanged regular-file fixture digests. The initial
scan saw zero registered devices, so pre-registration quarantine remains
**NOT_OBSERVED**. No persistence filesystem was mounted. The generated ISO,
kernel, and initramfs were removed locally; the [R11 report](prototype-evidence-boot-runtime-r11.md)
and compact JSON results remain. The recorded ISO digest cannot be rechecked
without rebuilding.

These observations are limited to the measured prototype. QEMU does not prove
firmware/bootloader behavior, Secure Boot, physical-media safety, full-lifecycle
no-host-write behavior, or production-builder suitability. Do not promote the
result to hardware or release evidence.

The measured `fail` is a first-class result, not a production-builder decision.
It must not be upgraded to pass based on a successful boot, matching A/B
digests, or a fixture file remaining unchanged.

## 6. What a passing C5 would and would not establish

A `pass` would mean **this build, on this host, was pinnable**. It would not
mean:

- that the build is reproducible — that is C1, it needs two independent
  builders ([ADR-0002](adr/0002-image-builder.md) D1.3), and `C5Result`
  reports `reproducibility_established: false` whatever the verdict;
- that `live-build` is selected — a selection is an ADR
  ([ADR-0009](adr/0009-builder-and-writer-contract.md) D8 P7), and
  `selects_a_builder` is false always;
- that the tool is supported. There is no `supported` verdict.

If the candidate cannot satisfy C5, it is **removed from the candidate set**
rather than argued into passing. That is what "the criterion most likely to
eliminate an otherwise attractive tool" means in practice.

## 7. What would change the recorded result

The C5 result changes only after a revised prototype is built and its actual
initramfs passes the ordering, hook pinning, and content checks in §3, followed
by runtime evidence that quarantine is established before host-storage
processing and persists into userspace, including a successful hotplug write
probe. Quarantine must be the first initramfs action and remain effective
through userspace; mere presence of a hook or marker is not a pass. The r8
static result passes, but its QEMU runtime result remains failed as described
above. Hardware-only and Secure-Boot claims require separate hardware
evidence.
