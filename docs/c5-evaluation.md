# C5 evaluation — deterministic control of the initramfs

Status: **instrument built, candidate not measured.** The current recorded
result for `live-build` is **`inconclusive` / `not_measured`**: no evaluation
build has been run, because no Debian 13 / amd64 build host was available to the
session that built this instrument. No image exists, no initramfs has been
inspected, and **no builder is selected** — [ADR-0002](adr/0002-image-builder.md)
D2/D3/D4 stand and [#4](https://github.com/01rabbit/Azazel-Boot/issues/4) is open.

Related: [ADR-0002](adr/0002-image-builder.md) C5 and D4 ·
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
  "verdict": "inconclusive",
  "evidence_type": "not_measured",
  "faults": [],
  "build_host_count": 0,
  "detail": "this host is ubuntu 24.04 / x86_64; an evaluation build runs on debian 13 / x86_64 or not at all",
  "reproducibility_established": false,
  "selects_a_builder": false
}
```

That is the gate's own output, produced by running `check_build_host` against
the session's `/etc/os-release`. The session had Ubuntu 24.04 and no
`live-build`, so the build did not happen and the result says so.

`inconclusive` is a first-class answer here. An evaluation that cannot run
records that it did not run; it does not leave a blank that later reads as a
pass, and it does not substitute the tool's documentation for a measurement.

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

One thing: a Debian 13 / amd64 host with `live-build` installed, an evaluation
build run there under §4's constraints, and an inspector that reads §3's four
facts out of the resulting initramfs. Until then this document records an
instrument and an `inconclusive`.
