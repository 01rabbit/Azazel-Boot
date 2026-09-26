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

This compact result reflects the **static inspection only**. The latest
machine-readable output's top-level C5 inspection verdict is `pass`, but its
nested boot-image policy result is `fail` pending runtime persistence evidence.
The bounded QEMU runtime fixture result is separately recorded as `pass`; it
does not retroactively rewrite the static result or prove full C5/hardware
behavior.

The latest measurement is bytepin-next11-r10. It pinned the predecessor
`quarantine.v1` artifact and selected `azazel_boot.quarantine`, not
`session_mode.py`, as Boot source. The current local policy is `quarantine.v2`,
so r10's measurements are evidence for its own frozen v1 inputs only and are
not evidence that a built image implements the v2 all-device/all-action scope.
Its [input manifest](../artifacts/prototype/2026-09-26/bytepin-next11-r10/input/prepared/build-input-manifest.json)
has SHA-256
`5a336d28693ad19dad7355c4823e518f090475c0be355828aa86dda10feb72bc`. Build A
and B produced identical unsigned ISO SHA-256
`4520a6aa7a98a0b849f87f39dbcfb42fb84cb955a1bb127e1fe4bb937033321a`; their
strict component comparison reports reproduced. The [static result](../artifacts/prototype/2026-09-26/bytepin-next11-r10/build-a/output/c5-result.json)
contains the nested `quarantine_not_persistent` failure. The [QEMU runtime
fixture result](../artifacts/prototype/2026-09-26/bytepin-next11-r10/qemu/c5-a/result.json)
is bounded to regular files and passes its runtime checks: initramfs `/dev/vda`
is made read-only before a one-byte write is attempted; `openat` succeeds and
the actual `write()` returns `-1 EPERM` while sysfs/blockdev RO are set. The
initial marker reported zero devices, so quarantine before kernel registration
is `NOT_OBSERVED`; the fixture was quarantined after registration and before
the probe. After multi-user, QMP hotplug of `/dev/vdb` was recognized through
udev and the quarantine helper; RO transitioned `0→1` and the subsequent write
returned `EPERM`. Raw enforcement ioctl tracing was not observed.

The userspace handoff marker and session/boot ID validation pass in this
fixture, but its device is explicitly `not_mounted`; no persistence filesystem
or encrypted persistence-media mount is demonstrated. QEMU write traces cover
only selected tracepoints, not all possible host I/O. Firmware, Secure Boot,
hardware HIL, stable physical-media identity, full-lifecycle no-write behavior,
and production-builder selection remain open. A separate
[post-build policy reconciliation](../artifacts/prototype/2026-09-26/bytepin-next11-r10/qemu/c5-policy-reconciliation.json)
re-ran the pinned Boot policy with the measured handoff fact and passed; the
original build-time manifest/result remain unchanged and retain the
`quarantine_not_persistent` pending-runtime finding. This does not establish a
persistence filesystem mount or any hardware-only property. See the [complete
prototype evidence report](prototype-evidence-bytepin-next11-r10.md).

The previous measured candidate was bytepin-next11-r8. Its frozen
[input manifest](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-a/output/build-input-manifest.json)
has SHA-256
`9f01979e8dd7e107cbaa88481bd7c96eb40ab13214bd4865f5cca51297d55c098`.
Its [static C5 manifest](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-a/output/c5-manifest.json)
has SHA-256
`2e1c05ef13bd3b7c4c5491b4e7631af1dd2bd8426f65be677a72750398f9faf5`, and
the [static result](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-a/output/c5-result.json)
is **pass** with no faults. The pinned initramfs execution sequence is:
`az-quarantine-block-devices`, `az-disable-resume`,
`az-disable-automount`, `az-disable-volume-assembly`,
`az-mark-boot-medium`, `az-start-udev`, `az-handoff-udev`. The manifest records
all seven hooks as `pinned_by_boot`, with per-hook digests and ordered execution
indices; the last hook is in `init-bottom`. Static manifest field
`quarantine_persists_into_userspace` is null and
`runtime_persistence_evidence_required` is true, so static inspection alone
does not claim persistence.

The [r8 QEMU regular-file fixture result](../artifacts/prototype/2026-09-25/bytepin-next11-r8/qemu/c5-build-b/result.json)
is **fail**. The guest reached `multi-user.target`; the initramfs `/dev/vda`
write probe and userspace persistence probe both reported read-only denial, and
the userspace handoff marker verified the quarantine state. However, the
hotplug `/dev/vdb` path set read-only state but emitted no write-probe event:
the helper logged `quarantine/probe origin and mode do not match` after being
invoked with origin/mode arguments it rejected, and the runner timed out waiting
for that event. Therefore the hotplug write-denial evidence is missing and the
runtime C5 verdict remains **fail**. The initial quarantine marker recorded
`devices=0` before fixture registration; pre-registration quarantine of the
fixture is **NOT_OBSERVED** (it was only seen after kernel registration).
The r8 inputs froze before the source-level fail-closed change that rejects
missing (`None`) userspace-persistence evidence; that change was tested
separately and is not part of this r8 payload. Hardware and Secure Boot remain
unverified.

The following bytepin-next4 record is **historical**, superseded as the latest
measurement by r8, and retained for comparison. Its
[input manifest](../artifacts/prototype/2026-09-25/bytepin-next4/input/prepared/build-input-manifest.json)
has SHA-256
`75c72c1061507b6aca8f70a04e894cec79622340388bb26254de1d12a81ccef4`.
Build A's machine-readable
[C5 manifest](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/c5-manifest.json)
records initramfs SHA-256
`97f4f96021fe6cafd8c5922d79f30e005b8581913e76eac0aeba5bcfb3cb4469` and
payload SHA-256
`5bf6f0e13c9fff2ef0d5dd25fc1569113b2efc54d4224bc365f9ae04b539ce45`. The
[static result](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/c5-result.json)
is **fail**, with faults `hook_order_changed`, `order_changed`,
`quarantine_not_persistent`, and `unpinned_hook`. In the inspected initrd,
the observed init-top sequence is `00-az-quarantine-block-devices` (pinned),
`10-resume`, `20-automount`, `30-volume assembly`, `40-mark-medium`, followed
by the builder-default hooks `all_generic_ide`, `blacklist`, `keymap`, and
`udev`. The quarantine hook being present and first among the pinned hooks
does not make the full sequence pinned or satisfy C5. In particular, the
manifest reports `quarantine_persists_into_userspace: false`.

The separate
[QEMU regular-file fixture result](../artifacts/prototype/2026-09-25/bytepin-next4/qemu/c5-a/result.json)
also says **fail**. Under q35 TCG, direct kernel/initramfs boot reached
`multi-user.target`, but the serial log reports “C5 fixture write failed for
an unverified reason”; there is no structured initramfs event, no persistence
marker, and the report does not establish read-only state or denial of writes.
The fixture hook loads `virtio_blk`, waits for `/dev/vda`, and then applies
`blockdev --setro`; this does not prove quarantine before kernel device
registration. The 32 MiB regular-file fixture attached as `/dev/vda` had an
unchanged digest, which is not proof of write denial. No host block device was
passed through; no USB or NIC was attached. This is not physical-device,
firmware/bootloader, or Secure Boot verification. The result explicitly records
`hardware_verified: false` and `secure_boot_verified: false`.

These next4 results are historical prototype evidence, not a change to an ADR
or to the C5 success criteria. The historical bytepin-next3 evidence is
retained at its existing paths and is not overwritten by the next4 record.

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
