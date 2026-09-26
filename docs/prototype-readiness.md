# Prototype readiness matrix

This is the hand-off point from design and fixture work to measured prototype
artifacts. A fixture result is never promoted to hardware or release evidence.
The latest Boot runtime prototype is R11: a manifest-bound remaster of a
previous measured ISO that cold-booted in QEMU with a regular-file block-device
fixture, reached userspace, and reconciled the static quarantine policy fault
against a same-session userspace handoff. The clean live-build attempt stalled;
R11 is not a clean rebuild or independent reproducibility measurement. The
latest clean A/B reproducibility and Nexus fixture lifecycle evidence remains
r10, summarized below as historical evidence. The initial C5 scan still saw no
registered devices, so pre-registration quarantine remains unobserved. No
persistence filesystem, physical medium, hardware, firmware, Secure Boot or
production-builder claim follows from these runs. See the [R11 report](prototype-evidence-boot-runtime-r11.md)
and the [historical r10 report](prototype-evidence-bytepin-next11-r10.md).

| Area | Current state | Evidence | Remaining gate |
| --- | --- | --- | --- |
| Nexus platform | Debian 13 amd64 unsigned ISO, kernel, initramfs, SquashFS and `.deb` generated from frozen inputs. ISO SHA-256 `4520a6aa7a98a0b849f87f39dbcfb42fb84cb955a1bb127e1fe4bb937033321a`. | [r10 evidence](prototype-evidence-bytepin-next11-r10.md), [Build A](../artifacts/prototype/2026-09-26/bytepin-next11-r10/build-a/output/build-result.json), [Build B](../artifacts/prototype/2026-09-26/bytepin-next11-r10/build-b/output/build-result.json) | Hardware validation remains open |
| Nexus lifecycle | **Limited r10 QEMU E2E passed:** install, status, fixture generations 1→2 and rollback to 1. Serial report frame complete (12/12 chunks, expected/received length and digest match). Direct fixture `ModelImport` only; no product CLI or commissioned trust store. | [r10 guest report](../artifacts/prototype/2026-09-26/bytepin-next11-r10/qemu/nexus-e2e-a/guest-report.json), [r10 result](../artifacts/prototype/2026-09-26/bytepin-next11-r10/qemu/nexus-e2e-a/result.json) | Exercise product CLI import and commissioned store when available |
| Nexus authority | Installer remains outside decision/enforcement authority. Operational units remained masked; provider admission, network fetch and Edge activation were not performed. | [r10 guest report](../artifacts/prototype/2026-09-26/bytepin-next11-r10/qemu/nexus-e2e-a/guest-report.json) | Preserve the existing authority boundary |
| Boot platform | R11 Debian 13 amd64 payload reached multi-user under q35 TCG with direct kernel/initramfs invocation. Firmware/bootloader path was not tested. | [R11 evidence](prototype-evidence-boot-runtime-r11.md) | Firmware, Secure Boot and hardware gates remain open |
| Initramfs C5 | R11 static ordering/content inspection and manifest-bound QEMU effective-policy reconciliation pass. The static result remains unchanged with `quarantine_not_persistent`; QEMU observed the matching userspace handoff, RO state, `EPERM` write denial and unchanged fixture digests. Initial scan reported zero registered devices, so pre-registration quarantine is `NOT_OBSERVED`. No persistence filesystem was mounted. | [R11 evidence](prototype-evidence-boot-runtime-r11.md) | Observe pre-registration devices; mount and validate actual persistence media; measure full-lifecycle hardware behavior |
| Boot recovery #47 | `BootSession` owns the five-attempt budget. | Boot tests and session regression tests | Exercise across real reboot/session boundaries |
| Boot boundary #49 | Static/runtime guard work exists in core modules. | Boundary and Boot tests | Adversarial checks against eventual image tooling |
| Payload | R11 unsigned ISO SHA-256 `3aa21d1c9c97dd74a5d981d17216738e16c2c066cb01dba454cd30e76a297dfa`; no Azazel signature/release envelope. Secure Boot was not tested. `live-build` was used for evaluation only; R11 was a remaster after the clean build stalled. | [R11 evidence](prototype-evidence-boot-runtime-r11.md) | Production builder remains unselected |
| Builder | **Not selected.** `live-build` remains evaluation-only. | [r8 Build B result](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-b/output/build-result.json) | Evaluate selection criteria and make a separate decision |
| Reproducibility | Strict comparison reports `reproduced`, `first_divergence: null`; all 16 checks including unsigned ISO, kernel, initramfs, SquashFS, rootfs, ISO/EFI and Nexus package match. Two clean VMs shared one Apple Silicon host/QEMU TCG. `/var/lib/dpkg/info` had identical observed size/allocation in r10; the earlier reported size difference was not explained and did not recur. | [r10 comparison](../artifacts/prototype/2026-09-26/bytepin-next11-r10/build/reproducibility-result.json), [r10 evidence](prototype-evidence-bytepin-next11-r10.md) | Measure across independent hosts/builders before broader reproducibility claims; investigate historical allocation observation only if it recurs |
| QEMU | R11 cold-booted with regular-file-backed vda attached before kernel start, reached userspace, denied tested writes and preserved fixture digests. Firmware/bootloader path was not exercised. r10 remains the latest Nexus lifecycle E2E. | [R11 C5/QEMU report](prototype-evidence-boot-runtime-r11.md), [r10 Nexus result](../artifacts/prototype/2026-09-26/bytepin-next11-r10/qemu/nexus-e2e-a/result.json) | Not hardware, Secure Boot, firmware, persistence-media mount, or full boot-path verification |
| Hardware / writer | **Unverified.** No USB or host disk writes were performed; no host block device was attached. | [r10 evidence](prototype-evidence-bytepin-next11-r10.md) | Keep hardware-only gates open; any future writer target must be a regular file or explicitly created test loop device |

## Next implementation phase

r10 is the latest A/B and runtime fixture evidence. The next prototype work is
to measure the actual persistence-device mount/handoff path and then hardware
gates when hardware is available; do not repeat the same build absent a changed
input or an identified build defect. Keep the initial marker's zero-device
observation, lack of mount evidence, static `quarantine_not_persistent` result,
and limits of selected QEMU tracepoints visible. This remains a prototype, not
production readiness.
