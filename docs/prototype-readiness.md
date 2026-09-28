# Prototype readiness

This is the concise hand-off from design and build tooling to future measured
prototype work. It records current limits; a QEMU result is never hardware or
release evidence.

| Area | Current state | Evidence / next gate |
| --- | --- | --- |
| Platform | Debian 13 Live / amd64 is the program baseline. | [ADR-0008](adr/0008-debian-13-live-baseline.md) |
| Build procedure | `tools/payload/build_candidate.sh` and its helpers construct an evaluation-only payload. `live-build` is not a production-builder selection. | See [build environment](build-environment.md), [builder CLI](p2-builder-cli.md), and [ADR-0002](adr/0002-image-builder.md). |
| R11 payload | An unsigned R11 remaster was generated and cold-booted to userspace under QEMU. Its ISO, kernel, and initramfs have been removed locally; recorded hashes are historical and the ISO cannot now be rehashed or written. | [R11 evidence](prototype-evidence-boot-runtime-r11.md), [input manifest](../artifacts/prototype/2026-09-26/boot-runtime-r11/input/build-input-manifest.json). Rebuild before further artifact inspection. |
| C5 quarantine | R11 static hook ordering/content inspection and manifest-bound QEMU policy reconciliation passed for regular-file fixtures. The initial scan observed zero devices, so pre-registration quarantine remains unobserved. No persistence filesystem was mounted. | [C5 static result](../artifacts/prototype/2026-09-26/boot-runtime-r11/output/c5-result.json), [QEMU result](../artifacts/prototype/2026-09-26/boot-runtime-r11/output/c5-qemu/result.json). Measure pre-registration and persistence-media behavior. |
| Reproducibility | No current build artifacts are retained for independent re-verification. Earlier same-host A/B measurements are historical only; they do not establish cross-host reproducibility. | Rebuild only for a changed input or a concrete verification need; production builder remains unselected. |
| Nexus lifecycle | No production install/import/activation capability is claimed by this Boot prototype. | Keep provider admission, network fetch, and Edge activation outside Boot's authority. |
| Hardware / writer | **Unverified.** No physical SSD write, laptop boot, firmware/NVRAM change, or Secure Boot test was performed. | Hardware-only gates remain open; the writer remains subject to its documented safety boundary. |

## Next work

Use the existing build procedure and pinned inputs; do not repeat historical
build iterations without a changed input or a specific evidence gap. Rebuild
the unsigned prototype when an artifact is needed, then separately complete
software review and the user-operated hardware gates. Do not describe QEMU as
hardware verification or the prototype builder as production-selected.
