# bytepin-next11-r7 prototype evidence

This is an evaluation-only Debian 13 amd64 build. `live-build` was used only
to construct a prototype; no production builder was selected. QEMU evidence
below is not hardware, firmware, or Secure Boot evidence.

## Inputs and Build B artifact

- Input manifest SHA-256: `53c698cae31ecfa0f42b13e48494383ee98dd20d4e8dc536d48632c61aa4e347`
- Toolchain lock SHA-256: `e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`
- Debian snapshot: `20260914T120000Z`; `SOURCE_DATE_EPOCH=1789387200`.
- Verified Debian 13 cloud base image SHA-256:
  `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`.
- Build B completed in one disposable QEMU TCG VM and recorded matching
  manifest/frozen-input digests at start and end.
- Unsigned ISO SHA-256:
  `8eeae5cc3943331b3955be9fec51e448a980dbbbf452556aff84f4f4194903d3`.
- Kernel SHA-256:
  `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08`.
- Initramfs SHA-256:
  `e03344ac89a7848af7807ebc23ecca398c66e90a9f88ebcd4a7a192c30a8ba6e`.
- SquashFS SHA-256:
  `8ad909d6dc81c161c62f3876fc4f6757ff21bfbde48ee7d747c6cd871ecc1416`.
- Nexus prototype package SHA-256:
  `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1`.
- Build result: `azazel-payload/build-result@4`, non-releasable/evaluation-only.
  The complete input, lock, inspection manifests, and build result are in
  [`r7 Build B output`](../artifacts/prototype/2026-09-25/bytepin-next11-r7/build-b/output/).

Build A did not complete: live-build failed during cleanup because
`/root/output/work/chroot/proc` was busy. A fresh A retry was stopped while
still in debootstrap to prioritize the corrected r8 A/B measurement. Its
partial output is not treated as a build result. **r7 reproducibility was not
measured**; one successful build is not an A/B comparison.

## C5 initramfs inspection and QEMU

The successful build produced a machine-readable C5 manifest/result. Static
inspection passed for the built initramfs. The C5 manifest records two archive
segments and 1,669 entries, including quarantine ordering/content checks.

The Build B ISO booted to `multi-user.target` in q35 TCG with direct
kernel/initramfs invocation. C5 runtime fixture verdict: **FAIL**. The initial
quarantine marker observed zero devices, so pre-registration fixture
quarantine was not observed. The hotplug fixture reached read-only state and
helper activity was logged, but the frozen evaluator did not accept a complete
hotplug write-probe sequence; QMP timed out waiting for the required event.
Both test targets were regular-file-backed fixtures. The selected QEMU
write/write-zero tracepoints recorded no writes, but do not prove absence of
all host I/O or discard activity.

## Nexus installer/lifecycle QEMU E2E

The frozen Build B ISO's Nexus package installed with exit 0 and reported
status. A disposable signed-fixture test then used the direct `ModelImport`
API for offline generations 1 and 2 and rolled back to generation 1. Result:
**PASS for this limited test only**. Operational units remained masked; the
test did not use the product CLI import path or commissioned trust store, and
did not perform network fetch, provider admission, or Edge activation.

## Reproducibility and hardware disposition

There is no successful independent Build A in r7, so no reproducibility
verdict is recorded. The two QEMU fixture files were regular files; no host
block device, USB device, or internal disk was passed to the guest. Secure
Boot, firmware/bootloader path, real hardware quarantine, writer behavior,
and HIL evidence remain unverified. This artifact is not production-ready.
