# bytepin-next11-r6 prototype evidence

This record describes a non-releasable Debian 13 / amd64 prototype built with
`live-build` for evaluation only. It does not select a production builder.
Build A and Build B ran in separate clean Debian VMs on the same Apple Silicon
host; this is not an independent-host reproducibility claim.

## Inputs and payload

- Input manifest: `sha256:ea1feb131ca0ddd3a78a9bc00fdf23fab983435533101d0f94ee09c20b300e49`
- Toolchain lock: `sha256:e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`
- Verified Debian 13 cloud base image: `sha256:5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`
- Repository snapshot: `20260914T120000Z`; `SOURCE_DATE_EPOCH=1789387200`.
- Package request set: `live-boot`, `live-config`, `initramfs-tools-core`,
  `strace`, `linux-image-amd64`, `python3`, and `openssl`; the complete resolved
  lock and package closure are in the input manifest and `filesystem.packages`.
- Both input manifests and selected source repository states are recorded in
  each build output. All three source repositories were dirty at build time;
  the manifest binds their recorded worktree-status hashes and selected input
  digests.
- Unsigned immutable ISO SHA-256 (A and B):
  `763c1cccaf8487e714d353a302ecca134ea77f224a867a212301eb76f2551cb4`.
- Kernel: `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08`.
- Initramfs: `db727b3f57e2cb930de3c0613138a3aa1f38618f41548fd6cdfe6ddcff6fdf65`.
- SquashFS: `1b8225c12f6af3d502ca4a0992ee8410215b17f43a7fb4cca5232a32205182e7`.
- Nexus prototype `.deb`: `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1`.

## C5 static inspection

The generated initramfs inspection passed: two archive segments and 1,669
entries. The machine-readable C5 manifest records the quarantine call directly
in `/init` after pseudo-filesystem setup and before `maybe_break`, init-top
hooks, module loading, and any non-pseudo mount. It records no forbidden
storage command or non-pseudo mount before quarantine; the single insertion
matches the pinned Debian init template. The C5 static result is PASS with no
faults, measured against the built initramfs. This proves ordering/content in
this image, not that every host device was already registered and quarantined.

## QEMU C5 runtime

The guest reached `multi-user.target`. The initial marker was emitted with
`devices=0`; therefore pre-registration quarantine of the fixture was **not
observed**. The initial `/dev/vda` fixture was subsequently made read-only in
initramfs: `BLKROSET` returned 0, sysfs and `blockdev` reported RO, it remained
unmounted, the observed write syscall was denied with `EPERM`, and its regular
file backing digest was unchanged.

After multi-user, a regular-file-only QMP hotplug fixture appeared as
`/dev/vdb`. Its serial and udev add provenance were recorded; the helper
successfully transitioned sysfs and `blockdev` RO from 0 to 1 before any mount,
and its backing digest remained unchanged. The selected QEMU write/write-zero
tracepoints recorded zero writes to either fixture. This is a limited trace
scope, not comprehensive host-I/O proof.

**Overall C5 QEMU runner verdict: FAIL.** The hotplug write-probe unit did not
produce the required structured probe event; the guest logged
`quarantine/probe origin and mode do not match`, and the runner timed out
waiting for its complete hotplug evidence chain. The parser also rejected the
hotplug udev-provenance record. Thus the observed RO transition and unchanged
fixture are useful partial evidence, but not a passing end-to-end quarantine
gate. The exact helper argv was not captured, so the instance-expansion cause
is a strong diagnosis rather than an argv-level measurement. No claim is made
that QEMU proved pre-registration quarantine of the fixture.

## Nexus installer/lifecycle QEMU E2E

Result: PASS for this limited test only. The ISO-embedded prototype package was
checksum-checked, installed with exit 0, and the installer/status checks
completed. Operational units remained masked and the activation controller
did not start. The guest then used a temporary signed fixture and direct
`ModelImport` API calls for two offline imports (generation 1 to 2), checked
the resulting fixture state, and rolled back to generation 1.

This did not exercise the product CLI import/verify path or commissioned
trust store; the signed fixture used a test-only key map. It did not exercise
network fetch, provider admission, Edge activation, or product-wide failure
atomicity. Installer package integrity was checked with a SHA-256 sidecar, not
an installer-signing trust store. Nexus reports that its hand-written Ed25519
verifier remains unsupported pending its separate review.

## Reproducibility

The strict post-build comparator reports `reproduced`, with
`first_divergence: null`; all listed kernel, initramfs, SquashFS, ISO/EFI,
rootfs, and Nexus package checks passed. Build A and B payload digests match
exactly. The C5 evidence manifest itself includes build-specific identity and
therefore has a different digest between builders; it is not confused with
the unsigned payload digest comparison.

| Artifact | Build A SHA-256 | Build B SHA-256 |
| --- | --- | --- |
| Unsigned payload ISO | `763c1cccaf8487e714d353a302ecca134ea77f224a867a212301eb76f2551cb4` | same |
| Kernel | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` | same |
| Initramfs | `db727b3f57e2cb930de3c0613138a3aa1f38618f41548fd6cdfe6ddcff6fdf65` | same |
| SquashFS | `1b8225c12f6af3d502ca4a0992ee8410215b17f43a7fb4cca5232a32205182e7` | same |

## Test and hardware disposition

The build result is marked `NON-RELEASABLE / EVALUATION ONLY`, with
`builder_selected_for_production=false` and `hardware_verified=false`. QEMU
used q35 with TCG and direct kernel/initramfs boot; it did not verify the
firmware/bootloader path or Secure Boot. No USB or host internal disk was
written or attached. Hardware-only gates remain open.

Verification after the follow-up source/test changes: Azazel `tests/` **152
passed, 1 skipped**; the focused C5/Nexus integration set **107 passed**;
targeted Ruff, shell syntax, and diff checks passed. Boot baseline remains
**1,245 passed, 5 skipped**; Nexus targeted baseline **50 passed** and umbrella
integration **2 passed**. Repository-wide Azazel lint still has 53
pre-existing warnings and was not broadened into cleanup. The systemd
hotplug-instance correction and the integration-fixture schema update are
after the frozen r6 input set; neither is included in these artifacts. The
hotplug correction therefore requires a new frozen input set, rebuild, and
QEMU measurement before it can be claimed as runtime-verified.

Evidence directory: `../artifacts/prototype/2026-09-25/bytepin-next11-r6/`.
