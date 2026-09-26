# Prototype evidence: bytepin next10

Measured prototype status only. This record does not select a production
builder and does not claim hardware, firmware, or Secure Boot verification.

## Frozen inputs and builder environments

- Target: Debian 13.7 / trixie, amd64.
- PREPARE manifest SHA-256: `f6059ea8dc9e9d84301fca8fd893136528e9f76f95372abf4e136a6f7bdbf59f`.
- Prepared-input archive SHA-256: `37a28709441152ac988746e3f9bec350374caff88d5645db50677b45b30186f2`.
- Debian repository: signed snapshot `https://snapshot.debian.org/archive/debian/20260914T120000Z/`.
- SOURCE_DATE_EPOCH: `1789387200`.
- Base cloud image SHA-256: `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`.
- Builder seed ISO SHA-256: `5a7beb9f1f19229cdbb3ec84d1cbf221eb502b166fae34a2f2a364ab4a278c3a`.
- Nexus selected-source bundle SHA-256: `97903b739b7d3f13efb175cef340f27167c61e084f329933622450cd1f4a0595`.
- A and B used distinct clean Debian VM overlays and machine IDs, each with its own 6 GiB qcow2 workspace disk attached as `/dev/vdb` and formatted ext4. Builds ran q35/TCG; no host block device or USB passthrough was used.
- `live-build` was used only to construct this evaluation prototype. Production-builder selection remains open.

See the [input manifest](../artifacts/prototype/2026-09-25/bytepin-next10/input/prepared/build-input-manifest.json), [A build result](../artifacts/prototype/2026-09-25/bytepin-next10/build-a/build-result.json), and [B build result](../artifacts/prototype/2026-09-25/bytepin-next10/build-b/build-result.json).

## Artifacts and digests

Both independent builds completed. The unsigned ISO artifact is 346,030,080
bytes and has SHA-256:

`43e8ae98accb9bee4c20ad6034d47e10b0438c5220ac0878bcfeff93dc99ff27`

The following A/B artifact digests are identical:

| Artifact | SHA-256 |
| --- | --- |
| Payload ISO | `43e8ae98accb9bee4c20ad6034d47e10b0438c5220ac0878bcfeff93dc99ff27` |
| Kernel | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` |
| Initramfs | `2204d1be7a2cc345c3bbf5888e6efeef0b0c76a2167379e963e07ed88df9e19f` |
| SquashFS | `e29b47dbaef495a185229e2cfd1e1d736381bec424764f329a0e8c0129bb386f` |
| Nexus prototype `.deb` | `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1` |

This is an unsigned prototype with no Azazel release/signature envelope. Debian
boot packages may be signed by Debian; that is not Secure Boot verification.

## C5 inspection and QEMU fixture

Static C5 inspection passed for both builds. The machine-readable C5 manifest
records `order_established=true`, image-policy verdict `pass`, and
`quarantine_persistence_declared_in_initramfs_and_rootfs=true`. The initramfs
and rootfs copies of `/usr/libexec/azazel-quarantine-block` have the same SHA-256
(`2d42671938a21d3ed1adf896cc0f90d33b37e9ef20154d57a621d57de4d2124c`). The
strictly pinned Debian 13 `99-systemd.rules` curation is valid: source digest
`d63ba2ea309aadf7794a5f84b0f394c2e48fe630640aa37e9963cd9d1b769d89`, curated
file digest `2d7221d25ef5e04a6a076c407653b45f032b84413293f6964dc5e10a2911b1e8`,
and exactly the two recorded fuse/configfs pseudo-mount requests were removed.

The QEMU guest reached multi-user and emitted
`AZAZEL_C5_INITRAMFS_QUARANTINE state=active devices=1 udev_rule=present`.
However, the runtime fixture verdict is **fail**:

- The initramfs write probe did not produce the required EROFS event, so the
  userspace persistence probe failed and no userspace persistence event was
  observed. The guest-side helper did not preserve its exact write-probe error
  text, so that errno classification remains unknown.
- QMP hotplug successfully attached the second regular-file fixture after
  multi-user using an explicit PCIe root port, but no hotplug-quarantine event
  followed. Both fixture file digests remained unchanged.
- The final QEMU C5 runner was modified after the frozen build to add the
  hotplug root port and correct the manifest digest prefix check. Its SHA-256 is
  `e7f2cd6e46636b597c6533cbac78a38c431ecf10d727b2c345273bad4d64a95a`, whereas
  the build result binds the earlier runner
  `9c37819dedc21875bfa19dbf356f4fbb6d158205c3d31d373f6f733ab4ac04f3`.
  Treat the QEMU C5 run as post-build diagnostic evidence, not as evidence from
  the exact frozen runner.

Therefore static ordering/content inspection passes, but runtime persistence,
hotplug quarantine, and isolation before kernel device registration remain
unproven. The fixture does not establish hardware host-storage safety.

Evidence: [C5 manifest](../artifacts/prototype/2026-09-25/bytepin-next10/build-a/c5-manifest.json), [static result](../artifacts/prototype/2026-09-25/bytepin-next10/build-a/c5-result.json), [QEMU result](../artifacts/prototype/2026-09-25/bytepin-next10/qemu/c5-a-final/result.json), [serial log](../artifacts/prototype/2026-09-25/bytepin-next10/qemu/c5-a-final/serial.log).

## QEMU and Nexus lifecycle

The next10 payload reached Debian multi-user under q35 TCG using direct kernel
and initramfs boot. The QEMU guest had no NIC, USB, or host block-device
passthrough. The next10 test service printed `AZAZEL_NEXUS_E2E_PASS`; its guest
operations include package installation, `status` exit 0, two disposable model
imports advancing generation 1→2, and rollback to generation 1. But the host
runner stopped on a partial serial JSON line before multi-user/report capture,
so the next10 wrapper verdict is **fail: guest_report_malformed_json** and is
not counted as validated E2E. A host-only polling fix was added afterward to
wait for a partial final JSON line, but the runner correctly refused the
next10 artifact because its digest no longer matches the frozen manifest; that
fix has not been validated against a rebuilt payload.

The independent next9 QEMU run has a complete host-validated pass for the same
Nexus installer/package workflow: [next9 guest report](../artifacts/prototype/2026-09-25/bytepin-next9/qemu/nexus-e2e-a/guest-report.json), [next9 result](../artifacts/prototype/2026-09-25/bytepin-next9/qemu/nexus-e2e-a/result.json). Its disposable import used the direct `ModelImport` API, not the product CLI or commissioned trust store. Provider admission, network fetch, and Edge activation were false/not performed. The next9 payload predates the initramfs helper-path correction, so it is evidence for Nexus lifecycle only, not C5.

No firmware/bootloader path, Secure Boot, hardware, or production deployment
behavior is established.

## Reproducibility result

The comparator result is **not reproduced** under its full checks. Fifteen of
sixteen checks passed. The only divergence is `rootfs_metadata`: the
`var/lib/dpkg/info` directory size is 49,152 bytes in A and 61,440 bytes in B,
while mode, owner, and pinned timestamp match. Rootfs file contents are equal
(15,395 entries); kernel, initramfs, SquashFS, Nexus package, ISO boot/filesystem
metadata, and final ISO digest are equal. This points to ext4 directory
allocation/layout variance before SquashFS packaging; it does not change the
measured final payload bytes. No normalization was added to hide the difference.

See the [full comparator report](../artifacts/prototype/2026-09-25/bytepin-next10/reproducibility.json).

## Verification and remaining gates

- Payload C5-measurement tests: 36 passed.
- QEMU C5 and Nexus runner tests: 18 passed.
- Targeted Ruff, shell syntax, and `git diff --check`: passed.
- Existing Boot baseline: 1,245 passed, 5 skipped. Existing Nexus targeted baseline: 92 passed. Existing umbrella integration baseline: 2 passed; unrelated full-suite/audit failures and 53 repository-wide Nexus lint warnings remain out of scope.
- Hardware-only gates stay open: real storage, reboot/session boundaries, firmware/bootloader, Secure Boot, physical writer behavior, and target hardware. No USB writes or internal-disk writes were performed.

Changed implementation is limited to C5 measurement/copy-path and QEMU
evidence-handling fixes plus their tests. No ADR, authority boundary, or
production-builder decision was changed.
