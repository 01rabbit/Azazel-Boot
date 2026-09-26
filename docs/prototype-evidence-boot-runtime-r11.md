# Boot runtime r11 prototype evidence

Run date: 2026-09-26. This is an unsigned Debian 13 amd64 prototype, not a
release image. It does not select a production builder or establish hardware,
firmware, Secure Boot, or writer safety evidence.

## Artifact and inputs

- ISO: `artifacts/prototype/2026-09-26/boot-runtime-r11/output/payload.iso`
- Size: 396,689,408 bytes
- SHA-256: `3aa21d1c9c97dd74a5d981d17216738e16c2c066cb01dba454cd30e76a297dfa`
- Input manifest: `artifacts/prototype/2026-09-26/boot-runtime-r11/input/build-input-manifest.json`
- Input manifest SHA-256: `e36d116ccec45750b84c7d2765094128b8a724e45b91273172cf96a2ae8eeb9a`
- Boot source: `24593009a1c268459a64e3a1c1dc874f1dee4da7`, dirty-tree digest recorded
  in the manifest. Azazel source: `1e74d82d4025f1860fec9e7ffddd1d879ca8d5a0`,
  dirty-tree digest recorded in the manifest.
- Tool versions and build disposition: `output/build-result.json` and
  `input/toolchain-lock.json`.

The ISO remains at the local artifact path above and is intentionally not
tracked in Git: it is 396,689,408 bytes, exceeding GitHub's ordinary per-file
limit. The commit carries its SHA-256, manifest, and inspection/QEMU evidence;
the remote repository does not host the ISO binary.

The clean live-build attempt was stopped during the chroot `apt-get update`
after more than 20 minutes without package-index progress. No second clean
build was started. To finish the requested prototype, r11 was made as a
manifest-bound remaster of the prior measured ISO
(`13afbd43a2efdfef2792d2b3807267ddb2079d3a7b9fb60a21fd31edd90c7fae`). The
manifest comparison found only three image inputs changed: Boot `runtime.py`,
the C5 userspace probe, and the initramfs quarantine entry hook. The fourth
changed input was the host-side QEMU runner. The new SquashFS/initramfs were
generated from the parent image, Debian ISO checksums were refreshed and
verified, and xorriso replayed the existing BIOS/UEFI hybrid boot metadata.
This is not reported as a completed clean live-build or an independent build.

## C5 and QEMU

Static inspection: C5 hook content and `/init` call ordering were measured from
the generated initramfs and rootfs (`output/c5-manifest.json`,
`output/c5-result.json`, and `output/initramfs-inspection.json`). The evaluator
has no ordering/content faults. Static image-policy evaluation retains one
expected fault, `quarantine_not_persistent`: static inspection cannot establish
that the initramfs quarantine marker survives into the running userspace.

The QEMU C5 run used the final r11 ISO, kernel, initramfs and manifest. A
newly-created regular-file-backed `/dev/vda` was attached before kernel start;
the runner records `cold_boot_block_device_attached: true`. It reached
`multi-user.target`. After the fixture driver registered vda, initramfs
quarantined it before the write probe; sysfs and `blockdev` both reported RO,
the attempted write returned `EPERM`, and the backing-file digest was
unchanged. The userspace handoff marker had the same session ID as the guest
boot ID, explicitly named `/dev/vda`, and userspace confirmed RO state and a
read-only-policy write denial. A later QEMU hotplugged regular-file-backed
`/dev/vdb`; udev changed it to RO before the probe, the write returned `EPERM`,
and that backing-file digest was unchanged. Event ordering passed.

The same manifest-bound QEMU evidence reconciles the sole static
`quarantine_not_persistent` policy fault to effective image-policy `pass`.
The original static C5 result remains unchanged and records its limitation;
see `output/c5-qemu/c5-policy-reconciliation.json` and
`output/c5-qemu/result.json`.

Limits: the initramfs initial scan reported zero registered block devices.
Although QEMU attached vda from cold boot, the virtio block device was
registered only after the fixture hook loaded its driver; pre-registration
device quarantine is therefore `NOT_OBSERVED`. The observed guarantee is
quarantine immediately after registration and before the fixture write probe.
No persistence filesystem was mounted. This QEMU file fixture is not hardware,
firmware, Secure Boot, USB-writer, or comprehensive host-I/O evidence. The
kernel/initramfs path was booted directly with the ISO attached; a firmware or
bootloader launch was not measured.

## Verification and remaining work

For the source snapshot bound by the input manifest, Boot full unit tests
reported 1,258 passed and 5 skipped; this turn's targeted runtime/quarantine
tests reported 120 passed. Azazel tests reported 156 passed, 1 skipped, and 78
passing subtests; this turn's targeted C5/initramfs tests reported 93 passed
and 69 passing subtests. Changed-file Ruff checks, shell syntax checks, and
`git diff --check` passed. The full and targeted test totals overlap; they are
not additive. These software results do not exercise hardware.

No USB write, physical-device write, laptop boot, firmware/NVRAM change, Secure
Boot change, or host block-device attachment was performed. Production builder
selection, independent clean-build reproducibility, device registration before
the initial quarantine scan, real persistence-media mount behavior, full
firmware/bootloader verification, and all hardware-only gates remain open.
Issues are not closed by this QEMU result where their acceptance criteria
require runtime composition integration or hardware evidence.
