# bytepin-next11-r9 prototype evidence

r9 is an unsigned Debian 13.7 amd64 evaluation payload built with
`live-build` in one clean disposable Debian 13 amd64 QEMU TCG VM. This is a
single-build measurement, not an A/B reproducibility run and not production
builder selection. The payload is non-releasable. QEMU is not hardware,
firmware, Secure Boot, or writer evidence.

## Inputs and artifacts

- Input manifest: [`build-input-manifest.json`](../artifacts/prototype/2026-09-25/bytepin-next11-r9/build/output/build-input-manifest.json), SHA-256 `61f4950c51b96b2126e9eacb585ef4f32bb0b8b9c93803205f97e5b16d13070d`.
- Toolchain lock SHA-256: `e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`.
- Prepared source archive SHA-256: `62391456fb6d51010c03589a73ff24f813ac61cc974fee2f0c2695dd07403a2c`.
- Debian snapshot: `https://snapshot.debian.org/archive/debian/20260914T120000Z/`; `SOURCE_DATE_EPOCH=1789387200`; locale `C.UTF-8`, timezone UTC, umask `022`.
- Debian 13 amd64 base image SHA-256: `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`.
- Builder seed SHA-256: `54b8f4d5533dc80bf64154cc3e12ac59658b107cbba88a192ea0b5a2ef539a35`.
- ISO SHA-256: `e4fa88252a26bdfee9cb042d65a99a12e59659693bf17da4f40a3398957f5cbd`.
- Kernel SHA-256: `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08`.
- Initramfs SHA-256: `2f666c15fadc8004033b7f6d4ee90268732ffff228f20004fefef07fbe43c644`.
- Build result SHA-256: `9351d68b880bcd8f63cfc0650c9c65b49c7c019b7aec658e400058413215af9d`.
- Nexus prototype `.deb` SHA-256: `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1`.
- Initramfs archive inspection: [`initramfs-inspection.json`](../artifacts/prototype/2026-09-25/bytepin-next11-r9/build/output/initramfs-inspection.json); static C5 content/order inspection itself passed. The [C5 result](../artifacts/prototype/2026-09-25/bytepin-next11-r9/build/output/c5-result.json) reports `quarantine_not_persistent`: the required runtime handoff value was intentionally still unknown at static-build time, so Boot's fail-closed static policy verdict is FAIL pending runtime evidence.

The reproducibility status for r9 is **not measured**. The earlier r8 independent clean-VM A/B comparison reproduced; that result does not transfer to r9.

## QEMU C5 measurement

The payload reached `multi-user.target` under q35 TCG with direct kernel/initramfs
boot. The QEMU [result](../artifacts/prototype/2026-09-25/bytepin-next11-r9/qemu/c5-build-r9/result.json)
is **FAIL**, despite successful boot and useful runtime observations:

- `/dev/vda` passed initramfs read-only enforcement and the userspace handoff/persistence checks. A write syscall was observed to fail with `EPERM` while both sysfs and block-device read-only state remained set.
- `/dev/vdb` was attached after multi-user. udev provenance was verified, the fixture transitioned from read-write to read-only, and its write probe was denied with `EPERM`; the regular-file fixtures' recorded before/after digests match.
- The frozen r9 helper's final event incorrectly emitted a DMI product hex string omitting `az`, although its fixture check and QEMU command used `Azazel C5 File Fixture`. Its `errno_name` extraction also had a malformed `sed` expression, so it emitted `write_errno=NOT_OBSERVED` despite the preceding EPERM write-probe record. The runner therefore marked aggregate hotplug enforcement/quarantine FAIL. These are evidence-instrumentation defects; they do not negate the directly recorded denied write, but the aggregate C5 verdict remains FAIL.
- The initial initramfs quarantine marker reported zero registered block devices because the fixture hook loads `virtio_blk` afterward. The same fixture was then registered, identity-checked/quarantined read-only, and probed before later userspace processing. The report correctly records device quarantine before registration as `NOT_OBSERVED`; this is not a claim that block-device registration itself must be preceded by identity-based RO enforcement. Preserve this distinction in C5 interpretation.
- Hotplug enforcement used the recorded `blockdev-setro` command and a measured RO-state transition; `strace` was unavailable in the udev service sandbox, so the raw enforcement ioctl syscall was not captured. The runner records this method explicitly rather than claiming raw syscall evidence.
- Selected QEMU write/write-zero tracepoints were empty; they do not establish comprehensive absence of host I/O.

The frozen r9 input runner SHA-256 was
`bebf5c634dd0c6d304de7d7b0f8d16eb9b1f94f86258c181eca669fea48c8585`.
The runtime measurement used a post-freeze host runner SHA-256
`742b32e046daaf758f0faecd1204bfe839c4092caa60f0755d3230e5d9972998` to allow
the explicitly pending static persistence gate to proceed to runtime measurement.
Payload inputs were not changed. See the machine-readable
[measurement context](../artifacts/prototype/2026-09-25/bytepin-next11-r9/qemu/c5-build-r9/qemu-measurement-context.json).
This provenance difference is disclosed; the post-freeze run does not replace
the frozen runner or turn the result into a fully frozen-harness pass. The
executed post-freeze runner source was not archived; its recorded digest cannot
now be independently recomputed from the saved bundle. The current working-tree
runner is a later revision and must not be substituted for it.

## Nexus and remaining gates

The limited Nexus installer/status/offline fixture import-generation/rollback
E2E passed on r8. r9 contains the same `.deb` digest, but **no separate r9 Nexus
QEMU E2E** was run. Product CLI import/verify and commissioned trust were not
exercised; operational units stayed masked; no network fetch, provider
admission, or Edge activation occurred.

No USB, physical device, host block device, or internal disk was attached or
written. Both QEMU targets were regular files in the evidence directory.
Secure Boot, firmware/bootloader path, HIL and hardware quarantine/write
behavior remain unverified. Production builder selection remains open.
