# Prototype evidence: bytepin-next4

Measured prototype evidence only; this is not a production, hardware, or
release qualification. The preserved [next3 record](prototype-evidence-bytepin-next3.md)
remains historical and is not changed by this update.

## Inputs and build environments

- Platform: Debian 13 / amd64. Two independent clean Linux build instances
  used the same input manifest, base image, seed, recipe, toolchain lock, and
  Debian snapshot.
- Input manifest SHA-256:
  `75c72c1061507b6aca8f70a04e894cec79622340388bb26254de1d12a81ccef4`
  ([manifest](../artifacts/prototype/2026-09-25/bytepin-next4/input/prepared/build-input-manifest.json)).
- Frozen manifest/input bundle SHA-256:
  `e03ebd2c87ad28d5b3b2248820e928a6dccfc70fb691308d890218e9e198b764`
  ([bundle](../artifacts/prototype/2026-09-25/bytepin-next4/input/prepared-inputs.tar.gz)).
- Toolchain lock SHA-256:
  `e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`
  ([lock](../artifacts/prototype/2026-09-25/bytepin-next4/input/prepared/frozen-inputs/toolchain-lock.json)).
- Recipe SHA-256:
  `9ad771ce4647cacb4f0472ed3d9fa61a25178d6be295dc621ea117ce966c3b8a`
  ([build recipe](../artifacts/prototype/2026-09-25/bytepin-next4/input/prepared/frozen-inputs/build_candidate.sh)).
- `SOURCE_DATE_EPOCH`: `1789387200`.
- Debian snapshot: [2026-09-14T12:00:00Z](https://snapshot.debian.org/archive/debian/20260914T120000Z/).
- Verified Debian 13 amd64 base image SHA-256:
  `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`.
- Builder instance ID hashes: A
  `8e19fa17a88c38356902a1c785cece4f9d77d38fa2a49f1e90d509786bb843e8`; B
  `5bd27a6510dc5a8cd4138d6c5bcab288cedfbceae0eb0d38f183a291e1109e89`.
- `live-build` was used for prototype construction/evaluation only. **No
  production builder has been selected.**

## Generated artifacts

The prototype ISO and Nexus `.deb` have no Azazel signature or release
signing envelope. Debian-signed boot packages may be included in the image;
their presence is not a Secure Boot test. The ISO contains the same tested
Nexus package in its root filesystem; build output and ISO-rootfs copy were
digest-checked.

| Artifact | SHA-256 | Evidence |
| --- | --- | --- |
| Debian 13 amd64 ISO | `5bf6f0e13c9fff2ef0d5dd25fc1569113b2efc54d4224bc365f9ae04b539ce45` | [ISO](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/payload.iso), [build result](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/build-result.json) |
| Kernel | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` | [vmlinuz](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/vmlinuz) |
| Initramfs | `97f4f96021fe6cafd8c5922d79f30e005b8581913e76eac0aeba5bcfb3cb4469` | [initrd](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/initrd.img), [entry listing](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/initramfs-entry-listing.txt), [inspection](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/initramfs-inspection.json) |
| SquashFS | `1769383cc6d0f32f988b6dae1d8c6fc1aaf8dd549c0324b28c4e031d109e6ba1` | [built filesystem](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/work/binary/live/filesystem.squashfs), [ISO-extracted copy](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/iso-extracted/filesystem.squashfs) |
| Nexus Debian package | `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1` | [`.deb`](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/azazel-nexus-prototype.deb), [package summary](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/nexus-package-summary.json) |

Package identity: `azazel-nexus-prototype`, version `0.0.1~prototype1`,
architecture `all`.

## C5 inspection and runtime fixture

**Static C5 verdict: FAIL.** The machine-readable
[manifest](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/c5-manifest.json)
records the built initramfs digest, hook paths, order and provenance. The Boot
quarantine hook is observed as the first `init-top` entry, before subsequent
default hooks. That local ordering observation does not satisfy C5: the
evaluator reports `hook_order_changed` / `order_changed`, `unpinned_hook`, and
`quarantine_not_persistent`. The sequence then contains the unpinned builder
defaults `all_generic_ide`, `blacklist`, `keymap`, and `udev`. Persistent
quarantine before storage writes is not established. See the
[static result](../artifacts/prototype/2026-09-25/bytepin-next4/build-a/c5-result.json).

**QEMU C5 fixture verdict: FAIL.** QEMU reached `multi-user.target`, but the
fixture hook printed `C5 fixture write failed for an unverified reason`; the
expected structured event and persistence marker were absent. The explicitly
created regular-file fixture was unchanged, but this does **not** show it was
read-only. The hook's control flow indicates that its block-device and sysfs
read-only flag checks passed before the write probe, but the probe returned an
error the hook did not recognize as verified read-only denial. The QEMU result
therefore does not record those flags or prove write-denial semantics. No
quarantine success is claimed. The fixture hook itself loads `virtio_blk` and
waits for `/dev/vda`, so this run also does not establish isolation before
kernel device registration. See the
[fixture result](../artifacts/prototype/2026-09-25/bytepin-next4/qemu/c5-a/result.json),
[serial log](../artifacts/prototype/2026-09-25/bytepin-next4/qemu/c5-a/serial.log),
and [fixture file](../artifacts/prototype/2026-09-25/bytepin-next4/qemu/c5-a/quarantine-fixture.raw).

## QEMU and Nexus E2E

The generated payload booted under q35 TCG amd64 emulation using direct
kernel/initramfs boot. The Nexus E2E result is **PASS**:

- Actual `dpkg` installation of the package in the image root filesystem
  exited 0; seven operational units were masked.
- Activation controller was enabled but not started; `status` exited 0.
- Disposable-fixture import exercised generations 1→2 and rollback restored
  generation 1, using direct `ModelImport` API calls.
- This did not use the commissioned product trust store or product CLI import
  path. It is not persistent-store/product lifecycle qualification.
- Provider admission, network fetch, and Edge activation were all false.

Evidence: [initial Build A guest report](../artifacts/prototype/2026-09-25/bytepin-next4/qemu/nexus-e2e-a/guest-report.json),
[initial QEMU result](../artifacts/prototype/2026-09-25/bytepin-next4/qemu/nexus-e2e-a/result.json),
and the independent [post-reproduction Build B guest report](../artifacts/prototype/2026-09-25/bytepin-next4/qemu/nexus-e2e-post-repro-b/guest-report.json),
[QEMU result](../artifacts/prototype/2026-09-25/bytepin-next4/qemu/nexus-e2e-post-repro-b/result.json),
[serial log](../artifacts/prototype/2026-09-25/bytepin-next4/qemu/nexus-e2e-post-repro-b/serial.log).
The post-reproduction result binds the same manifest, ISO, kernel, initramfs,
and Nexus package digests as Build B; its result JSON SHA-256 is
`ae21b3e9feba0337671b3d1f0cf487271c8981a56c7496952ed8cc455b12af98`.
QEMU used no NIC, USB passthrough, or host block device. The ISO's firmware/
bootloader route was not tested. **Hardware and Secure Boot verification are
false; no host disk or USB writes were performed.**

## Reproducibility

**Byte-identical: yes.** Builds A and B were performed in the two independent
clean instances above, with identical manifest, recipe, epoch, base, seed,
snapshot, and locked toolchain inputs. The
[comparison report](../artifacts/prototype/2026-09-25/bytepin-next4/reproducibility.json)
reports `reproduced`, `first_divergence: null`, and all comparator checks true.
ISO, kernel, initramfs, SquashFS, and Nexus package digests matched exactly.
No mismatch classification was needed.

## Open gates

- C5 remains **FAIL** in both static inspection and QEMU fixture testing. The
  first `init-top` entry observation must not be mistaken for effective,
  persistent quarantine before device/storage writes.
- Production builder remains unselected; `live-build` remains evaluation-only.
- Hardware, Secure Boot, firmware/bootloader boot path, real storage behavior,
  and hardware writer safety remain unverified. No USB or host-disk write was
  attempted.
- Nexus package install/status and disposable import/rollback passed only
  within the limits above; product trust-store, CLI import, and persistent
  commissioned-store integration remain open. The guest status also marks the
  hand-written Ed25519 implementation as unsupported pending Nexus#70 review;
  this prototype E2E does not resolve that review.
