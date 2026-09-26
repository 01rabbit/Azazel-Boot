# Prototype evidence: byte-pinned payload A/B

Date: 2026-09-25 (Asia/Tokyo)

> Historical candidate record. It is superseded by the current
> [prototype readiness matrix](prototype-readiness.md) and
> [`bytepin-next18` evidence](prototype-evidence-bytepin-next18.md). The
> measurements below remain preserved as historical evidence.

This is a later, final-candidate measurement supplement to
[`prototype-evidence-20260925.md`](prototype-evidence-20260925.md). It does not
replace the earlier failed attempts in that report. It records two successful
independent clean builds from a byte-pinned bundle and the subsequent QEMU
measurement. It is prototype evidence only: live-build remains evaluation-only,
the payload is unsigned, and hardware/Secure Boot/writer gates remain open.

## Outcome

| Measurement | Result |
| --- | --- |
| Build A and B | Both completed in separate fresh Debian 13 amd64 QEMU builder overlays; each emitted the full machine-readable evidence set |
| Payload | Unsigned Debian 13 amd64 live ISO, 338,690,048 bytes; SHA-256 `421771067f8bc162aa79077b93224ac898076929e74cdba52a1138981ceebe2a` in both builds |
| Kernel | SHA-256 `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` in both builds |
| Initramfs | SHA-256 `8c29fd461ca298c0dce836d8c0451776d47584a6699b1b5af9c0e2064c9c501b` in both builds; 2 segments, 1,661 newc entries |
| SquashFS | SHA-256 `d57a63fef5d530ebec2dd86216917829849041183cb1e857455bffa75bbd8b2f` in both builds |
| Static C5 inspection | **FAIL** on A and B; see the measured faults below |
| QEMU boot | **Reached `multi-user.target`** under QEMU 10.0.2 / q35 / TCG, booting the generated kernel/initramfs and mounting the generated ISO as live media |
| C5 quarantine fixture | **FAIL**: hook ran before `/dev/vda` was registered; no read-only state, rejected write probe, or persistent quarantine marker was evidenced |
| Nexus source-backed E2E | **14 passed, 3 not executed, 0 failed**; this is the existing fixture harness, not an installation into the generated guest |
| Reproducibility | **Reproduced bit-for-bit** for kernel, initramfs, SquashFS, ISO, initramfs archive/order, rootfs contents, and semantic metadata |

The machine-readable comparison is
[`artifacts/prototype/2026-09-25/bytepin-final/reproducibility-result.json`](../artifacts/prototype/2026-09-25/bytepin-final/reproducibility-result.json).
The original frozen comparator treated host extraction inode numbers and
initramfs directory mtimes rewritten during extraction as payload divergence.
After classifying those observations against the exact matching archive and
image digests, a post-build analyzer revision excludes only host inode numbers
and initramfs extraction-time directory mtimes. All 13 comparison checks then
pass. The report records both the revised analyzer hash and the pinned
build-time comparator hash. No artifact bytes were changed to force a match.

## Inputs and provenance

The same 66,765-byte input manifest is retained with each build. Its SHA-256 is
`ce70ecb25f9b6dc201fb6ebfc88feceadde10cdd699a23c36b17434ac895cbe4`. The
manifest binds the recipe, all frozen tooling, the policy/evaluator, source
repository commit and dirty-worktree hashes, base image, builder seed, package
versions, and C5/QEMU inspection code.

| Input | Pinned value |
| --- | --- |
| OS / architecture | Debian 13 (trixie) / amd64 |
| Debian repository | `https://snapshot.debian.org/archive/debian/20260914T120000Z/` (`main`) |
| Builder package closure | 333 exact package/version entries; lock SHA-256 `2c7719169b4ae65ce94bc26b38d33cfbd46e26da790fe55d81bca36c3679db33` |
| `SOURCE_DATE_EPOCH` | `1789387200` |
| Debian cloud base image | SHA-256 `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f` |
| Builder seed ISO | SHA-256 `9c031eaec60c9d38ac158bf4e7ca8c26aca37f51298a59116ae206e7749e0adb` |
| Frozen input source archive | SHA-256 `8c44bc1701a1538a5c326fda90db83142afc3cb2a1fe8d397b2b631aeb6caab5` |
| Builder candidate | `live-build-evaluation-only`; production builder selection remains false |
| Build separation | Two distinct qcow2 overlays and machine IDs, same verified base and read-only seed; both ran as separate Debian amd64 QEMU guests on Apple Silicon/TCG |

Exact manifest, package lock, frozen source bundle, payloads, component reports,
initramfs listing/metadata, C5 manifests/results, build logs, and QEMU fixture
outputs are retained under
[`artifacts/prototype/2026-09-25/bytepin-final/`](../artifacts/prototype/2026-09-25/bytepin-final/).
The four identical artifact digests are recorded above and in the comparison
JSON. Build A and B `build-result.json` files bind their reports and artifacts
to the same manifest digest.

## C5 inspection and QEMU boundary

The frozen Boot C5 evaluator returned **FAIL** for both measured initramfs
images. The machine-readable faults are:

- `unpinned_hook`: Debian's `all_generic_ide`, `blacklist`, `keymap`, and `udev`
  hooks are also present;
- `hook_order_changed`: the effective hook set/order is not the pinned policy
  set;
- `automount_rule_present`: CD-ROM udev automount rules are in the image;
- `quarantine_not_persistent`: an early-initramfs decision has no proven,
  continuous userspace enforcement record.

The QEMU runner attached only the explicitly created 32 MiB regular file
`qemu-c5-fixture/quarantine-fixture.raw` as `/dev/vda`; no host block device,
USB passthrough, network, or automatically selected writer target was used.
At the first init-top hook, serial output recorded `C5 fixture block device is
absent`. The kernel registered virtio-blk and `/dev/vda` later, after that
hook. The boot reached `multi-user.target`, but the persistence probe failed
closed because the quarantine marker was never established. The file digest
was unchanged (`e09320c5b00b34bb704802136c599a95b3996332ba84d7c7f21112b6231b6bd0`)
before and after; this is **not** a read-only proof. The recorded fixture
result is `fail` with `sysfs_read_only=false`,
`blockdev_read_only=false`, `write_probe_denied_by_read_only=false`, and
`quarantine_marker_persisted_into_userspace=false`.

This identifies a concrete C5 integration blocker: storage driver/device
registration currently occurs after the init-top quarantine hook in this
prototype. A normal-file QEMU result would still not establish real-machine
coverage. The static C5 gate stays open.

## Nexus integration

The Nexus test harness was rerun against a fresh temporary root. It passed the
source-backed install-files, commissioning, verified generation, activation,
status, injected failure, rollback/remask, audit, and offline fixture stages:
14 passed, 0 failed. Account creation/ownership, systemd enforcement, and the
dependent inventory stage were not executed (no root and no running systemd).
See [`nexus-e2e-report.md`](../artifacts/prototype/2026-09-25/bytepin-final/nexus-e2e-report.md)
and [`nexus-e2e-result.json`](../artifacts/prototype/2026-09-25/bytepin-final/nexus-e2e-result.json).

The generated payload package closure does not contain Python 3 or a packaged
offline Nexus installer/runtime bundle. Therefore the harness result is not a
claim that the final ISO ran `install → verify/status → generation → rollback`.
That guest integration remains blocked on distributing the installer runtime
and package artifacts; no installer authority was expanded.

## Verification and remaining gates

- Azazel payload/provenance/C5/normalization/reproducibility targeted suite:
  **26 passed**.
- Boot full suite on Python 3.12: **1,235 passed, 5 skipped**.
- Nexus source-backed harness: **14 passed, 3 not executed, 0 failed**.
- Changed-scope Ruff checks and `git diff --check`: pass. The known 53
  repository-wide Nexus lint warnings remain pre-existing and untouched.
- Umbrella integration baseline remains **2 passed**; it is not a substitute
  for the Nexus guest-install run.

Still open: implement Boot-owned quarantine before storage driver/device
discovery; package the offline Nexus runtime; validate the complete ISO
firmware/bootloader route; exercise real systemd/service accounts; select a
production builder via ADR; and perform hardware/Secure Boot and physical
writer testing on an explicitly authorized test device. No such hardware
verification or device write is claimed here.
