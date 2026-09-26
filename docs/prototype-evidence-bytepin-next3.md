# Prototype evidence: bytepin-next3 payload and guest integration

Date: 2026-09-25 (Asia/Tokyo)

> Historical run record. This run was superseded by the current
> [prototype readiness matrix](prototype-readiness.md) and later
> [`bytepin-next18` evidence](prototype-evidence-bytepin-next18.md). Its
> measurements remain preserved. It does **not** select a
production builder or establish hardware, Secure Boot, release, or writer
safety. `live-build` remains prototype construction only.

## Outcome

| Measurement | Result |
| --- | --- |
| Payload | Unsigned Debian 13.7 amd64 live ISO; 346,030,080 bytes; SHA-256 `6c2d55bf21f1d2b32a0f74f2d3102cecd0d455ff5f08ad484ff3b5a274735819` |
| Initramfs | Inspected; 40,749,452 bytes, 1,661 entries across two archive segments; SHA-256 `8c29fd461ca298c0dce836d8c0451776d47584a6699b1b5af9c0e2064c9c501b` |
| Static C5 | **FAIL**: automount rule present, quarantine not persistent, four unpinned hooks, and effective hook order differs from the pinned policy |
| QEMU boot | Generated kernel/initramfs booted Debian 13 to `multi-user.target` under QEMU 10.0.2 / q35 / TCG |
| Runtime C5 | **FAIL**: no initramfs quarantine event or persistence marker; sysfs and `blockdev` read-only flags false; read-only write probe not denied |
| Nexus guest E2E | **PASS with scoped evidence**: source-bundle installer exit 0, operational units masked, status exit 0; generation 1/2 import/rollback passed in a disposable guest fixture using direct API calls |
| Authority boundary | Guest report records network fetch, provider admission, Edge activation, hardware verification and Secure Boot verification all false |
| Reproducibility | **Reproduced** across two independent clean Debian 13 amd64 builder VMs: payload, kernel, initramfs, SquashFS and all 13 comparison checks match |
| Production/hardware | Production builder unselected; hardware-only gates remain open |

## Inputs and artifacts

Authoritative evidence directory:
[`artifacts/prototype/2026-09-25/bytepin-next3/`](../artifacts/prototype/2026-09-25/bytepin-next3/)

| Item | Identity / evidence |
| --- | --- |
| Frozen manifest | SHA-256 `f4937131b3d559cffdc45270e01ca6323028ef9a2a3124294d230adda33cc0e3`; schema 3, 31 frozen input records |
| Build recipe | SHA-256 `93b50b3b43af3da5ac695fa4200b51ccfdb4a318ffd65b12fc270b57d27d5f6f` |
| Toolchain lock | SHA-256 `e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`; exact Debian package/version closure |
| APT repository | Debian snapshot `https://snapshot.debian.org/archive/debian/20260914T120000Z/`, trixie/main; pinned source file SHA-256 `f70ee8c1aabce3facf4a16a26dd601af7d1a3429b46af997590b36b2c42bc85e` |
| Debian base image | Debian 13 genericcloud amd64; SHA-256 `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f` |
| Builder seed | SHA-256 `32531c2d23b34f08bb486eee34a5f88856c9501e41ef7f02ce760cf89c00d61b` |
| Nexus source bundle | 84 source files; SHA-256 `97903b739b7d3f13efb175cef340f27167c61e084f329933622450cd1f4a0595` |
| Builder | Two separate qcow2 overlays and machine identities, same base and seed, Debian 13 amd64 guests on Apple Silicon/QEMU TCG; `live-build-evaluation-only` |

Each build directory (`build-a/`, `build-b/`) retains the ISO, kernel,
initramfs, frozen manifest and sidecar, package list, build result, C5
manifest/result, initramfs listing/metadata, component digests and build log.
Its `evidence-file-digests.sha256` is a portable relative-path inventory; it
was regenerated after artifact collection and successfully verified in both
build directories with `sha256sum -c`.
The measured SHA-256 values were identical for A/B:

| Artifact | SHA-256 |
| --- | --- |
| `payload.iso` | `6c2d55bf21f1d2b32a0f74f2d3102cecd0d455ff5f08ad484ff3b5a274735819` |
| `vmlinuz` | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` |
| `initrd.img` | `8c29fd461ca298c0dce836d8c0451776d47584a6699b1b5af9c0e2064c9c501b` |
| `work/binary/live/filesystem.squashfs` | `ef0751c6c07279adec7e40fe80ec0ad912e5788dfb481dfb62eb7cb14bd753d8` |

## C5 inspection and fixture

The measured Build A/B machine-readable `c5-manifest.json` and `c5-result.json`
are retained in each build directory. The initramfs inspection identifies two
segments (uncompressed newc and zstd), 1,187 and 474 entries respectively.
The policy result is `fail` with these concrete findings:

- `automount_rule_present`: `60-cdrom_id.rules` is present;
- `quarantine_not_persistent`: no continuous userspace quarantine is proven;
- `unpinned_hook`: `all_generic_ide`, `blacklist`, `keymap`, and `udev` are in
  the initramfs outside the pinned Boot hook set;
- `hook_order_changed`: effective init-top order does not match the pinned
  policy set/order.

The C5 result's top-level evaluator summary has its own compact fault enum and
per-build host count; the nested `boot_image_policy_result.faults` above is
the detailed four-fault image-policy evaluation. The A/B reproducibility
comparison is a separate measurement and passed; the per-build C5 summary is
not a substitute for that cross-build comparison.

The separate QEMU C5 fixture record is at
[`qemu-c5/result.json`](../artifacts/prototype/2026-09-25/bytepin-next3/qemu-c5/result.json).
The guest reached `multi-user.target`, but `initramfs_event_count` is 0,
`event_before_persistence_before_multi_user` is false,
`sysfs_read_only` and `blockdev_read_only` are false,
`write_probe_denied_by_read_only` is false, and the persistence marker is
false. The explicitly created 32 MiB regular-file fixture remained bytewise
unchanged; that is not evidence of read-only enforcement. No host block device
or USB device was passed through. C5 remains a blocking prototype gate.

## QEMU Nexus guest E2E

The rerun result is
[`qemu-nexus-e2e-verified/result.json`](../artifacts/prototype/2026-09-25/bytepin-next3/qemu-nexus-e2e-verified/result.json),
and the parsed guest report is retained beside it. The host runner's initial
attempt missed JSON prefixed by systemd journal metadata; a parser fix and
regression test were added, then the same built payload was rerun successfully.
No payload input changed for this host-only parser correction.

The guest exercised:

1. Real offline installer invocation: exit code 0; seven operational units
   masked; activation controller enabled but not started.
2. Verification/status path: command exit code 0 and a status report returned.
3. **Fixture-only** signed offline import: generation 1 (`prototype-one`) and generation 2
   (`prototype-two`); both verified as present before rollback.
4. Rollback: generation 1 restored/current; generation 1 remains present and
   generation 2 becomes declared.

This was not a Nexus `.deb` installation: the ISO contains the offline source
bundle and prototype installer, which unpack the core/runtime Python trees and
then invoke the existing `packaging/install.sh`. The fixture imports use a
temporary root under `/var/tmp`, synthetic model files, an ephemeral signing
key, an injected trust-key map, and direct `ModelImport` API calls; they do not
exercise the commissioned trust store, CLI import path, or ordinary persistent
data root. The report records `verdict: pass`, with network fetch, provider admission,
Edge activation, hardware verification, and Secure Boot verification all
false. The guest QEMU command disabled networking and passed no host block or
USB device. This test does not cover disable/uninstall, firmware/bootloader
entry, hardware behavior, or production deployment.

## Reproducibility and verification

[`reproducibility-comparison.json`](../artifacts/prototype/2026-09-25/bytepin-next3/reproducibility-comparison.json)
records `result: reproduced`, no first divergence, identical manifest,
recipe, toolchain lock and source date epoch, and all 13 checks true. The
comparison covers EFI/boot components, ISO files/metadata, initramfs bytes and
archive structure/order/metadata, kernel, SquashFS, rootfs contents and
metadata. Earlier measurement noise from host extraction inode values and
initramfs extraction directory mtimes is explicitly normalized by the
comparator; payload bytes are not altered to force equality.

Verification performed for this working tree:

- Azazel payload and test suite: **40 passed**;
- `ruff check tools/payload tests`: pass;
- payload shell syntax, Python compilation, and `git diff --check`: pass;
- Nexus offline-bundle targeted tests: **6 passed**; targeted lint passed in
  the recorded run;
- Boot full suite rerun with Python 3.12: **1,235 passed, 5 skipped**. A first
  invocation through the host's Python 3.10 `pytest` shim failed because
  `tomllib` is unavailable on 3.10; no code was changed for that environment
  mismatch;
- supplied historical baselines (not rerun here): Nexus targeted **50
  passed**, umbrella integration **2 passed**;
- Nexus repository-wide lint still has the known 53 unrelated warnings; none
  were changed as part of this work.

## Remaining blockers and limits

- **Blocking prototype issue:** C5 ordering/content does not establish
  host-storage quarantine before storage can be written. Implement and
  measure Boot-owned quarantine before storage driver/device discovery.
- Nexus guest E2E now works for install/status/import/rollback; disable and
  uninstall remain unexercised in this QEMU guest workflow.
- No complete firmware/bootloader path, physical hardware, internal-disk
  no-write, USB identity/write, Secure Boot, dirty-shutdown recovery, or real
  hardware recovery-budget result is established.
- Production builder selection remains open; this run is not a selection
  decision. No USB write, physical disk write, or host internal-disk writer
  target was used.

No ADR or authority boundary was changed. Installer/import did not gain
provider-admission or Edge-activation authority.
