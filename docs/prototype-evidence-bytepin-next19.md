# Prototype evidence: bytepin next19

Measured prototype evidence only. This does not select a production builder or
claim release readiness, firmware-path verification, Secure Boot, or hardware
verification. `live-build` is used for prototype construction only. QEMU had no
USB or host block-device pass-through; all C5 writer fixtures were explicitly
created regular files. No ADR or Edge/Nexus authority boundary is changed.

## Frozen inputs and build environments

- Target: Debian 13 / amd64; package source snapshot:
  `https://snapshot.debian.org/archive/debian/20260914T120000Z/`.
- `SOURCE_DATE_EPOCH=1789387200`; toolchain lock SHA-256:
  `e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`.
- Authoritative final input manifest SHA-256:
  `e996c58b1cfe15add41610fa2a190a66793c575df5785c42e9e15bb56c56ffac`.
- Final prepared-input archive SHA-256:
  `3a89c7158b9d96b2679f5d11beaa7608ef0ded9f106993b145a0c96c55e8dc93`.
- Pinned Debian cloud base-image SHA-256:
  `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`;
  builder seed ISO SHA-256:
  `80ab8714a6f3c66d60e6255f5ce3927fc2f5e950ce8b30ab050664c613e197ce`.
- The final manifest, its sidecar, prepared bundle/archive, base image, and
  seed are preserved under
  [`artifacts/prototype/2026-09-25/bytepin-next19/input/`](../artifacts/prototype/2026-09-25/bytepin-next19/input/).
  `input/prepared/` is a superseded, unused draft; both builds used only
  `input/prepared-final/` and its pinned archive.
- A and B used separate fresh Debian VM overlays and workspace disks from the
  same pinned base/seed, on this single Apple Silicon host under QEMU TCG.
  Their recorded builder-instance hashes differ. Both verified the same frozen
  input manifest and tree before/after build. This is two clean build
  environments, not independent builder infrastructure. The input manifest
  records dirty source worktrees by commit and status digest; the frozen tree
  hashes and archive digest bind the actual inputs. `builder_selected_for_production=false`.

## Generated unsigned artifacts and reproducibility

Build A and B completed with `lb build` and emitted the same unsigned ISO and
the same kernel, initramfs, SquashFS, and Nexus prototype package digests:

| Artifact | SHA-256 (A = B) |
| --- | --- |
| Unsigned Debian 13 ISO (`payload.iso`) | `6a4d9bf52b93e35576456b3825a2bdd80d04a9e7872a5a7841e87eae148c63dd` |
| Kernel (`vmlinuz`) | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` |
| Initramfs (`initrd.img`) | `41609b305ea88df78b85fbbc933b8e3e058e3d769c7dcac5185cdf9c6176629a` |
| SquashFS | `1698aec1240064e2b8408dfc4744d6a278e9c31c33b418cc2fb552ae6dbffcfd` |
| Nexus prototype `.deb` | `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1` |

The ISO is 349,175,808 bytes. Each build-result binds manifest digest
`e996c58b…56ffac`; the per-build `evidence-file-digests.sha256` checks all
passed after transfer to the host. See [build A](../artifacts/prototype/2026-09-25/bytepin-next19/build-a/output/build-result.json),
[build B](../artifacts/prototype/2026-09-25/bytepin-next19/build-b/output/build-result.json),
and the [frozen input manifest](../artifacts/prototype/2026-09-25/bytepin-next19/input/prepared-final/build-input-manifest.json).

The payload digest reproduced across these builds. The strict rootfs-extraction
diagnostic comparison did not report byte/metadata-observation identity:
39,526 exact observation mismatches were recorded, chiefly 38,440 stat-field
observations (ctime/inode, plus a small number of size/block fields), 1,080
raw directory readdir-order observations, and mount/statvfs observations.
The comparator did not normalize them. This classifies host extraction
metadata/order variance, not a payload-byte mismatch: payload, SquashFS,
initramfs, kernel, package, and package/file-content digests match. C5 manifest
files differ only in their intentionally distinct `build_host_id`; both carry
the same image and initramfs digests and each static verdict is pass. See the
[strict comparison report](../artifacts/prototype/2026-09-25/bytepin-next19/rootfs-extraction-comparison.json)
and each build's raw
[A](../artifacts/prototype/2026-09-25/bytepin-next19/build-a/output/rootfs-extraction-diagnostics.json)/
[B](../artifacts/prototype/2026-09-25/bytepin-next19/build-b/output/rootfs-extraction-diagnostics.json)
observations. This result does not establish reproducibility on another host.

## Initramfs inspection and C5 ordering

The generated initramfs has two archive segments and 1,669 entries. The
machine-readable [C5 manifest](../artifacts/prototype/2026-09-25/bytepin-next19/build-a/output/c5-manifest.json)
and [static C5 result](../artifacts/prototype/2026-09-25/bytepin-next19/build-a/output/c5-result.json)
pass. Inspection establishes the quarantine entry call directly after
pseudo-filesystem setup and before `maybe_break`, init-top hooks, module loading,
and other inspected storage-sensitive setup; no forbidden storage command or
non-pseudo mount was found before quarantine. This is ordering/content evidence
for the initramfs, not evidence that quarantine precedes kernel block-device
registration.

## QEMU boot and runtime quarantine fixture

The exact Build A kernel/initramfs booted with its ISO under QEMU 10.0.2 x86_64
TCG and reached `multi-user.target`. The
[C5 QEMU result](../artifacts/prototype/2026-09-25/bytepin-next19/qemu/c5-a/result.json)
records ordered runtime events: initramfs quarantine marker, fixture probe,
userspace persistence/handoff, multi-user, then QMP hotplug and hotplug
quarantine. Initial `/dev/vda` was read-only and its one-byte fixture write
probe was denied with `EPERM`; userspace retained read-only state. Hotplug
`/dev/vdb` transitioned from writable to sysfs/blockdev read-only. Both backing
targets were new regular files under the evidence directory, and their
before/after hashes match. The observed hotplug quarantine and write-probe
events are in [serial.log](../artifacts/prototype/2026-09-25/bytepin-next19/qemu/c5-a/serial.log).

The overall C5 runtime verdict is **FAIL / incomplete**, deliberately. The
hotplug safety gate could not read the guest serial identity
(`disk_serial_read_status=NOT_OBSERVED`, zero serial bytes), so its destructive
write probe was withheld. Therefore this run does not prove hotplug write
denial; unchanged fixture digest and the limited QEMU trace do not substitute
for that missing probe. The serial gate remains fail-closed. Also, the runner
explicitly does not claim quarantine before kernel block-device registration,
comprehensive host I/O coverage, hardware quarantine, or Secure Boot. Static
C5 inspection and the runtime quarantine observations are positive evidence,
but they are not promoted to a full C5 pass.

## Nexus installer and generation/rollback E2E

The [Nexus QEMU result](../artifacts/prototype/2026-09-25/bytepin-next19/qemu/nexus-e2e-a/result.json)
and [guest report](../artifacts/prototype/2026-09-25/bytepin-next19/qemu/nexus-e2e-a/guest-report.json)
pass within their test-only scope. In the disposable guest the Nexus package
was installed, `status` succeeded, two signed offline fixtures were imported
as generations 1 and 2, both verified, and rollback returned the current
generation to 1. Generation work used the direct `ModelImport` API, not the
product CLI import path or a commissioned product trust store. The NIC was
disabled; network fetch, provider admission, and Edge activation were false.
This is not Mission Pack E2E and does not grant Installer/fetcher/import any
new authority.

## Verification and remaining gates

- Frozen-input verification: pass; both build-result manifests bind the final
  input digest. The per-build artifact/evidence digest lists: all pass.
- Targeted Python tests: **96 passed, 1 skipped, 52 subtests passed**. The skip
  is the host macOS filesystem's lack of non-UTF-8 filename support. Targeted
  Ruff unused-name checks (`--select F`) and the focused shell syntax checks
  pass. The repository-wide baseline still has 53 unrelated lint warnings;
  unrelated lint/refactoring was not included. A broader existing umbrella
  run previously reported 2 unrelated Boot quarantine persistence failures in
  the neighboring audit worktree; they were not changed here.
- Build A/B unsigned payload reproducibility: **pass** for the digests listed
  above; strict extracted-rootfs metadata/order comparison: **not identical**,
  with raw differences retained and classified above.
- QEMU boot and bounded Nexus installer/status/generation/rollback: **pass**.
  Static C5 inspection: **pass**. Runtime quarantine fixture: ordered and
  read-only behavior observed, but overall **fail/incomplete** because the
  hotplug serial identity gate withheld its write probe.
- Hardware-only gates remain open: independent physical builder infrastructure,
  firmware/bootloader path, Secure Boot, physical-media/HIL lifecycle, and
  hardware storage-quarantine/persistence evidence. No USB write or host
  internal-disk writer was used.

No existing issue met its full acceptance criteria, so none was closed:

| Issue | Remaining acceptance gap |
| --- | --- |
| Azazel-Boot #4 | Production builder decision, full C1–C9 evaluation, independent build infrastructure, and complete C5 evidence. |
| Azazel-Boot #6 | Hardware persistence and no-write HIL evidence. |
| Azazel-Boot #26 | Independent infrastructure and cross-platform artifact-record parity. |
| Azazel-Boot #28 | Complete C5 continuity/persistence/export conditions and independent review; hotplug write probe remains unobserved. |
| Azazel-Nexus #3 | Mission Pack admission, staged review, atomic activation, rollback/audit, and authority-boundary E2E. |
| Azazel-Nexus #93 | Complete provider-setup-to-admission/activation flow and HG-05 evaluation. |

The most immediate follow-up blocker is the C5 fixture's unreadable hotplug
serial identity. Preserve the failed, fail-closed result and diagnose the guest
sysfs/QEMU serial exposure before any adjustment to the gate. Do not reinterpret
this QEMU evidence as hardware evidence.
