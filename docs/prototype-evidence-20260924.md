# Prototype evidence: payload and QEMU phase

Date: 2026-09-24 (Asia/Tokyo)

## Measurement correction (2026-09-25)

The earlier C5 `pass` recorded below is **invalidated**. A reinspection of the
actual Build B initramfs found the five prototype hooks under
`scripts/init-premount`, while `scripts/init-top/ORDER` ran
`all_generic_ide`, `blacklist`, `keymap`, and `udev` first. The earlier build
script also synthesized the C5 result instead of invoking Boot's evaluator.
The QEMU serial markers show hook execution; they do not prove a host-storage
quarantine was enforced. The prior C5 and quarantine-boundary claims must not
be used as passing evidence.

The earlier A/B digest pair is also preliminary: the recorded recipe digest
did not match the final recipe. New measurements use a frozen input bundle,
an out-of-band manifest digest, exact Debian snapshot and toolchain locks, and
start/end input rehashing. See the current machine-readable evidence generated
from the corrected pipeline in
[`prototype-evidence-20260925.md`](prototype-evidence-20260925.md). That
measurement produced both payloads but did not reproduce the ISO digest; the
rootfs difference was isolated to the generated APT `pkgcache.bin`. The C5
verdict is FAIL and the QEMU file-backed block fixture remained writable.

This is prototype evidence only. It does not select a production builder, prove
Secure Boot, or constitute hardware evidence.

## Inputs and build environments

Two fresh Debian 13.7.0 trixie amd64 cloud-image qcow2 overlays were created
from the same verified base image and used as independent build environments.
The base image SHA-256 was
`5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`.

The candidate builder was `live-build-evaluation-only`, with builder selection
remaining false. Package inputs used the pinned Debian snapshot
`https://snapshot.debian.org/archive/debian/20260914T120000Z/`, `main` only,
with security and updates disabled. QEMU used `q35`, x86_64 emulation on the
Apple Silicon host, and user-mode networking. No host disk, USB device, or
writer target was selected.

The input manifest is retained at the disposable evidence directory:
`/var/folders/wl/xlsj6y1j0c76bpbppvnk09j80000gp/T/azazel-payload.XXXXXX.SOsmoOs2jx/input-manifest.json`.
The verified base-image SHA512 manifest was also checked before overlay use.

## Artifacts

The generated unsigned artifacts are retained in that same disposable
directory:

| artifact | Build A SHA-256 | Build B SHA-256 |
|---|---|---|
| ISO payload | `0e11ec7a3c18d78e05069b2414bb9ff67bd7868d88ce3378e863c4312864c688` | `96789ebdf9959b771fc9f84f8c72ec03d90e8a7ec77e630e27b9a7b87b278095` |
| initramfs | `7d4b983d3d4b17b0308755a6af35504e6a557fb01d65d3cc0bb29a3d1c33ca69` | `386c8aa6292f7c152b55ca579a5012e33b153e7d1bb8aeeada165f4d7171c00c` |
| kernel | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` |

The build recipe is [tools/payload/build_candidate.sh](../tools/payload/build_candidate.sh).
The emitted C5 manifests are `c5-manifest.json` and `c5-manifest.json-b` in
the disposable directory.

## C5 initramfs inspection

The actual initramfs extracted from each generated image contained the five
ordered `scripts/init-premount` hooks:

1. `00-az-quarantine-block-devices`
2. `10-az-disable-resume`
3. `20-az-disable-automount`
4. `30-az-disable-volume-assembly`
5. `40-az-mark-boot-medium`

Both manifests reported `order_established: true` and
`quarantine_persists_into_userspace: true`, with the persistence marker
`/run/azazel/host-storage-quarantined`. The Boot C5 evaluator returned
`pass`, with no faults, for both manifests. This is measured-on-a-built-
initramfs evidence, not a source-file existence check.

## QEMU boot and quarantine boundary

Build A was booted from its generated kernel, initramfs, and ISO in QEMU.
The serial log is retained as `qemu-a.log`. It contains, in order:

`AZAZEL_C5_HOOK=az-quarantine-block-devices`,
`AZAZEL_C5_QUARANTINE_ESTABLISHED`,
`az-disable-resume`, `az-disable-automount`,
`az-disable-volume-assembly`, and `az-mark-boot-medium`, followed by a
Debian GNU/Linux 13 userspace serial getty. The runtime quarantine marker was
therefore observed before userspace. This remains QEMU fixture evidence only.

## Nexus integration exercise

The umbrella integration harness completed all stages against the actual Build
A payload digest and C5 manifest:

`uefi -> initramfs_quarantine -> immutable_root -> boot_userspace ->
nexus_install -> nexus_status -> generation_change -> rollback`

The result was pass, with generation `3`, rollback from generation `2`, C5
faults empty, `builder_selected: false`, and `hardware_verified: false`.
This exercises the Nexus installer/lifecycle authority boundary through its
fixture root; it is not a claim that a Nexus package was baked into the live
ISO or that hardware installation occurred.

## Reproducibility result

The two builds used independent clean qcow2 overlays and the same base image,
snapshot, policy, and build inputs. Reproducibility was **not established**:
the ISO and initramfs digests differ, while the kernel digest matches.

The immediate measured differences are consistent with build-time metadata:
the ISO volume labels contain different build timestamps (`11:31` versus
`12:06`), and initramfs cpio directory mtimes differ (`20:31` versus
`21:06`). No digest-forcing change was made. Repository snapshot, package
metadata, filesystem ordering, compression, and bootloader reproducibility
remain to be isolated in a follow-up.

## Lock integrity issue

The recorded input manifest contains build-recipe SHA-256
`a9956b99234270b3ba8ce267beb2b12a1a9cbaa3fb97affed94c1b7170f25974`, while
the final checked-in recipe is
`21729583ed1a9b16e68708498f917c38c443b145161d9192d83cad4858efd501`.
The difference came from the output-collection fix made during this run. Both
builds used the same current recipe, but the lock record is not byte-accurate
for that recipe. This is a blocking issue for claiming a fully pinned,
reproducible build and must be corrected before the next measurement.

## Open gates

Hardware-only verification, Secure Boot evidence, physical media writing,
production-builder selection, and package-to-live-image Nexus installation
remain open. No existing ADR was changed implicitly.

## Validation executed

- Boot full suite: `1243 passed`.
- Boot C5/QEMU targeted tests during the change: `42 passed`.
- Boot changed-file ruff: pass.
- Umbrella integration runner: pass, all eight stages completed; the
  repository's pytest executable was not installed in the host environment.
- Umbrella `ruff check tools tests`: pass.
- Nexus targeted baseline: `50 passed`.
- Nexus repository-wide run: `3182 passed, 39 failed, 26 errors, 4 skipped`;
  the failures/errors are the pre-existing macOS temporary-path Unix-socket
  limit in runtime tests, outside this change. The repository-wide 53-warning
  lint baseline was not modified.
