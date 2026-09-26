# Prototype evidence: payload, initramfs and QEMU measurement

Date: 2026-09-25 (Asia/Tokyo)

> Historical measurement record. Its initial pinning/build outcomes were
> superseded by the current [prototype readiness matrix](prototype-readiness.md)
> and later [`bytepin-next18` evidence](prototype-evidence-bytepin-next18.md).
> Preserve this report for its original
> measurements; do not use its stale input/build claims as current state.

This is evaluation-only evidence. It does not select a production builder,
claim Secure Boot verification, or establish hardware safety. The previous
2026-09-24 C5 pass and digest pair remain invalidated as described in
[`prototype-evidence-20260924.md`](prototype-evidence-20260924.md).

The pinned input, C5 inspection, component comparison, QEMU fixture, and
Nexus installer-attempt records are retained under
[`artifacts/prototype/2026-09-25/`](../artifacts/prototype/2026-09-25/).

## Result at a glance

| Measurement | Result |
| --- | --- |
| Payload generation | Build A and B both produced Debian 13 amd64 ISO payloads; live-build itself exited successfully |
| Input pinning | Both guests received byte-identical frozen bundle, expected manifest SHA-256 `446b82e22c3bf15e1ed66fe8aea18d6809d42a500625528948b36edc6b67f961` |
| Build wrapper | Both stopped after image creation (exit 44): the collector counted generic and versioned aliases of the same initrd as separate artifacts. The source collector is corrected, but the corrected collector was not rerun on these frozen builds |
| C5 inspection | **FAIL** on both; manifest says the quarantine hook is first in init-top, but the image does not establish or persist an actual block-device quarantine |
| QEMU payload boot | **PASS** for direct boot of generated kernel/initramfs with the generated ISO mounted read-only as the live medium; reached Debian 13 multi-user |
| QEMU quarantine fixture | **FAIL**: an explicitly created 32 MiB regular-file-backed `/dev/vda` remained writable (`RO=0`, `blockdev --getro=0`); its digest did not change during boot |
| Nexus installer | Actual `packaging/install.sh` was invoked in the guest and failed closed before writes: `python3: not found` (Python 3.11+ required) |
| Nexus verify/status/generation/rollback in guest | Not run. The image has no Python runtime or Nexus package, and the umbrella fixture harness correctly refused the failed C5 result |
| Reproducibility | **Not reproduced**; the only rootfs file-content difference isolated was generated APT `pkgcache.bin` |

## Exact inputs and build environments

The source manifest is retained at:

`/var/folders/wl/xlsj6y1j0c76bpbppvnk09j80000gp/T/azazel-payload.XXXXXX.SOsmoOs2jx/clean-input-bundle/build-input-manifest.json`

Its SHA-256 is `446b82e22c3bf15e1ed66fe8aea18d6809d42a500625528948b36edc6b67f961`.
The input manifest itself records 18 frozen files, exact repository revisions
and worktree status hashes, policy/evaluator, five initramfs hooks, APT source
hashes, the base image, seed, recipe, and builder toolchain. The frozen recipe
SHA-256 was
`ba84d534709e1aa49e6d36099f53d29217e789420b199602ba0bdab3d71d73df`.

| Input | Identity |
| --- | --- |
| Target | Debian 13.7.0 trixie, amd64 |
| Base cloud image | SHA-256 `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f` |
| Builder seed ISO | SHA-256 `9c031eaec60c9d38ac158bf4e7ca8c26aca37f51298a59116ae206e7749e0adb` |
| Repository | Debian snapshot `https://snapshot.debian.org/archive/debian/20260914T120000Z/`, `main`; security/updates disabled |
| Normalization | `SOURCE_DATE_EPOCH=1789387200`, UTC, `C.UTF-8`, umask `022` |
| Requested image packages | `live-boot`, `live-config`, `initramfs-tools-core`, `linux-image-amd64` |
| Builder toolchain | 333 exact Debian package/version entries; lock SHA-256 `2c7719169b4ae65ce94bc26b38d33cfbd46e26da790fe55d81bca36c3679db33`; same in A and B |
| Builder status | `live-build-evaluation-only`; production builder selection remains false |
| Environments | Two fresh qcow2 overlays, separate Debian 13 amd64 QEMU guests, same Apple Silicon host and same seed; not proof of independent production-builder infrastructure |

The output collector initially expected `filesystem.manifest`, while this
live-build version emitted the versioned closure as
`binary/live/filesystem.packages` (233 package/version lines). The source
collector is now corrected to retain that file. A/B package list bytes match
(SHA-256 `fa9f531ac16e22c1415ed573425c598c3a8dcce55fe071c561f46bf9dbd5ade6`).
This package-output mismatch is separate from the rootfs cache nondeterminism.

## Artifacts and digests

The measured unsigned ISO payloads are retained in the evidence directory as
[`unsigned-payload-a.iso`](../artifacts/prototype/2026-09-25/unsigned-payload-a.iso)
and
[`unsigned-payload-b.iso`](../artifacts/prototype/2026-09-25/unsigned-payload-b.iso),
and their full evidence-tree checksums are covered by `SHA256SUMS`. They are
evaluation artifacts, not release outputs.
The artifact has no Azazel product-level signature. Debian-provided GRUB/EFI
packages appearing in the build do not imply that the image was booted or
verified under Secure Boot.

| Component | Build A SHA-256 | Build B SHA-256 | Match |
| --- | --- | --- | --- |
| ISO payload | `4dc13efd35e327eb2c7baba424338b82dc3ad0905a6b07ce63aaa0488382c638` | `4882dfd5fe4d66daa622514118677128f133ff557a138df5c5fdd08f139d2907` | No |
| SquashFS | `5aa63e09d7fd376ec4b08966da3241f57871285bab025380c3f39ca306806e44` | `3f78973d7d7069a26ebfeafb8c2f98800284759c4870faa215bce09fe47972c6` | No |
| initramfs | `61d07d2b921619f40294629c4735166b714308d60de206bf7abd6b7c29751247` | same | Yes |
| kernel | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` | same | Yes |
| versioned package list | `fa9f531ac16e22c1415ed573425c598c3a8dcce55fe071c561f46bf9dbd5ade6` | same | Yes |

The two ISO component inventories each contain 296 files. The only differing
component bytes are `live/filesystem.squashfs` and `sha256sum.txt` (which
records the SquashFS digest). Within the decompressed rootfs, all 14,632 file
paths are present in both builds and only one file's bytes differ:
`var/cache/apt/pkgcache.bin`. All 18,285 filesystem-object path/mode/owner/
mtime records otherwise match. This classifies the observed non-reproducibility
as an unremoved generated APT binary package cache, not kernel/initramfs,
repository snapshot, package versions, or file-order drift. No digest-forcing
change was made. A fresh A/B measurement after excluding this cache is still
required.

The post-build collector also had two issues discovered by this run:

1. `initrd.img` and `initrd.img-<version>` (and the matching kernel aliases)
   are byte-identical aliases. The source collector now deduplicates aliases
   by content and refuses only distinct candidates.
2. The emitted package closure filename differs from the collector's former
   `filesystem.manifest` assumption. The collector now uses the actual
   versioned `filesystem.packages` output.

These source fixes are validated syntactically and by targeted tests but were
not part of the frozen build recipe used for A/B above.

## C5 evidence

Machine-readable Build A/B C5 manifests and results are retained in the
evidence directory as `c5-manifest-a.json`, `c5-result-a.json`,
`c5-manifest-b.json`, and `c5-result-b.json`. They are post-build inspection records tied to the
artifact ISO and initramfs digests, not release attestations.

The measured initramfs has `/init`, `/scripts/functions`, and
`scripts/init-top/ORDER`. The C5 hook `az-quarantine-block-devices` is the
first init-top entry, and all five prototype hooks are present and hashed.
However, both Boot evaluator results are `fail` with:

- `unpinned_hook`: Debian initramfs also contains `all_generic_ide`,
  `blacklist`, `keymap`, and `udev` hooks;
- `hook_order_changed`: the effective hook set is not the pinned-only policy
  set;
- `quarantine_not_persistent`: userspace has no proven continuation of the
  quarantine;
- the inspected image includes udev CD-ROM automount rules.

The five prototype hooks print markers; the first marker is not enforcement.
QEMU serial output showed these marker lines before udev and live-root mount,
but the file-backed virtual block device still reported `RO=0` after boot.
The regular-file fixture SHA-256 remained
`83ee47245398adee79bd9c0a8bc57b821e92aba10f5f9ade8a5d1fae4d8c4302` before
and after. Thus no fixture write was observed, but no write attempt was made
and C5 quarantine was **not established**.

The machine-readable C5 manifest pairs each `ORDER` call line with its actual
script path; the order-line mapping was regenerated from the extracted A
initramfs using the corrected inspector, and copied to B only after confirming
the A/B initramfs and `ORDER` digests match. The separate high-level Boot C5 result includes a build-pinning
summary; its nested `boot_image_policy_result.faults` is the concrete list of
measured C5 faults.

Provenance caveat: the original frozen C5 inspector could not load Boot's
transitive `azazel_boot.refusals` dependency because that module was missing
from the frozen closure. A later read-only post-build inspection used the
same frozen evaluator/policy/quarantine module plus that Boot module from the
current Boot worktree. The exact inspector and dependency hashes, and this
supplemental-input relationship, are recorded in
`artifacts/prototype/2026-09-25/c5-posthoc-provenance.json`; the complete
supplemental bundle is included in `SHA256SUMS`. `prepare_inputs.py` is now
corrected to freeze this dependency for future builds. The C5 FAIL and QEMU
`RO=0` are conservative, but these post-build C5 manifests are supplemental
rather than a fully replayable in-build attestation.

## QEMU and Nexus integration

QEMU 10.0.2 on the Apple Silicon host booted Build A's generated x86_64 kernel
and initramfs using TCG; the ISO was attached read-only and supplied the live
SquashFS. Kernel command line included `boot=live components
console=ttyS0,115200n8`. Boot reached Debian GNU/Linux 13, live userspace,
systemd `multi-user.target`, and a serial login. This is a direct
kernel/initramfs payload boot; the complete firmware/ISO bootloader route is
not yet verified.

The fixture test used only the read-only payload/test CDs and an explicitly
created regular file as `/dev/vda`; no host internal disk or USB device was
passed through. The fixture reported `RO=0`. The image therefore fails the
current host-storage quarantine check even though its backing file digest
stayed unchanged.

The actual Nexus `packaging/install.sh` (SHA-256
`3c4b8fa1fa787c90486155b35548f3d802194ad8734d2f218f563111828ed266`) was
mounted from a separate read-only test ISO and invoked as root in the Debian
Live guest. It refused at its Python-floor preflight because the image has no
`python3` executable; it wrote no installer files/accounts and did not reach
the service-manager stage. The harness also has no `.deb`/release packaging
workflow for this prototype. The umbrella integration harness refused the
new C5 manifest before Nexus fixture stages with
`unpinned_hook`, `order_changed`, and `quarantine_not_persistent`. Therefore
live-guest `verify/status/generation/rollback` remains **not run**; previous
fixture-only lifecycle results are not promoted to this QEMU integration.

## Tests and repository changes

During this measurement:

- payload provenance and C5 measurement unit tests: 7 passed (6 provenance,
  1 order-evidence mapping);
- changed payload tool Ruff: pass;
- payload shell syntax: pass;
- payload Python compile: pass;
- umbrella fixture harness invocation with the measured failing C5 manifest:
  correctly refused before lifecycle execution;
- Boot/Nexus historical suites were not rerun in full during this artifact
  measurement. Their previously recorded targeted baselines remain separate.

No Boot/Nexus ADR or authority boundary changed. Repository-wide Nexus lint's
known 53 warnings remain outside this change and were not modified. The live
image/build collector changes and C5 input-closure correction are prototype
construction tooling only. Production builder selection, hardware/Secure
Boot, and any physical writer target remain open.
