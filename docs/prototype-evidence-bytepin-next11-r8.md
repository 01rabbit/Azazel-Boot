# bytepin-next11-r8 prototype evidence

This is an evaluation-only Debian 13.7 amd64 build using `live-build`; it does
not select a production builder. The payload is unsigned and non-releasable.
QEMU results are not hardware, firmware, Secure Boot, or writer evidence.

## Frozen inputs and artifacts

- Input manifest: [`build-input-manifest.json`](../artifacts/prototype/2026-09-25/bytepin-next11-r8/input/prepared/build-input-manifest.json), SHA-256 `9f01979e8dd7e107cbaa88481bd7c96eb40ab13214bd4865f5cca51297d55c098`.
- Toolchain lock SHA-256: `e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`.
- Frozen input archive SHA-256: `b1e7f9f8b8c33d0f2f0b003bfcb9d41866afa2ce68d7a0a2ce0aa13cc09c35ea`.
- Debian snapshot: `https://snapshot.debian.org/archive/debian/20260914T120000Z/`; `SOURCE_DATE_EPOCH=1789387200`; locale `C.UTF-8`, timezone UTC, umask `022`.
- Verified Debian 13 amd64 cloud base image SHA-256: `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`.
- Builder seed ISO SHA-256: `94c6171c5f53566e7f52ffb2089ed44829d6c894da9014b4efc0d852eef98af4`.
- Build A and B used separate clean Debian 13 amd64 QEMU TCG VMs and overlays from the same base/seed. Their recorded instance identity hashes differ. Both ran on the same Apple Silicon host, so this is not independent-host reproduction.
- Unsigned ISO (A = B) SHA-256: `baf03eea536d7bf21f2df6aeb85c200d6434e791f2f5cd7fe74cacfc90dec2d3`.
- Kernel SHA-256: `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08`.
- Initramfs SHA-256: `1638e1798dcc26e5f86fe1613ab85bee73ed1f64c2af99fb58f253971fa43e87`.
- SquashFS SHA-256: `eae8a2e15e79132ef9b696717992b835247392e1bafb1cc61d3dd4b9243e1143`.
- Nexus prototype `.deb` SHA-256: `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1`.
- Both builds report `NON-RELEASABLE / EVALUATION ONLY`, with production builder selection false. See [Build A](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-a/output/build-result.json), [Build B](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-b/output/build-result.json), and [base-image-use proof](../artifacts/prototype/2026-09-25/bytepin-next11-r8/reproducibility/builder-base-image-use.json).

## Initramfs C5 inspection and QEMU

Static inspection passed for both builds. The machine-readable [C5 manifest](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-b/output/c5-manifest.json) and [C5 result](../artifacts/prototype/2026-09-25/bytepin-next11-r8/build-b/output/c5-result.json) record the ordered quarantine hook/content checks before `maybe_break`, init-top, and module-loading stages. Inspection covered two archive segments and 1,669 entries.

The Build B ISO booted to `multi-user.target` in q35 TCG using direct kernel/initramfs invocation. The full [QEMU C5 runtime result](../artifacts/prototype/2026-09-25/bytepin-next11-r8/qemu/c5-build-b/result.json) is **FAIL**:

- Initial marker reported `devices=0`; pre-registration fixture quarantine is **NOT_OBSERVED**. `/dev/vda` was quarantined after kernel registration and before its write probe.
- `/dev/vda` read-only enforcement denied the initramfs write probe. The userspace handoff/persistence probe also recorded read-only state and a denied write.
- Hotplug `/dev/vdb` was discovered through udev and transitioned read-only before any observed write probe. The hotplug helper's final log is `quarantine/probe origin and mode do not match`; it rejected the valid `probe:probe` pair because the original POSIX `&&`/`||` expression grouped incorrectly. Thus no hotplug write-denial evidence was produced, and the runner timed out waiting for the final event. QMP device attachment itself succeeded; its command was not the root cause.
- Both backing targets were newly created regular files. Both files remained unchanged. The selected QEMU write/write-zero tracepoints recorded zero writes; the trace has no discard tracepoint and is not comprehensive host-I/O proof.

The source helper's mode check was fixed after the r8 inputs were frozen and a source regression test was added. Those later source changes are not included in r8 and do not change its FAIL verdict; they require a new frozen build and QEMU run to establish a new runtime result.

## Nexus installer/lifecycle E2E

The Build B ISO's test-only installer installed the package and `status` completed. The disposable guest then imported signed offline fixtures directly through `ModelImport` (generations 1 and 2), verified both, and rolled back to generation 1. The bounded [guest report](../artifacts/prototype/2026-09-25/bytepin-next11-r8/qemu/nexus-e2e-build-b/guest-report.json) and [runner result](../artifacts/prototype/2026-09-25/bytepin-next11-r8/qemu/nexus-e2e-build-b/result.json) are **PASS for this limited scope**. Product CLI import/verify and commissioned product trust were not exercised. Operational units remained masked; no network fetch, provider admission, or Edge activation occurred.

## Reproducibility, tests, and limits

The strict [A/B comparison](../artifacts/prototype/2026-09-25/bytepin-next11-r8/reproducibility/build-comparison.json) reports `reproduced`, `first_divergence: null`. It matched the unsigned payload/ISO, kernel, initramfs (including archive ordering/metadata), SquashFS, rootfs contents/metadata, ISO/EFI components, and Nexus package. Same pinned input manifest, recipe, lock, and epoch were recorded for both VMs. This demonstrates same-host clean-VM reproducibility only; it does not establish independent-host or independent-builder reproducibility.

The QEMU guests used q35 TCG and direct kernel/initramfs invocation. No USB, host block device, internal disk, or physical writer target was attached. Secure Boot, firmware/bootloader path, hardware storage quarantine, hardware write behavior, and HIL remain unverified. Production builder selection remains open.

The r8 result is prototype evidence, not production readiness. It demonstrates: payload generated, C5 statically inspected, guest booted, limited Nexus integration exercised, and A/B reproducibility measured; runtime C5 remains blocked by the hotplug probe failure and unobserved pre-registration quarantine.
