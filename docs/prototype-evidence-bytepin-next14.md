# Prototype evidence: bytepin next14

Measured prototype evidence only. This record does not select a production
builder and does not claim firmware, Secure Boot, hardware, or release
verification. `live-build` was used only to construct this evaluation payload.
QEMU used explicit regular-file fixtures; no USB device or host block device
was passed through. The Boot C5 policy remains the source of the required
quarantine contract; this report records observations and does not amend that
policy or any ADR.

## Frozen inputs and builds

- Target: Debian 13.7.0 (trixie), amd64; package source snapshot:
  `https://snapshot.debian.org/archive/debian/20260914T120000Z/`.
- Input manifest SHA-256:
  `95a094b2e46767c972ac4a707e6150d0a888acb00eae5589cd9639dd5e9934d9`.
- Prepared-input archive SHA-256:
  `2f06b5dabd16a764b7370a969eb48cfe3896d70b59253219145d38d5b7c343dd`.
- Toolchain lock SHA-256:
  `e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`.
- Base Debian cloud image SHA-256:
  `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`.
- Builder seed ISO SHA-256:
  `80ab8714a6f3c66d60e6255f5ce3927fc2f5e950ce8b30ab050664c613e197ce`.
- Nexus source bundle SHA-256:
  `97903b739b7d3f13efb175cef340f27167c61e084f329933622450cd1f4a0595`.
- `SOURCE_DATE_EPOCH=1789387200`; the manifest, frozen inputs, and toolchain
  lock are archived under
  [`artifacts/prototype/2026-09-25/bytepin-next14/input/`](../artifacts/prototype/2026-09-25/bytepin-next14/input/).
- A and B were separate clean Debian builder VM instances using the same base
  image and seed on the same Apple Silicon host under QEMU TCG. This is not
  evidence from two physical builder hosts. Repository source worktrees were
  recorded as dirty in the build reports; the selected inputs and their
  digests are captured in the manifest.

See the [input manifest](../artifacts/prototype/2026-09-25/bytepin-next14/input/prepared/build-input-manifest.json), [build A](../artifacts/prototype/2026-09-25/bytepin-next14/build-a/output/build-result.json), and [build B](../artifacts/prototype/2026-09-25/bytepin-next14/build-b/output/build-result.json).

## Generated unsigned artifacts

Build A and B produced the following matching digests:

| Artifact | SHA-256 |
| --- | --- |
| Unsigned prototype ISO | `ad69c8dac33a52e9376073230744279bea9fc43b349a1dcc3c32da73d79b7635` |
| Kernel | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` |
| Initramfs | `dbba2e6bdba8a85fe542682ed569623095e35b9877e656ae3e19077709a9b567` |
| SquashFS | `fc9769176beafc798bd321026ae59b1ce482092d3b1e1e69c11be7794c086e76` |
| Nexus prototype `.deb` | `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1` |

The machine-readable [component digest manifest](../artifacts/prototype/2026-09-25/bytepin-next14/build-a/output/binary-component-digests.sha256) and both build output trees are preserved with the evidence. This is an unsigned, non-releasable evaluation payload. Debian-supplied boot components do not constitute a Secure Boot test. `builder_selected_for_production` is false.

## Initramfs C5 inspection and QEMU runtime

The built initramfs was inspected. The machine-readable [static C5 result](../artifacts/prototype/2026-09-25/bytepin-next14/build-a/output/c5-result.json) reports `pass`, with no static evaluator faults; the [C5 manifest](../artifacts/prototype/2026-09-25/bytepin-next14/build-a/output/c5-manifest.json) and initramfs inspection are archived alongside it. This is the static image-inspection result only, not a pass of the runtime C5 gate.

The exact Build A kernel and initramfs were booted in a q35 QEMU TCG guest. The guest reached `multi-user.target`, but the machine-readable [runtime result](../artifacts/prototype/2026-09-25/bytepin-next14/qemu/c5-a/result.json) is **FAIL**. The fixture used explicitly created regular files as backing targets; no real host storage was attached.

Observed positive fixture evidence for `/dev/vda`:

- An initramfs `initial_quarantine` record was emitted while the fixture device
  was not yet registered. Later records show the helper setting `/dev/vda`
  read-only, with both sysfs and `blockdev` reporting `1`.
- The captured target write syscall returned `-1 EPERM`. In userspace, the
  handoff marker was present and bound to the current boot ID; the device was
  not mounted, the read-only values remained `1`, and the write probe again
  recorded `-1 EPERM`.
- These observations show denial for the recorded fixture probes. They do not
  establish that quarantine preceded kernel block-device registration: the
  result report explicitly lists that as unproven. The unchanged backing-file
  digest is not, by itself, proof that no write occurred.

The hotplug `/dev/vdb` fixture did **not** reach a quarantined state. The
observed enforcement command returned `1`; no enforcement ioctl syscall was
observed; sysfs and `blockdev` read-only state remained `0`; and the QEMU runner
timed out waiting for the expected hotplug quarantine event. No write probe
was performed against `/dev/vdb`. The named QEMU block write tracepoints
recorded zero write events, but the result describes that trace as limited and
not comprehensive host-I/O evidence. Therefore neither the `/dev/vda`
observations nor unchanged fixture digests override the overall C5 runtime
failure.

See the [QEMU result](../artifacts/prototype/2026-09-25/bytepin-next14/qemu/c5-a/result.json), [serial log](../artifacts/prototype/2026-09-25/bytepin-next14/qemu/c5-a/serial.log), and [block trace](../artifacts/prototype/2026-09-25/bytepin-next14/qemu/c5-a/qemu-block-trace.log). The hotplug failure cause is not established by this run.

## Nexus installer and generation fixture E2E

The [QEMU Nexus result](../artifacts/prototype/2026-09-25/bytepin-next14/qemu/nexus-e2e-a/result.json) and its [guest report](../artifacts/prototype/2026-09-25/bytepin-next14/qemu/nexus-e2e-a/guest-report.json) both report `pass` for this disposable guest test. It used the exact Build A payload and Nexus package digest recorded above. The package installed with exit code 0, and `azazel-nexus status` returned exit code 0.

The generation exercise imported two signed offline fixture models directly
through the disposable `ModelImport` API (generation 1 then generation 2),
verified both fixture entries, and rolled back to generation 1; generation 1
remained present afterward. **The product CLI import path was not used, and no
commissioned product trust store was used.** This is limited fixture evidence,
not a complete product-CLI lifecycle or commissioning test. Provider
admission, network fetch, and Edge activation were not performed; the report
records all three as false. This test does not expand Installer authority.

## Reproducibility measurement

The build-time strict comparison reported **`not_reproduced`**, first
diverging at extracted rootfs metadata. The differing values were host
extraction filesystem directory `st_size` observations, rather than different
file contents. A separately identified post-build analysis was then performed;
its [report](../artifacts/prototype/2026-09-25/bytepin-next14/reproducibility.json)
reports **`reproduced`** with `first_divergence: null`. It records equal ISO,
kernel, initramfs, SquashFS, Nexus package, initramfs archive structure and
metadata, ISO metadata, and rootfs file contents. It excludes three extracted
rootfs directory-size observations from the rootfs metadata comparison; file
metadata and contents were not normalized by this exception.

This result is conditional on that explicitly reported post-build treatment
of host extraction observations; it must not be restated as the original
strict comparison passing or as proof that every host-extracted metadata
observation was identical. The report separately identifies the post-build
analyzer SHA-256 `a4d39c4308a5e9eca51105572ca1cb4d1eb50be896ea53a90738be9fff55bcb7`
and the frozen comparator SHA-256
`2be04707992e9106f78a9fd6a84908246b734c6a1a706cdd78cec55c8b3b4363`.

## Verification boundaries and remaining gates

- Static initramfs C5 inspection: **PASS**. QEMU runtime C5: **FAIL** due to
  the unquarantined hotplug fixture and incomplete runtime proof described
  above. The normative C5 quarantine gate remains open.
- QEMU guest boot and limited Nexus installer/status/fixture generation test:
  **PASS**, with the scope limitations above. QEMU is not hardware evidence.
- Build A/B payload digests: equal. The post-build comparator reports
  reproducibility only with its explicit extracted-directory-size exception;
  the original strict build-time comparison reported `not_reproduced`.
- Production builder selection remains open; `live-build` remains
  evaluation-only. No release disposition is implied.
- No physical hardware, USB, host-disk writer, firmware boot path, or Secure
  Boot verification was performed. Hardware-only and Secure Boot gates remain
  open (`hardware_verified=false`, `secure_boot_verified=false`). Any future
  writer test remains restricted to a regular file or an explicitly created
  test loop device.
- No ADR or authority boundary was changed. Edge remains the decision and
  enforcement authority; this evidence does not confer provider admission or
  activation authority on Nexus or its installer.

Relevant normative sources remain [Azazel-Boot quarantine policy](quarantine-policy.md) and [Azazel-Nexus contract ownership](https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/contract-ownership.md); measured prototype evidence does not override them.
