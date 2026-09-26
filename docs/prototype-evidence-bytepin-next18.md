# Prototype evidence: bytepin next18

Measured prototype evidence only. This record does not select a production
builder and does not claim firmware, Secure Boot, hardware, or release
verification. `live-build` remains evaluation-only. QEMU was given only
explicitly created regular-file fixtures; no USB or host block device was
passed through. This evidence does not amend the Boot C5 policy, any ADR, or
the Edge/Nexus authority boundary.

## Frozen inputs and independent clean builds

- Target: Debian 13 / amd64; repository snapshot:
  `https://snapshot.debian.org/archive/debian/20260914T120000Z/`.
- `SOURCE_DATE_EPOCH=1789387200`; toolchain-lock SHA-256:
  `e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`.
- Input-manifest SHA-256:
  `aa0059c3a10d1939458eb9789f3f077d667ab327f84baffcb49a9fb664d77cbc`.
- Prepared-input archive SHA-256:
  `93b4c883befddf70888ed60656a1e72bfb46af42c44944eb3a1789334fe9e380`.
- Pinned Debian 13 amd64 cloud base-image SHA-256:
  `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`;
  builder-seed ISO SHA-256:
  `80ab8714a6f3c66d60e6255f5ce3927fc2f5e950ce8b30ab050664c613e197ce`.
- The complete input manifest, detached digest, prepared input archive, and
  base/seed images are preserved under
  [`artifacts/prototype/2026-09-25/bytepin-next18/input/`](../artifacts/prototype/2026-09-25/bytepin-next18/input/).
- A and B were separately provisioned clean Debian builder VMs, with fresh
  overlays and workspace disks, on the same Apple Silicon host using QEMU
  TCG. Their machine IDs differ. They are independent build environments, not
  independent physical hosts. Each VM verified the frozen input tree before
  and after building. `builder_selected_for_production=false`.

See [build A](../artifacts/prototype/2026-09-25/bytepin-next18/build-a/output/build-result.json), [build B](../artifacts/prototype/2026-09-25/bytepin-next18/build-b/output/build-result.json), and the [input manifest](../artifacts/prototype/2026-09-25/bytepin-next18/input/build-input-manifest.json).

## Generated unsigned artifacts and reproducibility

Build A and B produced identical SHA-256 digests for all compared payload
components:

| Artifact | SHA-256 (A = B) |
| --- | --- |
| Unsigned Debian ISO | `0065601649eb6814d6c37dc48cb2f4f69b99ef728aa972bfe49c4dc8f787b561` |
| Kernel | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` |
| Initramfs | `310b818e03c3b21e1e2ab77227d1f2083958ca9a01efd4305db263ecdde608b1` |
| SquashFS | `6fe6799bbb7e33a3f937c1e0dbdde261ada9b1645cbb8937500bf15047e17a36` |
| Nexus prototype `.deb` | `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1` |

The strict post-build comparator reports `reproduced`, `first_divergence: null`,
and all recorded component/content/metadata checks pass. It explicitly
normalizes only host extraction observations (host inode numbers, initramfs
extraction-time directory mtimes, and rootfs extraction directory sizes for
rootfs metadata comparison); archived initramfs entry metadata and ordering
are compared separately. This is reproducibility across these two clean VMs
on one host, not a claim about other hosts or a selected production builder.
See the [comparison report](../artifacts/prototype/2026-09-25/bytepin-next18/reproducibility-strict.json).

## Static C5 initramfs inspection

The built initramfs contains 1,669 entries in two archive segments. The
machine-readable [C5 manifest](../artifacts/prototype/2026-09-25/bytepin-next18/build-a/output/c5-manifest.json) and [static result](../artifacts/prototype/2026-09-25/bytepin-next18/build-a/output/c5-result.json) report PASS. The patched `/init` calls the quarantine-first script before `maybe_break`, init-top hooks, module loading, and subsequent storage-sensitive setup; the evaluator found no forbidden storage commands or non-pseudo mounts before quarantine. This is static ordering/content evidence only; runtime evidence is reported separately below.

## QEMU boot and runtime C5 fixture

The exact Build A kernel/initramfs booted under q35 QEMU TCG and reached
`multi-user.target`. The [runtime result](../artifacts/prototype/2026-09-25/bytepin-next18/qemu/c5-a/result.json) is **FAIL** overall:

- The captured serial log places the initial initramfs quarantine marker
  before the `/dev/vda` registration log and before fixture helper/quarantine
  events and its explicit one-byte write probe. However, the runner's
  `measurement_scope.does_not_prove` explicitly disclaims proof that
  quarantine preceded kernel block-device registration; serial-log ordering
  alone is not promoted to that guarantee. `/dev/vda`
  reported sysfs and `blockdev` read-only state `1`; the guest probe recorded
  `write(...) = -1 EPERM`. The userspace persistence/handoff check retained
  read-only state and again observed EPERM.
- After QMP hotplug, `/dev/vdb` was discovered by udev. The quarantine helper
  changed sysfs and `blockdev` read-only state from `0` to `1`, and emitted a
  quarantine event. However, the destructive-probe gate reported
  `disk_serial_status=FAIL`; therefore **no `/dev/vdb` write probe ran**, and
  the result correctly fails the complete runtime C5 test. Although QEMU was
  configured with serial `AZC5-VDB-FILE-01` (within the virtio serial limit),
  the result does not record the resolved guest sysfs serial value. This run
  cannot distinguish an unavailable/misresolved attribute from a value
  mismatch. The next diagnostic must capture a bounded, escaped/hex serial
  observation before changing the gate or claiming a cause.
- Both QEMU backing targets were newly created regular files, and their
  before/after digests match. The configured QEMU block write tracepoints
  recorded zero writes, but the runner explicitly scopes this as incomplete
  host-I/O evidence. Neither unchanged digests nor that limited trace turns
  the unperformed `/dev/vdb` probe into a pass.
- Guest-visible cmdline, DMI, marker, and device attributes are not a secure
  proof against a hostile guest/QEMU configuration. This fixture only records
  the controlled runner invocation; it does not establish a general guarantee
  that arbitrary VM backing storage is a regular file.

See the [QEMU result](../artifacts/prototype/2026-09-25/bytepin-next18/qemu/c5-a/result.json), [serial log](../artifacts/prototype/2026-09-25/bytepin-next18/qemu/c5-a/serial.log), and [block trace](../artifacts/prototype/2026-09-25/bytepin-next18/qemu/c5-a/qemu-block-trace.log). No host block device or network interface was passed through. The guest reached multi-user, but this is not firmware or hardware boot evidence.

## Nexus installer/status/generation fixture E2E

The [QEMU E2E result](../artifacts/prototype/2026-09-25/bytepin-next18/qemu/nexus-e2e-a/result.json) and [guest report](../artifacts/prototype/2026-09-25/bytepin-next18/qemu/nexus-e2e-a/guest-report.json) report **PASS** for the bounded disposable guest scope. The `.deb` included in the generated image was installed (exit 0), operational units remained masked, and `azazel-nexus status` returned 0. Two signed offline fixtures were imported as generations 1 and 2 through the direct `ModelImport` API, verified, and rollback restored generation 1.

This did **not** exercise the product CLI import path or a commissioned product
trust store, nor the complete Mission Pack lifecycle. Network fetch, provider
admission, and Edge activation were all false. The Installer gained no
decision/enforcement authority.

## Verification, issues, and remaining gates

- Static C5 ordering/content: **PASS**. Runtime C5: **FAIL / incomplete** because
  the hotplug fixture's serial safety gate did not pass, so its write probe
  was withheld. C5 remains open; first capture the missing guest serial
  evidence, then rerun the fixture and reassess the gate.
- QEMU boot and bounded Nexus installer/status/fixture rollback E2E: **PASS**
  within the limited scopes described above.
- Independent clean-VM build A/B: **reproduced** for the unsigned payload and
  listed components. Both VMs shared one host and the evaluation-only
  `live-build` recipe.
- No production builder was selected. No firmware boot path, Secure Boot,
  physical hardware, USB, writer target, or host-disk test was performed.
  Hardware-only gates remain open (`hardware_verified=false`).
- No ADR or authority boundary changed. Nexus does not gain provider-admission
  or Edge-activation authority. The result is prototype evidence, not release
  or production readiness.

Relevant open issue gates were rechecked during this work. None met its full
acceptance criteria, so no issue was closed:

| Issue | Why it remains open |
| --- | --- |
| Boot #4 | Production-builder selection ADR and independent build-infrastructure reproducibility plus the issue's C1–C9/supply-chain evaluation remain incomplete. These two VMs shared one host. |
| Boot #6 | Physical x86_64 laptop/media HIL, including a measured no-internal-storage-write lifecycle, remains unperformed. |
| Boot #26 | Required independent-infrastructure reproducibility remains open; next18 used two clean VMs on one host. |
| Boot #28 | Static ordering evidence advances the issue, but its independent review is outstanding and runtime hotplug write-denial evidence is incomplete. |
| Nexus #3 | Signed Mission Pack manifest/admission and pack-scoped validation, atomic activation, rollback, and authority-boundary acceptance remain untested. The model-import fixture is not Mission Pack E2E. |
| Nexus #93 | Provider setup through staged verification/admission/activation and the GPU evaluation remain incomplete; bounded installer/import E2E does not meet the parent issue. |

Related issues already closed before this work were not reopened or duplicated.
