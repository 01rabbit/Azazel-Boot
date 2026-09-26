# Prototype evidence: bytepin next11

Measured prototype evidence only. `live-build` remains an evaluation-only
construction method. This report does not select a production builder and does
not claim firmware, Secure Boot, hardware, or release verification. QEMU used
only explicit regular-file fixtures; no host block device or USB device was
passed through.

## Frozen inputs and independent builders

- Target: Debian 13 / trixie, amd64; repository snapshot:
  `https://snapshot.debian.org/archive/debian/20260914T120000Z/`.
- Input manifest SHA-256: `123771f92adfc756b3aaf119da93c5ddbedccc358b4d70f887da9bb7238ed757`.
- Prepared-input archive SHA-256: `5f9d48cb71e64f3515c3c0a3b0702c5567971c5947787f0c988ecf89a4ade5b0`.
- Base cloud image SHA-256: `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`.
- Builder seed ISO SHA-256: `5a7beb9f1f19229cdbb3ec84d1cbf221eb502b166fae34a2f2a364ab4a278c3a`.
- Nexus source bundle SHA-256: `97903b739b7d3f13efb175cef340f27167c61e084f329933622450cd1f4a0595`.
- A and B used distinct clean Debian VM instances and separately formatted 6 GiB ext4 workspace disks. Builder instance IDs are in each build result. Both recipe-start and recipe-end manifest/frozen-input measurements matched the manifest above.
- `strace` is included in the pinned live-image package requests for syscall observation. The build input bundle, lock, source hashes, and tool versions are preserved under `../artifacts/prototype/2026-09-25/bytepin-next11/`.

See the [input manifest](../artifacts/prototype/2026-09-25/bytepin-next11/input/prepared/build-input-manifest.json), [A build result](../artifacts/prototype/2026-09-25/bytepin-next11/build-a/build-result.json), and [B build result](../artifacts/prototype/2026-09-25/bytepin-next11/build-b/build-result.json).

## Generated artifacts

Build A and B produced byte-identical artifacts:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Unsigned prototype ISO | 349,175,808 | `133ac9039e4ee7ee809f4a6b69fc7736a80c1b5b330aa596ef9c7fd991a54d4f` |
| Kernel | 12,142,528 | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` |
| Initramfs | 41,487,934 | `4ec41801ee11b6868f3fe54a54ac628cc400f18cdc348f63b8ab4b96849af1f3` |
| SquashFS | 273,894,440 | `a2ec3f37e24dbbb8489d0265a728c19b177114bcf079a8dc19c900c9d5b1f9e2` |
| Nexus prototype `.deb` | 239,088 | `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1` |

The image is an unsigned Azazel prototype, not a release envelope. Debian's
bootloader packages may contain Debian signatures; this is not Secure Boot
verification. `live-build` is not thereby selected as the production builder.

## Initramfs C5 inspection and QEMU runtime

Both static C5 results are `pass`. The machine-readable manifests establish
the quarantine entry at `/init` before `maybe_break`, init-top scripts, module
loading, and storage-touching commands; initramfs order/content inspection
enumerated two archive segments and 1,669 entries. The quarantine helper and
udev policy were included in the generated initramfs and rootfs. The guest
reached Debian `multi-user.target` under q35 TCG.

The runtime C5 evaluator verdict is **fail / incomplete**, not a quarantine
pass:

- For `/dev/vda`, initramfs phase records show `discovered` and `quarantine`
  with both sysfs and blockdev read-only values set to 1 before the probe. The
  raw trace records `openat` success followed by `write(...)= -1 EPERM` (errno
  1). The fixture remained unchanged. No errno was hard-coded or altered.
- The frozen evaluator expects exactly one read-only phase record for that
  target, so the valid pre/post RO observations are reported as a duplicate and
  rejected. This is a deterministic evaluator false-fail risk.
- In userspace, the marker schema and boot-id binding passed, the device was
  not mounted, and RO values remained 1. However the probe reports
  `open_succeeded_without_write` and `handoff_valid=NOT_OBSERVED`: the frozen
  probe correlates a write only with the fd returned by `openat`, while `dd`
  remaps the opened output to fd 1. The guest log says “Operation not
  permitted,” but the raw target write result was not preserved as a
  machine-readable record. Userspace write-denial evidence is therefore
  incomplete.
- QMP attached a second regular-file fixture after multi-user. Kernel
  discovery, udev rule, helper, and both RO states were observed; the final
  event says `write_result=write_denied`, and the fixture remained unchanged.
  The evaluator's ordered chain still fails because the expected raw hotplug
  write-syscall observation is absent. This establishes a fixture quarantine
  event after device registration, not pre-registration isolation or absence
  of all earlier I/O.

The evidence preserves the machine-readable [C5 result](../artifacts/prototype/2026-09-25/bytepin-next11/qemu/c5-a/result.json), [serial log](../artifacts/prototype/2026-09-25/bytepin-next11/qemu/c5-a/serial.log), and [QMP command log](../artifacts/prototype/2026-09-25/bytepin-next11/qemu/c5-a/qmp-commands.json). The C5 runtime gate remains open until probe/evaluator evidence is fixed and rerun against a newly frozen build; do not rewrite this next11 record.

## Nexus installer E2E

The next11 [host result](../artifacts/prototype/2026-09-25/bytepin-next11/qemu/nexus-e2e-a/result.json) is **pass** and binds the exact input manifest, build result, ISO, kernel, initramfs, Nexus package, guest report, and frozen runner digests. The guest reached multi-user, installed the `.deb` from the image, reported package status with exit code 0, imported two signed offline fixture models (generation 1 then 2), verified both, and rolled back to generation 1. The report records Edge activation, provider admission, and network fetch as false.

This exercise uses the disposable direct `ModelImport` API, not the product CLI
or a commissioned product trust store. It validates the prototype installer
and test fixture path only; it does not expand Installer authority or prove
production commissioning behavior.

## Reproducibility

The strict independent-build comparator result is **not reproduced**, with
`rootfs_metadata` as the first divergence. Final ISO, kernel, initramfs,
SquashFS, Nexus `.deb`, embedded package, ISO metadata, initramfs archive
structure, and all 15,417 rootfs file-content hashes match. The three differing
metadata entries are directories `etc/ssl/certs`, `usr/lib/systemd/system`,
and `usr/share/man/man7`: their `st_size` is 16,384 bytes in A and 20,480 bytes
in B. These are directory-allocation/entry-storage observations in the
independently formatted ext4 workspace extraction, not differing package file
contents. No normalization was added. Do not claim strict metadata
reproducibility.

See the [machine-readable comparator report](../artifacts/prototype/2026-09-25/bytepin-next11/reproducibility.json).

## Verification and remaining gates

- Targeted tests: **78 passed, 13 subtests passed**.
- Targeted Ruff checks on changed Python files: pass; changed shell scripts pass `sh -n`; `git diff --check` passes.
- Repository-wide Nexus lint still has the previously recorded unrelated warnings; they were not broadened into this change. The broader prototype integration attempt also retains two unrelated audit-worktree fixture failures (`quarantine_not_persistent`); no audit/product source was changed.
- No USB or physical writer test, host-disk write, firmware/bootloader validation, Secure Boot verification, or hardware verification was performed. Hardware-only gates remain open.
- Blocking issues for the next prototype iteration: C5 read-only evidence cardinality, fd aliasing in userspace write tracing, and missing raw hotplug syscall evidence. Fix and re-freeze these without hard-coding the observed errno, then rebuild and rerun QEMU.

No ADR, decision/enforcement authority boundary, or production-builder decision
was changed.
