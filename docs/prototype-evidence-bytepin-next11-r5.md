# Prototype evidence: bytepin-next11-r5

This is a measured, unsigned Debian 13 amd64 prototype built with
`live-build` for evaluation only. It does not select a production builder,
establish a release process, or verify firmware, Secure Boot, or hardware.

## Frozen inputs and artifacts

The input manifest is
[`build-input-manifest.json`](../artifacts/prototype/2026-09-25/bytepin-next11-r5/input/prepared-final3/build-input-manifest.json),
SHA-256 `1dc22de1cf4d0fa43b8fa9ec6e202f000fd0a9399a9b02ab8e92bbb07704f670`.
The toolchain lock SHA-256 is
`e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`; builds
used Debian snapshot `20260914T120000Z`, source epoch `1789387200`, and 333
pinned packages. The verified base cloud image SHA-256 is
`5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`.

Build A's
[`unsigned payload ISO`](../artifacts/prototype/2026-09-25/bytepin-next11-r5/build-a/output/payload.iso)
SHA-256 is `7c6418ede7e01c0223c7fbade02116df1b61884c5390b9cb24e3c43904e3eda4`.
Build B produced the same digest. Components measured in A and B:

| Artifact | SHA-256 |
| --- | --- |
| Kernel | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` |
| Initramfs | `fe06437c20ddbf414c78c946b1484d39d0be3af4232d058371f10740b7572b77` |
| SquashFS | `8747430cc2f4f42035fc3707f0ff90452309a77a720141cfff48db0025b3e99a` |
| Nexus prototype `.deb` | `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1` |

The machine-readable
[`build comparison`](../artifacts/prototype/2026-09-25/bytepin-next11-r5/reproducibility/build-comparison.json)
reports `reproduced` with no first divergence across the payload and compared
components. The two clean build VMs ran on one Apple Silicon host, so this is
not independent-host or production-builder reproducibility evidence.

## Initramfs C5 and QEMU

The initramfs inspector found 1,669 entries in two segments. The static
[`C5 manifest`](../artifacts/prototype/2026-09-25/bytepin-next11-r5/build-a/output/c5-manifest.json)
and
[`static C5 result`](../artifacts/prototype/2026-09-25/bytepin-next11-r5/build-a/output/c5-result.json)
pass; runtime persistence evidence is still required.

The original
[`QEMU C5 result`](../artifacts/prototype/2026-09-25/bytepin-next11-r5/qemu/c5-a/result.json)
is **FAIL** and remains unchanged. QEMU reached multi-user, and its regular-file
fixture hashes did not change. The initial quarantine marker had zero devices,
so pre-registration device quarantine was not observed. The hotplug disk was
set read-only, but its deferred write probe was rejected before execution:
systemd supplied an instance value the helper did not accept. The user-space
write probe recorded `EPERM`; the then-current evaluator treated it as
unattributed, so this run does not establish an overall C5 runtime pass. A
later source change uses the escaped `%i` instance and accounts for Linux
6.12's read-only block-write `EPERM`; it is not retroactive evidence for this
artifact. No host block device, USB, or physical writer target was used.

## Nexus installer fixture

The QEMU
[`result`](../artifacts/prototype/2026-09-25/bytepin-next11-r5/qemu/nexus-e2e-a/result.json)
and
[`guest report`](../artifacts/prototype/2026-09-25/bytepin-next11-r5/qemu/nexus-e2e-a/guest-report.json)
pass for package installation, status, two signed offline fixture imports
(generation 1 then 2), verification, and rollback to generation 1. The
fixture used the direct `ModelImport` API, not the product CLI import path or
commissioned product trust store. Provider admission, network fetch, and Edge
activation were not performed; operational units remained masked.

## Verification and remaining gates

After the C5 evaluator/source correction, Azazel's full suite reports 150
tests passed with 1 skipped; selected Ruff, shell syntax, and `git diff --check`
pass. Boot's full suite reports 1,245 passed and 5 skipped under Python 3.14.
The Nexus targeted and umbrella baselines remain 50 and 2 tests passed,
respectively. Existing repository-wide lint warnings are unrelated and were
not changed.

Production builder selection, firmware boot, Secure Boot, cross-host
reproducibility, product-CLI import, commissioned trust, provider admission,
Edge activation, hardware behavior, and pre-registration hardware evidence
remain open. This artifact is a prototype, not production-ready media.
