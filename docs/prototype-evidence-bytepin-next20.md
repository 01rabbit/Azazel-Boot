# Prototype evidence: bytepin-next20

This is an unsigned, disposable Debian 13 amd64 prototype measurement. It does
not select a production builder or establish release, firmware, Secure Boot,
or hardware readiness. `live-build` was used only to construct this prototype.
The build VMs were independent clean QEMU TCG guests on one Apple Silicon host;
they are not independent build infrastructures.

## Inputs and artifacts

The frozen input bundle is
[`input/prepared-final/`](../artifacts/prototype/2026-09-25/bytepin-next20/input/prepared-final/).
Its `build-input-manifest.json` SHA-256 is
`3358d321ebb3a3767576bc722265a91b191f01bb6c7d8d24bb8473aacc316718`; the
pinned toolchain lock SHA-256 is
`e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`. Both
Build A and Build B recorded matching manifest hashes at start and end. The
Debian snapshot is `20260914T120000Z`; the build epoch is `1789387200`.

Build A produced the unsigned ISO at
[`build-a/output/payload.iso`](../artifacts/prototype/2026-09-25/bytepin-next20/build-a/output/payload.iso),
349,175,808 bytes, SHA-256
`46d1206d6bba055686e7d125af130569a9e37bb5ea56fc4cdeb2fe61afb59066`.
Other measured artifacts:

| Artifact | SHA-256 |
| --- | --- |
| Kernel | `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08` |
| Initramfs | `6a472742e5f9bf27ac9cc279be3a668571d8063b33b1fd7e03e0433f2470f11d` |
| SquashFS | `8d1438e4e5e32655533d6d50462401e3d31812a25d12911f5bf3115bdfb0679e` |
| Nexus prototype `.deb` | `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1` |

The initramfs inspection found 1,669 entries across an uncompressed cpio
segment and a zstd segment. The machine-readable
[`C5 manifest`](../artifacts/prototype/2026-09-25/bytepin-next20/build-a/output/c5-manifest.json)
and [`static result`](../artifacts/prototype/2026-09-25/bytepin-next20/build-a/output/c5-result.json)
both pass. The manifest establishes the required initramfs ordering and
quarantine content in the built image; it does not claim quarantine before
kernel block-device registration.

## QEMU C5

The first frozen runtime measurement is retained unchanged at
[`qemu/c5-a/result.json`](../artifacts/prototype/2026-09-25/bytepin-next20/qemu/c5-a/result.json)
and has verdict **FAIL**. Its log exposed two evaluator defects: OSC terminal
controls were not removed before line parsing, and the hotplug read-only
observation did not accept explicit `sysfs_ro_after` / `blockdev_ro_after`
fields. The raw run itself showed a passing hotplug write-denial record, but
that observation was not sufficient to override the fail-closed result.

After correcting those parser issues and adding regression tests, the same
Build A payload and static C5 evidence were run again into a separate, empty
output directory. The new
[`QEMU result`](../artifacts/prototype/2026-09-25/bytepin-next20/qemu/c5-a-parserfix-rerun/result.json)
and [`serial log`](../artifacts/prototype/2026-09-25/bytepin-next20/qemu/c5-a-parserfix-rerun/serial.log)
both report runtime **PASS**. Initramfs quarantine, read-only transition,
denied write probe, and userspace handoff passed. The file-backed hotplug
fixture was discovered, made read-only, and its write was denied; all tested
fixture files retained their before/after hashes. The runner's event ordering
places its initial quarantine marker before the recorded kernel `vda`
registration line, but the marker reports zero devices at that instant; this
is not evidence that a device was quarantined before kernel registration.
QEMU used q35 TCG with direct kernel/initramfs boot. Only newly created regular
files were used as disk fixtures; no host block device, USB, or host writer
target was attached.

The original FAIL and later PASS are distinct immutable runs. The later result
does not rewrite the first result; the difference is attributed to the
evaluator fixes, not to a rebuilt payload.

## Nexus installer and lifecycle fixture

The [`Nexus guest result`](../artifacts/prototype/2026-09-25/bytepin-next20/qemu/nexus-e2e-a/result.json)
and [`guest report`](../artifacts/prototype/2026-09-25/bytepin-next20/qemu/nexus-e2e-a/guest-report.json)
pass for the bounded disposable-guest flow: package install, status, two
offline signed fixture imports (generation 1 then 2), verification, and
rollback to generation 1 with a required reason. Operational units remained
masked. This uses the direct `ModelImport` API, not the product CLI import
path or commissioned product trust store. No network fetch, provider
admission, or Edge activation was performed; this is not the complete product
Mission Pack flow.

## Reproducibility

[`rootfs-extraction-comparison.json`](../artifacts/prototype/2026-09-25/bytepin-next20/rootfs-extraction-comparison.json)
reports `reproduced` with no first divergence. Builds A and B used distinct
fresh guest identities and independently clean build workspaces, while using
the exact same frozen manifest and pinned inputs. Their unsigned ISO, kernel,
initramfs, SquashFS, package, and compared rootfs/initramfs contents match.
This is a two-VM measurement on one host, not a cross-host or production
builder reproducibility claim.

## Verification and remaining gates

The C5 runner tests pass (37 tests), Ruff `--select F` passes on the changed
runner and test module, Python bytecode compilation passes, and `git diff
--check` passes. The repository-wide lint baseline still has 53 unrelated
warnings; they were not changed. Existing Boot and Nexus issue acceptance
conditions remain open; this prototype does not justify closing them.

Hardware and firmware boot, Secure Boot, real device hotplug, HIL no-write
evidence, USB writing, independent-host reproducibility, production-builder
selection, product-CLI import, commissioned trust, provider admission, and Edge
activation remain unverified or out of scope. The artifact is unsigned and
must not be treated as production-ready.
