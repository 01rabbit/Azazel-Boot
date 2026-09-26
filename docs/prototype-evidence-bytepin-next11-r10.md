# bytepin-next11-r10 prototype evidence

This is a prototype-only measurement. The two clean Debian 13 amd64 builder
guests shared one Apple Silicon host and QEMU TCG. `live-build` remains an
evaluation construction method; no production builder is selected. Nothing in
this report is hardware, firmware, Secure Boot, release, or writer evidence.

## Frozen inputs and payloads

- Input manifest: [`build-input-manifest.json`](../artifacts/prototype/2026-09-26/bytepin-next11-r10/input/prepared/build-input-manifest.json), SHA-256 `5a336d28693ad19dad7355c4823e518f090475c0be355828aa86dda10feb72bc`.
- Prepared input archive SHA-256: `0d8226d6b01efe48d40db91016f12f3b3f5de27e99e86250b9ed924f491906cb`.
- Debian base image SHA-256: `5754395abffb1d384d50f6d0945d46d1beb7be42a7e786e4fc4a6f27270ab16f`; builder seed SHA-256: `54b8f4d5533dc80bf64154cc3e12ac59658b107cbba88a192ea0b5a2ef539a35`.
- Debian snapshot: `https://snapshot.debian.org/archive/debian/20260914T120000Z/`; toolchain lock SHA-256: `e05a2286906a885857bfe9b28a26fc19011ad5ee56701e02f7e57dabd52f134c`.
- Build A and B ISO SHA-256: `4520a6aa7a98a0b849f87f39dbcfb42fb84cb955a1bb127e1fe4bb937033321a` (349,175,808 bytes).
- Kernel SHA-256: `2b2358b37674d2505350528875bb17afae2a36522a9e8a9417eaca65a7da0e08`; initramfs SHA-256: `4f865e9decc3ba6d5ae3d16b4dfbb9c0e564b05eb95f6341006e2326884465a5` (41,497,088 bytes).
- SquashFS SHA-256: `e564542ce13abd903a5b767c79865df4a91da4fa9988aaa52aa9f5347caf8084` (280,485,888 bytes); Nexus `.deb` SHA-256: `e1e93f9566f97c1f400346b1d8c6385c9cb5aa5d4134154e4ab569eb7475bad1` (239,088 bytes).
- [`reproducibility-result.json`](../artifacts/prototype/2026-09-26/bytepin-next11-r10/build/reproducibility-result.json) reports `reproduced`, `first_divergence: null`; all 16 component comparisons are true, including final ISO, kernel, initramfs/order/metadata, SquashFS, rootfs content/metadata, boot components and Nexus package.
- Runner source hashes in the frozen manifest match the executed C5 (`fbfbdbaaf0eb461b840bdc245808c47a0337a0830fd9e5fe3a18f12e2916bc7e`) and Nexus (`f72f2d28cbb16612c2530a508e4e5a4a65fbd8022ddb35263a0097c4f9efb27d`) runner hashes. This evidence does not claim independent-host reproducibility.
- [`runner-freeze-audit.json`](../artifacts/prototype/2026-09-26/bytepin-next11-r10/build/runner-freeze-audit.json) records the post-measurement hash reconciliation: manifest, frozen bundle, runtime result, and post-measurement source hashes agree for both runners; both builds also record identical frozen-input start/end digests.

The first builder launch used a next10 seed ISO instead of the seed pinned by
this manifest; its SSH key did not match and no build started. That launch was
stopped and recorded in [`build-attempts.json`](../artifacts/prototype/2026-09-26/bytepin-next11-r10/build/build-attempts.json).
The corrected A/B builds both completed. Two earlier attempts stopped before
producing a payload; their failure evidence is retained. Only the three
disposable builder overlays were moved to OS Trash after logs and output
artifacts were collected. They remain recoverable there; OS Trash was not
emptied.

## Initramfs C5 and QEMU runtime

Static initramfs content/order inspection passed. The static C5 policy result
still has a nested `quarantine_not_persistent` failure because static build
time cannot establish the later runtime handoff. Keep that static policy result
distinct from the QEMU fixture runtime result.

The [C5 QEMU result](../artifacts/prototype/2026-09-26/bytepin-next11-r10/qemu/c5-a/result.json)
is `pass` for its bounded regular-file-backed fixture scope and reached
`multi-user.target`. For `/dev/vda`, the initial marker reported zero registered
devices. Kernel registration was logged at guest uptime about 3.367 s; the
initramfs helper then observed sysfs and blockdev RO state `1` before the write
probe. `openat(O_WRONLY|O_CREAT|O_TRUNC)` succeeded, but the subsequent 1-byte
`write()` returned `-1`, exact errno `EPERM`. This was observed after the RO
transition, so the report classifies it as a read-only-policy denial supported
by measured RO state—not `EROFS`, and not a failed open. Quarantine before
kernel registration was `NOT_OBSERVED`.

Userspace handoff sub-observations are recorded separately in the same JSON:
device discovery, marker presence and schema validation, boot/session binding,
RO state and write denial are `PASS`. The marker's session ID matched the guest
boot ID. The fixture was **not mounted** (`mount_state=not_mounted`; mount type,
point and flags are N/A). Therefore this is a quarantine-state handoff fixture,
not evidence that a persistence partition was mounted or that encrypted
persistence storage works. A `mounted_after=PASS` token in one event is not
interpreted as mount success because the explicit mount state is
`not_mounted`.

The QEMU hotplug test is a separate userspace continuing-rule observation:
QMP `device_add` succeeded after multi-user; kernel discovery was logged around
37.499 s, udev add/provenance at 37.56 s, quarantine helper activity at 37.62 s,
and the RO transition from `0` to `1` around 37.97 s. The later `write()` at
39.57 s returned `-1 EPERM`. The udev rule/helper and resulting RO state are
observed; the raw ioctl itself was not captured (`blockdev-setro` returned 0,
raw syscall/errno `NOT_OBSERVED`). Event ordering is recorded in guest uptime
and serial offsets, not as a synchronized host/guest wall clock. The fixture
file digest remained unchanged.

Selected QEMU write tracepoints recorded zero write events, but no discard
tracepoint was available; this is not comprehensive proof that no host I/O of
any kind occurred. Both attached targets were newly created regular files. No
host block device, internal disk or USB writer target was attached. QEMU is not
hardware verification.

## Nexus E2E and serial transport

The [Nexus QEMU result](../artifacts/prototype/2026-09-26/bytepin-next11-r10/qemu/nexus-e2e-a/result.json)
passed: test `.deb` install, status, generations 1 and 2, verification and
rollback to generation 1. The serial report frame completed 12/12 chunks;
received and expected length were 8,916 bytes and their SHA-256 values matched
(`d888c6c5b3e7ba176150882c663e8923c19c341b1e344b7b15097fb5778316e3`). No
partial frame was reported. This run therefore did not reproduce the prior
serial truncation.

Scope is limited: generation operations used disposable fixtures through the
direct `ModelImport` API. The product CLI import path and commissioned product
trust store were not used. Network fetch, provider admission and Edge activation
were not performed; operational units remained masked. This does not prove the
full operator commissioning/import flow.

## `/var/lib/dpkg/info` allocation observation

The detailed [allocation analysis](../artifacts/prototype/2026-09-26/bytepin-next11-r10/build/dpkg-allocation-analysis.json)
compares both the historical next10 difference and this r10 repeat. In next10,
the comparator found one rootfs metadata delta only: `/var/lib/dpkg/info`
`st_size` was 49,152 bytes in A and 61,440 bytes in B, while mode, owner,
pinned mtime, 1,103 child names and rootfs file contents matched. Builder logs
show both scratch filesystems were ext4. Different host inode numbers were
recorded; raw readdir/creation order, `st_blocks`, xattrs and ACLs were not
captured then. The SquashFS and final ISO SHA-256 were nevertheless identical
in next10, so this host-directory size delta did not appear in serialized
payload bytes. Its exact ext4 insertion/index mechanism is not proven; no
normalization was used.

In both r10 extracted-rootfs observations, the directory had 1,109 entries,
size 57,344 bytes, 112 4-KiB blocks, ext4 backing filesystem and no recorded
xattrs; the raw readdir name-order digest matched. Rootfs contents/metadata,
SquashFS and final ISO were byte-identical A/B. Entry creation order remains
unobserved. Thus the original difference is classified at the filesystem
directory-allocation layer and did not recur in the r10 repeat, while its exact
microcause remains open.

## Remaining gates

Keep open: physical/hardware HIL; stable identity and complete persistence-media
mount behavior; comprehensive no-host-write evidence; firmware/bootloader and
Secure Boot; production builder selection; independent-host/builder
reproducibility; Nexus product CLI and commissioned trust flow. Do not promote
this QEMU evidence to any of those claims.
