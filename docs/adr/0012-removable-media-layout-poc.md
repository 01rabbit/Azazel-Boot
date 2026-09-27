# ADR-0012: Removable SSD layout for the first persistence prototype

Status: proposed for #58. Software design only; no physical medium has been written or verified.

## Scope and inherited rules

This record narrows ADR-0008 D4.1 to one PoC image. It does not change the three-partition constraint, ADR-0008 D4.1.1's key-protected binding, ADR-0009's writer contract, ADR-0010's fail-closed behavior, or ADR-0011's initramfs-only secret boundary. The root remains immutable. The writable state is restricted to an explicit manifest inside P3. A recovery partition and a volume manager are forbidden.

## Layout

GPT partition order is fixed. This PoC profile requires 512-byte logical sectors. Align each partition start to 1 MiB and require at least 32 GiB of removable capacity. A different logical sector size needs a reviewed profile, not arithmetic guessed by a writer.

| Role | PoC size | Format | Purpose |
| --- | ---: | --- | --- |
| P1 ESP | 512 MiB | FAT32 | UEFI boot files, kernel and initramfs |
| P2 boot_root | 16 GiB | SquashFS directly on partition, read-only | Debian 13 immutable root; unused tail is not a writable filesystem |
| P3 persistence | remainder, at least 8 GiB | LUKS2, ext4 directly on dm-crypt | Selectively mounted Azazel state and in-partition snapshots |

The writer must verify the actual payload fits P2. P1 contains the firmware-readable boot chain plus kernel and initramfs. The custom initramfs mounts the raw P2 SquashFS read-only as the system root, then places a RAM-backed writable overlay over it. It must establish host-storage quarantine before device classification or any unlock prompt. The prototype does not assume Debian Live's default live-boot flow, which normally finds a file named live/filesystem.squashfs; #58 must verify the custom root/overlay path against the built artifact before the first destructive write. The writer uses the boot-medium binding to select P2 and must never fall back to an internal disk. The ESP is mounted read-only after boot or not mounted. Partition labels are descriptive only and cannot establish device identity. No device path, partition number, label or bus topology can replace the binding checks. These sizes are a PoC profile, not a universal disk requirement. Debian Live documents both the read-only SquashFS system image and the medium-dependent bootloader/initramfs relationship in its [manual](https://live-team.pages.debian.net/live-manual/html/live-manual/the-basics.en.html#what-is-a-live-system).

## PoC encryption profile

Use LUKS2 with AES-256-XTS (`aes-xts-plain64`, 512-bit combined key), Argon2id, and ext4 on the opened mapping without LVM. Provisioning must use cryptsetup's memory-bounded Argon2id settings: 256 MiB maximum, one parallel lane, and a 2-second time target. Verify the parameters recorded in the resulting header, since cryptsetup may calibrate iteration count. If target hardware cannot unlock within its resource envelope, fail this profile and revise the ADR before creating media; do not silently weaken it. Use a fresh random LUKS UUID for each medium. Slot 0 holds the operator passphrase. A separate recovery slot and credential handling require an explicit later decision; no recovery secret is copied into the image or repository. Header backup is an operator-controlled encrypted offline artifact, never placed on P1/P2 or in CI evidence.

The password entry and binding check belong to the initramfs-only helper in ADR-0011. The provisioning service may create P3 only as a separate, explicitly confirmed action after #27's verified image write. No public command takes a raw block-device path. A regular-file image can be built in tests, but passing that test does not authorize writing a physical medium.

## Boot and failure behavior

At initramfs entry, quarantine host storage first. Then classify and bind the boot medium, verify the image and commissioning state, and only then attempt a local hidden prompt. An absent/malformed P3, missing key, failed binding, or failed unlock settles an allowed ephemeral CORE session without writing to internal storage. When the boot SSD disappears, services stop/fence; continued operation from cached squashfs pages is not evidence of a healthy session. Reboot/recovery is required. No automatic fsck or journal replay of a quarantined P3 is allowed.

The image digest in the media binding still needs authenticated signed metadata even when firmware Secure Boot is disabled for a PoC. An unsigned boot chain must be explicitly labelled `unsigned prototype` and cannot claim a verified firmware chain. The PoC is physical-SSD-first: once the media ADR and #27 target-code writer are reviewed and a verified prototype artifact exists, the first removable SSD boot may proceed without waiting for QEMU; QEMU exercises run in parallel as supplemental evidence. Secure Boot HIL, full no-host-write measurement, recovery, and independent build reproduction remain Stage B/C gates in #57. This record asserts no hardware result.
