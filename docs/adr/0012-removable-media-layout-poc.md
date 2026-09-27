# ADR-0012: Removable SSD layout for the first persistence prototype

Status: proposed for #58. Software design only; no physical medium has been written or verified.

## Scope and inherited rules

This record narrows ADR-0008 D4.1 to one PoC image. It does not change the three-partition constraint, ADR-0008 D4.1.1's key-protected binding, ADR-0009's writer contract, ADR-0010's fail-closed behavior, or ADR-0011's initramfs-only secret boundary. The root remains immutable. The writable state is restricted to an explicit manifest inside P3. A recovery partition and a volume manager are forbidden.

## Layout

GPT partition order is fixed. This PoC profile requires 512-byte logical sectors. Align each partition start to 1 MiB and require at least 32 GiB of removable capacity. A different logical sector size needs a reviewed profile, not arithmetic guessed by a writer.

| Role | PoC size | Format | Purpose |
| --- | ---: | --- | --- |
| P1 ESP | 512 MiB | FAT32 | UEFI boot files, kernel and initramfs |
| P2 boot_root | 16 GiB | ext4 container, mounted read-only | Contains `/live/filesystem.squashfs`; the SquashFS is the immutable Debian 13 root |
| P3 persistence | remainder, at least 8 GiB | LUKS2, ext4 directly on dm-crypt | Selectively mounted Azazel state and in-partition snapshots |

P1 contains the firmware-readable boot chain plus kernel and initramfs. P2 is an ext4 filesystem containing the standard Debian Live path `/live/filesystem.squashfs`; the initramfs mounts P2 read-only and Debian Live uses its standard SquashFS root and RAM overlay. The writer verifies that the built SquashFS fits P2. The early quarantine hook must run before live-boot scans block media, before device classification, and before any unlock prompt. #58 must verify the final initramfs hook order and that live-boot discovers P2 without accepting an internal disk as its root source. If standard discovery violates that boundary, the layout must stop for review rather than add an unreviewed search hook. The writer uses the boot-medium binding to select P2 and must never fall back to an internal disk. The ESP is mounted read-only after boot or not mounted. Partition labels are descriptive only and cannot establish device identity. No device path, partition number, label or bus topology can replace the binding checks. These sizes are a PoC profile, not a universal disk requirement. Debian Live's [manual](https://live-team.pages.debian.net/live-manual/html/live-manual/the-basics.en.html#what-is-a-live-system) describes the read-only SquashFS system image and the associated kernel/initrd boot flow; its [tool overview](https://live-team.pages.debian.net/live-manual/html/live-manual/overview-of-tools.en.html) describes discovery of a `/live/` directory and RAM-backed writable overlay.

## PoC encryption profile

Use LUKS2 with AES-256-XTS (`aes-xts-plain64`, 512-bit combined key), Argon2id, and ext4 on the opened mapping without LVM. Provisioning must use cryptsetup's memory-bounded Argon2id settings: 256 MiB maximum, one parallel lane, and a 2-second time target. Verify the parameters recorded in the resulting header, since cryptsetup may calibrate iteration count. If target hardware cannot unlock within its resource envelope, fail this profile and revise the ADR before creating media; do not silently weaken it. Use a fresh random LUKS UUID for each medium. Slot 0 holds the operator passphrase. A separate recovery slot and credential handling require an explicit later decision; no recovery secret is copied into the image or repository. Header backup is an operator-controlled encrypted offline artifact, never placed on P1/P2 or in CI evidence.

The password entry and binding check belong to the initramfs-only helper in ADR-0011. The provisioning service may create P3 only as a separate, explicitly confirmed action after #27's verified image write. No public command takes a raw block-device path. A regular-file image can be built in tests, but passing that test does not authorize writing a physical medium.

## Boot and failure behavior

At initramfs entry, quarantine host storage first. Then classify and bind the boot medium, verify the image and commissioning state, and only then attempt a local hidden prompt. An absent/malformed P3, missing key, failed binding, or failed unlock settles an allowed ephemeral CORE session without writing to internal storage. When the boot SSD disappears, services stop/fence; continued operation from cached squashfs pages is not evidence of a healthy session. Reboot/recovery is required. No automatic fsck or journal replay of a quarantined P3 is allowed.

The image digest in the media binding still needs authenticated signed metadata. The available R11 prototype is unsigned, so it cannot satisfy the Secure Boot enabled baseline. Any PoC boot with Secure Boot disabled is allowed only under ADR-0005's owner-approved fallback, after recording the recovery-key location and restoring firmware state at the end; it must be reported as an unsigned prototype and not as Secure Boot verified. The PoC is physical-SSD-first: once the media ADR and #27 target-code writer are reviewed and the exact prototype artifact is available, a physical boot may be tested without waiting for QEMU; QEMU remains supplemental evidence. Full Secure Boot HIL, no-host-write measurement, recovery, and independent build reproduction remain open gates. This record asserts no hardware result.
