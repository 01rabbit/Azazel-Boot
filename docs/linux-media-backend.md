# Linux media backend: Issue #27 review boundary

This is prototype implementation and synthetic-test evidence only. It is not
approval to write physical media, a formal security review, or hardware
evidence. The implementation branch is deliberately unable to write media.

## Read-only discovery

`LinuxLsblkInventory` reads `lsblk` JSON and sysfs topology. It does not open a
block node. Root ancestry is derived only from an exact `/` mountpoint and the
`PKNAME` chain; if a root source or ancestor cannot be identified, candidates
fail closed. Missing mountpoint metadata is treated as mounted. Removability
requires USB transport, positive `RM`, and a sysfs USB port position. Unknown,
duplicate, or unstable identities receive no target code.

`LinuxMediaSession` issues random opaque codes tied to one listing. `inspect`
consumes a code once, re-enumerates, compares identity and operator-relevant
attributes, and opens only the selected node read-only. CLI input has no device
path field. Display and `repr` omit hardware identifiers and location fields.
These checks have synthetic inventory coverage; they have not been run on a
Linux host in this task.

## Writer status and failure semantics

The writer service accepts opaque target and artifact codes. It requires
separate target-code re-entry and destructive confirmation, checks current
target eligibility immediately before opening, retains the opened descriptor,
and reads back the written extent from that same descriptor. Artifact bytes
are copied into a private unlinked temporary snapshot and hashed before the
first target write, so subsequent changes to the source file cannot alter the
bytes being sent. If an I/O error occurs after a write attempt, the result is
`write_state_unknown`; it is never represented as a refusal meaning that
nothing changed.

Writer ports require a transaction-scoped capability issued only inside the
service execution path. The hard gate `_physical_writer_reviewed()` still
returns `False` unconditionally. There is no environment variable, CLI flag,
or runtime opt-in. Do not change that gate to `True`.

Important deployment gaps remain: this is still an in-process Python service,
not a separate privileged broker. There is no authenticated IPC, peer-credential
check, service isolation/unit policy, or review-signed activation bound to an
approved PR and exact deployed package digest. The transaction capability
narrows accidental/direct port use but is not a security boundary against code
already executing inside the privileged process. Those are required before an
independent reviewer can approve physical enablement. No physical write was
attempted.

## R11 detached PoC attestation

`tools/poc_r11_attestation.py` is independent of `azazel_boot.artifact.verify`
and the product CLI. It signs/verifies a detached canonical statement pinned
to profile `r11-hybrid-iso-whole-device`, the recorded R11 whole-file SHA-256,
size, input-manifest digest, and classification `unsigned-prototype/boot-only`.
Verification requires an out-of-band SHA-256 pin over the public key's DER
SubjectPublicKeyInfo. Wrong/missing pins, keys, profiles, payloads, sizes,
manifest digests, claims, or signatures are refused. The result type is
evidence only and exposes no writer authorization. A separate explicit adapter
`verification_for_r11_writer()` verifies the full statement, binds the result
to an unsigned candidate record and calls the narrowly scoped private issuance
bridge. `WriteAuthority` then carries `r11-hybrid-iso-whole-device` into its
plan/result; ordinary `artifact.verify()` remains unchanged and still returns
`digest_only` for unsigned R11. A static test confines use of the private bridge
to this one developer-tool module. OpenSSL is required; the tool does not
create or persist private keys.

No trusted R11 signing key/pin or detached attestation has been supplied, so
the adapter has only synthetic test coverage and no R11 write has been
authorized. The adapter must remain a separately reviewed PoC-only path and
must not alter release roots or default verification.

## R11, firmware, and HIL scope

The expected R11 ISO was verified in the checkpoint worktree, not this feature
worktree: 396,689,408 bytes, SHA-256
`3aa21d1c9c97dd74a5d981d17216738e16c2c066cb01dba454cd30e76a297dfa`; manifest
SHA-256 `e36d116ccec45750b84c7d2765094128b8a724e45b91273172cf96a2ae8eeb9a`.
It is a hybrid ISO9660/El Torito image with EFI/GRUB, kernel, initramfs, and
`/live/filesystem.squashfs`. The examined UEFI entry's `BOOTX64.EFI` is GRUB
with no PE signature table; Secure Boot compatibility has not been established.
This is a whole-device boot-only R11 experiment, not the P1/P2/P3 layout of
Issue #59. It does not establish Secure Boot, persistence, release status, or
hardware compatibility beyond an actually recorded individual HIL run.

Tests use injected inventory/readers and synthetic data or regular files. They
do not open `/dev`, block devices, loop devices, physical media, firmware, or
Secure Boot state. Issues #27/#63/#66 remain open pending reviewable writer
architecture, PoC-only writer integration, formal independent review and
deployment activation, an explicitly identified expendable SSD, and the target
laptop HIL. The HIL write/read-back/boot is the hardware experiment itself; a
different prior hardware experiment is not required.
