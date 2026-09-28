# ADR-0012: Boot assists tools in a user-provided environment

Status: **accepted and clarified by owner (2026-09-28); implementation details deferred**.

## Decision

Azazel-Boot does **not** build or remaster Debian Live or another operating
system. It does not select or maintain an image builder, produce boot media,
partition or format a device, write an image to USB/SSD, own an initramfs boot
path, or provide Boot-owned encrypted OS persistence.

Boot's current role is user assistance in an operating environment already
provided and started by the user. The intended field flow may use a
user-prepared Debian Live SSD with persistence configured by the user, then the
existing Nexus tools installer, followed by boot verification on a separate
PC. Boot may document and assist the persistence setup and verification, but
does not create the LiveOS, write/partition/format the SSD, manage the
persistence volume, or duplicate the Nexus installer. The exact Live image,
persistence choices, supported PC set, and operator procedure remain to be
verified; no Boot installer or autonomous host mutation is approved.

Nexus continues to own its persistent gateway/appliance installation. Boot is
not a parallel Nexus base installer. Edge remains the sole decision and
enforcement authority. This decision does not authorize provider admission,
network fetch, model acquisition, or Edge activation.

## Consequences

- The previous Boot image-builder and media-writer contracts are retired.
- Boot-owned USB layout, writer, initramfs quarantine, encrypted-persistence
  lifecycle, unlock, dirty-write, snapshot, and recovery plans are out of scope.
  User-managed Live persistence guidance and a separate-PC boot check are in
  scope. Existing QEMU/R10 and R11 records remain historical only and do not
  satisfy this workflow's acceptance.
- Guidance must identify the exact user-supplied Live image and distinguish
  Debian Live's persistence mechanism from Boot-owned persistence. It must
  point to the current Nexus installer and accurately describe its prerequisites
  and effects.
- Boot may not expose raw device paths or write arbitrary media. No installer
  behavior is implied by this ADR.
- Boot's status scaffold and any reusable decision code do not become an
  operational product merely because the direction is recorded.
- The retired ADRs and work items are not deleted from Git history, but their
  current-tree copies, prototypes, generated evidence, and implementation
  backlog may be removed to avoid presenting them as live requirements.

## Reopening conditions

Reconsider Boot-owned OS construction or writing only if the owner explicitly
restores that product requirement and updates the Azazel program plan. The
user-managed Live/persistence/verification flow does not reopen the retired
builder, writer, or Boot-owned persistence scope.
