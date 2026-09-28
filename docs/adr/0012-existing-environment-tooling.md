# ADR-0012: Boot assists tools in a user-provided environment

Status: **accepted by owner (2026-09-28); implementation details deferred**.

## Decision

Azazel-Boot does **not** build or remaster Debian Live or another operating
system. It does not select or maintain an image builder, produce boot media,
partition or format a device, write an image to USB/SSD, own an initramfs boot
path, or provide Boot-owned encrypted OS persistence.

Boot's current role is limited to user assistance in an operating environment
that already exists and is started by the user. The only candidate product
direction is to help introduce and use a small set of responder tools that
make Boot useful in a way distinct from Nexus. No concrete tool, supported host
matrix, package source, trust root, privilege model, or install/uninstall flow
is approved yet. No operational installer may be implemented until one such
tool and its effects are specified.

Nexus continues to own its persistent gateway/appliance installation. Boot is
not a parallel Nexus base installer. Edge remains the sole decision and
enforcement authority. This decision does not authorize provider admission,
network fetch, model acquisition, or Edge activation.

## Consequences

- The previous Boot image-builder and media-writer contracts are retired.
- Boot-specific USB layout, initramfs quarantine, Secure Boot, laptop-HIL,
  encrypted persistence, unlock, dirty-write, snapshot, and recovery plans are
  out of the current product scope. Existing QEMU and R11 records are historical
  observations only; their generated artifacts and procedures are not inputs
  to future Boot work.
- A future helper must target a user-provided host. Before implementation it
  must specify supported environments, exact inputs, package authenticity,
  privileges, files and services changed, network behavior, explicit approval,
  rollback/uninstall, and what its success evidence proves.
- A future helper may not expose raw device paths or write arbitrary media.
  No installer behavior is implied by this ADR.
- Boot's status scaffold and any reusable decision code do not become an
  operational product merely because the direction is recorded.
- The retired ADRs and work items are not deleted from Git history, but their
  current-tree copies, prototypes, generated evidence, and implementation
  backlog may be removed to avoid presenting them as live requirements.

## Reopening conditions

Reconsider this decision only if the owner explicitly restores an OS-image or
removable-media product requirement and updates the Azazel program plan. A
future helper proposal does not reopen the retired builder or writer scope.
