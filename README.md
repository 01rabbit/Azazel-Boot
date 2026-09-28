# Azazel-Boot Responder

Azazel-Boot is a software companion for helping a user prepare and use selected
Azazel tools in an operating environment the user already has. The intended
workflow is a **user-prepared Debian Live SSD**, user-configured persistence,
the existing Nexus tools installer, then a boot check on a separate PC. **Boot
does not install Debian, create/remaster LiveOS, build boot media, partition or
format a disk, or write an image to USB/SSD.** It is not a portable operating
system or a second appliance installer beside Nexus.

The current assistance scope includes guiding that user-managed flow. A future
small helper installer for Boot-specific tools remains only a proposal: the
exact tool set, supported host environments, effects and trust/update model are
not specified. This repository contains no operational installer and makes no
claim that a tool has been installed or verified on a host.

## Current state

- Boot-owned image-building, media-writing, initramfs quarantine, and
  persistence-management tracks have been retired. User guidance for Debian
  Live persistence and separate-PC boot verification remains in scope.
- R11 and other generated prototype artifacts are not retained. Historical Git
  commits are not a source of currently supported inputs or procedures.
- No OS image or writer is implemented. The operator runbook explains how the
  user's existing Live image, persistence choice, and Nexus-owned installer
  fit together, and what a separate-PC boot check must record.
- Boot creates no decision or enforcement authority. Azazel-Edge remains the
  sole decision and enforcement authority; Boot helpers may not admit
  providers, activate Edge, or fetch models unless a separately approved
  contract explicitly permits it.
- Nexus remains the persistent gateway/appliance integration. Boot must not
  duplicate its base installer or silently inherit Edge's device-specific
  network installer.

## Work procedure

1. Write the user problem and why the tool belongs in Boot rather than Nexus.
2. Define supported host environments and all filesystem, package, network,
   privilege and rollback effects before implementation.
3. Keep Boot guidance read-only. It must not select, partition, format, or
   write a disk, or invoke an OS/media writer. Nexus remains the owner of its
   installer; Boot points to that existing flow rather than duplicating it.
4. Tests must not write physical media. The user may perform the separate-PC
   boot check using their own prepared SSD; QEMU does not substitute for it.
5. Add only the minimum implementation and tests for an approved helper. Keep
   provider admission, network fetch, and Edge activation disabled unless their
   owning contracts separately authorize them.

See [the current scope ADR](docs/adr/0012-existing-environment-tooling.md),
[architecture](docs/architecture.md), and [open issue map](docs/issue-map.md).
For the user-managed flow, see [existing Debian Live and Nexus tools](docs/user-prepared-live.md).

## Governance

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Architecture decisions](docs/adr/README.md)
- [License](LICENSE)
