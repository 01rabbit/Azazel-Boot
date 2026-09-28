# Azazel-Boot Responder

Azazel-Boot is a software companion for helping a user prepare and use selected
Azazel tools in an operating environment the user already has. **Boot does not
create or remaster Debian Live or another operating system, build boot media,
partition or format a disk, or write an OS image to USB/SSD.** It is not a
portable operating system or a second appliance installer beside Nexus.

The only product direction presently authorized is to explore a small helper
installer for Boot-specific tools and user-assistance utilities that provide a
clear purpose distinct from Azazel-Nexus. The exact tool set, supported host
environments, installation effects, trust/update model and operator flow are
not yet specified. Until they are specified and reviewed, this repository
contains no operational installer and no claim that a tool has been installed
or verified on a host.

## Current state

- The historical image-builder, media-writer, initramfs, persistence and HIL
  prototype tracks have been retired from the current Boot scope.
- R11 and other generated prototype artifacts are not retained. Historical Git
  commits are not a source of currently supported inputs or procedures.
- The repository is being reduced to current direction, governance and the
  procedure for defining and validating future user-assistance tools.
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
3. Keep planning and inspection read-only. Any installation must show an exact
   plan, require explicit user approval, verify pinned inputs, and report what
   changed; never select a disk or invoke an OS/media writer.
4. Use synthetic fixtures for tests. Do not boot, format, partition, or write
   physical media as part of Boot development.
5. Add only the minimum implementation and tests for an approved helper. Keep
   provider admission, network fetch, and Edge activation disabled unless their
   owning contracts separately authorize them.

See [the current scope ADR](docs/adr/0012-existing-environment-tooling.md),
[architecture](docs/architecture.md), and [open issue map](docs/issue-map.md).

## Governance

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Architecture decisions](docs/adr/README.md)
- [License](LICENSE)
