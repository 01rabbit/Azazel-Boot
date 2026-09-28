# Security policy

Azazel-Boot Responder (`AZ-03`) is currently a non-operational user-assistance
and possible tool-installation scaffold for an environment supplied and
started by the user. It does not build OS images or write boot media. Azazel-
Edge remains the sole decision and enforcement authority.

## Reporting

Report privately via GitHub Security Advisories:
<https://github.com/01rabbit/Azazel-Boot/security/advisories/new>

Do not open a public issue for a suspected vulnerability. Include the affected
commit, concise reproduction steps, and observed impact. Remove credentials,
private keys, and unnecessary host identifiers from all attached material.

Acknowledgement target: 7 days. Initial assessment target: 14 days. No bounty
program; reporters are credited unless anonymity is requested.

## Current scope and in-scope reports

There is no operational installer and no supported host matrix. Reports about
the current scaffold or its documented boundaries are in scope, particularly:

- authority escalation or a path that admits a provider, fetches a model, or
  activates Edge without its owning contract;
- unsafe privilege, package provenance, path handling, or host mutation in a
  future approved helper;
- leakage of credentials or unnecessary host identifiers;
- documentation that overstates implementation, verification, or support.

OS-image building, block-device writing, initramfs quarantine, firmware
management, and Boot-owned encrypted persistence are not Boot product
surfaces. A future helper that requires such a capability needs a new owner
decision before implementation.

## Supported versions

None. There are no operational releases or supported configurations. Report
against the commit under review; do not describe the scaffold as operationally
certified or supported.
