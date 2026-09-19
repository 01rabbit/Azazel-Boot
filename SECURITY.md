# Security Policy

Azazel-Boot (`AZ-03`, `Azazel-Boot Responder`, no codename assigned) is a civil
emergency environment started from removable USB SSD media on a commissioned,
compatible x86_64 laptop. It integrates released Azazel components; it is never
a second decision or enforcement authority. Azazel-Edge's deterministic arbiter
holds that authority in every capability state.

## Reporting a vulnerability

Report privately via GitHub Security Advisories:
<https://github.com/01rabbit/Azazel-Boot/security/advisories/new>

Do **not** open a public issue for a suspected vulnerability.

Include: affected commit, the document or behavior concerned, repro steps or a
minimal PoC where code exists, and observed impact. Sanitize anything you
attach — strip keys, passphrases, recovery material, host identifiers, and real
incident data.

No bounty program. Reporters are credited unless anonymity is requested.

## Response targets

- Acknowledgement: within 7 days
- Initial assessment (severity, affected versions): within 14 days
- Fix and disclosure are coordinated with the reporter.

## Current scope is unusual — read this first

This repository contains **no product code**. There is no image, no installer,
no package, and no Fabric pin. Nothing is implemented or verified.

There is therefore no running Azazel-Boot to find a runtime vulnerability in.
What can be reported today is a **defect in the target contract**: a documented
design that, if built as written, would violate one of the invariants below.
Such a report is in scope and is treated as a security report, because the
documents are what implementers will build from.

## In scope

Vulnerability classes specific to this product's invariants, whether found in a
future implementation or in the documented design:

- **Host-write escape**: any path that writes content to an internal host block
  device without an explicit operator-approved export target — including
  initramfs automount, filesystem repair or journal replay, host swap or resume
  activation, LVM/md/ZFS assembly, a firmware updater, an enrollment tool, or a
  write-capable host mount reachable before or after activation.
- **Quarantine bypass**: reaching internal storage after the initramfs
  quarantine is meant to have closed it, including through a hotplug event, a
  suspend/resume cycle, or a later-loaded driver.
- **Authority escalation**: any path by which Boot, a capability report, a
  configuration overlay, a model response, an advisory result, or a UI action
  authorizes an action that Azazel-Edge's arbiter did not decide.
- **Capability gating bypass**: enabling capture, enforcement, or Deception
  from a resource measurement alone, or from an interface role that was
  inferred rather than operator-confirmed against a composite identity.
- **Trust-class inflation**: presenting an `UNVERIFIED_PLATFORM` or
  `EXTERNALLY_VERIFIED_MEDIA` session as carrying `VERIFIED_FIRMWARE`
  assurance, or labeling evidence as rollback-verified when audit assurance is
  `LOCAL_CONTINUITY_ONLY`.
- **Persistence integrity break**: undetected tampering with encrypted USB
  persistence, silent acceptance of a rolled-back persistence generation, or
  recovery of a dirty volume that promotes attacker-controlled state.
- **Update and boot-chain break**: accepting an artifact with a correct
  signature from the wrong role, an obsolete-but-signed generation, or a
  boot-metadata state that no longer has one verified bootable generation.
- **Surprise-removal unsafety**: owned disruptive rules or routes surviving
  media removal, or a removal path that leaves the host network modified.
- **Evidence and custody defects**: export of evidence whose provenance,
  assurance label, or continuity claim overstates what was demonstrated.

## Out of scope

- The absence of a feature. Nothing is implemented; "Azazel-Boot does not do X"
  is not a vulnerability, it is the current state.
- Hardware that is not in the compatibility envelope. The envelope is empty
  (see `docs/compatibility.md`), so no boot failure, firmware quirk, or driver
  problem on any specific laptop is a security defect today.
- Degraded operation when an optional component is absent. `FULL -> LITE ->
  CORE` degradation is the designed behavior.
- Threat-intelligence content quality or false positives — that belongs to
  Azazel-Knowledge.
- Shared contract defects — report those to Azazel-Fabric.
- Deterministic arbitration or enforcement semantics — report those to
  Azazel-Edge.

## Supported versions

None. There are no releases, no tags, and no supported configuration. Only
`main` exists; report against the commit you read. Nothing in this repository
may be described as operationally certified or supported.
