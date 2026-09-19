# Threat Model

Status: **target contract**. Nothing in this document is implemented or
verified. No hardware test, no boot test, and no host-storage test has ever
been run. Every mitigation below states an intended design, not an observed
property.

Related: [Architecture](architecture.md) · [Compatibility](compatibility.md) ·
[Security policy](../SECURITY.md) ·
[Program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
§5 R7

## 1. What is being protected, and from what

Azazel-Boot Responder runs on hardware it does not own, in a civil emergency,
operated by someone who may not be a security engineer. That shapes every
entry below.

Three assets:

1. **The host laptop.** It belongs to a clinic, a city office, or a volunteer.
   It must be returned in the state it was lent in. Protecting it from
   Azazel-Boot is as much a goal as protecting it from an attacker.
2. **The portable evidence and audit record.** It travels on removable media
   through uncontrolled hands and may be the only record of what happened.
3. **The integrity of the deterministic control path.** Azazel-Edge's arbiter
   must keep deciding correctly, or stop, and must never be replaced by
   something on the media that is easier to talk into saying yes.

Three adversary classes are in scope: an attacker on the protected network the
responder is assessing; an attacker with **transient physical access** to the
media or the laptop between deployments; and an attacker who can substitute or
tamper with artifacts in transit — an update, a bundle, a model, an overlay.

## 2. Removable-media and platform trust classes

Boot runs on platforms whose firmware trust varies from "verified and owned by
us" to "unknown, possibly hostile". Integrity and evidence claims are limited
to the assurance the class actually demonstrates. The three classes are defined
by the program plan §5 R7:

| Class | What it means | What may be claimed |
| --- | --- | --- |
| `VERIFIED_FIRMWARE` | Platform firmware verifies the Boot media's signature chain before executing it, and platform ownership permits enrolling or relying on that verification. | Boot code integrity is anchored below the operating system. Evidence may cite firmware-anchored verification. |
| `EXTERNALLY_VERIFIED_MEDIA` | Platform firmware does not verify the media, but the media's own signed metadata and digests were verified against a trust root established outside this platform — for example, media prepared and attested elsewhere and carried by the operator. | Boot code integrity is anchored in the media and its external preparation. Evidence may cite media verification, **not** platform verification. |
| `UNVERIFIED_PLATFORM` | Neither holds. Firmware trust is unknown or unavailable, and no external verification of this media on this platform exists. | No integrity claim below the running system. Evidence is labeled accordingly and must not be described as platform- or firmware-verified. |

Rules:

- The class is **determined and displayed**, never assumed, and never silently
  upgraded. An operator must be able to see which class the current session is
  in before acting on its output.
- A class cannot be raised by a successful boot, a passing self-check, or an
  operator's assertion. Those are not evidence about the firmware.
- Assurance claims attached to exported evidence carry the class. Presenting an
  `UNVERIFIED_PLATFORM` session's output as firmware-verified is a security
  defect (see [SECURITY.md](../SECURITY.md)).
- Trust class is an input to the trust/health dimension of the capability model
  ([architecture](architecture.md) §3.4) and can therefore withdraw
  capabilities — a low class does not merely annotate, it constrains.

Where platform ownership is unavailable and firmware verification cannot be
used, the design must still provide a documented portable passphrase and
recovery path. Falling back to "no verification and no recovery" is not
acceptable; falling back to `UNVERIFIED_PLATFORM` **with the claim reduced
accordingly** is.

### 2.1 Media-level threats

| Threat | Intended mitigation |
| --- | --- |
| Substituted or cloned USB SSD presented to the operator as theirs | Signed immutable image with redundant signed boot metadata; media identity displayed at startup; cloning produces a new node and session identity and carries no active or one-shot lease. |
| Tampered update installed to the media | Updates are written to the **inactive** slot; the full digest is verified before selection; promotion happens only after a health-confirmed trial boot; failure falls back automatically. |
| Correctly signed but obsolete or wrong-role artifact | Admission requires an exact tested compatibility tuple, the correct signer role, and a minimum security epoch, in addition to a valid signature. Anti-rollback by version number alone is insufficient. |
| Media physically stolen | Persistence is encrypted; evidence export is encrypted; the passphrase/recovery path is documented and portable. Theft of the media must not yield plaintext evidence. |

## 3. Initramfs host-storage quarantine

**This is the product's defining safety property.** The target is zero content
writes to internal host block devices from initramfs entry through shutdown,
until an operator explicitly selects and approves an export target.

The quarantine is established in the initramfs, **before** anything that could
touch a disk starts, and holds for the whole session. Within it, Boot MUST NOT:

- activate host swap or resume from a host hibernation image;
- automount any non-Boot block device;
- run filesystem repair, `fsck`, or journal replay on a host filesystem;
- assemble or activate LVM volume groups, md arrays, or ZFS pools;
- run a firmware updater or an enrollment tool;
- mount any host filesystem write-capable.

Read-only inspection of a host device is a separate, operator-initiated action
and is not implied by boot.

### 3.1 Why the initramfs is the boundary

By the time a general-purpose userspace is running, several subsystems will
have already tried to be helpful: udev rules automount, LVM and md scan and
activate, systemd resumes from a hibernation image, and a filesystem driver
replays a dirty journal on mount. Each of those is a **write**, and each
happens before any Boot policy code would run. A quarantine that starts in
userspace starts too late. It must be the first thing the initramfs does and
must survive into userspace rather than being re-established there.

### 3.2 Threats and intended mitigations

| Threat | Intended mitigation |
| --- | --- |
| Automount or journal replay silently modifies a host filesystem | Host block devices are blocked at the device layer before any filesystem driver sees them; no automount rule is present in the image. |
| Host hibernation image is resumed, corrupting the owner's session | Resume is disabled unconditionally; a host hibernation signature is never consumed. |
| LVM/md/ZFS auto-assembly writes metadata | Auto-assembly is disabled; no scan runs against host devices. |
| A device appears **after** the initramfs (hotplug, dock, resume from suspend) | The quarantine is a continuing rule, not a one-time scan. A device that appears later is quarantined on appearance. This is explicitly a place where a one-time implementation would be wrong. |
| Firmware NVRAM changes made by the platform itself (boot entry creation, boot order update) | **Not preventable by Boot.** These are reported separately and are explicitly excluded from the zero-content-writes claim. Reporting them is required; preventing them is not promised. |
| An operator genuinely needs to write to the host | Only through an explicitly selected, explicitly approved export target. The approval is per-target and per-session, is recorded in the audit record, and is never a persisted preference. |

### 3.3 What must be demonstrated before this is more than a claim

The program gate requires a hardware-in-the-loop record of **zero content
writes to internal block devices** across a full session, and a separate report
of any unavoidable firmware NVRAM change. Until that record exists, this
section is a design, and the README's status table says so.

## 4. Surprise USB removal

The media will be removed while running. Someone will trip over it, a responder
will grab the wrong device, or the machine will be needed back immediately.
This is an expected event, not an exceptional one.

The danger is specific: Boot may have installed disruptive network rules and
routes on the host. If the media disappears, the code that would withdraw them
disappears with it — and the host is left modified, which is the one outcome
the product exists to prevent.

| Threat | Intended mitigation |
| --- | --- |
| Owned disruptive rules and routes survive removal | A **RAM-resident** release supervisor withdraws owned rules and routes independently of the persistence media. It must not need to read anything from the removed device to do its job. |
| New actions are taken after removal, without an audit path | Removal fences new actions immediately; existing actions follow their predeclared safe expiry or fence behavior. |
| Partially written persistence leaves an unrecoverable volume | Journal/WAL with explicit sync boundaries, redundant metadata, and a dirty-shutdown marker. The operation order is prepare-and-sync, apply, verify, persist receipt: a prepare or sync failure produces zero changes. |
| Operator assumes the session is still usable | After removal the system displays a reboot requirement rather than continuing in an ambiguous state. |
| Removal is used deliberately to strand a rule an attacker benefits from | Same mitigation: withdrawal is RAM-resident and does not depend on the removed media. This is why the supervisor's independence is a security property and not a robustness nicety. |

## 5. Persistence tampering

Encrypted persistence is created on first use, outside the reproducible base
image. It holds session state, audit checkpoints, and evidence. It is the part
of the system an attacker with transient physical access will reach for.

| Threat | Intended mitigation |
| --- | --- |
| Offline modification of persistence contents | Encryption with integrity protection; a modification that is not authenticated is detected at boot and the volume is quarantined rather than repaired into use. |
| Rollback to an older persistence generation | Generation counters bound into the signed checkpoint chain; an older generation is detected, not silently accepted. A rollback of software never restores obsolete trust state, policy, or hardware bindings. |
| Audit chain truncation or splice | Two-copy signed checkpoints binding product/node/boot identity, log and security epoch, monotonic sequence, previous checkpoint, current head, active versions, and generation; an operator-carried or remote anchor when available. |
| No anchor is available (common on borrowed hardware) | Audit assurance is reported as `LOCAL_CONTINUITY_ONLY`. That state forbids live Deception, forbids disruptive actions, and forbids claiming rollback-verified finalized evidence unless a named emergency policy records explicit operator acceptance. Exports are labeled locally consistent and **not** rollback verified. This is a reduced claim, not a disabled product. |
| Dirty volume from an unclean shutdown is repaired into a state an attacker chose | Boot-time repair is bounded and conservative; a volume that cannot be repaired to a verified state is quarantined, and the failure is visible rather than silent. |
| Persistence migration loses data or cannot be rolled back | Migrations are backward compatible, or require a verified pre-trial snapshot and a restore path. A failed trial restores the snapshot. |
| Passphrase loss makes evidence unrecoverable | A documented portable passphrase and recovery path exists, especially for the `UNVERIFIED_PLATFORM` case where platform-sealed key material is unavailable. Recovery authority cannot sign ordinary field checkpoints or hide a discontinuity. |

## 6. Authority and capability threats

These are not media threats, but they are the ones that make a compromised
Boot dangerous rather than merely broken.

| Threat | Intended mitigation |
| --- | --- |
| Boot becomes a second decision authority under time pressure | Edge's deterministic arbiter is the only authority in every capability state. There is no emergency exception, no offline exception, and no degraded-mode exception. |
| A capability report, overlay, manifest, model response, or UI action is treated as authorization | Descriptive records are recursively stripped of command, unit, route, firewall, device-path, executor, boolean-authorization, and trust-decision fields. A description never authorizes. |
| Capture, enforcement, or Deception is enabled because the laptop has enough RAM | Capability is the intersection of resource, topology, verified assets, and trust/health. A resource measurement cannot enable a NIC role. |
| An interface role is inferred from a name, link state, or default route | Roles require read-only inventory plus explicit operator confirmation against a composite identity. |
| A stressed operator confirms something they do not understand | The confirmation interface must present physically checkable facts. This is a genuine residual risk: the design reduces it, and does not eliminate it. |
| Enforcement severs the path used to supervise it | Management paths are out of ordinary action scope; high-impact changes require an independent management path or a physical local console plus a two-stage commit with operator acknowledgement inside the lease window. A single-NIC laptop therefore does not get enforcement eligibility. |

## 7. What Azazel-Boot explicitly does not defend against

Stating these plainly is part of the threat model. A product that pretends to
cover them is more dangerous than one that does not cover them.

- **Compromised platform firmware.** A UEFI implant, a malicious option ROM, or
  a tampered firmware image is below everything Boot can observe. On an
  `UNVERIFIED_PLATFORM` this is not merely undefended, it is undetected, and
  the trust class exists to say so.
- **Hardware implants and DMA-capable peripherals.** A malicious Thunderbolt or
  PCIe device, a hardware keylogger, or an interposer on the USB path defeats
  the software boundary. Boot does not attempt to detect them.
- **A hostile host owner.** If the person lending the laptop is the adversary,
  they control the platform and the physical environment. Boot's guarantee runs
  the other way — it protects the host from Boot — and cannot protect Boot from
  the host.
- **Evil-maid access to the media between deployments.** Signature verification
  detects tampering with signed content. It does not detect a hardware
  substitution of the enclosure, and it does not protect a passphrase typed on
  a compromised keyboard.
- **Cold-boot and memory-remanence attacks.** Key material in RAM during a
  session is exposed to an attacker with physical access to a running or
  just-powered-off machine.
- **Side channels and traffic analysis.** Timing, power, electromagnetic, and
  network-metadata channels are out of scope.
- **Firmware NVRAM changes made by the platform.** Boot entries and boot-order
  updates written by the firmware itself are reported, not prevented. The
  no-host-write property covers **content writes to internal block devices**,
  and saying otherwise would be false.
- **Physical destruction or seizure of the media.** Encryption protects
  confidentiality. Nothing here protects availability of the only copy.
- **An operator acting against the mission.** Boot records what was approved;
  it does not adjudicate whether the approval was legitimate.
- **Correctness of external advisory content.** Threat-intelligence quality
  belongs to Azazel-Knowledge; shared contract defects belong to Azazel-Fabric;
  arbitration semantics belong to Azazel-Edge.
- **Hardware outside the compatibility envelope.** The envelope is currently
  **empty** ([compatibility](compatibility.md)). Boot makes no claim about any
  specific laptop, and a failure on an unqualified machine is not a defect
  against a promise that was never made.

## 8. Residual risk this document does not resolve

- Every mitigation above is unimplemented. The gap between this document and a
  running system is the entire product.
- The non-technical-operator confirmation problem (§6) is reduced by design and
  not eliminated by it.
- `UNVERIFIED_PLATFORM` is expected to be the common case in civil emergency
  use. The product must remain useful there while making weaker claims, and the
  discipline that keeps those claims weak is not yet enforced by any code.
