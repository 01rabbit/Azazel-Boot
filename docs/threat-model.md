# Threat Model

Status: **target contract**. Nothing in this document is implemented or
verified. No hardware test, no boot test, and no host-storage test has ever
been run. Every mitigation below states an intended design, not an observed
property.

Related: [Architecture](architecture.md) · [Compatibility](compatibility.md) ·
[Quarantine policy](quarantine-policy.md) ·
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
| Persistence opened on a medium that is not the one it was created on | Opening requires a **hardware-provided stable media identity** — a USB serial descriptor, a SCSI VPD WWN, an NVMe EUI-64 or NGUID, an ATA serial — bound under a **key-protected HMAC** together with the LUKS persistence UUID, the signed Boot image digest and the commissioning generation. Any of the four changing refuses. Topology is never identity: a bus path, a device node, a port or an enumeration order is not an accepted source. |

**What the media binding does not defend against, stated here rather than
discovered later.** It does not defeat a full byte-for-byte clone of the medium
made together with its hardware identity, and it does not defeat an enclosure
or bridge that reports an identity of the adversary's choosing — cheap USB-SATA
and USB-NVMe bridges are programmable, and a whole production run may ship with
one serial descriptor. Boot refuses the placeholders it can recognise, which is
a floor and not a guarantee: a bridge reporting a plausible unique string is
indistinguishable from a genuine device at this layer. The *source* vocabulary
also cannot be a topology one — there is no value for a bus path or a port —
but nothing stops a caller putting a bus path in the **value** under a hardware
source, so that half is enforcement and this half is discipline. Both cases are hardware
substitution, which §9 already excludes. What the binding does is make the
**ordinary** failures refuse rather than open: a different medium, a re-created
volume, a rolled-back generation, a different Boot image.

The raw identity is treated as the owner's hardware. It is held in the
encrypted commissioning record and nowhere else — **not** in the audit, a
journal, a terminal, an issue, a pull request or an external report. The audit
is a place for traceability, not a guarantee of confidentiality. No such
encrypted record exists in this repository yet; what exists is the discipline
that makes one possible, and it is enforced by test rather than by convention.

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
| Rollback to an older persistence generation | Generation counters bound into the signed checkpoint chain; an older generation is detected, not silently accepted. A rollback of software never restores obsolete trust state, policy, or hardware bindings. §2.1's media binding includes the commissioning generation, so a binding **cannot be reused across generations** — which is not the same as rollback resistance, and an earlier version of this row said it was. A rollback restores the volume together with the binding stored beside it, both halves move, and the pair still matches. Rollback resistance comes from the checkpoint chain named above, which compares the generation against a value the attacker cannot roll back. |
| Persistence carried to a second medium, or re-created under the same name | The binding covers the LUKS volume UUID and the device identity the quarantine holds, as well as the medium's hardware identity, so a re-created volume is a different volume and a binding cannot be presented alongside a different device. A changed identity and a forged binding are **one refusal**: naming which input was wrong would make the refusal an oracle. |
| The medium's identity changes **while a volume is already open** | Not detected. The binding is checked at each act — creating, unlocking — and an open volume stays open until the next one. Surprise removal is what §4 covers; a live substitution without a removal event is not modelled, and is stated here rather than implied by "a medium whose identity changed is refused". |
| Audit chain truncation or splice | Two-copy signed checkpoints binding product/node/boot identity, log and security epoch, monotonic sequence, previous checkpoint, current head, active versions, and generation; an operator-carried or remote anchor when available. |
| No anchor is available (common on borrowed hardware) | Audit assurance is reported as `LOCAL_CONTINUITY_ONLY`. That state forbids live Deception, forbids disruptive actions, and forbids claiming rollback-verified finalized evidence unless a named emergency policy records explicit operator acceptance. Exports are labeled locally consistent and **not** rollback verified. This is a reduced claim, not a disabled product. |
| Dirty volume from an unclean shutdown is repaired into a state an attacker chose | **Boot does not repair.** [ADR-0010](adr/0010-persistence-key-and-migration.md) D4 removed the bounded-repair path that used to stand here: a suspected torn write stops the **whole volume** in a fail-closed quarantine, and the failure is visible rather than silent. D5 adds that nothing is described as erased. |
| Persistence migration loses data or cannot be rolled back | Migrations are backward compatible, or require a verified pre-trial snapshot ([ADR-0010](adr/0010-persistence-key-and-migration.md) D6, D7 — no snapshot, no migration, under any acceptance). **A failed trial restores nothing**: D8 makes restoring an explicit, operator-started workflow, and what it hands back is a *candidate* — the quarantine does not lift. See [snapshot and recovery](snapshot-and-recovery.md). |
| Passphrase loss makes evidence unrecoverable | A documented portable passphrase and recovery path exists, especially for the `UNVERIFIED_PLATFORM` case where platform-sealed key material is unavailable. Recovery authority cannot sign ordinary field checkpoints or hide a discontinuity. |

## 6. Per-host commissioning

Boot commissions **every host, every time**
([architecture](architecture.md) §4). That section states the discipline; this
one states what attacks it.

Commissioning is where an attacker's cheapest lie lands. Defeating a
deterministic arbiter is hard. Making a stressed operator confirm that the
wrong cable is the observation interface, on a laptop nobody in the room has
seen before, is not — and it produces the same result without touching the
arbiter at all.

**Boot's version of this problem is the hardest in the program.** A Nexus is
commissioned once, by someone who owns the machine, for an installation they
keep, and who can compare what they see against what was there yesterday. Boot
is carried to a laptop it has never seen: someone else's, borrowed under time
pressure, running an unknown operating system that may already be compromised,
possibly a different machine tomorrow and possibly the same one again with a
different dock attached. The operator has **no baseline for this hardware and
no way to acquire one**. Every fact commissioning records is being recorded for
the first time, against nothing.

One boundary holds throughout and is not a mitigation but a definition: an
operator confirming a role is **confirming a fact about the hardware** — that
this adapter is the one plugged into that port — and is not granting permission
to act. Azazel-Edge's deterministic arbiter decides and enforces exactly what it
decided and enforced before the confirmation. A commissioning record, an
inventory, and an interface assignment are descriptive; none of them authorizes
anything (§7).

| Threat | Intended mitigation |
| --- | --- |
| An interface is presented that matches on a weak subset of its identity — a spoofed MAC, a duplicated vendor/device pair, an adapter swapped for one that answers the same way | Identification uses the **composite identity** the program plan fixes: bus path, permanent MAC, VID/PID or PCI identity, serial where present, driver/firmware, wireless PHY, and the physical label the operator recorded (program plan §5 R2). **MAC-only matching is insufficient and MUST NOT be accepted** — a MAC is software-settable, is the field an attacker on the wire can choose freely, and is the one most likely to be reused by an operator trying to be helpful. |
| An ambiguous or absent match is treated as close enough to continue | Matching is **fail-closed**: exactly one match identifies the interface. Zero matches or more than one match return the affected capability to `COMMISSIONING_REQUIRED` and report the competing candidates (program plan §5 R2; [architecture](architecture.md) §4.2). Boot never silently rebinds and never falls back to a kernel name or a default route. |
| A commissioned capability survives a hardware change it was never confirmed against — a USB NIC moved to another port, a dock attached or removed, a renumbered PCI slot, a driver or firmware update | "Changed NIC identity returns the affected capability to `COMMISSIONING_REQUIRED`" (program plan §5 R2 exit gate). Identity is a continuing condition, not a one-time gate at startup, for the same reason the host-storage quarantine is (§3.2). On borrowed laptops this is expected to fire routinely rather than rarely. |
| A role is inferred from something an attacker can arrange — an interface name, carrier or link state, the presence of a default route, an autoconfigured address, or any resource measurement | Roles are assigned **only** by explicit operator confirmation against the read-only inventory, and unassigned interfaces stay unassigned and have no capability ([architecture](architecture.md) §4.3). An attacker who can make an interface *look* like the protected one gains nothing, because looking like it is not how a role is assigned. |
| Inventory itself becomes the disclosure — the host, or a hostile network, learns Boot is present before any role exists | Inventory reads hardware and interface facts and **writes nothing**, to the network or to host storage. Before activation completes Boot transmits no frame outside a bounded, operator-selected `ASSET_ACQUISITION` state, does not associate with a wireless network, does not forward or route, does not start capture, enforcement or Deception, and runs no DHCP, router solicitation, mDNS, or LLDP ([architecture](architecture.md) §4.1; program plan §5 R2 exit gate). A laptop radio must not associate, probe, or beacon during inventory; the default is that it is down. |
| A previous host's or previous session's commissioning is reused on a machine it was never confirmed against | A commissioning record is bound to the host that produced it **and** to the session identity. Booting the same media on a different laptop does not reuse the previous host's roles, and USB cloning creates a new node and session identity carrying no active or one-shot lease ([architecture](architecture.md) §4.4; program plan §4.5). |
| Commissioning is re-opened on a live system to widen roles — remotely, or by software alone | The commissioning service **closes after activation**. Re-entry requires a physical local action, strong administrator authentication, a maintenance state, and explicit handling of active leases before roles can change (program plan §5 R2). A remote path into role change is not a path that exists. |
| Rendering falls back to something plausible when a role is unassigned or its identity is ambiguous | Generated configuration is rendered from commissioned logical roles only, into disposable output, and there is **no fallback**: rendering fails and the dependent capability stays unavailable. Boot MUST NOT substitute a physical interface name, a kernel device number, a default route, or a "first available" interface for a missing role ([architecture](architecture.md) §4.5). |
| A confirmation is treated as an authorization — the operator "approved" the interface, therefore the action is approved | A confirmed role is a fact about hardware. It is not an approval, a lease, an intent, or a decision, and it cannot become one: descriptive records are recursively stripped of command, unit, route, firewall, device-path, executor, boolean-authorization, and trust-decision fields (§7 of this document). Edge's arbiter holds the same and only authority before and after commissioning. |
| A stressed, non-technical operator confirms a topology they do not understand | The confirmation interface must present **physically checkable facts** — what is plugged in where, in terms the operator can verify by looking at the laptop. This raises the bar on the interface; it never lowers the bar to inference. It is a genuine residual risk that the design reduces and does not eliminate (§10). |
| The host itself is hostile and shapes what inventory sees | Not defended against, and not claimed to be (§9). Boot's guarantee runs the other way: it protects the borrowed host from Boot. What commissioning limits is what an untrustworthy host can make Boot **assume** — no role is derived from anything the host presents — and the session's platform trust class states how little can be claimed below the running system (§2). |

### 6.1 What must be demonstrated before this is more than a claim

None of the above is implemented. There is no inventory, no composite-identity
matcher, no confirmation interface, no commissioning record, and no
`COMMISSIONING_REQUIRED` state that Boot can report — the status scaffold
reports commissioning as `absent` and every capability dimension as unassessed.
The mitigations in this section are intended behavior in the
[handoff §7](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
sense and nothing more.

Four things are unproven for reasons beyond "nobody has written it yet", and
each is worth naming separately:

1. **Boot cannot represent a commissioning record at all.** The records this
   section depends on — `HardwareInventory`, `InterfaceAssignment`,
   `CommissioningRecord`, `TopologyProfile` — are assigned to
   `azazel_fabric.provisioning_contracts`, which **does not exist at Boot's
   pinned Fabric tag** ([architecture](architecture.md) §2.2;
   [ADR-0004](adr/0004-exact-tag-fabric-consumption.md)). Boot must not invent a
   local shape for them in the meantime, so the fail-closed matching rule has
   nothing to match *on* yet.
2. **"Physically checkable facts" has no defined form.** Nothing upstream says
   what a sufficient confirmation looks like to a non-technical responder, and
   the program's own test of it — civil emergency exercises with non-technical
   operators (program plan §6.7 item 8) — has never been run. The R2 exit
   gate's first condition, that "a nontechnical operator can complete a clean
   installation or USB startup from the written quick-start guide", is unmet in
   the most basic way: there is no quick-start guide.
3. **The silence requirements are measurable and unmeasured.** The R2 exit gate
   requires that observation roles "remain Layer-3 unnumbered and transmit zero
   DHCP, RA, mDNS, LLDP, Wi-Fi probe, or other packets through link flap,
   resume, and driver reload tests", and the program's service objectives set
   "zero transmitted frames during a 10-minute link/RA/DHCP/resume stress
   interval" (program plan §8). Those are pass/fail measurements against
   hardware. No interface has ever been observed, on any machine.
4. **Re-entry has undefined parts.** "Strong administrator authentication" and
   "maintenance state" are inherited terms with no Boot-local definition, and
   the guided setup flow that would establish an administrator identity
   (program plan §5 R2) does not exist. Until it does, the re-entry mitigation
   describes a door with no lock specified, in a building that has not been
   built.

One consequence of the composite-identity rule deserves recording rather than
resolving: because driver and firmware version are identity fields, an ordinary
driver update on a borrowed laptop changes the composite identity and therefore
returns the affected capability to `COMMISSIONING_REQUIRED`. That follows from
the rule as written and Boot does not soften it locally. How often it fires in
the field, and what that costs a responder mid-incident, is unmeasured.

## 7. Authority and capability threats

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

## 8. Update promotion: what each wrong answer costs

A trial boot that is promoted when it should not be, or held back when it
should not be, is a threat to the responder rather than to the media. The two
are not symmetric, and [ADR-0006](adr/0006-trial-boot-health-confirmation.md)
decides the health check from that asymmetry.

| Wrong answer | What the responder is left holding | Recoverable in the field? | Consequence for the design |
| --- | --- | --- | --- |
| **False promote** — a broken generation becomes default | No working system. The A/B fallback fired during the trial and was consumed, so the next boot lands on the broken generation again. | **No.** Recovery needs a second machine, a network, or an expert — the three things §1 assumes are absent. | Every health signal is a positive assertion, and anything that cannot be evaluated counts as a failure. |
| **False fallback** — a healthy generation is not promoted | The previous generation, which was the running one and is therefore known to boot. An older Boot, not a dead laptop. | **Yes**, trivially: they are working. The update is re-offered later. | Fallback is the safe direction, so the check is allowed to be strict — provided the signals are ones a healthy generation produces every time. |
| **A promote that cannot be recorded** | Boot metadata that describes neither generation coherently. | Depends entirely on the redundant-copy design, which is open ([ADR-0003](adr/0003-immutable-ab-update.md) D4). | The trial fails if the promotion record cannot be written and read back (ADR-0006 H5), before it can reach that state. |

The specific threat this rules out is an update path that silently drops the
host-storage quarantine of §3. A generation that boots but does not quarantine
would damage the borrowed laptop through the mechanism meant to protect it, so
the quarantine being established **and having held** are promotion conditions
(ADR-0006 H2 and H3), not merely runtime properties.

Residual risk: the 300-second window and the single attempt are values chosen
against a program target that has never been measured on real hardware. Both
can be wrong in the stranding direction, and neither has been tested.

## 9. What Azazel-Boot explicitly does not defend against

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

## 10. Residual risk this document does not resolve

- Every mitigation above is unimplemented. The gap between this document and a
  running system is the entire product.
- The non-technical-operator confirmation problem (§7) is reduced by design and
  not eliminated by it.
- `UNVERIFIED_PLATFORM` is expected to be the common case in civil emergency
  use. The product must remain useful there while making weaker claims, and the
  discipline that keeps those claims weak is not yet enforced by any code.
