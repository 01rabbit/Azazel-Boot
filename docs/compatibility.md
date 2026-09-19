# Laptop Compatibility Envelope

Status: **target contract**. This document defines the *shape* of a
compatibility entry. It contains **no qualified hardware**, because none has
been tested and none has been ratified.

Related: [Architecture](architecture.md) · [Threat model](threat-model.md) ·
[Program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
§5 R7, §6.7 item 8

## 1. The qualified hardware list is empty

> **There is no supported laptop. There is no tested laptop. There is no
> laptop on which Azazel-Boot has ever been started.**

This is not an omission to be filled in by whoever gets there first. Adding an
entry requires two things that do not exist:

1. **Owner ratification.** The compatibility envelope is a product claim in the
   Azazel series sense — it states what the product supports. Ratifying it is
   the repository owner's decision, recorded against the program plan, not an
   implementer's.
2. **Real testing on real hardware.** Every field of a qualified entry (§3) is
   a measurement or an artifact. None can be produced by reasoning about a
   specification sheet.

Neither exists. So the table in §4 is empty, and it stays empty until both do.

### 1.1 Why an empty list is the correct content

Azazel-Boot's central claim is that it leaves the host laptop unchanged. That
claim is only meaningful about a machine where it was measured. A speculative
list — "probably works on recent x86_64 UEFI laptops" — converts an untested
guess into an operational promise that a civil responder might rely on while
borrowing a clinic's computer. A broad version range or a hardware family name
is a **descriptive compatibility claim and cannot authorize activation**; the
program uses a deny-by-default set of exactly tested tuples for precisely this
reason.

Product claims refer to the tested compatibility envelope. An arbitrary laptop
is outside it. Both statements are currently equivalent to "nothing is
supported", and that is the honest state.

## 2. Envelope boundaries that are already decided

These constrain what may eventually be qualified. They are not themselves
qualifications.

The firmware row changed twice on 2026-09-19. It first read "UEFI boot path"
and cited the program plan, which at that point said no such thing — the
roadmaps contained no occurrence of `UEFI`, `Secure Boot`, `CSM` or `legacy
BIOS` — so the citation laundered a Boot assumption into an inherited decision,
and the row was corrected to read "not yet decided". Later the same day the
program closed that gap as finding **OF-03**, and the row below records the
frame it decided. The frame is decided; what any particular machine does with
it is measured into a qualified entry under §3.3, not declared here.

| Boundary | Value | Source |
| --- | --- | --- |
| Architecture | x86_64 | R0 baseline product definition |
| Firmware | **UEFI is the assumed boot path**, and booting with **Secure Boot enabled** through a signed shim chain is the target. Disabling Secure Boot is a fallback, never the default; no key is enrolled into a host's firmware. The state on any given machine is **measured** (§3.3), never declared | program plan §15 OF-03, restated in §5 R2; adopted for Boot in [ADR-0005](adr/0005-uefi-secure-boot-posture.md) |
| Media | removable USB SSD | product definition |
| Host storage | untouched by default; internal block devices quarantined from initramfs entry | R7 Boot deliverables |
| Internal behavior | zero content writes to internal block devices until an operator approves an export target; unavoidable firmware NVRAM change reported separately | program plan §5 R7 exit gate, §8 |
| Resource classes measured | 8, 16, 32, 64 GB | program plan §8 |
| Capability rule | resource ∩ topology ∩ verified assets ∩ trust/health; RAM alone enables nothing | R0 baseline capability rules |

Nothing here says any particular machine satisfies them.

### 2.1 What the firmware row says, and what it does not

The frame is the program's, quoted rather than paraphrased (program plan §15,
finding OF-03, resolved 2026-09-19):

1. "**Booting with Secure Boot enabled is the target**, via the standard signed
   chain: a Microsoft-UEFI-CA-signed `shim` as the first stage, which verifies
   the next stage against a certificate embedded in the shim itself… UEFI is the
   assumed boot path."
2. "**Disabling Secure Boot is a fallback, never the default**, and it is
   permitted only with the machine owner's explicit agreement, only after the
   location of the host's disk-encryption recovery key has been established, and
   it must be restored at the end of the session."
3. "**Enrolling a product key into the host (MOK) is not adopted.** It writes a
   key into someone else's firmware and survives the session."
4. "**A qualified hardware entry records the Secure Boot state that was
   observed**", which is §3.3's "firmware settings required to reach the media…
   including Secure Boot state" and is not restated here.

**Why the fallback is hedged, in the one sentence that matters on a borrowed
laptop.** Windows BitLocker with a TPM protector is by default sealed against a
PCR that measures the Secure Boot state: turning Secure Boot off changes that
measurement, the TPM does not release the key, and the next Windows boot demands
the recovery key. **Booting from USB does not by itself do this — only changing
the Secure Boot state does.** "Put the USB first in the boot order" and "turn
Secure Boot off" are two actions with very different consequences for the
machine's owner, and an operator who reads them as one action may take a
clinic's data away from it on a day the clinic is already in trouble. The second
cost is access: on managed clinic, municipal and corporate laptops a firmware
password is common and the responder does not have it, so a plan that requires
firmware changes does not run on those machines at all.

**What the row does not say.** "UEFI is the assumed boot path" is not "every
UEFI machine is supported", and "Secure Boot enabled is the target" is not
"Secure Boot has been observed to work". No image has been built, no machine has
been booted, and no Secure Boot state has been measured; §4 is still empty and
§1 still governs. The frame also states an assumption, not an exclusion — it
says nothing about `CSM` or legacy BIOS, and this document does not turn the
assumption into a prohibition. And "the state of the industry transition away from the
expiring Microsoft UEFI CA 2011 certificate must be checked against firmware in
hand rather than assumed" (program plan §15 OF-03) — no firmware has been in
anyone's hand, so nothing here asserts which certificate any firmware trusts.

## 3. The shape of a qualified entry

An entry may be added only when **every** field below is present and evidenced.
A partial entry is not a provisional qualification; it is not an entry.

### 3.1 Composite identity

The machine and its relevant devices are identified by composite identity, the
same discipline commissioning uses for interfaces — never by a marketing model
name alone, and never by a MAC address alone.

- system vendor, product name, product family, and firmware-reported SKU;
- firmware vendor, firmware version, and firmware release date;
- CPU model and the CPU feature set relied on;
- chipset and platform generation;
- usable RAM in MiB **after firmware reservation** (not nominal module size),
  and the resource class it selects;
- each network interface by bus path (PCI path or USB topology path), permanent
  MAC obtained from the adapter rather than the current MAC, vendor/device
  identity, serial where exposed, driver name and version, and wireless PHY
  identity where applicable;
- internal storage controller and device identities, since these are what the
  quarantine must hold;
- the operator-recorded physical label for each externally visible port.

A machine whose firmware version differs is a **different** entry until tested,
because firmware is what determines the trust class and the boot path.

### 3.2 Firmware verification capability

- which trust class the platform can reach —`VERIFIED_FIRMWARE`,
  `EXTERNALLY_VERIFIED_MEDIA`, or `UNVERIFIED_PLATFORM` (see
  [threat model](threat-model.md) §2);
- whether platform ownership is available on this machine in the intended
  deployment, since a verification capability the responder cannot use is not a
  capability;
- if `VERIFIED_FIRMWARE`: how verification was established and what it covers;
- if not: the documented portable passphrase and recovery path that applies,
  and the explicit statement of which integrity claims are consequently
  unavailable.

An entry that cannot state its trust class is not qualified, because every
evidence claim made on that machine depends on it.

### 3.3 Tested boot path

- the exact media image identity: unsigned payload digest, signed artifact
  digest, and version;
- firmware settings required to reach the media, stated as what the operator
  must do, including Secure Boot state, boot-order handling, and any
  compatibility setting;
- whether the boot succeeded from a cold start, from a warm reboot, and after a
  suspend/resume cycle;
- measured time from power-on to Core ready after encrypted-volume unlock,
  against the program's 120-second objective;
- the observed resource profile and the capabilities the intersection actually
  produced on this machine, including which were **unavailable** and why;
- interface inventory as observed, and which roles were commissionable;
- the host-storage result: content writes to internal block devices across the
  full session — the required value is **zero** — and separately, any firmware
  NVRAM change observed;
- surprise-removal behavior: that owned rules and routes were withdrawn by the
  RAM-resident supervisor and the host network returned to its prior state;
- controlled shutdown and the state the machine was left in.

### 3.4 Evidence link

- a link to the hardware-in-the-loop record containing the above measurements,
  including the no-host-write record required by the R7 exit gate;
- the date of the test and the image version tested;
- the person or team who performed it, and an independent confirmation where
  the program requires one;
- the ratification record in which the owner accepted the entry;
- known limitations and the conditions under which the entry expires — a
  firmware update, a driver change, or a hardware revision each invalidate it.

An entry without a working evidence link is a claim without evidence and is
removed.

## 4. Qualified hardware

*(empty)*

| System | Firmware | Trust class | Image tested | Host-write result | Evidence |
| --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — |

No rows. See §1.

## 5. Candidate hardware

*(empty)*

There is no candidate list either. Naming candidates before any test exists
would create the same expectation the empty qualified list is meant to prevent:
a reader who sees their machine listed as a candidate will try it. Candidates
will be recorded when a test program exists to move them through.

## 6. What this document does not establish

- That Azazel-Boot boots on anything.
- That any machine boots with Secure Boot enabled, or that a non-UEFI or legacy
  path is excluded. §2 records a decided frame and no measurement.
- That any laptop's internal storage is left unchanged. No such test has run.
- That the 120-second Core-ready objective is achievable on laptop hardware.
- That a class of machines can be qualified together. Until evidence says
  otherwise, qualification is per system **and** per firmware version.
