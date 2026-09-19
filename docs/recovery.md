# Recovery

Status: **target contract**. Nothing here is implemented, and nothing here has
ever been exercised. **No hardware, boot, or no-host-write evidence exists** —
the [README](../README.md) status table says exactly that, and this document
does not say more. Every procedure below is an intended design.

Recovery on borrowed hardware is a different problem from recovery on a machine
you own. The first thing to recover is not the session, the data, or the
software. It is **somebody else's laptop**.

Related: [Threat model](threat-model.md) · [Architecture](architecture.md) ·
[Update channel](update-channel.md) · [Release policy](release-policy.md) ·
[Support matrix](support-matrix.md) ·
[ADR-0003 immutable A/B update](adr/0003-immutable-ab-update.md) ·
[Program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
§5 R2, §5 R7

## 1. What "recovery" means here

Three things can need recovering, and they are recovered separately because
they fail separately. The program plan records Boot's update and recovery unit
as **image/persistence** (§12 cross-product test matrix), and the host is a
third thing that belongs to neither.

| What | Recovered how | Who it belongs to |
| --- | --- | --- |
| **The host laptop** | by not having been changed. Recovery is verification and reporting, not repair | the clinic, the city office, the volunteer |
| **The medium** (image) | immutable A/B slots: fall back to the prior verified generation ([ADR-0003](adr/0003-immutable-ab-update.md)) | the responder |
| **The medium** (persistence, audit, evidence) | bounded, conservative boot-time repair, or quarantine — never repair-into-use ([threat model](threat-model.md) §5) | the responder |

The order matters. A recovery step that restored a session at the cost of
writing to the host would be a failure, not a recovery.

## 2. The host is left as found

This is the recovery case the product exists for, and the only one whose
failure is unrecoverable by anything Boot can do afterwards.

> **An aborted, crashed, or failed session leaves the borrowed laptop
> unaltered.**

The claim is precise and its boundary is stated rather than implied:

- **Covered:** content writes to internal host block devices, from initramfs
  entry through shutdown. The target is **zero**, in every session, including
  every session that ends badly — a crash, a power loss, a surprise removal, a
  failed update, an operator abort. Internal block devices are blocked at the
  device layer before any filesystem driver sees them
  ([threat model](threat-model.md) §3), so a session that dies has nothing to
  undo: there was never anything to undo.
- **Covered:** disruptive network rules and routes Boot installed on the host.
  These are the one thing Boot genuinely does to a host, and §3 is about
  withdrawing them.
- **Not covered, and reported instead:** firmware NVRAM changes the platform
  makes on its own — boot entry creation, boot-order update. These are **not
  preventable by Boot** ([threat model](threat-model.md) §3.2). Reporting them
  is required; preventing them is not promised. An operator returning a laptop
  should be able to say what the firmware changed, and saying that the
  no-host-write property covers it would be false.

Nothing in the quarantine is a recovery *action*. There is no post-session
cleanup pass over host storage, because a cleanup pass would itself be a write
and would imply there had been something to clean. The mechanism is that the
quarantine is a **continuing rule** established in the initramfs before
anything that could touch a disk starts, and that it survives into userspace
rather than being re-established there ([threat model](threat-model.md) §3.1).
A device that appears later — a hotplug, a dock, a resume from suspend — is
quarantined on appearance.

The single exception is an **operator-approved export target**: per-target,
per-session, recorded in the audit record, and never a persisted preference
([threat model](threat-model.md) §3.2). Approval does not survive the session
that granted it, so it cannot become a default that a later failed session
inherits.

## 3. Surprise removal

The medium will be pulled while the system is running. Someone trips over the
cable, a responder grabs the wrong device, or the laptop is needed back
immediately. The [threat model](threat-model.md) §4 treats this as an
**expected event, not an exceptional one**, and recovery has to mean something
in a case where the code that would perform it has just been physically
disconnected.

**What recovers the host, and why it can.** A **RAM-resident** release
supervisor withdraws owned disruptive rules and routes independently of the
persistence media, and must not need to read anything from the removed device
to do its job ([threat model](threat-model.md) §4; program plan §4.5). That
independence is a security property rather than a robustness nicety: removal is
otherwise a way to deliberately strand a rule an attacker benefits from.

**What happens to the session.** Removal fences new actions immediately.
Existing actions follow their predeclared safe expiry or fence behavior. The
system then displays a **reboot requirement** rather than continuing in an
ambiguous state — the intended outcome is an operator who knows the session is
over, not one who keeps working against a system whose state store is gone.

**What the operator does with the host afterwards.** Reboot or power it off,
and confirm before returning it that the host network is as it was. The
supervisor's withdrawal is what should make that true; the operator's check is
what makes it verified rather than assumed. Nothing needs to be uninstalled,
because nothing was installed: the host's internal storage was quarantined for
the whole session, and the machine returns to its own operating system on the
next boot.

**What is lost.** Everything not already persisted with its receipt. The write
ordering is prepare-and-sync, apply, verify, persist receipt, so a prepare or
sync failure produces **zero** changes rather than a partial one
([threat model](threat-model.md) §4). A removal mid-write therefore loses the
in-flight item; it is not supposed to produce an unrecoverable volume.

## 4. Failed start, failed update, and power loss

| Failure | Intended recovery | Source |
| --- | --- | --- |
| A trial boot of a newly installed generation does not confirm healthy | automatic fallback to the prior verified generation, without an operator diagnosing anything. The trial is **one-shot**, so a machine that never completes it does not loop into it | [ADR-0003](adr/0003-immutable-ab-update.md) D1 |
| An update fails outright | return to the prior verified generation "without losing the last valid audit checkpoint" | program plan §5 R7 exit gate |
| Power is interrupted after any inactive-slot, boot-metadata, checkpoint, or persistence-migration write | **one verified bootable generation and the last valid audit checkpoint remain recoverable**, at every one of those write points; a failed trial restores any required persistence snapshot | program plan §5 R7 exit gate; [ADR-0003](adr/0003-immutable-ab-update.md) D2 |
| Boot metadata is torn by an interrupted write | metadata is signed and **redundant** — at least two copies, so a torn write to one does not lose the ability to boot | [ADR-0003](adr/0003-immutable-ab-update.md) D1 |
| A persistence migration fails | migrations are backward compatible, or require a verified pre-trial snapshot and a restore path; a failed trial restores the snapshot | [threat model](threat-model.md) §5; program plan §6.7 item 2 |

Two things this list does **not** recover, and must not be read as recovering:

- **A fallback does not restore authority or trust.** It may reduce capability
  and changes authority by exactly zero. "Software rollback never restores
  obsolete trust state, policy, or hardware bindings" (program plan §4.2) — not
  a revoked key, not an older security epoch, not a previous host's
  commissioning ([ADR-0003](adr/0003-immutable-ab-update.md) D3).
- **A fallback does not protect the host.** The no-host-storage-write property
  is a separate mechanism — the initramfs quarantine — and A/B slots neither
  provide it nor protect it ([ADR-0003](adr/0003-immutable-ab-update.md), what
  it does not establish).

## 5. Missing or unverifiable assets leave a working Core

> "model download or verification failure leaves a working Core environment"
> — program plan §5 R2 exit gate

[Architecture](architecture.md) §3.3 states the general rule: a missing or
rejected asset removes **its own** capability and nothing else, and model or
bundle verification failure must leave a working Core environment.

This is a recovery property because of where Boot is used. A responder whose
model asset failed to download at a damaged site, or whose Knowledge Lite
bundle fails verification, still has the reason they booted: deterministic Core
assessment, bounded topology-gated response, evidence handling, and recovery
support **without external services** ([architecture](architecture.md) §1).
Boot must be useful as `CORE` with no Knowledge, no Deception, no remote
cognition, and no cloud.

Recovering from this is therefore not an action at all; it is the absence of a
cascade. `FULL -> LITE -> CORE` degradation is the designed behavior and not a
failure state ([SECURITY.md](../SECURITY.md), out of scope). Restoration above
`CORE` requires a passing health window, revalidation, and an audited
transition — **a restart alone never restores a capability**
([architecture](architecture.md) §3.5).

## 6. Changed NIC identity returns the capability to `COMMISSIONING_REQUIRED`

> "changed NIC identity returns the affected capability to
> `COMMISSIONING_REQUIRED`"
> — program plan §5 R2 exit gate

Matching is fail-closed against a composite identity: exactly one match
identifies the interface, and zero matches or more than one match returns the
affected capability to `COMMISSIONING_REQUIRED` and reports the competing
candidates. Boot never silently rebinds, and never falls back to a kernel name
or a default route ([architecture](architecture.md) §4.2).

On borrowed laptops this is a routine recovery path rather than a rare one. A
USB-Ethernet adapter moved to another port, a docking station, a driver
difference between two otherwise identical machines, a renumbered PCI slot —
each changes the composite identity, and each returns the affected capability
to `COMMISSIONING_REQUIRED`.

What recovery means here is deliberately unglamorous: **recommission**. The
operator confirms the interface against what is physically plugged into the
laptop, and the capability becomes available again if the commissioning
succeeds. What it never means is Boot restoring the capability by guessing
which adapter the old one became. Recommissioning confirms a fact about
hardware; it grants no authority, and Azazel-Edge's arbiter decides everything
it ever decided.

Sessions do not inherit each other. A commissioning record is bound to the host
that produced it and to the session identity, and booting the same medium on a
different laptop does not reuse the previous host's roles
([architecture](architecture.md) §4.4). "Recovery" on a second laptop is
therefore a fresh commissioning, always.

## 7. Persistence, passphrases, and what quarantine means

Encrypted persistence is the only writable state and therefore holds every
recoverable thing that is not the image.

| Situation | Intended outcome |
| --- | --- |
| Unclean shutdown leaves a dirty volume | boot-time repair is **bounded and conservative**; a volume that cannot be repaired to a verified state is **quarantined rather than repaired into use**, and the failure is visible rather than silent ([threat model](threat-model.md) §5) |
| Offline modification of persistence contents | detected at boot through integrity-protected encryption; the volume is quarantined, not repaired into use |
| An older persistence generation is presented | generation counters bound into the signed checkpoint chain detect it; it is not silently accepted |
| The audit chain is truncated or spliced | two-copy signed checkpoints, with an operator-carried or remote anchor when one is available |
| The passphrase is lost | a **documented portable passphrase and recovery path** exists, and is specifically required for the `UNVERIFIED_PLATFORM` case where platform-sealed key material is unavailable (program plan §6.7 item 2; §10 SR-08). Recovery authority cannot sign ordinary field checkpoints or hide a discontinuity |

Quarantine is the recurring answer, and it is chosen over repair for a reason
worth stating: a volume repaired into use is a volume an attacker may have
chosen the contents of. Losing a session is recoverable. Silently continuing on
attacker-selected state is not.

## 8. Evidence: what survives, and whose it is

| Survives a failed session | Does not survive |
| --- | --- |
| Anything persisted with its receipt, under the prepare-and-sync / apply / verify / persist-receipt ordering | anything in flight at the moment of removal or power loss |
| The last valid audit checkpoint, through a failed update and through a power cut at any write point (program plan §5 R7 exit gate) | audit continuity across a quarantined, unrepairable persistence volume — the discontinuity is visible, which is the point |
| The assurance label the evidence was made under | any claim stronger than that label. A `LOCAL_CONTINUITY_ONLY` export is "locally consistent" and **not** rollback verified ([architecture](architecture.md) §3.4) |
| The platform trust class of the session that produced it | any upgrade of that class by a later, better-verified session ([threat model](threat-model.md) §2) |

Boot will frequently be in `LOCAL_CONTINUITY_ONLY`, because borrowed hardware
often has no anchor. That state forbids live Deception, forbids disruptive
actions, and forbids claiming rollback-verified finalized evidence unless a
named emergency policy records explicit operator acceptance. It is a **reduced
claim, not a disabled product** ([threat model](threat-model.md) §5).

**Custody.** Evidence on the medium is the responder's, not the host owner's.
This follows from the quarantine rather than from a policy statement: nothing
is written to the borrowed laptop, so the machine returned to its owner carries
no copy of the responder's evidence, and the owner acquires no custody of it by
having lent the hardware. The reverse holds too — evidence reaches the host
only through an explicitly selected, explicitly approved, per-session export
target, and that approval is recorded. Persistence and export are encrypted, so
theft of the medium must not yield plaintext evidence
([threat model](threat-model.md) §2.1); what encryption does not protect is
availability of the only copy ([threat model](threat-model.md) §8).

## 9. Recovery has to be executable by someone who did not build the system

> "recovery procedures are executable from offline media by an operator who did
> not build the system"
> — program plan §5 R7 exit gate

Two constraints follow, and both are harder for Boot than for a fixed
installation:

- **Offline.** The recovery path may not require a network, a key server, or a
  vendor endpoint. A responder recovering a medium at a damaged site has
  whatever is in their bag ([release policy](release-policy.md) §2).
- **Not the author.** The operator may be a non-technical civil responder under
  stress, on hardware they have never seen. A confirmation interface must
  present physically checkable facts — what is plugged in where, in terms the
  operator can verify by looking at the laptop. That reduces the residual risk
  in [threat model](threat-model.md) §9 and does not eliminate it, and no
  recovery procedure written here may assume it does.

There is no such procedure to run today. There is no offline medium to run it
from, and nobody has attempted the exercise the exit gate describes.

## 10. What this document does not establish

- That any of this works. Nothing is implemented, and no recovery path has been
  built, run, or tested.
- **That Azazel-Boot leaves a host unchanged.** That is the product's central
  claim and it is currently a design. The hardware-in-the-loop record of zero
  content writes required by the R7 exit gate does not exist
  ([threat model](threat-model.md) §3.3), and the
  [README](../README.md) status table records hardware, boot, and no-host-write
  evidence as **none**.
- That a RAM-resident supervisor exists, or that owned rules and routes have
  ever been withdrawn after a removal. No removal test has been run, because no
  system has ever been started.
- That a failed update returns to a prior generation, or that a power cut at
  any write point is survivable. Neither has been attempted
  ([ADR-0003](adr/0003-immutable-ab-update.md)).
- That the recovery exercise in §9 has been performed by anyone, let alone by
  an operator who did not build the system.
- That "health-confirmed" has a definition. It does not, upstream or here, and
  the fallback behavior in §4 depends on one
  ([update channel](update-channel.md) §7).
