# Update Channel

Status: **target contract**. **There is no update channel.** There is no
release, no signing key, no published manifest, no bundle, and no updater. This
document states how updates would have to reach removable media, and what the
medium being removable changes about the question.

Nothing below may be cited as evidence that Azazel-Boot can be updated,
verified, rolled back, or distributed. None of it has been built or attempted.

This document does not restate [release policy](release-policy.md). That
document owns what a release carries, what a signature attests and does not
attest, and what is still open about signing roles and formats. This one owns
delivery to the medium. Where they touch, this document links rather than
re-derives, and a disagreement between them is a defect here.

Related: [Release policy](release-policy.md) · [Recovery](recovery.md) ·
[Support matrix](support-matrix.md) · [Threat model](threat-model.md) ·
[ADR-0003 immutable A/B update](adr/0003-immutable-ab-update.md) ·
[ADR-0002 image builder](adr/0002-image-builder.md) ·
[Program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
§5 R2, §5 R7

## 1. What does not exist

| Thing | State |
| --- | --- |
| A published update channel of any kind | **none** |
| A release to distribute through one | **none, ever** ([release policy](release-policy.md) §1) |
| A signing key, root, or delegated role | **none** — and the key hierarchy is not decided ([release policy](release-policy.md) §6) |
| A published manifest, online or offline | **none** |
| An encrypted offline bundle | **none** |
| An updater, slot layout, or boot-metadata format | **none** — layout and format are open ([ADR-0003](adr/0003-immutable-ab-update.md) D4) |
| A definition of "health-confirmed" for a trial boot | **not decided anywhere**, upstream or here ([ADR-0003](adr/0003-immutable-ab-update.md) D4) |
| Any released media on which an update could be installed | **none** — an unsigned prototype ISO exists, but it is not released and no production builder or update mechanism is selected ([R11 evidence](prototype-evidence-boot-runtime-r11.md), [ADR-0002](adr/0002-image-builder.md)) |

An operator has no released media to update and no update channel or trust
material. The local R11 prototype does not change that state.

## 2. An update to Boot is not a service update

The unit being updated is the thing the operator is holding.

Boot ships as a signed immutable image with a **read-only root** on removable
USB SSD media ([ADR-0003](adr/0003-immutable-ab-update.md) D1). There is no
package manager on a running responder's system to upgrade, no service to
restart into a new version, and no writable root for an update to drift into.
The only writable state is encrypted persistence created on first use outside
the reproducible base image, and the program plan's cross-product table records
Boot's update and recovery unit as **image/persistence** — two separate things,
updated and recovered separately (§12 cross-product test matrix; §4.5).

So an "update" is one of exactly two physical events:

| Form | What happens | What it costs |
| --- | --- | --- |
| **Media rewrite** | the payload is written to the **inactive** slot on the medium the operator already has; the full digest is verified before that slot is selected; selection is a one-shot trial boot; promotion happens only after a health confirmation; failure falls back automatically ([ADR-0003](adr/0003-immutable-ab-update.md) D1) | the operator's own medium is modified — the one carrying their evidence and their audit chain. It must survive a power cut at every write point ([ADR-0003](adr/0003-immutable-ab-update.md) D2) |
| **A new medium** | a separately prepared USB SSD replaces the one in hand | nothing on the old medium is carried across by the act of replacing it. Persistence, audit continuity, and evidence belong to the medium they were written on |

Neither form touches the host. There is no Boot state on a borrowed laptop to
update, by construction: internal block devices are quarantined for the whole
session ([threat model](threat-model.md) §3), so the host has nothing installed
on it that could become stale. This is the one place where Boot's defining
safety property makes the update problem *smaller* rather than harder.

What it makes harder is everything else. A fixed installation is updated on a
machine its owner controls, with a network, with a console, by someone who can
come back tomorrow. Boot's medium is updated wherever the responder happens to
be.

## 3. Both delivery forms are required, and offline matters more

The program plan requires both:

> "support signed online manifests and encrypted offline installation bundles
> through the product-local release-admission policy"
> — program plan §5 R2 deliverables

| Form | Why it is required | What Boot adds |
| --- | --- | --- |
| **Signed online manifest** | the ordinary case: a prepared medium refreshed before deployment, where a network exists | it is the *convenient* path, never the assumed one. Boot may not require it to start, to verify, or to recover |
| **Encrypted offline bundle** | a responder in the field may have no usable network at all — a damaged site, a network that is the incident, or a network the operator is deliberately not joining | this is the path Boot is designed around, not the fallback. Anything reachable only online is unavailable exactly when Boot is being used |

Offline capability is not only a delivery convenience; §5 R8's exit gate
requires that "release evidence can be verified offline", and
[release policy](release-policy.md) §2 states the consequence in Boot's terms:
a verification path that needs a transparency log, a key server, or a vendor
endpoint does not satisfy it. A channel that can distribute bytes offline but
can only *check* them online has not solved the problem.

The `ASSET_ACQUISITION` state the plan specifies for Boot's bounded outbound
work (§5 R2) is the only context in which an online fetch could happen at all —
one operator-selected interface, outbound-only, endpoint allowlists, metadata
and certificate pinning, no forwarding or listening services, bounded
downloads, and cleanup of routes, credentials, DNS, proxy state, and
association afterwards. Updating is not a reason to relax it, and outside that
state nothing may start before commissioning.

## 4. Admission is product-local and separate from distribution

Publishing an update does not make it installable. The ordered admission
sequence — authenticity, exact tested compatibility tuple, semantic content
policy, resource and topology admission, operator or policy-authority approval,
staged activation — runs on the laptop, against that laptop, every time
([release policy](release-policy.md) §5; program plan §4.1).

What a signature does and does not attest is
[release policy](release-policy.md) §4, and is not repeated here. Two of its
consequences bind the channel directly:

- A correctly signed but **obsolete or wrong-role** artifact is rejected.
  Anti-rollback by version number alone is insufficient
  ([threat model](threat-model.md) §2.1).
- A signature says nothing about whether the image boots on the machine in
  front of the operator. The qualified set is empty
  ([support matrix](support-matrix.md) §2), so **every** update, however
  perfectly signed, is being installed onto an unqualified configuration today.

And one that binds the medium: a signed update is written to the inactive slot
of a medium whose own trust class is determined per session, not inherited from
the signature. See §6.

## 5. An update may not weaken Edge

The program plan's R2 exit gate states it of overlays:

> "a deployment overlay cannot weaken Edge approval, scope, lease, policy, or
> trust settings"
> — program plan §5 R2 exit gate

An update that carries, replaces, or regenerates an overlay inherits that
constraint whole; there is no version of shipping an overlay inside an image
that escapes it. Alongside it:

- **Promotion grants nothing.** A successful trial boot and promotion is an
  integrity and availability outcome. Azazel-Edge's deterministic arbiter is
  the only decision and enforcement authority before the update, during the
  trial, after promotion, and after a fallback
  ([ADR-0003](adr/0003-immutable-ab-update.md) D3).
- **Fallback is not a degraded-authority mode.** It may reduce capability. It
  changes authority by exactly zero.
- **Rollback does not resurrect trust.** "Software rollback never restores
  obsolete trust state, policy, or hardware bindings" (program plan §4.2).
  Falling back to a previous image must not restore a revoked key, an older
  security epoch, or a previous host's commissioning
  ([architecture](architecture.md) §4.4).
- **An update never becomes a reason to proceed unverified.** Not under time
  pressure, not on a disconnected site, not because a responder is mid-incident.
  The program plan admits no emergency exception and neither does this channel.

An update that would weaken any of these is not an update that needs a careful
rollout. It is rejected.

## 6. A medium updated on an untrusted machine is an untrusted medium

This is the question Boot cannot dodge, and the one a fixed installation never
has to ask. Somebody has to write the update somewhere — and a responder in the
field has whatever machine is available, which may be another borrowed laptop
in the same building as the incident.

The trust classes in [threat model](threat-model.md) §2 already carry the
answer, and the rule is not to invent a parallel vocabulary for the write
station but to apply the existing one to what the write produced:

| Where the update was written | What the resulting medium can support |
| --- | --- |
| On a machine whose trust root is established **outside** the platform the medium will later boot — media prepared and attested elsewhere and carried by the operator | the conditions `EXTERNALLY_VERIFIED_MEDIA` describes: integrity anchored in the media and its external preparation. Evidence may cite **media** verification, never platform verification |
| On a platform that verifies the media's signature chain before executing it, where platform ownership permits relying on that verification | the conditions `VERIFIED_FIRMWARE` describes — but the class belongs to the **booting** session, not to the write. A good write station does not raise the class of a later boot on a different laptop |
| On an unknown, uncontrolled, or possibly compromised machine | `UNVERIFIED_PLATFORM`: **no integrity claim below the running system**, and evidence labeled accordingly |

The rules that make this binding are already stated in §2 of the threat model
and apply unchanged here. The class is **determined and displayed**, never
assumed and never silently upgraded. It cannot be raised by a successful boot,
a passing self-check, an operator's assertion — or by a signature verifying
during the write. Trust class is an input to the trust/health dimension of the
capability model ([architecture](architecture.md) §3.4), so a low class does
not merely annotate an update; it withdraws capability from the session that
follows.

Three named threats meet here, and the channel does not get to treat any of
them as solved:

- **A tampered update installed to the media** — mitigated by inactive-slot
  installation, full-digest verification before selection, health-confirmed
  trial boot and automatic fallback ([threat model](threat-model.md) §2.1).
  That mitigation is about the *payload*, and says nothing about the machine
  that ran the writer.
- **A substituted or cloned USB SSD presented to the operator as theirs** —
  media identity is displayed at startup, and cloning creates a new node and
  session identity carrying no active or one-shot lease
  ([threat model](threat-model.md) §2.1). An update session is exactly when a
  substitution is easiest to hide.
- **Evil-maid access to the media between deployments** — explicitly
  **undefended** ([threat model](threat-model.md) §8). Signature verification
  detects tampering with signed content. It does not detect a substituted
  enclosure, and it does not protect a passphrase typed on a compromised
  keyboard. An update performed on an untrusted machine is the same exposure
  with the operator present.

The honest summary: the channel can make an update's *contents* checkable
offline. It cannot make the machine that wrote them trustworthy, and Boot's
answer is to say so in the trust class rather than to claim otherwise.

## 7. What is open

Some of this is open here; most of it is open above here. None of it is settled
by this document.

| Question | State |
| --- | --- |
| Signing key hierarchy, roots, custody, thresholds, rotation, revocation | **open** — not fixed by the program plan and not invented here ([release policy](release-policy.md) §6) |
| SBOM format, provenance format, signature envelope, digest algorithm, offline evidence packaging | **open**, and triggered by the image-builder selection ([release policy](release-policy.md) §7) |
| Slot layout, retained generations, boot-metadata format and placement, torn-write detection | **open** — builder outputs before they are updater inputs ([ADR-0003](adr/0003-immutable-ab-update.md) D4) |
| **What "health-confirmed" measures**, and in what time | **open, and the most consequential item here**. An over-eager check promotes a broken image; an over-strict one strands a working responder on the previous generation ([ADR-0003](adr/0003-immutable-ab-update.md) D4) |
| Trial-boot timeout and how many failures precede a permanent fallback | **open** ([ADR-0003](adr/0003-immutable-ab-update.md) D4) |
| Persistence migration snapshot format and restore path | **open** — the persistence design does not exist ([ADR-0003](adr/0003-immutable-ab-update.md) D4) |
| Where and by whom media is prepared in a civil emergency deployment, and what trust root that preparation establishes | **not decided**; §6 states the constraint the answer must satisfy, not the answer |
| Release cadence | **none, by design** — releases are capability gates, not calendar commitments ([release policy](release-policy.md) §8) |

## 8. What this document does not establish

- That an update channel exists. It does not, in any form.
- That Azazel-Boot can be updated, verified, promoted, or rolled back. Nothing
  is implemented and nothing has been tested.
- That the R7 exit-gate conditions on failed updates and power interruption are
  met, or that they have been attempted
  ([ADR-0003](adr/0003-immutable-ab-update.md) D2).
- That media prepared by any particular process reaches any particular trust
  class. The class is determined per session on the platform that boots it.
- That the open items in §7 have a preferred answer here. They are open, and
  this document exists partly to keep them open rather than settled inside the
  first update script anyone writes.
