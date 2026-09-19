# Release, SBOM, and Provenance Policy

Status: **target contract**. Azazel-Boot has **never produced a release**. There
is no tag, no artifact, no signing key, no SBOM, no provenance attestation, and
no operational code to release. This document states what a release will have to
carry when one becomes possible, and marks what nobody has decided yet.

Nothing below may be cited as evidence that Azazel-Boot has been built, signed,
attested, or released. None of those things has happened.

Related: [ADR index](adr/README.md) · [ADR-0002 image builder](adr/0002-image-builder.md) ·
[ADR-0003 immutable A/B update](adr/0003-immutable-ab-update.md) ·
[ADR-0004 Fabric pin](adr/0004-exact-tag-fabric-consumption.md) ·
[Threat model](threat-model.md) · [Compatibility](compatibility.md) ·
[Support matrix](support-matrix.md) · [Update channel](update-channel.md) ·
[Recovery](recovery.md) · [Security policy](../SECURITY.md)

## 1. What does not exist

| Thing | State |
| --- | --- |
| A released artifact of any kind | **none, ever** |
| Boot media, signed or unsigned | **none** — no image has been built; no builder is selected ([ADR-0002](adr/0002-image-builder.md)) |
| A signing key, root, or delegated role for Boot | **none** |
| An SBOM for anything in this repository | **none** |
| A provenance attestation | **none** |
| A release channel or update server | **none** — the policy is written in [update channel](update-channel.md); no channel, key, or published manifest exists |
| A support matrix | **published and empty of support** — [support matrix](support-matrix.md); nothing is supported, and [compatibility](compatibility.md) §4 has no rows |
| A recovery procedure | **written, never exercised** — [recovery](recovery.md); no recovery path has been built or run |
| Reproducibility evidence | **none** — no build has been reproduced, because no build has been performed |

The R0 exit criteria require that "Nexus and Boot publish their own security
policy, support matrix, license, update channel, and recovery procedure before a
release is called supported" (R0 baseline, line 68). All five documents now
exist. None of them governs anything: there is no release for a support matrix
to describe, no artifact for a channel to carry, and no system on which a
recovery procedure has ever been run. Publishing them removes a precondition;
it does not move Azazel-Boot toward *supported* (§9).

## 2. What a release must carry

These are program-level requirements, not local preferences.

| Requirement | Source |
| --- | --- |
| "Every release records component versions, hashes, signatures, **SBOM references**, profile, hardware inventory, and applied overlay digest." | Program plan §4, rule 6 (line 97) |
| "exact released component pins, **SBOMs**, signatures, source revisions, migration notes, and compatibility matrix" | Program plan §5 R8 deliverables (line 345) |
| "clean-room Nexus installation and **Boot media build from released artifacts only**" | §5 R8 (line 346) |
| "no test uses an unpublished branch or unpinned mutable artifact" | §5 R8 exit gate (line 354) |
| "**release evidence can be verified offline**" | §5 R8 exit gate (line 355) |
| "SBOM/provenance verification" as completion evidence for the deployment work | §6 (line 442) |

Two consequences are worth stating in Boot's own terms.

**Offline verifiability is not a nicety.** A responder verifying media in a
building with no working network must be able to check everything the release
claims. A verification path that requires reaching a transparency log, a key
server, or a vendor endpoint does not satisfy §5 R8 for this product.

**The component pins are part of the release.** Boot integrates released
components rather than copying source ([ADR-0004](adr/0004-exact-tag-fabric-consumption.md);
program plan §1, line 13). Every one of them — the Edge package, any Knowledge
Lite bundle, any Deception package, any model, and `azazel-fabric` at exactly
`v0.8.0` — appears in the release record by exact version and digest, each with
its own SBOM reference.

## 3. Reproducibility

The requirement is fixed and quoted verbatim, twice, in the program plan:

> "two independent builders reproduce the unsigned immutable payload digest from
> pinned toolchain and repository snapshots; signatures attest that subject
> digest separately"
> — §5 R8 deliverables (line 348); restated as a release eligibility condition
> in §9.5 (line 565)

So a Boot release makes **two separate claims**, and they must not be collapsed
into one:

1. **Reproducibility** — an independent party, using the pinned toolchain and
   repository snapshots, arrives at the same unsigned immutable payload digest.
   This claim is about the build and depends on no key.
2. **Attestation** — a signature over that subject digest, by an authorized
   signer role. This claim is about who vouches for it and depends on no rebuild.

The reason to keep them apart is what each one covers when the other is absent.
A reproduced-but-unsigned payload tells you the build is honest and nothing about
who authorized it. A signed-but-unreproduced payload tells you someone with a key
vouched for bytes that nobody else has ever derived. The release record therefore
carries the **unsigned payload digest and the signed artifact digest as distinct
fields**; [compatibility](compatibility.md) §3.3 already requires both in a
qualified hardware entry, and the release record must be able to supply them.

## 4. What a signature attests — and what it does not

The program plan is explicit that authenticity is one input among several:

> "Cryptographic authenticity is one input to admission." — §4.1 (line 101)

> "A signature from the wrong role or a correctly signed obsolete/incompatible
> artifact is rejected." — §4.1 (line 112)

> "Broad version ranges are descriptive compatibility claims and cannot authorize
> activation." — §4.1 (line 114)

A valid Boot release signature attests:

- that the named signer role vouched for **this exact subject digest**;
- that the artifact is the one the signer intended to release;
- nothing else.

A valid signature does **not** attest, and must never be presented as attesting:

- **that the image boots.** That is hardware evidence, per machine and per
  firmware version ([compatibility](compatibility.md), [ADR-0001](adr/0001-x86_64-uefi-compatibility.md)).
- **that any laptop is compatible.** The qualified set is empty.
- **that the build was reproduced.** That is the separate claim in §3, made by
  independent builders, not by a key.
- **that the contents are semantically safe.** Admission applies semantic content
  policy *after* authenticity (§4.1, line 104).
- **that the artifact is current.** Obsolete-but-correctly-signed artifacts are a
  named rejection case, and anti-rollback by version number alone is insufficient
  ([threat model](threat-model.md) §2.1).
- **that anything is authorized to act.** Azazel-Edge's deterministic arbiter is
  the only decision and enforcement authority. A manifest, a receipt, a
  capability report, and a release record are descriptive; the program plan
  requires directive fields to be recursively rejected from descriptive objects
  (§5 R1, line 188). A signed release grants Boot no authority it did not have
  unsigned, which is none.

### 4.1 On the platform, the claim is narrower still

Verification of a Boot release on a given laptop is bounded by that session's
platform trust class ([threat model](threat-model.md) §2). The same correctly
signed image supports a firmware-anchored integrity claim under
`VERIFIED_FIRMWARE`, a media-anchored one under `EXTERNALLY_VERIFIED_MEDIA`, and
**no integrity claim below the running system** under `UNVERIFIED_PLATFORM` —
which is expected to be the common case in civil emergency use. The release does
not raise the class, and a passing signature check does not either.

## 5. Admission is separate from release

Publishing a release does not make it installable. The product-local admission
sequence runs on the host, in order (§4.1, line 104):

```text
authenticity
  -> exact tested compatibility tuple
  -> semantic content policy
  -> resource/topology admission
  -> operator or policy-authority approval
  -> staged activation
```

A release passes step one. Steps two through six happen on a laptop, against
that laptop, every time. An update additionally obeys the A/B discipline in
[ADR-0003](adr/0003-immutable-ab-update.md): inactive slot, full digest verified
before selection, one-shot trial boot, promotion only after health confirmation,
automatic fallback.

## 6. Signing roles — decided in shape, open in substance

**Decided at program level.** The admission policy "uses separately provisioned
offline roots and delegated roles for OS images, Edge packages, Knowledge
bundles, Deception packages, models, and emergency overlays. It records threshold
rules, rotation, revocation, target product/profile/architecture, required
feature IDs, minimum security epoch, and maximum rollback version" (§4.1, line
112). Separately, "Policy signing, intent signing, update signing, commissioning
approval, audit checkpoint, and recovery use separate credential roles. Only the
Edge arbiter workload identity can use the intent-signing credential" (§4.3, line
140).

Two things follow for Boot and are therefore not open:

- Boot's **update signing** role is distinct from Edge's **intent signing**
  credential. Boot cannot hold, read, or reuse the arbiter's credential — the
  authority boundary is enforced in the key material, not only in the code.
- The Boot media image and the components it embeds are **different artifact
  classes with different delegated roles**. One key does not sign all of it.

**Open, and deliberately not invented here.** The concrete key hierarchy — which
roots exist, who holds them, threshold values, rotation and revocation mechanics,
custody for an offline root, and the ceremony that provisions any of it — is
fixed nowhere in the program plan. This document does not invent one. It will be
decided in its own record, and a release cannot happen before it is.

## 7. Formats — open

The program plan requires SBOMs and provenance. It names **no format** for
either, and none is chosen here.

| Question | State |
| --- | --- |
| SBOM format (SPDX, CycloneDX, other) | **open** — the plan says "SBOM references" (§4 rule 6) and "SBOMs" (§5 R8) and stops there |
| Provenance attestation format (in-toto, SLSA provenance, other) | **open** — the plan requires provenance verification (§6, line 442) and that a signed envelope verify "the same subject digest, authorized signer role, and provenance" (§9.5, line 565), without naming a scheme |
| Signature envelope and algorithms | **open** |
| Digest algorithm for the unsigned payload subject | **open** |
| How release evidence is packaged for **offline** verification | **open**, and constrained: §5 R8 (line 355) requires that it be possible |

**Trigger.** These are decided together with the image builder
([ADR-0002](adr/0002-image-builder.md) D4), because the builder is what emits the
SBOM and the provenance inputs, and a format chosen before the builder is chosen
would be a constraint imposed by guesswork. Each decision lands as an ADR, not
inside an implementation PR.

## 8. Cadence — there is none, by design

> "These releases are capability gates rather than calendar commitments. A gate
> closes only when its evidence is stored and review findings are resolved."
> — program plan §5 (line 160)

Boot has no release cadence, no version-number schedule, and no support window.
Inventing any of them would create an expectation the product cannot meet and is
not required to meet. A release happens when its gate closes.

A release becomes eligible under the conditions in §9.5 of the program plan
(line 561): P0 and P1 findings resolved and independently verified; P2 findings
with owner, mitigation, expiry, and an operator-visible limitation; two
independent builders reproducing the unsigned payload digest; rollback and
recovery exercised; documentation matching observed behavior; and the authority
invariant and standalone Core behavior holding under every tested failure. The
authoring, specialist, and integrated-verification loop in §9.1–§9.3 applies —
including that "an independent reviewer runs the documented build and tests from
clean released inputs" (line 539) rather than trusting the author's logs.

## 9. A release does not promote status

Producing a release does not move Azazel-Boot along the
[status vocabulary](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
§7. *implemented* requires code and focused tests. *verified* requires a declared
evidence gate to have passed. *supported* requires "documented release,
security/support posture, and operational evidence… for the declared
environment" — and Boot's declared environment is currently empty, because the
compatibility set is empty.

A signed, reproducible, fully attested Boot image running on an unqualified
laptop is still an unsupported configuration. The signature says nothing about
the machine.

## 10. What this document does not establish

- That Azazel-Boot can be released. It cannot: there is no code, no builder, and
  no key.
- That any SBOM or provenance mechanism has been selected, prototyped, or
  evaluated.
- That the reproducibility requirement in §3 is achievable for this image. It has
  never been attempted.
- That the open items in §6 and §7 have a preferred answer here. They are open,
  and this document exists partly to keep them visibly open rather than settled
  by whoever writes the first build script.
