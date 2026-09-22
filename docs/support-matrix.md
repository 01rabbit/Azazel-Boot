# Support Matrix

Status: **target contract**. Azazel-Boot supports **nothing**. There is no
release, no qualified machine, no signed image, and no operational code. This
document states what a Boot release will be able to say it supports, and — row
by row — separates the few facts that are checkable in this repository today
from the claims that need hardware nobody has run.

Nothing below may be cited as evidence that Azazel-Boot boots, runs, or is
supported anywhere. It does not.

Related: [Compatibility](compatibility.md) · [Release policy](release-policy.md) ·
[Update channel](update-channel.md) · [Recovery](recovery.md) ·
[Threat model](threat-model.md) · [Architecture](architecture.md) ·
[ADR index](adr/README.md) · [Security policy](../SECURITY.md) ·
[Program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
§5 R7, §6.7

## 0. The platform baseline

**Debian 13 Live / amd64**, with `main` plus `non-free-firmware`, built
reproducibly onto a removable USB SSD; UEFI with Secure Boot enabled is
required; persistence, if any, is USB-side and its LUKS2 is optional; an
update is a media rewrite or a new signed medium, never a change to a host.

Fixed at program level as [§15 finding OF-07](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md) and adopted for Boot in
[ADR-0008](adr/0008-debian-13-live-baseline.md). **Cited, not restated**: the
frame is stated once, above this repository.

**Nothing has been built from it.** No image exists, no medium has been
written, and no machine has booted one. The builder is still unselected —
`live-build` is the builder the baseline is written against, and
[ADR-0002](adr/0002-image-builder.md)'s selection conditions are untouched.

## 1. What "supported" would mean, and why nothing is

The series
[status vocabulary](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
§7 defines *supported* as "documented release, security/support posture, and
operational evidence exist **for the declared environment**". Boot fails that
definition three times over: there is no release, there is no operational
evidence of any kind, and the declared environment is empty because
[compatibility](compatibility.md) §4 has no rows.

Publishing this document is an R0 exit-criterion item — "Nexus and Boot publish
their own security policy, support matrix, license, update channel, and
recovery procedure before a release is called supported"
([R0 baseline](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-r0-baseline.md),
R0 exit criteria). Publishing it is a precondition for calling a release
supported. It is not itself a support claim, and it does not promote Boot's
status ([ADR index](adr/README.md), rule 4).

Two different objects get confused in a document like this, so they are kept
apart throughout:

| Object | What it is | What exists |
| --- | --- | --- |
| **The product** | a signed immutable image on removable USB SSD media, booted on a borrowed laptop | **nothing** — no image, no builder ([ADR-0002](adr/0002-image-builder.md)), no release ([release policy](release-policy.md) §1) |
| **The status scaffold** | the `azazel-boot` Python package in this repository, which reports that the product does not exist | a package, a CLI, and CI that tests it on a declared Python matrix |

Only the second has a support matrix that can be checked today, and what it
supports is the act of reporting an absence. Rows below say which object they
are about.

## 2. Host hardware — the list is empty

> **No laptop is supported. No laptop has been tested. Azazel-Boot has never
> been started on a laptop.**

That is [compatibility](compatibility.md) §1's statement and this document does
not restate its contents; read it there. What belongs here is the consequence
for a support claim.

| Dimension | Declared support | Source |
| --- | --- | --- |
| Instruction set | `x86_64` | R0 baseline product definition; [compatibility](compatibility.md) §2 |
| Specific machines | **none** | [compatibility](compatibility.md) §4 is empty; [ADR-0001](adr/0001-x86_64-uefi-compatibility.md) D3 |
| Firmware and boot mode | **UEFI assumed; Secure Boot enabled is the target** — frame decided, per-machine state unmeasured; see §3 | program plan §15 OF-03; [ADR-0005](adr/0005-uefi-secure-boot-posture.md) |
| Media | removable USB SSD | product definition; [compatibility](compatibility.md) §2 |
| Internal host storage | quarantined from initramfs entry; never a default write target | [threat model](threat-model.md) §3 |
| Qualification granularity | per system **and** per firmware version | [ADR-0001](adr/0001-x86_64-uefi-compatibility.md) D2 |

Three rules from [ADR-0001](adr/0001-x86_64-uefi-compatibility.md) govern this
section and are why it names nothing:

- **A row is one exact tuple, not a machine or a family** (D1, D2). A class-level
  or family-level support claim is not available and cannot be introduced here.
- **Absence of a row is not a claim of incompatibility** (D6). "Nothing is
  supported" and "nothing has been tested" are currently both true and
  equivalent.
- **No machine may be named anywhere in this repository until it has a ratified
  row** (D7) — not as a candidate, not as an example, not in this document. A
  reader who sees a model name will try it on somebody else's laptop.

`x86_64` is necessary and inherited. It is not sufficient, and it is the only
hardware property Boot has ever declared.

## 3. Firmware, boot mode, and Secure Boot — the frame is decided, the machine is not

This is the row a reader most wants filled in. Three of its four questions were
answered on 2026-09-19; one was not, and is left alone rather than forced.

**The program plan now decides the boot path.** It did not when §2's sources and
[ADR-0001](adr/0001-x86_64-uefi-compatibility.md) were written: the plan
contained no occurrence of `UEFI`, `Secure Boot`, `CSM`, or `legacy BIOS`, which
is the gap Nexus and Boot each hit while writing these matrices. It was raised
as program finding **OF-03** and resolved the same day by owner decision
(program plan §15, `### OF-03`; restated as a blockquote in §5 R2). Boot adopts
the result in [ADR-0005](adr/0005-uefi-secure-boot-posture.md). Quoted, not
paraphrased:

> 1. "**Booting with Secure Boot enabled is the target**, via the standard signed
>    chain: a Microsoft-UEFI-CA-signed `shim` as the first stage, which verifies
>    the next stage against a certificate embedded in the shim itself. This is how
>    mainstream Linux live media already boot on Secure Boot machines. UEFI is the
>    assumed boot path."
> 2. "**Disabling Secure Boot is a fallback, never the default**, and it is
>    permitted only with the machine owner's explicit agreement, only after the
>    location of the host's disk-encryption recovery key has been established, and
>    it must be restored at the end of the session."
> 3. "**Enrolling a product key into the host (MOK) is not adopted.** It writes a
>    key into someone else's firmware and survives the session."
> 4. "**A qualified hardware entry records the Secure Boot state that was
>    observed**… No product declares Secure Boot support for a machine nobody has
>    tested."

So this matrix declares:

| Question | State |
| --- | --- |
| Is UEFI required, assumed, or supported? | **assumed** — "UEFI is the assumed boot path" (program plan §15 OF-03, item 1). Assumed is not tested and not supported: no machine has been booted |
| Is a non-UEFI or legacy path excluded? | **still undeclared** — the frame states an assumption, not an exclusion, and says nothing about `CSM` or legacy BIOS. Boot does not convert the assumption into a prohibition covering machines nobody has tested |
| Is Secure Boot required, supported, tolerated, or incompatible? | **enabled is the target**, through the signed shim chain (item 1). Disabling it is "a fallback, never the default", permitted only with the machine owner's explicit agreement, only after the location of the host's disk-encryption recovery key has been established, and restored at the end of the session (item 2). Nothing is declared *supported*: the state is measured per machine (item 4) |
| Is shim, key enrollment, or a vendor signature in scope? | **shim yes, vendor signature yes, enrolling a key into a host no.** The first stage is "a Microsoft-UEFI-CA-signed `shim`… which verifies the next stage against a certificate embedded in the shim itself" (item 1); "**Enrolling a product key into the host (MOK) is not adopted**" (item 3) |
| Does firmware verification give a stronger claim where it exists? | **yes, and that much was already decided** — "use firmware verification where the supported hardware permits" (program plan §6.7 item 2), expressed as the three trust classes in [threat model](threat-model.md) §2. OF-03 does not change them |

The fourth row is a build requirement before it is a boot requirement: the
image "must carry a signed shim and a chain that shim will verify, which in
practice means building on a distribution whose shim and kernel signatures are
already trusted, or completing shim review for a self-signed chain" (program
plan §15 OF-03). No builder is selected —
[ADR-0002](adr/0002-image-builder.md) is still open — and this constrains that
selection rather than making it ([ADR-0005](adr/0005-uefi-secure-boot-posture.md)
D6).

The distinction is still worth holding, in both directions: the *trust classes*
and the *boot path* are different questions, and deciding the second did not
decide the first. A platform that verifies the media reaches `VERIFIED_FIRMWARE`
and may claim integrity anchored below the operating system; a platform that
does not reaches `EXTERNALLY_VERIFIED_MEDIA` or `UNVERIFIED_PLATFORM` and claims
correspondingly less. A machine that boots the shim chain has not thereby
demonstrated a trust class, and a trust class is not a boot-path claim.

**Why the per-machine state stays a measurement rather than a support row.**
Boot's operator is on borrowed hardware and **does not control the host's
firmware settings**. They may not have the password, may not be permitted to
change a setting on a clinic's or a city office's machine, and may be holding a
laptop whose owner is standing next to them. That is also why item 2 is hedged
the way it is, and the reason has to travel with it: Windows BitLocker with a
TPM protector is by default sealed against a PCR that measures the Secure Boot
state, so turning Secure Boot off changes that measurement, the TPM does not
release the key, and the next Windows boot demands the recovery key.
**Booting from USB does not by itself do this — only changing the Secure Boot
state does.** "Put the USB first and turn Secure Boot off" is two actions with
very different risk profiles, and a reader who collapses them into one may take
a clinic's data away from it. [Compatibility](compatibility.md) §3.3 already
requires a qualified entry to record "firmware settings required to reach the
media… including Secure Boot state" as a **measurement**. That field is filled
in by a test, not by this document.

Until then, an operator asking "will it boot on this laptop?" gets the honest
answer: unknown, on every machine, in every firmware configuration.

## 4. Runtime matrix — the one thing that is checkable

This section is about **the status scaffold**, not the product.

| Claim | Value | The file that makes it true |
| --- | --- | --- |
| Declared Python requirement | `requires-python = ">=3.11"` | `pyproject.toml`, `[project]` |
| Python versions actually exercised | `3.11`, `3.12` | `.github/workflows/docs.yml`, the `package` job's `strategy.matrix.python-version` |
| What the `package` job runs on each | install against the dependency lock, verify the installed set matches it, `ruff check src tests tools`, `python -m pytest tests -q`, and an import plus CLI run with **no** optional dependency present | same job |
| Documentation link check | `python3 tools/check_docs_links.py` on `3.11` | the `links` job |
| Fabric success path | `pip install -c constraints-dev.txt -e ".[dev,fabric]"` on `3.11`, with a step that fails the build if any Fabric test skipped | the `fabric-projection` job |
| Runtime dependencies | **none** — the scaffold is standard library only | `pyproject.toml`, `dependencies = []` |
| Development dependencies | `pytest==8.3.4`, `ruff==0.8.4`, exact | `constraints-dev.txt` |

The workflow states the relationship in its own comment: `requires-python` is
the claim, and the `package` job is what makes it true.

Two honest qualifications:

1. **`>=3.11` is open upward; CI is not.** Nothing in this repository has ever
   run on 3.13 or later. The declared floor is evidenced at 3.11 and 3.12 and
   is an untested extrapolation above that.
2. **This is not the product's runtime.** The Boot media carries its own
   operating system and its own interpreter, chosen by an image builder that
   has not been selected ([ADR-0002](adr/0002-image-builder.md) D2). No Python
   version, kernel version, or OS ABI is declared for the product, because
   nothing builds it. A responder's laptop runs the image, not this package.

## 5. Azazel-Fabric — exactly one tag, one import site

| Property | Value | Source |
| --- | --- | --- |
| Pin | `azazel-fabric @ git+https://github.com/01rabbit/Azazel-Fabric.git@v0.9.0rc1` — a release **candidate**: pinnable, no stability promise ([ADR-0007](adr/0007-repin-fabric-to-v0-9-0rc1.md)) | `pyproject.toml`, `[project.optional-dependencies]` `fabric` |
| Form | an **optional extra**, never a runtime requirement; no branch pin, no submodule, no copied source | [ADR-0004](adr/0004-exact-tag-fabric-consumption.md) D1, D2 |
| Import sites | exactly one: `src/azazel_boot/fabric_projection.py`, enforced by `tests/unit/test_boundary_static.py` | [ADR-0004](adr/0004-exact-tag-fabric-consumption.md) D3 |
| Behavior when absent | the reported status degrades and says why; the scaffold does not crash; **no authority is granted** | [ADR-0004](adr/0004-exact-tag-fabric-consumption.md) D4 |
| Provisioning contracts | `azazel_fabric.provisioning_contracts` **does not exist at `v0.8.0`** | [ADR-0004](adr/0004-exact-tag-fabric-consumption.md), Evidence |

The last row is the supported state, not a defect being worked around. The
records Boot needs — `HardwareInventory`, `ResourceProfile`, `TopologyProfile`,
`CommissioningRecord` and the rest — are assigned to a module that has not
shipped, so Boot validates no provisioning record at all and defines no local
substitute ([architecture](architecture.md) §2.2;
[ADR-0004](adr/0004-exact-tag-fabric-consumption.md) D5).

Supporting the pin does **not** mean supporting Fabric's absence as a degraded
product mode with reduced guarantees. Fabric present and Fabric absent produce
the same authority — none — and differ only in how much of the status can be
projected.

## 6. Resource classes — inherited, never declared here

Boot declares **no RAM threshold of its own**
([architecture](architecture.md) §2.1 discipline; §3.1). The selector is fixed
at program level, and Boot's role is to apply it and raise a finding if it is
wrong, never to substitute local numbers.

| Item | Where it is decided |
| --- | --- |
| The resource classes measured by the program: 8, 16, 32, 64 GB | program plan §8; [compatibility](compatibility.md) §2 |
| The single product-local selector over **usable RAM in MiB after firmware reservation**, and its boundaries — inherited as 7168 / 15360 / 31744 MiB usable, each the nominal size it admits minus a 1024 MiB firmware-reservation allowance | program plan §5 R2, finding OF-01 resolved 2026-09-19; restated with Boot's consequences in [architecture](architecture.md) §3.1 |
| That RAM alone enables nothing | [architecture](architecture.md) §3; program plan §10 SR-02 |
| Whether the qualifier "subject to the measured Core reserve" moves a boundary | **unmeasured** — Boot's Core reserve on removable media has never been measured ([architecture](architecture.md) §3.1) |
| How a selected tier maps to a reported capability state | **open at program level** — finding OF-02, `standard` versus `FULL` and `diagnostic` having no counterpart. No product may invent the mapping locally |

Two consequences for anyone reading this as a buying guide. First, a machine's
nominal memory size is not what selects its tier: usable RAM after firmware
reservation is, and on borrowed laptops an integrated GPU commonly takes 512
MiB with no way for the operator to reclaim it. A machine whose firmware
reserves more than the allowance falls a tier below its nominal class, and that
is a stated limit rather than a bug to patch around. Second, and more
important: **the resource tier is not the capability**. Effective capability is
the intersection of resource profile, topology profile, verified asset set, and
trust/health state, and a laptop with a large memory envelope and one usable
NIC is observe-only.

## 7. Support posture

| Question | Answer | Source |
| --- | --- | --- |
| Which versions are supported? | **none**; there are no releases and no tags, only `main` | [SECURITY.md](../SECURITY.md), "Supported versions" |
| Is there a release cadence or support window? | **no, by design** — releases are capability gates, not calendar commitments | [release policy](release-policy.md) §8 |
| Is there an update channel? | **no** — see [update channel](update-channel.md) | [release policy](release-policy.md) §1 |
| Is there a recovery procedure that has been exercised? | **no** — the procedure is written as target contract; nobody has run it | [recovery](recovery.md) |
| What may be reported as a security issue against an unsupported repository? | a defect in the target contract, treated as a security report | [SECURITY.md](../SECURITY.md) |
| Is hardware outside the envelope a supported configuration? | no, and a failure there is not a defect against a promise that was never made | [threat model](threat-model.md) §8 |

## 8. What has to happen before any row here becomes a support claim

For hardware, all of it, in order: an image that builds
([ADR-0002](adr/0002-image-builder.md)), a signing story
([release policy](release-policy.md) §6), a hardware-in-the-loop record
containing the [compatibility](compatibility.md) §3.3 measurements — including
**zero content writes to internal block devices** across a full session and a
separate report of any firmware NVRAM change — and then owner ratification of
the row ([ADR-0001](adr/0001-x86_64-uefi-compatibility.md) D3). Evidence first,
ratification second, and neither substitutes for the other.

For the firmware and Secure Boot rows in §3, the program-level statement arrived
first (program plan §15 OF-03) and is recorded in an ADR of its own
([ADR-0005](adr/0005-uefi-secure-boot-posture.md)). What is still outstanding is
evidence: the first ratified entry's **measured** Secure Boot state
([compatibility](compatibility.md) §3.3), which is also what would let the one
row still marked undeclared — whether a non-UEFI or legacy path is excluded — be
answered on something other than a guess.

For the runtime rows in §4, nothing — they are already true, and they are also
already the least interesting thing in this document.

## 9. What this document does not establish

- That Azazel-Boot is supported on anything, in any configuration. It is not.
- That Azazel-Boot boots. No boot has ever been attempted on any machine.
- That the empty hardware table will ever have a row. That depends on a test
  program, hardware, and an owner decision, none of which exists.
- That UEFI, Secure Boot, or any firmware configuration is supported on any
  machine. §3 records a decided frame — UEFI assumed, Secure Boot enabled the
  target — and not one measurement; whether a non-UEFI or legacy path is
  excluded is still undeclared, and this document does not decide it.
- Anything about the industry transition away from the expiring Microsoft UEFI
  CA 2011 certificate. The program plan requires that be checked against
  firmware in hand rather than assumed, and no firmware has been in anyone's
  hand.
- That the declared Python matrix says anything about the product. It describes
  a package that reports the product's absence.
- That the Fabric pin gives Boot a validated provisioning record. The module
  that would define one is not in the pinned tag.
