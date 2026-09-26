# Builder and Writer contract

Status: **target contract**. No builder exists, no build tool is selected, no
image has been produced, and no medium has been written. This document fixes
what the builder and the writer must be *driveable as*, so that the still-open
tool selection ([ADR-0002](adr/0002-image-builder.md)) has a fixed target to be
evaluated against. It selects nothing and measures nothing.

Decided in [ADR-0009](adr/0009-builder-and-writer-contract.md). Related:
[ADR-0002 image builder](adr/0002-image-builder.md) ·
[ADR-0008 Debian 13 Live baseline](adr/0008-debian-13-live-baseline.md) ·
[Threat model](threat-model.md) · [Release policy](release-policy.md) ·
[Compatibility](compatibility.md) · [Recovery](recovery.md)

## 1. Why this document exists separately from the tool selection

[ADR-0002](adr/0002-image-builder.md) D4 ends with a rule: "an image-building PR
that arrives without a selection ADR is rejected on that ground". That rule is
about *which tool produces the payload*. Every criterion C1–C9 it protects is
about what a tool does with inputs and what it emits.

None of C1–C9 says how an operator invokes the build, what the build records
about itself, which process is allowed to open a block device, or what the
writer must refuse. Those are answerable now, they constrain the selection
rather than pre-empt it, and writing them down first is what keeps the eventual
evaluation from being conducted against a moving target.

## 2. The seven verbs

The operator-facing surface is exactly these seven. No verb has a mode that
turns it into another one. `prepare-host` is intentionally separate from
`build`: it can show and, only through an approved executor, prepare the
isolated Debian build host; it cannot build an image or select a source.

| Verb | What it does | Privilege | Touches a block device |
| --- | --- | --- | --- |
| `doctor` | Reports whether this host can drive the other six verbs, and what is missing. Changes nothing. | unprivileged | no |
| `prepare-host` | Shows the isolated build-host plan and performs no act without a separate approval. Without an available executor it refuses with `host_backend_unavailable` or `no_executor_available`; any approved act is confined to the VM executor. | unprivileged | no |
| `build` | Produces an unsigned payload and its artifact record from pinned inputs, inside an isolated build environment. | build environment only | no |
| `verify` | Checks an artifact against its record and, when one exists, its signature. Answers about a file, never about a medium. | unprivileged | no |
| `list-media` | Enumerates removable candidates and issues a per-session target code for each. Read-only. | unprivileged | read-only enumeration |
| `write` | Writes an already-verified artifact to one target code confirmed in this session. | write service only | yes |
| `inspect` | Reports what a written medium contains and whether it matches the artifact record. | unprivileged | read-only |

### 2.1 `build` and `write` are never one verb

They are separated by an artifact, not by a flag. There is no `--write` on
`build`, no `--build` on `write`, no `build-and-write`, and no configuration
that makes one imply the other.

The separation is not ergonomic taste. `build` runs against inputs the operator
did not choose at the command line; `write` destroys the contents of a device
the operator did choose. A single verb spanning both would place a destructive
act at the end of a long, mostly-unattended operation, where the confirmation
that authorises it is hours away from the moment it takes effect. It would also
make "write what I built" the easy path, and re-verifying a built artifact
before writing it the path someone skips.

An artifact that reaches `write` has been through `verify`. That is checkable
precisely because the two verbs are separate programs run at separate times.

## 3. The artifact record

One build emits one payload and one record. The record is the only thing a
later reader has; a field absent from it is a fact that is gone.

| Field | What it fixes |
| --- | --- |
| `image_version` | Which image this is, in the release policy's version vocabulary. |
| `git_revision` | The exact commit of this repository the build was driven from. |
| `builder_version` | The version of the builder itself — part of what a release attests to ([ADR-0002](adr/0002-image-builder.md) D4.3). |
| `debian_snapshot` | The Debian snapshot identity the packages came from, not a distribution name. |
| `package_manifest_ref` | Where the package manifest sits inside the artifact. |
| `package_manifest_digest` | A digest binding that manifest's contents. |
| `firmware_manifest_ref` | Where the firmware manifest sits, `non-free-firmware` included, per [ADR-0008](adr/0008-debian-13-live-baseline.md) D1 item 3. |
| `firmware_manifest_digest` | A digest binding that manifest's contents. |
| `sbom_ref` | Where the SBOM sits inside the artifact (release policy §2). |
| `sbom_digest` | A digest binding the SBOM's contents. |
| `source_date_epoch` | The `SOURCE_DATE_EPOCH` the build was pinned to. |
| `build_input_digest` | A digest over the closed set of inputs — the thing a second builder is given. |
| `partition_layout_digest` | The layout, separately from its contents. |
| `root_filesystem_digest` | The read-only root, separately from the whole payload. |
| `boot_chain_identity` | Which shim, bootloader and kernel signatures the medium boots through ([ADR-0005](adr/0005-uefi-secure-boot-posture.md)). |
| `unsigned_payload_digest` | The subject of the reproducibility claim ([ADR-0002](adr/0002-image-builder.md) D1.1). |
| `signed_artifact_digest` | The signed artifact, when one exists. Absent is a valid value; unsigned is the normal state today. |
| `signature` | The signature over the subject digest, when one exists. Absent is a valid value. |
| `build_time` | When the build ran. Distinct from `source_date_epoch`, which is an input. |
| `compatibility_claim` | `candidate` or `hardware_verified`, and nothing else ([compatibility](compatibility.md)). |
| `quarantine_policy_version` | Which version of the host-storage quarantine policy the payload carries ([threat model](threat-model.md) §3). |

The medium's own block layout is fixed alongside this: GPT, an ESP, the signed
read-only root, and an optional LUKS2 persistence partition holding a filesystem
formatted directly on it. **No volume manager is assembled, imported or
auto-activated on either the host's storage or the medium**; LUKS2's `dm-crypt`
mapping is the one exception, and it exists to open persistence
([ADR-0008](adr/0008-debian-13-live-baseline.md) D4.1).

### 3.0 The record holds scalars; the manifests are sidecars

Every field above is a **JSON scalar** — a string, an integer, or absent. The
structured package manifest, firmware manifest and SBOM are separate files
inside the signed artifact; the record references them and binds their contents
by digest ([ADR-0009](adr/0009-builder-and-writer-contract.md) D2, revised).

A `*_ref` is a **normalised relative reference inside the artifact**. An
arbitrary URL, an absolute path and a parent traversal are refused: a reference
that can leave the artifact turns a record into an instruction to fetch
something.

Each `*_digest` binds its sidecar's contents; the signed artifact digest binds
the record **and** the set of sidecars, so an added, removed or swapped sidecar
is detectable against the signature.

The claim these fields make is therefore: **every included item is represented
by a verified, referenced manifest or SBOM** — not "every package is in the
record". A fingerprint over a record containing arbitrary nested documents is a
canonicalisation hazard, and a binding that cannot be computed identically twice
is not a binding.

### 3.1 Why "image digest" is two fields

The owner's contract said *image digest*. [ADR-0002](adr/0002-image-builder.md)
D1.1 makes the reproduced subject the **unsigned** payload and signing a
separate act over a digest that was already independently reproduced. A single
field would force a reader to guess which of the two a given release recorded,
and the guess would be wrong exactly when it mattered. So the one field is
carried as two, and `signature` may legitimately be absent while
`unsigned_payload_digest` is present.

### 3.2 `compatibility_claim` has two values

`candidate` means a machine or a medium is expected to work and nobody has
tried. `hardware_verified` means a hardware-in-the-loop record exists. No third
value exists, no value is inferred from a successful build, and a `candidate`
never becomes `hardware_verified` because a build succeeded — only a hardware
record moves it, under [compatibility](compatibility.md)'s ratification rule.

## 4. The build host

| Property | v1 |
| --- | --- |
| Build host OS | Debian 13 / amd64 only ([ADR-0008](adr/0008-debian-13-live-baseline.md)) |
| Where the build runs | inside an isolated build environment, never directly on the operator's host |
| Host paths as build input or output | refused; the build reads its closed input set and writes into the environment's own output directory |
| Root or loop-mount requirements | contained in the build environment; the operator's host does not gain a privileged build step |
| macOS | never builds natively (§6) |

Another build-host distribution is a change to this table and to
[ADR-0008](adr/0008-debian-13-live-baseline.md)'s baseline, not a flag.

## 5. Nothing the operator types becomes a source

The builder accepts **no** URL, no apt repository, no package name, no image
overlay path and no shell fragment from operator input. Sources are selected by
**symbolic ID** resolved in versioned configuration in this repository or in a
signed manifest.

| The operator may choose | The operator may not choose |
| --- | --- |
| a profile ID that exists in versioned configuration | a repository URL, mirror, or apt line |
| a snapshot ID that the configuration already pins | a package name to add or remove |
| an output directory inside the build environment | a script, hook, or shell fragment to run in the build |
| whether to build at all | a digest to accept in place of the one the inputs produce |

An added driver, an extra repository, or a package outside `main` plus
`non-free-firmware` arrives as its own manifest and its own hardware evidence
([ADR-0008](adr/0008-debian-13-live-baseline.md) D1 item 3), never as an
argument.

## 6. macOS is a console, not a builder

macOS never builds a Debian image natively. It drives a fixed Debian 13 build
environment and nothing else.

- Before starting the environment, the frontend verifies its digest and
  signature. An unverified environment is not started.
- With no local build environment present, the frontend **refuses**. It does not
  fetch one, and it does not offer a remote builder.
- On Apple Silicon the environment is emulated. Emulation performance is never
  reported as supported performance, and no timing measured there is admissible
  evidence for any performance claim.
- Same inputs, either host: the artifact record must match. A Linux-built and a
  macOS-driven record that differ is a defect in the contract, and the test for
  it is part of the harness, not of a release.

## 7. The writer

### 7.1 There is no device path on the public surface

`write` accepts no `--device`, no `/dev/...` argument, and no path to a block
device in any option. A target is named only by a **target code** issued by
`list-media` in the same session.

| `write` accepts | Value domain |
| --- | --- |
| a target code | one issued by `list-media` in this session, and not yet used |
| a verified artifact | a file that passed `verify` |
| a confirmation of the target code | typed back by the operator |
| a second confirmation of the destructive act | typed back by the operator |

A device path is not a name an operator can be sure of. It changes between
enumerations, it is reused after a reboot, and the one they read a minute ago
may now belong to the disk they cannot afford to lose. The target code exists so
that the identity the operator confirmed and the device the writer opens are the
same object, checked, rather than the same string, trusted.

### 7.2 What the writer re-verifies after selection

Between `list-media` and the write, the writer re-checks and refuses on any
mismatch:

- the removable attribute;
- the capacity;
- the partition table as enumerated;
- the stable identity the target code was issued against.

A substitution after enumeration is refused. It is not a warning and not a
prompt.

### 7.3 What the writer refuses outright

| Refused | Why |
| --- | --- |
| an internal disk | the product exists to not write to one ([threat model](threat-model.md) §3) |
| a disk holding the running root filesystem | same, and it also destroys the session that would report it |
| a disk whose removability cannot be determined | unknown is not removable |
| a mounted volume | something else is using it, and unmounting it silently is the writer deciding for the operator |
| an artifact that did not pass `verify` | writing an unverified payload to a medium makes it look like one that was verified |

### 7.4 Order of operations

1. `verify` passes on the artifact.
2. The operator re-confirms the target code.
3. The operator confirms the destructive act separately.
4. The write service unmounts and writes, with least privilege, against a fixed
   allowlist of operations, recording an audit classification.
5. The medium is re-read and verified read-only against the artifact record.
6. A medium that fails step 5 is **never** labelled valid. It is reported as
   failed, and `inspect` on it reports the mismatch rather than the record.

### 7.5 Persistence is a separate operation

Creating encrypted persistence is its own explicit act, on the USB medium only
([ADR-0008](adr/0008-debian-13-live-baseline.md) D4). It is never created on an
internal disk, never implied by `write`, and never created because a medium
booted.

### 7.6 Device identity is not printed

The model, the serial, and the raw device identity of a candidate are not
written to the terminal, the journal, an external report, or GitHub. The
operator screen carries the physical characteristics that let a human pick the
right object — a capacity, a bus position, a physical label — and the target
code. This follows the classification rule Nexus records in
[inventory confidentiality](https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/inventory-confidentiality.md).

## 8. The privilege boundary

| Component | Privilege |
| --- | --- |
| the CLI the operator runs | unprivileged |
| the build environment | privileged inside itself, with no path out to the host |
| the write service | the only component that opens a block device for writing, least privilege, fixed allowlist |
| everything else | unprivileged |

`write` is the only verb that reaches the write service, and the write service
performs no other kind of work.

## 9. What this document does not establish

- That a builder exists or has been selected. Neither is true
  ([ADR-0002](adr/0002-image-builder.md) D2 stands).
- That an image has been built, that a medium has been written, or that any
  medium boots. None of that has happened.
- That the host-storage quarantine works. It has never run
  ([threat model](threat-model.md) §3.3).
- That anything here has been reviewed on hardware. Nothing has.
