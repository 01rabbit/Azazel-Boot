# Build environment and the reproducibility evaluation

Status: **target contract, with tooling but no measurement**. The resolver, the
evaluation runner and the comparator described here exist in `tools/builder/`.
**No evaluation build has been run.** No candidate builder has been wrapped, no
Debian 13 Live payload has been produced, no digest has been measured, and no
builder has been selected.

Related: [ADR-0002 image builder](adr/0002-image-builder.md) ·
[ADR-0009 builder and writer contract](adr/0009-builder-and-writer-contract.md) ·
[Builder and writer contract](builder-writer-contract.md) ·
[Release policy](release-policy.md)

## 1. What this covers

[ADR-0009](adr/0009-builder-and-writer-contract.md) D8 lists the steps that
would satisfy [ADR-0002](adr/0002-image-builder.md) D4. This document covers the
machinery for P1–P4: a closed set of pinned inputs, a build that cannot be
mistaken for a release, and a comparison whose verdict cannot select anything.

It does not cover signing, the key hierarchy or the release channel
([release policy](release-policy.md) §6–§7, still open).

## 2. The build host

| Property | v1 |
| --- | --- |
| Build host OS | Debian 13 / amd64 only |
| Where the build runs | an isolated build environment; the operator's host gains no privileged build step |
| Host paths as input or output | refused |
| macOS | drives a verified Debian 13 environment; never builds natively |

## 3. The input closure

`tools/builder/closure.py` resolves a **symbolic profile ID** against two
versioned files under `config/builder/`:

- `profiles.json` — which inputs a profile uses, and which quarantine policy the
  payload carries. It contains no URL, mirror, apt line, package name or path.
- `pins.json` — the immutable pin for each input. A pin is `sha256:<64 hex>` or
  `snapshot:<YYYYMMDDTHHMMSSZ>`. A tag, a branch, a codename or a bare version
  is refused: the same name can later mean different bytes, which is what
  [ADR-0002](adr/0002-image-builder.md) D3 C2 rules out.

Resolution is all-or-nothing. There is no partial closure and no warning path,
and the refusal names one cause:

| Refusal | Cause |
| --- | --- |
| `not_symbolic` | the name is not a symbolic ID — a URL, path, apt line or shell fragment cannot be one |
| `unknown_profile` | versioned configuration does not name it |
| `unpinned_input` | an input has no pin; an input resolved at build time is not an input |
| `mutable_pin` | the pin is not an immutable form |
| `orphan_pin` | a pin names an input the profile does not use |
| `duplicate_input` | the same input is listed twice |
| `empty_profile` | a profile with no inputs |
| `unpinned_quarantine_policy` | the payload's defining safety property is not an implicit default |

**The configuration this repository ships pins nothing**, so every profile in it
refuses to resolve. That is the accurate state: no snapshot, toolchain, firmware
set or image configuration has been chosen. Pinning one is a decision and
belongs in its own change.

The `build_input_digest` is taken over a sorted, ASCII, newline-terminated JSON
form, so two hosts that resolved the same configuration produce the same bytes
whatever their locale or filesystem ordering.

## 4. An evaluation build is not a release

[ADR-0009](adr/0009-builder-and-writer-contract.md) D8.1 permits a build whose
only purpose is to produce a measurement. The separation from a release is
structural, not a matter of intent:

- the **evaluation record** has no signature field, no signed-artifact field and
  no compatibility-claim field. A record that cannot carry a claim cannot be
  read as making one;
- `NON-RELEASABLE / EVALUATION ONLY` is stamped in the record **and** required in
  the payload's own metadata. An unstamped payload produces no record at all;
- the output directory is a dedicated temporary directory **outside every Git
  working tree**. The guard reads `.git` as a name — a directory in a clone, a
  file in a worktree — and never executes `git`;
- the payload must land inside that directory, and the directory must be empty
  when the build starts.

The record's fields are the build's identity (profile, quarantine policy, Git
revision, builder name and version), its inputs (`build_input_digest`,
`source_date_epoch`), its result (`unsigned_payload_digest`, `payload_bytes`),
and its provenance (an **anonymous** build host ID and the build time). A
hostname, an FQDN, a serial or an asset tag is refused as a host ID.

`build_time` and `build_host_id` are recorded and are deliberately not inputs to
any digest: two hosts building the same closure at different moments must still
agree.

### Why the output directory rule is a rule

A synthetic measurement once reached a draft branch in a sibling repository
because an unrelated `git add -A` swept up a file a tool had written into the
checkout. Nothing was claimed from it, and it was still an integrity incident: a
non-authoritative artifact became reachable as if it were evidence. The guard
covers every working tree, not just this one.

## 5. The reproduction comparison

`tools/builder/reproduction.py` compares two evaluation records and refuses
three comparisons outright: two records from the **same** build host (one
builder twice is not the two-builder claim,
[ADR-0002](adr/0002-image-builder.md) D1.3), records built from different input
closures, and records for different profiles.

The verdict is asymmetric on purpose:

- a **mismatch** refuses the selection. It is filed as evidence. It is not a
  retry — re-running until the digests agree turns a real non-determinism into
  an occasional mystery;
- a **match** decides nothing. It satisfies the measurement C1 asks for and
  leaves C2–C9, the Fabric provisioning gate and the supply-chain record exactly
  where they were. There is no verdict value that selects a builder.

## 6. What has not happened

- No candidate builder has been wrapped as an adapter, and none has been
  evaluated against C1–C9.
- No image, payload or medium exists. No digest has been measured.
- C5 — deterministic control of the initramfs — has not been evaluated, and it
  is the criterion that eliminates first.
- Nothing here is evidence that a reproducible Debian 13 Live build is
  achievable. Nobody has tried.
