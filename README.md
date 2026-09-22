# Azazel-Boot

**Azazel-Boot Responder** (`AZ-03`) is a civil emergency Azazel environment
started from removable USB SSD media on a commissioned, compatible x86_64
laptop. It gives a responder a deterministic assessment capability, bounded
and topology-gated response, evidence handling, and recovery support on
borrowed hardware, without taking the hardware over.

No codename is assigned to `AZ-03`. Use the formal name
`Azazel-Boot Responder`; see the series
[naming specification](https://github.com/01rabbit/Azazel/blob/main/docs/specs/naming.md).

## Status

**This repository is target contract.** It contains documentation and
repository governance. Nothing here is implemented or verified.

| Fact | State |
| --- | --- |
| Platform baseline | **Debian 13 Live / amd64**, fixed at program level ([§15 OF-07](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md), adopted in [ADR-0008](docs/adr/0008-debian-13-live-baseline.md)). **Nothing has been built from it** — no image, no medium, no boot |
| Product code, installer, image builder | **does not exist**. No build tool is selected either: `live-build` is the builder the baseline is written against, and [ADR-0002](docs/adr/0002-image-builder.md)'s selection conditions are untouched |
| Image builder and media writer | **contract, plus decision logic** — [ADR-0009](docs/adr/0009-builder-and-writer-contract.md) and [the builder/writer contract](docs/builder-writer-contract.md) fix six verbs (`build` and `write` never merged), the artifact record, the isolated build host, and a writer that names a target by per-session code rather than by device path. `azazel_boot.artifact`, `azazel_boot.media` and `azazel_boot.writer` decide whether an artifact may be written and which devices may be offered — they **open no device** ([docs/media-writer.md](docs/media-writer.md)). No medium has been written, and no builder is selected |
| Python package and CLI | a **non-operational status scaffold only** — `azazel-boot status` reports what this repository is and does nothing else |
| Host-storage quarantine | **decision logic and a pinned policy** (`azazel_boot.quarantine`, `config/quarantine/policy-v1.json`): classifies devices on appearance by stable identity, refuses every action against anything that is not the medium, and checks a built image's initramfs manifest against the hook contract ([docs/quarantine-policy.md](docs/quarantine-policy.md), [ADR-0008 D4.1](docs/adr/0008-debian-13-live-baseline.md)). **Nothing has run**: no initramfs has been built, no device has been quarantined, and the no-host-write property is **not verified**. See [#28](https://github.com/01rabbit/Azazel-Boot/issues/28) |
| Reproducibility evaluation | **tooling, no measurement** (`tools/builder/`, `config/builder/`): resolves a symbolic profile into a closed set of pinned inputs, runs a candidate builder as **non-releasable evidence**, and compares two records without ever selecting anything ([docs/build-environment.md](docs/build-environment.md)). The shipped configuration pins nothing, so every profile refuses; no build has been run and no digest has been measured. See [#26](https://github.com/01rabbit/Azazel-Boot/issues/26) |
| Knowledge Lite admission | **decision logic only** (`azazel_boot.lite_cache`): decides whether an artifact may be read and what happens when it may not. It reads no artifact and writes no cache; verification is injected and **the default admits nothing**, because Knowledge signs with Ed25519 and this bootstrap is standard-library only. See [#16](https://github.com/01rabbit/Azazel-Boot/issues/16) |
| Interface inventory and commissioning | **parsing and refusal logic only** (`azazel_boot.inventory`, `azazel_boot.commissioning`): reads a sysfs tree, builds composite identities, and reports what an operator would have to settle. It reads no real NIC — the permanent MAC needs an ioctl, which the bootstrap may not perform — assigns no role, and confirms nothing. See [#9](https://github.com/01rabbit/Azazel-Boot/issues/9) |
| Persistence, session mode and dirty-write | **decision logic only** (`azazel_boot.persistence`, `azazel_boot.session_mode`, `azazel_boot.dirty_write`): decides whether persistence may open, fixes the session mode once at commissioning under a five-attempt budget, and stops the **whole volume** on a suspected torn write ([ADR-0010](docs/adr/0010-persistence-key-and-migration.md) D1–D5, [persistence](docs/persistence.md), [session mode](docs/session-mode.md)). No volume has been created, opened, sealed, torn or quarantined; no passphrase has been attempted. See [#40](https://github.com/01rabbit/Azazel-Boot/issues/40), [#41](https://github.com/01rabbit/Azazel-Boot/issues/41) |
| Snapshot, preflight and recovery | **decision logic only** (`azazel_boot.snapshot`): judges whether a migration may run and whether a recovery may commit, and hands back a **candidate** — a recovery does not lift the quarantine ([ADR-0010](docs/adr/0010-persistence-key-and-migration.md) D6–D8, [snapshot and recovery](docs/snapshot-and-recovery.md)). No snapshot has been written, no migration run, no trial interrupted and no restore attempted on any device; a recovery **cannot complete outside a test**, because the real key acquisition and the real unlock do not exist. See [#42](https://github.com/01rabbit/Azazel-Boot/issues/42) |
| Azazel-Fabric pin | exact tag `v0.9.0rc1` (a release candidate), consumed in one boundary module; its absence degrades the reported status and grants nothing |
| Architecture decision records | see [docs/adr/](docs/adr/) |
| CI | documentation links, plus static checks, unit tests and a dependency-lock check on the declared Python matrix |
| Laptop compatibility list | **empty** — see [compatibility](docs/compatibility.md) |
| Hardware, boot, or no-host-write evidence | **none** |

Read [the series status vocabulary](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
§7 and apply it strictly. Everything in `docs/` describes intended behavior.
None of it is an operational claim, and none of it may be cited as evidence
that Azazel-Boot does anything at all today.

## The defining safety property

> **Azazel-Boot writes nothing to internal host storage without explicit
> operator approval.**

The laptop belongs to someone else — a clinic, a city office, a volunteer.
Booting Azazel-Boot on it must not alter it. Internal block devices are
quarantined in the initramfs before anything else starts, and stay quarantined
for the whole session unless an operator explicitly selects and approves an
export target. The program-level target is zero content writes to internal
block devices from initramfs entry through shutdown. Firmware NVRAM changes
that the platform makes on its own are reported separately and are not covered
by that claim.

This property is the product. A feature that cannot be delivered without
relaxing it is not delivered.

## Authority

> Fabric describes. Knowledge advises. **Edge decides and enforces.** Deception
> materializes an Edge-approved environment. Nexus and Boot integrate these
> products without creating another decision authority.

Azazel-Edge's deterministic arbiter is the only decision and enforcement
authority in any configuration of Azazel-Boot. Boot assembles released
components, commissions the host it is running on, and presents results. It
never arbitrates, never overrides, and never becomes a fallback authority when
Edge is degraded or absent.

`FULL`, `LITE`, and `CORE` are **capability states, not authority levels**.
Degrading to `CORE` removes optional capacity. It removes, transfers, and
expands exactly zero authority.

Effective capability is an intersection, never a sum:

```text
effective capability = resource profile
                     ∩ topology profile
                     ∩ verified asset set
                     ∩ current trust/health state
```

RAM alone never enables NIC roles, capture, enforcement, or Deception. A
laptop with a large memory envelope and one unusable NIC is observe-only, and
that is the correct outcome.

## Documentation

- [Architecture](docs/architecture.md) — Boot's relationship to Azazel-Edge,
  the capability model by reference to Nexus's vocabulary, per-host
  commissioning, and what Boot deliberately does not inherit.
- [Threat model](docs/threat-model.md) — removable-media trust classes,
  initramfs host-storage quarantine, surprise removal, persistence tampering,
  per-host commissioning, and the attackers Boot does not defend against.
- [Compatibility](docs/compatibility.md) — the shape of the laptop
  compatibility envelope, and why its hardware list is empty.
- [Architecture decision records](docs/adr/) — what is decided, what merely
  records a program-level decision, and what is deliberately still open.
- [Release policy](docs/release-policy.md) — what a release will have to carry,
  what a signature does and does not attest, and why none of it exists yet.
- [Support matrix](docs/support-matrix.md) — what a release will be able to say
  it supports; the hardware list is empty, the firmware frame is decided but
  measured on no machine — UEFI assumed, Secure Boot enabled the target — and the
  only checkable rows describe the status scaffold.
- [Update channel](docs/update-channel.md) — why an update to removable media is
  a media rewrite or a new medium rather than a service update, why the offline
  path matters more than the online one, and why no channel exists.
- [Recovery](docs/recovery.md) — surprise removal, failed updates and power loss,
  what leaving the host as found does and does not cover, and what survives a
  failed session.
- [Snapshot and recovery](docs/snapshot-and-recovery.md) — why a recovery ends
  in a **candidate** rather than a usable volume, and why the quarantine does
  not lift when one succeeds.
- [Session mode](docs/session-mode.md) — persistent or ephemeral, decided once
  per boot; why no key means ephemeral with no exception, why five attempts is
  not brute-force resistance, and why the passphrase never reaches the module
  that decides.
- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Program context

Azazel-Boot is one workstream of a cross-repository program. These documents
are authoritative over this repository and are not maintained here:

- [Third-party development handoff](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
  — read first; permanent design decisions and status vocabulary.
- [Nexus and Boot program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
  — §5 R7 is Boot's release gate; §6.7 is Boot's backlog.
- [R0 product and compatibility baseline](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-r0-baseline.md)
  — observed version facts and open R0 work.
- [Azazel-Nexus docs](https://github.com/01rabbit/Azazel-Nexus/tree/main/docs)
  — Boot mirrors Nexus's capability, commissioning, and contract-ownership
  vocabulary rather than inventing parallel terms.

Boot's bootstrap issue is
[Azazel-Boot #1](https://github.com/01rabbit/Azazel-Boot/issues/1).

## License

MIT — see [LICENSE](LICENSE).
