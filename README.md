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
| Product code, installer, image builder | **does not exist** |
| Python package and CLI | a **non-operational status scaffold only** — `azazel-boot status` reports what this repository is and does nothing else |
| Azazel-Fabric pin | exact tag `v0.8.0`, consumed in one boundary module; its absence degrades the reported status and grants nothing |
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
  and the attackers Boot does not defend against.
- [Compatibility](docs/compatibility.md) — the shape of the laptop
  compatibility envelope, and why its hardware list is empty.
- [Architecture decision records](docs/adr/) — what is decided, what merely
  records a program-level decision, and what is deliberately still open.
- [Release policy](docs/release-policy.md) — what a release will have to carry,
  what a signature does and does not attest, and why none of it exists yet.
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
