# Contributing to Azazel-Boot

Azazel-Boot Responder (`AZ-03`) is a civil emergency environment started from
removable USB SSD media on a commissioned, compatible x86_64 laptop. Two rules
are judged before anything else in a contribution:

1. **Azazel-Edge's deterministic arbiter is the only decision and enforcement
   authority.** Boot integrates released components. It never becomes a second
   authority, not even while Edge is degraded or absent.
2. **Boot writes nothing to internal host storage without explicit operator
   approval.** This is the product's defining safety property, not a
   configurable default.

A change that weakens either rule is rejected regardless of what else it
achieves.

## This is a documentation-stage repository

There is no product code, no package, no dependency manifest, no Fabric pin,
and no image builder. Nothing is implemented or verified. Contributions today
are documentation, governance, and the small stdlib-only tooling that checks
them.

That constrains what a pull request may claim. Write in the series status
vocabulary from the
[third-party development handoff](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
§7 — **target contract**, **implemented**, **verified**, **supported**,
**experimental**, **retired** — and never collapse them. A design written down
here is target contract. It becomes `implemented` when code and focused tests
exist, and `verified` only when a declared evidence gate has passed. Do not
promote a status in the same PR that introduces the behavior.

## Before you start

Read, in this order:

1. [Third-party development handoff](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
   — permanent design decisions, product ownership, status vocabulary.
2. [Nexus and Boot program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
   — §5 R7 is Boot's release gate, §6.7 is Boot's backlog.
3. [R0 baseline](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-r0-baseline.md)
   — observed version facts and open R0 work.
4. [Series naming specification](https://github.com/01rabbit/Azazel/blob/main/docs/specs/naming.md)
   — the formal name is `Azazel-Boot Responder`; `AZ-03` has no codename.
5. This repository's [README](README.md), [architecture](docs/architecture.md),
   and [threat model](docs/threat-model.md).
6. [Azazel-Nexus docs](https://github.com/01rabbit/Azazel-Nexus/tree/main/docs)
   — mirror its capability, commissioning, and contract-ownership vocabulary.

Do not treat a closed issue, an archived roadmap, or a demonstration artifact
as current product authority.

## Boundaries a pull request must respect

- **Do not invent vocabulary.** Reuse the program's terms: `FULL` / `LITE` /
  `CORE`, `ResourceProfile`, `TopologyProfile`, `CommissioningRecord`,
  `VERIFIED_FIRMWARE`, `EXTERNALLY_VERIFIED_MEDIA`, `UNVERIFIED_PLATFORM`,
  `ROLLBACK_ANCHORED`, `LOCAL_CONTINUITY_ONLY`. If a term is genuinely
  missing, raise it against the owning repository rather than coining a
  Boot-local synonym.
- **Do not define a canonical form for a shared record.** Azazel-Fabric owns
  every record that crosses a product boundary. Boot may describe an adapter;
  it may not fork a Fabric model or publish a Boot-local wire shape.
- **Do not inherit Azazel-Edge's device-specific network installer.**
  `installer/internal/install_internal_network.sh` assumes `br0`, `eth0`, and
  `wlan0`. Boot's interface layout is unknown until inventory, so any inherited
  fixed value would be a guess presented as a fact. Boot must not invoke,
  import, reimplement, or copy its values.
- **Do not infer interface roles.** A role comes from read-only inventory plus
  explicit operator confirmation against a composite identity — never from an
  interface name, carrier state, default route, or resource measurement.
- **Do not let RAM enable anything.** Resource capacity selects an envelope.
  Capture, enforcement, and Deception additionally require topology, verified
  assets, and current trust, evaluated independently and intersected.
- **Do not add a dependency.** A stdlib-only `tools/` script is fine. Anything
  beyond that requires a dependency manifest and a recorded decision, neither
  of which exists yet.
- **Do not add a Fabric pin, package layout, or CI test job casually.** Each is
  a program-level commitment tracked by issue #1 and the R0 exit criteria.

## Branch naming

`<type>/<short-description>`, e.g. `docs/threat-model-removal-path`,
`fix/link-check-anchors`.

## Commit message format

`<type>(<scope>): <summary>`

Scopes in use today: `docs`, `ci`, `tools`, `meta`. Japanese or English body
text is fine; say what changed and why. If a change alters a documented
contract, the document is revised in the **same** commit — never left to
diverge silently.

## Pull request rules

- 1 PR = 1 purpose.
- CI passes. Today that is one job: the documentation internal-link check.
- Run it locally before pushing:

  ```bash
  python3 tools/check_docs_links.py
  ```

  It needs only Python 3.9+ from the standard library.
- If you add a document, link it from `README.md`. An unreferenced document
  drifts.
- State explicitly, in the PR body, what your change does **not** establish.
  "Written down" and "true" are different, and the PR is where that difference
  is recorded.

## What not to do

- No operational network, enforcement, installer, model-fetch, or container
  activation code in this repository until the corresponding program gate opens.
- No claim that Azazel-Boot boots, is safe on any laptop, or preserves host
  storage. No such test has ever been run.
- No hardware entry in `docs/compatibility.md` without owner ratification and a
  linked evidence record. The list is empty on purpose.
- No security report in a public issue — use
  [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the project's MIT license ([LICENSE](LICENSE)).
