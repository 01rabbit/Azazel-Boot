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

There is no operational product code and no image builder. What exists is a
**non-operational status scaffold** — a package that reports what this
repository is, a guarded Azazel-Fabric boundary, and the tests and CI that hold
both to their claims (issue #1). Nothing is implemented or verified in the
sense of doing the product's job: `status.BootStatus.is_operational()` returns
False by construction, and `tests/unit/test_boundary_static.py` fails the build
if the package acquires a network, process or host-storage surface.

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
- **Do not add a runtime dependency.** The scaffold is stdlib-only and must
  stay that way: it has to stand on a machine where nothing optional is
  installed. `azazel-fabric` is an **optional extra** pinned to an exact tag
  (ADR-0004) and may be imported in `src/azazel_boot/fabric_projection.py`
  alone; a static test fails the build on a second import site. A new
  development dependency goes in `constraints-dev.txt` with an exact version,
  and CI verifies the installed set against it.
- **Do not add operational code.** No network, enforcement, installer,
  model-fetch or container activation, per issue #1's last acceptance
  criterion. This is enforced, not merely asked for.
- **Do not name a laptop anywhere in this repository** until it has a ratified
  compatibility row ([ADR-0001](docs/adr/0001-x86_64-uefi-compatibility.md) D7).
  Not as a candidate, a target, an example, or in an issue or commit message. A
  reader who sees their machine named will try it, and no machine has been
  tested.

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
- CI passes. That is the documentation internal-link check, plus static checks,
  unit tests and a dependency-lock check on the declared Python matrix, plus a
  job that installs the `fabric` extra so the projection's success path is
  actually exercised rather than skipped.
- Run them locally before pushing:

  ```bash
  python3 tools/check_docs_links.py
  ruff check src tests tools
  python -m pytest tests -q
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
