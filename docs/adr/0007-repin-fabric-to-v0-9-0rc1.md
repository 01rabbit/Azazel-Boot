# ADR-0007: Re-pin Azazel-Fabric to `v0.9.0rc1`, the first tag carrying the provisioning contracts

Status: **accepted (2026-09-19)** — supersedes [ADR-0004](0004-exact-tag-fabric-consumption.md) **D1 only**.
D2 (optional extra), D3 (one import site) and D4 (the guard) are untouched and
are the reason this re-pin is a one-line change rather than a migration. It
moves a tag. It commissions nothing, implements no consumer, and has never run
on a machine.

Related: [ADR-0004](0004-exact-tag-fabric-consumption.md) ·
[Architecture](../architecture.md) · [Compatibility](../compatibility.md) ·
[Release policy](../release-policy.md)

## Context

ADR-0004 pinned `v0.8.0` and built a section around what that tag did **not**
contain:

> **There is no `provisioning_contracts` module at `v0.8.0`** … R1 has not
> shipped. So Boot adopts a pin in full knowledge that the module it most needs
> is absent from it.

That is no longer the state of the program. Azazel-Fabric published
**`v0.9.0rc1`** on 2026-09-19 — the R1b release candidate — and it carries
`provisioning_contracts`, `mio_contracts` and `outcome_contracts`, none of
which exist at `v0.8.0`.

Verified against the tag, not against a changelog:

```console
$ pip install "azazel-fabric @ git+…/Azazel-Fabric.git@v0.9.0rc1"
$ python -c "import azazel_fabric; print(azazel_fabric.__version__)"
0.9.0rc1
  azazel_fabric.view:                    present
  azazel_fabric.provisioning_contracts:  present
  azazel_fabric.mio_contracts:           present
```

Three Boot issues are blocked on reaching those contracts, and all three named
the same obstacle: the modules exist only on Fabric's `main`, and **D1 forbids
pinning a branch** — correctly. A branch pin was never the answer; a tag was
missing.

## Decision

### D1 — The pin is exactly `v0.9.0rc1`

`azazel-fabric` is declared as
`azazel-fabric @ git+https://github.com/01rabbit/Azazel-Fabric.git@v0.9.0rc1`.
No branch pin. No submodule. No vendored or copied source. No version range,
and no "or later". ADR-0004 D1's *discipline* is adopted unchanged; only its
value moves.

### D2 — A release candidate is an exact tag, and that is the whole of what it is

`v0.9.0rc1` is a candidate. It is pinnable — which is the only property D1 ever
required — and it promises **no stability**. Fabric says so itself: its
changelog records that a candidate exists so consumers can pin an exact tag
instead of `main` and produce the downstream evidence a stable release needs.

Boot therefore expects to re-pin to `v0.9.0` when Fabric cuts it. That is a
value change under this ADR, not a new decision.

### D3 — The alternative was worse, and it is worth recording why

Staying on `v0.8.0` was the other option. It would have kept a stable tag at the
cost of leaving [#9](https://github.com/01rabbit/Azazel-Boot/issues/9),
[#11](https://github.com/01rabbit/Azazel-Boot/issues/11) and
[#16](https://github.com/01rabbit/Azazel-Boot/issues/16) blocked indefinitely on
a tag that does not exist yet, while the contracts they need sat finished on a
branch nobody may pin.

The stability a stable tag buys is worth less here than it looks: Boot consumes
Fabric through one module, behind a guard, for a projection that grants no
authority. The blast radius of a candidate that later changes is that module
and its tests — which is exactly the blast radius ADR-0004 D3 was designed to
produce.

## Consequences

- `fabric_projection.FABRIC_PIN` becomes `v0.9.0rc1`, and `missing_planned` is
  now **empty**: nothing Boot plans to consume is absent from the pin.
- ADR-0004's "The absent module is the point" section describes a state that has
  ended. It is retained as the record of why the guard was built and what it was
  first tested against — the guard did not become decorative, it changed what it
  reports.
- The test that asserted `provisioning_contracts` was **absent** is inverted
  rather than deleted, and two tests are added: that every planned module
  actually imports at the pin, and that the contracts the re-pin exists for
  (`InterfaceIdentity`, `InterfaceIdentitySelector`) are reachable. A later
  re-pin to a tag without them breaks here, loudly, instead of at a consumer.
- Boot#9, #11 and #16 become startable. **None of them becomes done**: this ADR
  moves a tag and writes no consumer.
- If Fabric withdraws or re-cuts `v0.9.0rc1`, Boot's extra stops resolving. That
  is the ordinary consequence of an exact pin and is preferable to the failure a
  branch pin hides.

## What this ADR does not establish

- That Boot commissions anything, inventories anything, or reads a NIC. It does
  not; [#9](https://github.com/01rabbit/Azazel-Boot/issues/9) is open and this
  ADR does not touch it.
- That `v0.9.0rc1` is *correct*, or that its contracts fit Boot's needs. Only
  that they are reachable at an exact tag. The first consumer will say whether
  they fit, and that is the evidence Fabric's own R1c gate is waiting for.
- That a candidate is a supported release. It is not, and Boot's support matrix
  claims nothing new because of this change.
- Any authority. Fabric describes; Boot integrates. Azazel-Edge's deterministic
  arbiter remains the only decision and enforcement authority in every
  configuration and failure mode of Azazel-Boot, with or without this pin.
