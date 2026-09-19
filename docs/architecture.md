# Architecture

Status: **target contract**. Nothing in this document is implemented or
verified. This repository contains no product code, no package, no dependency
manifest, and no Azazel-Fabric pin.

Related: [Threat model](threat-model.md) · [Compatibility](compatibility.md) ·
[Program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
§5 R7 and §6.7

## 1. What Azazel-Boot is

`AZ-03 Azazel-Boot Responder` is a civil emergency Azazel environment started
from removable USB SSD media on a commissioned, compatible x86_64 laptop.

It exists for a situation Azazel-Edge and Azazel-Nexus do not cover: a
responder arrives somewhere with no installed defensive node, needs an
assessment capability within minutes, and has only borrowed hardware —
a clinic laptop, a municipal office PC, a volunteer's machine. Boot supplies
the environment; the laptop supplies nothing but CPU, memory, and NICs, and
gets nothing written to it.

Its minimum independent behavior is deterministic Core assessment, bounded
topology-gated response, evidence handling, and recovery support **without
external services**.

## 2. Boot is not an authority

> Fabric describes. Knowledge advises. **Edge decides and enforces.** Deception
> materializes an Edge-approved environment. Nexus and Boot integrate these
> products without creating another decision authority.

Azazel-Edge's deterministic arbiter is the only decision and enforcement
authority in every configuration, capability state, and failure mode of
Azazel-Boot.

Concretely, Boot MUST NOT:

- arbitrate, approve, or veto an enforcement action;
- substitute its own decision when Edge is slow, degraded, or absent;
- convert a capability report, deployment overlay, package manifest, advisory
  result, model response, or operator UI action into executable authority;
- treat an emergency, a disconnected site, or a time constraint as grounds for
  an exception.

Boot owns what it *performs on the host it borrowed*: media integrity, host
storage quarantine, read-only inventory, commissioning, activation, rendering,
encrypted portable persistence, evidence export, controlled shutdown, and the
removal path. These are product-local because they have side effects. They are
not authority.

### 2.1 Edge is consumed as a released package

Boot consumes Azazel-Edge as a released, signed package through an explicit
adapter. It does not copy the Edge source tree, and it does not vendor a
development branch.

**Boot MUST NOT invoke, import, reimplement, or inherit the values of Edge's
device-specific network installer** (`installer/internal/install_internal_network.sh`).
That installer encodes fixed interface names — `br0`, `eth0`, `wlan0` — and
fixed addressing, which are correct for constrained-device profiles and wrong
everywhere else. Boot's interface layout is unknown until inventory runs on a
laptop it has never seen, so any inherited fixed value would be a guess
presented as a fact. No Boot profile may be able to select it. Edge's installer
remains supported for Edge's own profiles.

The same rule that Azazel-Nexus states for itself applies here; see
[Nexus commissioning](https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/commissioning.md)
§1.

### 2.2 Contract ownership

Azazel-Fabric owns every record that crosses a product boundary, together with
its canonical serialization, digests, validation, and fixtures. Boot MUST NOT
define a Boot-local canonical form for a shared record, and MUST NOT fork a
Fabric model.

The provisioning records Boot needs — `HardwareInventory`, `ResourceProfile`,
`TopologyProfile`, `InterfaceAssignment`, `CommissioningRecord`,
`ProductManifest`, `AssetManifest`, `CompatibilityManifest` — are assigned to
Fabric `provisioning_contracts`, which **does not exist yet**. They are target
contracts. Boot must not invent a local canonical shape for them in the
meantime, and must not adopt a provisioning pin before Fabric releases one.

Boot pins Azazel-Fabric at exactly `v0.8.0`
([ADR-0004](adr/0004-exact-tag-fabric-consumption.md)): an optional extra, one
exact tag, no branch pin, no submodule, no copied source. It is imported in
`src/azazel_boot/fabric_projection.py` and nowhere else, and a static test
fails the build on a second import site.

The pin is not a provisioning pin. `azazel_fabric.provisioning_contracts`, to
which the program plan assigns Boot's `HardwareInventory`, `ResourceProfile`,
`TopologyProfile` and `CommissioningRecord`, **does not exist at that tag**.
Fabric's absence, or a missing submodule, degrades the reported status and
grants nothing.

## 3. Capability model

Boot uses the same model as Azazel-Nexus. The authoritative statement is
[Nexus's capability model](https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/capability-model.md);
this section states how it lands on borrowed laptop hardware. Where the two
disagree, Nexus's document and the program plan win, and the disagreement is a
defect to be fixed here.

Effective capability is an **intersection** of four independently determined
records:

```text
effective capability = resource profile
                     ∩ topology profile
                     ∩ verified asset set
                     ∩ current trust/health state
```

A dimension can only *remove* capability. No dimension grants a property
another dimension does not have. In particular:

> **RAM capacity never enables NIC roles, capture, enforcement, or Deception.**

`CORE`, `LITE`, and `FULL` are **capability states, not authority levels**.
Edge's arbiter holds the same and only authority in all three. Degrading from
`FULL` to `CORE` removes optional capacity and changes no authority whatsoever.

### 3.1 Resource profile

Measured capacity only: CPU cores and features, usable RAM after firmware
reservation, storage, and thermal/power budget. On laptop hardware the
thermal and battery budget is a first-class input, not a footnote — a fanless
ultrabook in a hot room has a lower sustained envelope than its RAM suggests.

The resource profile says **nothing** about the network. A profile that permits
Deception Lite means the host has room for it. It does not mean Deception Lite
is eligible.

The RAM classes measured and reported by the program are 8, 16, 32, and 64 GB.

**The selector thresholds are decided at program level, not by Boot.** The
program plan (§5 R2) fixes one product-local selector over usable RAM in MiB
after firmware reservation: below 7168 diagnostic, 7168-15359 `core`,
15360-31743 `lite`, 31744 and above `standard`.

Each boundary is the nominal size it admits **minus a 1024 MiB
firmware-reservation allowance** (8192-1024, 16384-1024, 32768-1024). The
boundaries used to sit at the nominal sizes themselves, which meant a host of a
given nominal class never reached the tier named after it — a nominal 16 GB
machine measured 16,095 MiB usable and selected `core`. That is program-plan
finding OF-01, resolved 2026-09-19.

The allowance matters to Boot more than to Nexus, because Boot runs on
**borrowed laptops**, where an integrated GPU commonly reserves 512 MiB and the
operator cannot change firmware settings to reclaim it. A machine whose
firmware reserves more than 1024 MiB still falls a tier below its nominal
class. That is a stated limit, not a defect to work around locally: Boot raises
a finding rather than adjusting the selector.

What is *not* settled is the clause the plan attaches to the selector —
"subject to the measured Core reserve". Boot's Core reserve on removable media
has never been measured (issue #8), so the thresholds are decided and their
qualifier is not. A measured reserve may move where a tier begins; it does not
license Boot to invent a different selector.

### 3.2 Topology profile

What the network actually permits, determined by commissioning (§4) and never
by RAM: commissioned interfaces and their operator-confirmed roles, capture
support proven on the observation interface, management reachability over a
path independent of the enforced path, and proven isolation for a decoy zone.

A capability whose topology precondition is unproven is **unavailable**,
regardless of resource headroom.

Laptops make this sharper than rugged PCs do. Many have exactly one usable
network interface, and a USB NIC can be unplugged mid-session. A single-
interface Boot host defaults to observe, evaluate, explain, and audit;
enforcement eligibility is reported separately and withheld, because the
two-stage commit needs an independent management path or a physical local
console that a one-NIC laptop does not have.

### 3.3 Verified asset set

Which signed artifacts passed the full admission sequence: authenticity, an
exact tested compatibility tuple, semantic content policy, resource and
topology admission, operator or policy-authority approval, and staged
activation. A signature from the wrong role, and a correctly signed but
obsolete or incompatible artifact, are both rejected.

A missing or rejected asset removes its own capability and nothing else. Model
or bundle verification failure MUST leave a working Core environment.

### 3.4 Trust and health state

Current, revocable facts: policy signature validity, audit chain continuity and
anchor availability, clock trust, security epoch, peer manifest freshness,
isolation attestation, service health — and, specific to Boot, the media trust
class (see [threat model](threat-model.md) §2) and the presence of the media
itself.

This dimension is continuous, not a one-time gate. It withdraws capability
while the node is running.

Audit assurance is reported as `ROLLBACK_ANCHORED` or `LOCAL_CONTINUITY_ONLY`.
Boot will frequently be in the latter: it uses two-copy signed checkpoints and
an operator-carried or remote anchor when one is available, and on borrowed
hardware there often is none. `LOCAL_CONTINUITY_ONLY` forbids live Deception,
forbids disruptive actions, and forbids any claim of rollback-verified
finalized evidence, unless a named emergency policy records explicit operator
acceptance. Exports made in that state are labeled locally consistent and
**not** rollback verified.

### 3.5 Degradation

The path is `FULL -> LITE -> CORE`, driven by the loss of an optional
component and never by a change in authority. Optional-component failure MUST
NOT block the deterministic control path and MUST NOT grant a new authority.
Restoration above `CORE` requires a passing health window, revalidation, and an
audited transition; a restart alone never restores a capability.

## 4. Per-host commissioning

Boot commissions **every host, every time**. A Nexus is commissioned once for
an installation it keeps. Boot is carried to a laptop it has never seen, and
the same USB SSD may be used on a different laptop the next day. There is no
"the network" for Boot to remember — only this host, this session.

Boot follows the Nexus commissioning discipline; see
[Nexus commissioning](https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/commissioning.md).
The Boot-specific consequences are these.

### 4.1 Inventory is read-only and silent

Inventory reads hardware and interface facts and writes nothing — not to the
network, and not to host storage. Before activation completes, Boot MUST NOT
transmit any frame outside a bounded, operator-selected asset-acquisition
state, associate with a wireless network, forward or route, start capture or
enforcement or Deception, or run DHCP, router solicitation, mDNS, or LLDP.

Wireless deserves explicit mention: a laptop's radio must not associate, probe,
or beacon during inventory. The default is that the radio is down.

### 4.2 Composite identity, not a kernel name

An interface is identified by bus path, permanent MAC, vendor/device identity,
serial where exposed, driver and firmware version, wireless PHY identity where
applicable, and the physical label the operator recorded. MAC-only matching is
insufficient and MUST NOT be accepted.

Matching is fail-closed: exactly one match identifies the interface; zero
matches or more than one match returns the affected capability to
`COMMISSIONING_REQUIRED` and reports the competing candidates. Boot never
silently rebinds and never falls back to a kernel name or a default route.

On laptops this matters more than on fixed hardware. A USB-Ethernet adapter
moved between ports, a docking station, and a driver difference between two
otherwise identical machines all change the composite identity. Each returns
the affected capability to `COMMISSIONING_REQUIRED` rather than guessing.

### 4.3 Roles come from the operator

Logical roles are `protected`, `observation`, `management`, `decoy`, and
`egress/module`. A role is assigned only by explicit operator confirmation
against the inventory.

Boot MUST NOT infer a role from an interface name, carrier or link state, the
presence of a default route, an autoconfigured address, or any resource
measurement. Unassigned interfaces stay unassigned and have no capability.

The operator here may be a non-technical civil responder under stress. That
raises the bar on the confirmation interface — it must show what is physically
plugged in where, in terms the operator can check by looking at the laptop —
but it never lowers the bar to inference. A confirmation the operator cannot
understand is not a confirmation.

### 4.4 Sessions do not inherit each other

A commissioning record is bound to the host that produced it and to the session
identity. Booting the same media on a different laptop does not reuse the
previous host's roles. USB cloning creates a new node and session identity and
carries no active or one-shot lease.

### 4.5 Rendering from roles only

Generated configuration is rendered from commissioned logical roles, into
disposable output. There is no fallback: if a role is unassigned or its
identity is ambiguous or changed, rendering fails and the dependent capability
stays unavailable. Boot MUST NOT substitute a physical interface name, a kernel
device number, a default route, or a "first available" interface for a missing
role.

## 5. What this document does not establish

- That any of the above exists. None of it is implemented. The package that
  does exist reports this absence; it does not reduce it.
- When Boot will consume Fabric's provisioning contracts. The tag is pinned;
  the contracts it would need are not in it.
- The RAM thresholds, the Core reserve on removable media, or the startup-time
  budget. None is measured.
- That the boot path works on any laptop. See
  [compatibility](compatibility.md) — the envelope is empty.
