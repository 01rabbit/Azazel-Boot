# The snapshot, the preflight, and a recovery that ends in a candidate

Status: **decision logic only.** `azazel_boot.snapshot` decides whether a
migration may run and whether a recovery may advance. It **writes no snapshot,
runs no migration, opens no trial, restores nothing and measures no free
space** — the caller performs those acts and reports what it saw, and this
module judges the reports. Nothing here has run on hardware.

Implements [ADR-0010](adr/0010-persistence-key-and-migration.md) **D6, D7 and
D8**.

Related: [Persistence](persistence.md) §4.1 · [Recovery](recovery.md) ·
[Quarantine policy](quarantine-policy.md) §4 ·
[ADR-0011](adr/0011-unlock-helper-boundary.md) ·
[#42](https://github.com/01rabbit/Azazel-Boot/issues/42)

## The one rule everything here is built around

**A recovery does not lift the quarantine. Nothing in this module does.**

A recovery that passed every gate hands back a `RecoveryCandidate`, and **a
candidate is not a volume**. It cannot be read, written, exported or mounted;
its whole public surface is `schema_version` and `authority`, and `authority`
is `()`. The `Quarantine` that judged the medium refuses exactly as much
afterwards as before — a test drives a completed recovery and then asserts
every ordinary act still refuses.

Getting back to ordinary use means a **different session, starting over**:
commissioning, the media binding, key acquisition, integrity verification and
an operator confirmation, from the beginning.

That is not an inconvenience to be optimised away later. **A recovery workflow
that ended the quarantine would *be* the unquarantine call D4 refuses**,
wearing four gates as a disguise — and those four gates would then be the only
thing between a torn volume and ordinary use. Keeping the candidate separate
means the gates are a second opinion rather than the sole one.

So it is checked structurally, not trusted as prose:

- an **exact allowlist** of every public name the module exports, so a new one
  has to be added to the test deliberately;
- no method on either acting class whose name contains `unquarantine`, `clear`,
  `lift`, `restore`, `reopen`, `release`, `trust`, `permit`, `enable`, `mount`,
  `fsck`, `repair`, `export`, `download` or `upload`;
- no *call* to `fence`, `quarantine_volume`, `approve_export`, `withdraw_export`
  or `observe`, and no assignment to `_fenced` or `_volume_quarantined` — the
  indirect route, which a method-name check would miss entirely;
- `is_fenced` and `volume_is_quarantined` **are** read, which is the point.

## The snapshot (D6)

Inside the single existing encrypted persistence partition. **No second
partition**, so [ADR-0008](adr/0008-debian-13-live-baseline.md) D4.1's
three-partition layout is not revised — and `check_layout` still refuses a
fourth, driven here rather than assumed, because "the other module still does
it" is the kind of claim that stops being true quietly.

A `SnapshotDescriptor` states its **container version** and its **schema
version**, and an unknown container version is refused rather than guessed at:
a snapshot whose layout nobody here knows is a sequence of bytes with a hopeful
name on it. `KNOWN_CONTAINER_VERSIONS` is a literal tuple rather than a `<=
LATEST` comparison, which would accept every version anyone ever writes,
including the ones written after this code was last read.

**Integrity is judged on the snapshot alone.** D6 requires it: a snapshot that
can only be judged by the thing it would restore is not a snapshot. No function
here takes the live data and the snapshot together, and the test asserts that
on the signatures rather than on the bodies.

The three fields are **checked where the descriptor is built**. An annotation
is not a check — `azazel_boot.dirty_write` paid for that lesson when a review
built its observation out of three strings naming the worst faults there are
and got a clean write.

## Preflight (D7)

Read-only **by construction**: it takes reports and returns a verdict. It has
no port to write through and the module imports nothing that could write, so a
refused migration has written nothing because nothing here writes at all. The
test pins the *shape* — no parameter named for a writer, a port, a store, a
device, a path, a file or a handle — rather than reviewing the body, since a
body-reviewed claim lasts until the body changes.

The order is fixed and is part of the contract:

| # | Check | Why here |
| --- | --- | --- |
| 1 | the fence | D9: a version upgrade is not a way round it, and asking a removed medium about its free space means reasoning about a device that is not there |
| 2 | the volume is not quarantined | D4 stops the whole volume on a suspected torn write, and a migration is a large write to exactly that volume |
| 3 | the snapshot exists | D7's load-bearing rule, before the cheap answers |
| 4 | its container version is known | |
| 5 | its integrity verified | `INDETERMINATE` lands with `FAILED`; ambiguity refuses |
| 6 | required vs available space | |
| 7 | schema compatibility | forward by a known step; a downgrade and a no-op both refuse |
| 8 | binding, generation, image digest | |

Each failing check refuses with **its own classification**, so an operator
learns which one — and nothing behind it.

**There is no migration without a snapshot**, and it is asserted as an absence
as well as a refusal: `preflight` has no parameter containing `force`,
`accept`, `override`, `without_snapshot`, `degraded` or `emergency`. An
operator cannot consent to it, so there is nothing to consent with.

A refusal **keeps the old schema working**, which is the safe outcome rather
than a degraded one — driven by unlocking on the old schema afterwards.

## Recovery (D8)

Operator-started, one-way, and every stage entered explicitly.

`started_by_operator` is a **required keyword with no default**. A default of
`True` would make the automatic start D8 refuses the easiest thing to write; a
default of `False` would make it a flag somebody flips. There is no `retry`, no
`resume`, no `auto`, no `background` and no `schedule` anywhere on the surface,
and no `RecoveryStage` member meaning automatic.

```
NOT_STARTED → PREFLIGHT_PASSED → TRIAL_OPEN → COMMITTED
                     ↘                ↘
                    REFUSED       INTERRUPTED
```

`COMMITTED`, `REFUSED` and `INTERRUPTED` are **terminal**. There is no call
that restarts a finished workflow, because restarting is a new workflow that
runs every gate again — which is what starting one does.

**The gates run before the trial opens and again before the commit**, not once
at the start — except key acquisition, which runs only at the commit, because
that is where an operator is asked to type. A medium can be pulled while an
operator reads a confirmation screen, and a gate checked once is a gate checked
at a moment that has passed. Tests fence the quarantine between the start and
the trial, and again between the trial and the commit, and assert each refuses;
the trial-side recheck was untested until a review deleted it and the suite
stayed green.

The gates, in order — D8's four, with two that precede them:

1. **the medium is not fenced**
2. **there is something to recover** — running this over a healthy volume would
   be a restore of live data from a snapshot: the write D8 refuses to make
   automatically, made deliberately over something that was fine
3. **target binding** — [ADR-0008 D4.1.1](adr/0008-debian-13-live-baseline.md)'s,
   re-derived from the supplied inventory, not a stored answer
4. **key acquisition** — `session_mode`'s `KeyAcquisition` Protocol, reused
   rather than reimplemented, so what crosses back is the same single enum and
   this module never sees a passphrase
5. **integrity verification**
6. **operator confirmation** — `confirmed` grants nothing by itself, which the
   first test in the file drives: the volume is still quarantined afterwards

Each is driven failing on its own to show the next is not reached. A binding
from another machine refuses with the acquisition **never invoked**.

**One pair cannot be contested, and saying so is better than a test that looks
like it proves it.** D8 orders key acquisition before integrity, but at the
commit the snapshot is pinned to the one the workflow started on — so a
failed-integrity snapshot cannot be presented there, the substitution rule
answering first. At `start` there is no acquisition, because that is where an
operator has not yet been asked to type. No input makes both gates fail at the
same moment. A re-review found that the helper written to contest that pair was
**defined and never called**, and that reversing the two left the suite green.
The helper is deleted rather than wired up, because wiring it up would not have
worked either; what is pinned instead is the fact that makes it untestable.

**A snapshot swapped under the workflow is refused.** The workflow holds what
it started on and compares; an older fingerprint, a lower schema version or a
weakened integrity verdict presented at the trial is refused rather than used.

## What never leaves, and what the audit may hold

No second partition, no host disk, no network, no USB export, no temporary file
— not "just while the migration runs". Asserted as an import allowlist plus the
names that make a call unnecessary (`__builtins__`, `globals`, `vars`, `eval`,
`exec`, `compile`, `__import__`, `open`, `input`), plus a refusal of calls on a
subscript.

**The first version of this paragraph claimed more than the scan did.** It
boasted that a denylist of module names is one `__import__` wide — true, and a
review then walked past *this* scan a different way, with no import statement
at all: `().__class__.__base__.__subclasses__()` to a class whose
`__globals__["__builtins__"]` yields `open`, and a file written to the host
disk with the whole suite green. The chain's attribute names are now denied,
and `getattr` — which had a blanket exemption, and which *was* the hole once
the names are strings — is allowed only in the seal's one shape,
`getattr(self, "_sealed", False)`.

**A static scan is not a proof of absence.** Two have now been defeated here,
each in a way the previous fix did not anticipate. The honest reading is that
the next hole is closed when it is found.

Eight audit classifications. `SnapshotAuditEntry` has five fields — `event`,
`check`, `gate`, `schema_version`, `fingerprint` — and **no** field for
snapshot contents, a byte count, a free-space figure, a capacity, a raw key, a
passphrase, a device identity, a path or an operator identifier.

**The capacity figures never render at all.** `CapacityReport.__repr__` is
`CapacityReport(<redacted>)`, and a test asserts no digit appears in it: those
numbers describe how much medium the operator is carrying and how much of it is
used.

`SnapshotDescriptor` redacts its fingerprint for the same reason, **and so does
`SnapshotAuditEntry`** — which is the object actually destined for a log. The
descriptor's redaction carried the comment that a fingerprint in a repr is one
in every traceback, and the same value then rendered verbatim through the audit
entry's generated repr. A review found it by rendering `repr(workflow.audit())`,
which the absence test had not.

The refusal raised from `_raise_gate_refused` holds **nothing** in its frame —
no gate, no snapshot, no binding, no sitting. The limit `session_mode` states
applies unchanged: the frames above still hold what they were handed, because a
frame cannot forget its own argument.

## What this does not establish

- **No storage act has happened.** No snapshot has been written, no migration
  run, no trial interrupted, no restore attempted, on any device. Whether a
  snapshot fits, whether a trial is atomic against real hardware, and whether a
  restore survives a real interruption are all claims about hardware, and no
  real USB SSD or real laptop has been involved.
- **A recovery cannot complete outside a test.** The real key acquisition and
  the real LUKS unlock do not exist — [ADR-0011](adr/0011-unlock-helper-boundary.md)
  decides their shape and nothing implements it — so no acquisition in this
  repository can return `OPENED`.
- **Nothing is restored and nothing is written.** `RECOVERY_COMPLETED` and
  `SNAPSHOT_WRITTEN` are classifications of what a caller reports, not acts
  this module performed; a candidate says which schema version it *would*
  restore to. `MigrationLedger` used to record `SNAPSHOT_WRITTEN` at permission
  time, before the caller had acted, which is now two methods: `may_migrate`
  answers, `note_snapshot_written` records afterwards.
- **`azazel_boot.snapshot` is imported by nothing in `src/`.** No consumer
  exists for a `RecoveryCandidate`. The central claim is therefore true by
  structure *and* currently by disuse, and the structure is what these tests
  are for — it has to hold when something is finally wired up.
- **The atomicity of a trial is the caller's**, and is not demonstrated here.
  This module decides whether a trial may open and whether a commit may happen;
  what happens to bytes between those two points is performed elsewhere, on a
  device, by code that does not exist.
- **`hardware-unverified`** throughout, and
  [#42](https://github.com/01rabbit/Azazel-Boot/issues/42) cannot be closed as
  verified.
