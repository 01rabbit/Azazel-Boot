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
- **a quarantine may appear only as the receiver of its four reads** —
  `is_fenced`, `volume_is_quarantined`, `medium_is_bound()` and `session_id` —
  or in one of the travels the test names: into this module's own `_require_*`
  checks, into the gate evaluator, into `type(...)`, into the workflow's one
  slot, into an identity comparison, and into the two module-side indexes.
  That is the load-bearing rule, and it replaces a shape match on
  `self._quarantine.<attr>`, which a third review defeated by aliasing the
  quarantine to a local first — `q = self._quarantine; q._audit.clear()` —
  emptying the audit and the dispositions with neither flag moving. The rule
  finds a quarantine **by the name it travels under**, so it is paired with a
  second one: a parameter annotated `Quarantine` is spelled `quarantine`,
  everywhere. `_mint` took one as `judged`, and the live object went into the
  verdict through a parameter the walk was not looking at — a guard keyed on a
  spelling is one rename wide;
- no *call* to `fence`, `quarantine_volume`, `approve_export`, `withdraw_export`
  or `observe`, no assignment to `_fenced` or `_volume_quarantined`, and no
  `object.__setattr__` except on a function's **own first parameter** or on an
  object it constructed in that same function. The exemption used to be by
  parameter *name*, so a module-level `def _settle(self, key, value)`
  inherited it and wrote the flags through it;
- `is_fenced` and `volume_is_quarantined` **are** read, which is the point.

**And none of the above is the claim.** A fourth review made the point that
settles it: the behavioural guard that *did* hold — driving every public method
and comparing the flags before and after — drove them with one fixed
descriptor. A payload reading `if snapshot.schema_version > 1:` then clearing
both flags passed the entire suite, because a schema-1 recovery behaved
perfectly and no test committed a schema-2 one. It also emptied the
`_dispositions` of every other device, deleted `_sealed` so the medium could be
unquarantined by ordinary assignment one line later, and rebound
`Quarantine.__setattr__` process-wide — none of which a comparison of two flags
and one disposition can see.

So the claim now rests on a guard that **varies what it feeds**: both schema
versions, every container version, every integrity verdict, both flag states,
both operator flags and every acquisition outcome, with the **whole** of the
quarantine's state compared before and after — every slot, plus
`Quarantine.__setattr__`'s identity, plus the seal still refusing an ordinary
assignment afterwards. The static rules above remain, and are worth what they
are worth.

A fifth review then rebound `Quarantine.volume_is_quarantined` itself — a
property that answered `False` for chosen instances. No slot moved, the dunder
identities held, the seal still refused an ordinary assignment, and the medium
was out of quarantine for every caller in the process. The class is state too,
so the guard compares the whole of `vars(Quarantine)` by identity, asks every
function and property on it which module it was defined in, and puts the
question to a control instance — an answer that changed is an answer that is
wrong, however it changed. The same review called a permitted-name `__init__`
with the quarantine as its `self`, which the `__setattr__`-call rule never
looked at because the call site's name was `__init__`: no dunder is called
through an attribute now, except `object.__setattr__` in its four functions and
a bare `super().__init__`.

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

`SnapshotDescriptor` and `SnapshotAuditEntry` are not dataclasses — a fourth
field each, a hand-written `__init__` doing what `__post_init__` did, and an
explicit `__eq__`/`__hash__`, for the reason `CapacityReport` gives for
itself: `dataclasses.asdict()` walks `dataclasses.fields()` directly and
bypasses `__getstate__`/`__reduce__` entirely, handing a redacted fingerprint
back in plain sight. Both `__eq__` methods type-check **both** operands before
deciding: one checked only `other`, so a subclass with no `__eq__` of its own
inherited equality that a caller could pass as either argument, and Python
tries the reflected call — `other.__eq__(self)` — when the first returns
`NotImplemented`, which the one-sided check never did. Neither `__eq__` is
what `_require_the_same_snapshot` uses to decide a substitution, below — that
check is a type pin plus a field-by-field comparison on its own terms, not a
call to either class's `__eq__`.

`_require_an_opaque_value`, which every fingerprint and every audited string
passes through, refuses more than a length: `len(value.splitlines()) > 1`
refuses any value `str.splitlines()` would treat as more than one line — form
feeds and Unicode line separators included, not only `\n`/`\r` — because that
is the same boundary a `.splitlines()`-based log viewer would split on. A
value made of several such "lines" joined by a boundary the check does not ask
about would satisfy a narrower check and still render as several lines
wherever the audit is read back.

## Preflight (D7)

Read-only **by construction**: it takes reports and returns a verdict. It has
no port to write through and the module imports nothing that could write, so a
refused migration has written nothing because nothing here writes at all. The
test pins the *shape* — no parameter named for a writer, a port, a store, a
device, a path, a file or a handle — rather than reviewing the body, since a
body-reviewed claim lasts until the body changes.

The order is fixed and is part of the contract — and it is now a **constant**,
`PREFLIGHT_ORDER`, that `preflight` iterates, rather than the order the lines
happen to sit in. A review permuted fourteen of sixteen adjacent pairs and
demotions with the whole suite green. No bad input passed, because the chain
short-circuits and a permutation cannot change the set that passes; what
changed was the **classification** an operator is given, which is what D7
promises. The worst of them: with the first two swapped, an operator whose
medium had been **pulled** was told `volume_quarantined` — a state a recovery
workflow exists for — instead of `medium_fenced`. Rewriting the branches of
`_gate_fails` now changes nothing, and every gate is driven against all of its
successors failing at once.

| # | Check | Why here |
| --- | --- | --- |
| 1 | the fence | D9: a version upgrade is not a way round it, and asking a removed medium about its free space means reasoning about a device that is not there |
| 2 | the volume is not quarantined | D4 stops the whole volume on a suspected torn write, and a migration is a large write to exactly that volume |
| 3 | the snapshot exists | D7's load-bearing rule, before the cheap answers |
| 4 | its container version is known | |
| 5 | its integrity verified | `INDETERMINATE` lands with `FAILED`; ambiguity refuses |
| 6 | required vs available space | |
| 7 | schema compatibility | forward to a version this build knows; a downgrade, a no-op and a version outside the supported set all refuse |
| 8 | binding, generation, image digest | |

A verdict also names **which checks were asked**, in order, passes included.
It used to be `refused_by is None` and nothing else, so a verdict from a
`preflight` that ran three gates was indistinguishable from one that ran all
ten — which is the structural reason the order could be permuted unnoticed.
Complete in the sense `Azazel-Knowledge`'s scorer means it: "not evaluated" and
"passed" are different answers.

**A verdict carries nothing that says it was minted.** It used to carry a
token, and removing the constructor *parameter* left the *read* path untouched:
every verdict a caller was handed, refusals included, had the live sentinel one
attribute access away. Which verdicts this module minted is now a fact the
module keeps in a `WeakSet` the verdict does not point at. A value that is not
on the object cannot be copied off it. The limit stated elsewhere is unchanged:
this module is importable, so this is careless-caller defence and not a
capability boundary.

**One snapshot, one recorded write.** Nothing marked a verdict spent, and a
review recorded four `SNAPSHOT_WRITTEN` classifications across two ledgers from
one judged snapshot. Marking the *verdict* spent was then one `preflight()`
call wide — a preflight is free, read-only and unlimited, so four of them over
one snapshot mint four spendable verdicts — so the ledger also refuses a
snapshot whose write it has already recorded.

**A verdict is not a permission that outlives what it judged.** It carries no
session, no medium, no boot and no clock, and a review minted one over a
healthy volume, fenced the medium, quarantined the volume, and the ledger still
answered and recorded a write — a durable bearer token for a large write to a
volume since judged torn, which is what D9 refuses under the name of an
upgrade. `may_migrate` and `note_snapshot_written` take the quarantine and
re-read it, as the workflow's gates do.

**And it is spent against the medium its own preflight judged**, by identity,
unconditionally: a verdict minted over one medium is not an answer about
another. Which medium that was is a fact the module keeps **beside** the
verdict, in `_JUDGED_BY`, for the reason mintedness is: the first version put
the `Quarantine` on the verdict as `_judged`, which handed `fence()`,
`quarantine_volume()`, the sitting and the boot medium identity to everyone a
verdict was handed — through the object whose own docstring says there is
nothing to read off it. The four values the snapshot had when it was judged are
kept the same way, so a descriptor rewritten in place between the preflight and
the record is refused rather than recorded under a key no preflight produced.

**One medium, one write — and a sitting is not a medium.** The record was keyed
on `(sitting, the snapshot's four values)`, and a `PersistenceSession` holds one
sitting and can hold more than one quarantined medium: two media in one boot
collided, and the second's genuine first write was refused as "a second write
that did not happen". The key is the `Quarantine` object.

**And the ledger asks `evaluated` back.** Reporting which checks ran bought
nothing while nothing consumed it: rebinding `PREFLIGHT_ORDER` produced a
legitimately minted passing verdict, asked one check, over a medium that was
fenced, quarantined and failing its binding. A passing verdict now has to name
all ten, in order, or it is not a pass.

Each failing check refuses with **its own classification**, so an operator
learns which one — and nothing behind it.

**There is no migration without a snapshot**, and it is asserted as an absence
as well as a refusal: `preflight` has no parameter containing `force`,
`accept`, `override`, `without_snapshot`, `degraded` or `emergency`. An
operator cannot consent to it, so there is nothing to consent with.

A refusal **keeps the old schema working**, which is the safe outcome rather
than a degraded one — driven by unlocking on the old schema afterwards.

**One spend rule, and it is the one that can fail.** There were three: the
verdict in a `WeakSet`, the ledger's own list of written values, and the
module-wide record. A review proved the first two unable to fire in front of
the third — a replayed verdict carries the same medium and the same judged
values, so the module-wide record answers first, every time — and the middle
one was worse than dead: keyed on the values with no medium, it refused a
*second medium's* first write inside one ledger, which is the failure the
module-wide key was given a medium to fix. Two guards that could not fire, in
front of one that could, one of which refused a legitimate caller when it did.

**The workflow holds no snapshot object.** It held the caller's descriptor in a
`_snapshot` slot that was written twice and read nowhere — a field whose
presence implies a check that does not exist — and a review moved the commit's
one mint line from `_pinned` to it, committing on a descriptor mutated from
inside the passphrase prompt, minting a candidate for schema 99 and recording a
`recovery_completed` naming it, with no substitution recorded anywhere and the
suite green. The slot is gone rather than compared: what the workflow pins at
the start is a descriptor built from the values read at that moment, in an
object the caller never had a reference to, and there is nothing left to swap
the mint over to.

## Recovery (D8)

Operator-started, one-way, and every stage entered explicitly.

`started_by_operator` is a **required keyword with no default**, and it must be
an actual `bool`. A default of `True` would make the automatic start D8 refuses
the easiest thing to write; a default of `False` would make it a flag somebody
flips; and accepting any truthy object made both moot — a third review reached
`COMMITTED` and minted a candidate with `started_by_operator="no"` and
`confirmed="declined"`. `preflight` had been checking its three flags with the
comment *"a truthy object is not a check"* while the two flags carrying D8's
operator gates were not checked at all. There is no `retry`, no
`resume`, no `auto`, no `background` and no `schedule` anywhere on the surface,
and no `RecoveryStage` member meaning automatic.

```
NOT_STARTED → PREFLIGHT_PASSED → TRIAL_OPEN → COMMITTED
     ↓               ↓               ↓
  REFUSED /      REFUSED /       REFUSED /
 INTERRUPTED    INTERRUPTED     INTERRUPTED
```

Every non-terminal stage reaches either terminal one: a refused automatic start
ends at `REFUSED` from `NOT_STARTED`, and an interruption is available
throughout. An earlier version of this diagram showed `REFUSED` branching only
from `PREFLIGHT_PASSED` and `INTERRUPTED` only from `TRIAL_OPEN`, which was
narrower than the code and than the tests.

A stage the gates lead to is **reached by passing them**. Naming the fields
that move and the edges the stage may travel was not enough: `trial_open →
committed` is a legal edge, and D8's key acquisition and operator confirmation
live inside `commit` rather than in the graph — so a review took the legal edge
from a genuine `TRIAL_OPEN` and minted an accepted candidate for schema 99 with
no acquisition ever constructed and no operator ever asked, on an audit
byte-identical to a real commit. `_require_the_gates` issues a clearance when
every gate has just passed; the next transition spends it. `REFUSED` and
`INTERRUPTED` need none, being what a refusal and an interruption reach.

`COMMITTED`, `REFUSED` and `INTERRUPTED` are **terminal**. There is no call
that restarts a finished workflow, because restarting is a new workflow that
runs every gate again — which is what starting one does.

**The gates run before the trial opens and again before the commit**, not once
at the start — except key acquisition, which runs only at the commit, because
that is where an operator is asked to type. **And the medium *and the snapshot* are read once more after the prompt
returns**: `attempt()` is the only step in this workflow that blocks on a
human, and it is caller-supplied code. The last fence read used to sit before
it, so a medium pulled while the operator typed committed anyway — and when
that was fixed for the flags it was not fixed for the snapshot, so a review
mutated the frozen descriptor from inside the acquisition, reached
`COMMITTED`, and recorded a `recovery_completed` naming a schema version and a
fingerprint no gate had judged. The commit now re-checks the pin there too,
and mints the candidate from `_pinned` — a copy built at `start`, which the
caller never had a reference to — rather than from the argument. A medium can be pulled while an
operator reads a confirmation screen, and a gate checked once is a gate checked
at a moment that has passed. Tests fence the quarantine between the start and
the trial, and again between the trial and the commit, and assert each refuses;
the trial-side recheck was untested until a review deleted it and the suite
stayed green.

The gates, in order — `RecoveryGate` has **eight** members, D8's four with the
four that precede them:

1. **the medium is not fenced** (`MEDIUM_FENCED`)
2. **there is something to recover** (`NOTHING_TO_RECOVER`) — running this over
   a healthy volume would be a restore of live data from a snapshot: the write
   D8 refuses to make automatically, made deliberately over something that was
   fine
3. **the medium is recognised** (`MEDIUM_NOT_RECOGNISED`) — *which medium this
   recovery is for*, and *whose sitting it is*. The quarantine is asked its own
   question, `medium_is_bound()`, which is also `False` after a fence, so no
   device identity crosses into this module. It used to be the **host**
   binding wearing this gate's name: a review committed a whole recovery over a
   quarantine that had never observed any device, and over two different media
   in turn, and the audit said `recovery_completed` for a volume the module
   could not name. The quarantine must also be this sitting's —
   `PersistenceSession` refuses the identical pairing, and this type-checked
   all three inputs and compared none of them. The comparison itself
   (`self._quarantine.session_id != self._session_id`) puts the quarantine's
   own field on the left, where its `__ne__` decides first; a round-fourteen
   review built a genuine `Quarantine`, through its own public constructor,
   whose `session_id` was a `str` subclass answering `False` to every
   `!=`, and reached `COMMITTED` over a quarantine whose honest sitting was
   someone else's. `RecoveryWorkflow.__init__` now pins `quarantine.
   session_id` to exactly `str` where it takes the quarantine, the same way
   it pins `binding`'s two fields — `Quarantine.__init__` itself performs no
   such validation and is tracked separately, out of this file's ownership,
   as [#51](https://github.com/01rabbit/Azazel-Boot/issues/51).
4. **host binding** (`HOST_BINDING`) — `commissioning.binding_applies`,
   re-derived from the supplied inventory rather than re-compared against a
   stored answer, now named for what it answers. `binding_applies` decides it
   with `binding.host_fingerprint == observed and binding.session_id ==
   session_id` — the `SessionBinding`'s own operand on the left of `==` — and
   a round-thirteen review built a genuine `SessionBinding`, through its own
   public constructor, whose `host_fingerprint` was a `str` subclass
   answering `True` to every comparison; it passed the gate for a host the
   real fingerprint never matched. `RecoveryWorkflow.__init__` pins
   `type(binding) is SessionBinding` but had never pinned the *fields inside
   it*, the same gap `_require_an_exact_str` already existed to close for
   every operand this module owns directly. Fixed the same way: `binding.
   host_fingerprint` and `binding.session_id` are now pinned to exactly
   `str` where the binding is received, not merely type-checked as a
   container.
5. **target binding** (`TARGET_BINDING`) — **ADR-0010 D8 gate 1**: ADR-0008
   D4.1.1's key-protected media binding. **Not checked here directly**: it
   needs a `BindingKey`, and key material in a decision module would break the
   rule that the secret never arrives. The check stays in
   `azazel_boot.persistence`; this gate is the caller's re-derived `bool`
   report, `media_binding_holds`, asked again at every stage.
6. **key acquisition** (`KEY_ACQUISITION`) — `session_mode`'s `KeyAcquisition`
   Protocol, reused rather than reimplemented, so what crosses back is the
   same single enum and this module never sees a passphrase. `commit`
   **requires** one: `None` used to skip the gate entirely and leave an audit
   byte-identical to a legitimate commit, so nothing downstream could tell a
   recovery that unlocked the volume from one where nobody was ever prompted
7. **integrity verification** (`INTEGRITY_VERIFICATION`)
8. **operator confirmation** (`OPERATOR_CONFIRMATION`) — `confirmed` grants
   nothing by itself, which the first test in the file drives: the volume is
   still quarantined afterwards, and it is type-checked inside the gates
   themselves, not only at `commit` — a direct call to the gate evaluator used
   to accept a truthy non-bool and take the full clearance without ever asking
   an operator

Each is driven failing on its own to show the next is not reached, and three
adjacent pairs are contested with **both** gates failing at once — target
binding against key acquisition, the host binding against target binding, and
integrity against operator confirmation. Every row of the "each gate with every
later gate also failing" drive passed `media_binding_holds=True`, so the gate
that reads it was contested against nothing and three reorderings shipped green.
A binding from another machine refuses with the acquisition **never invoked**.

**Reaching the gates is reaching all of them, and reaching their inputs too.**
`_require_the_gates` is a bound method at the same reach as `_sealed_assign`,
and a review called it directly with `acquisition=None` to take a clearance
without D8's gates 2 and 4. Both are required arguments now, where `None` means
"this stage does not ask it" rather than "skip it", and the clearance says
*which* set passed: only a run that asked an acquisition **and** a confirmation
issues the one a commit spends. The rest of the inputs were still the caller's,
though — the snapshot the integrity gate reads, the observations the host
binding is derived from, the sitting, and the snapshot this workflow pinned —
so those are checked inside the gates as well, not only at the three entrances
a direct call does not use.

**A clearance is spent over the medium the gates read.** It said the gates
passed and nothing about *when*: a review passed them, fenced the medium, and
then moved the stage, arriving at a stage reached over a medium that was fenced
at every instant after the read. The fence is re-read at the moment the
clearance is spent. The volume quarantine is not, and the reason is written
down: `quarantine_volume()` is one-way, the gates refuse unless it is already
on, and the quarantine itself cannot be swapped — so that branch is one nothing
could drive, and a branch nothing can drive is not a check.

That read happens **twice, in two vocabularies**. Each stage method asks it as
a gate, so what a caller meets is `GATE_REFUSED` with `medium_fenced` in the
audit; the seal keeps its own rule as the structural backstop for a direct
`_sealed_assign`. The seal's own recheck used to answer a bare
`AttributeError` there — a seal's answer, outside the `RecoveryRefused`
vocabulary a caller writes `except` for — and the fence is raised by device
monitoring rather than by any call here, so a legitimate stage move can meet
it. A round-ten review drove exactly that window (a fence landing between
`commit`'s own gate check and the mint) and reached the crash; the fix has
`_sealed_assign`'s internal recheck call `_refuse_gate` directly rather than
raise, recursing once into a stage move — `REFUSED` — that the fence branch
does not re-enter, so no `try`/`except` was needed for it either. The same
shape was fixed once already, for an interruption raised from inside
`attempt()`.

**A candidate is held by a workflow that committed**, asked by stage as well as
by identity. `commit` writes the candidate and then moves the stage, and
anything raising between those two writes left a workflow stuck at `TRIAL_OPEN`
answering `True` for a candidate no commit finished. The fence check sits
before the mint for the same reason.

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

**A snapshot swapped under the workflow is refused**, at the trial and at the
commit, and the refusal is terminal and audited. The workflow type-checks the
descriptor **exactly** and compares it **field by field**: it used to accept
any object and compare with `!=`, so a third review passed a stand-in with
three class attributes — satisfying both integrity gates — whose `__eq__`
returned `True`, and walked straight through the check this module calls "the
substitution this whole design exists to notice", committing on a substitute
with no `RECOVERY_SNAPSHOT_SUBSTITUTED` recorded.

An older fingerprint, a lower schema version or a weakened integrity verdict
presented at either stage is refused rather than used.

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

**A static scan is not a proof of absence.** Three have now been defeated here,
each in a way the previous fix did not anticipate — most recently `locals()`,
which at module level *is* the module dict, into which CPython puts
`__builtins__`, reached with no import, no subscript, no `getattr` and no
`except`, and with the spelling assembled from fragments the scan never reads.

Four things follow, and only the last two are claims. The name rule is no longer a
denylist: **every free name the module reads is listed, and the assertion is
equality**, so a builtin that is not one of the seventeen is unreachable by any
spelling. And the question is asked of the runtime instead — the workflow is
driven end to end under `sys.addaudithook`, which cannot be removed once
installed, and the assertion is that **no audited operation happens at all**,
whatever it was spelled. That also covers what this module *calls*: the same
escape placed in `azazel_boot.quarantine`, whose `is_fenced` every gate reads,
left the suite green, because a per-file scan is not a bound on anything but
its own file.

The fifth review broke both of those too, and the fixes are the same shape
again. The import allowlist was by module *root*, so `from .inventory import
Path` — root `inventory`, already allowed — re-exported `pathlib` and wrote to
the host filesystem **at import time**, which the hook never saw because it was
installed afterwards. So the imported **names** are listed and asserted by
equality, and the hook goes on before the module is imported, with an allowlist
of what the interpreter's own import machinery does and bytecode writing off.
And the drive held `binding_holds`, the capacity and `current_schema` at their
passing values, so a write on the binding branch never ran under the hook: the
drive varies them now. The limit of the runtime check, stated and unchanged:
it covers the paths that drive reaches — and a fifth review showed what that
costs when the drive is careless. A `fenced = build(); fenced.fence()` sat in
it and was handed to nothing, so `is_fenced` answered `False` on every read
under the hook and `volume_is_quarantined` answered `True`; the same escape
placed on either unreached branch of `azazel_boot.quarantine` wrote a
boot-medium identity to the host disk with the suite green, twice. The drive
builds all four flag states now. A dead variable is not coverage.

Nine audit classifications. `SnapshotAuditEntry` has five fields — `event`,
`check`, `gate`, `schema_version`, `fingerprint` — and **no** field for
snapshot contents, a byte count, a free-space figure, a capacity, a raw key, a
passphrase, a device identity, a path or an operator identifier.

**This module never renders the capacity figures.** `CapacityReport.__repr__`
is `CapacityReport(<redacted>)`, a test asserts no digit appears in it, and no
audit entry, refusal message or verdict carries one: those numbers describe how
much medium the operator is carrying and how much of it is used. What that does
**not** say is that the numbers are gone. The caller measured them, passed them
in and still holds them, and they are still on the object it built — reading
`report._available` renders one perfectly well. The claim is about what this
module puts into a log, a screen and a traceback, which is the place the
figures would otherwise reach; it is not a secrecy property of the object.

`SnapshotDescriptor` redacts its fingerprint for the same reason, **and so does
`SnapshotAuditEntry`** — which is the object actually destined for a log. The
descriptor's redaction carried the comment that a fingerprint in a repr is one
in every traceback, and the same value then rendered verbatim through the audit
entry's generated repr. A review found it by rendering `repr(workflow.audit())`,
which the absence test had not.

**The same fourth limit `azazel_boot.quarantine` states applies here.** A
`__setattr__` stops an attribute being rebound; it does not stop the object it
points at being mutated, and both `RecoveryWorkflow` and `MigrationLedger`
hold their audits in plain lists. `flow._audit.clear()` erases the record of a
recovery while the candidate still applies. That is the same reach as
`object.__setattr__`, and the same answer: careless-caller defence, not a
capability boundary.

It extends to this module's own globals. `_SNAPSHOTS_RECORDED` is what makes a
write recordable once, and clearing it makes one recordable again — a container
write by anything holding the module, no hook involved. The seals have one more
door than they used to: `__delattr__` refuses `del x._sealed`, which was
cheaper than everything built on top of it and let a plain assignment write a
stage, a candidate, a quarantine and a sitting onto a workflow, reaching
`COMMITTED` with a forged candidate and an empty audit.

**`_JUDGED_BY` and `_SNAPSHOTS_RECORDED` hold a live `Quarantine` for the life
of the process**, and each is a two-round history of the same lesson landing
somewhere new. They were `WeakKeyDictionary` instances keyed by the medium; a
round-ten review called the entirely ordinary `.keys()` and got back every
medium any preflight had judged, live, through the exact container chosen to
avoid handing one back. The fix, `_WeakIdentityIndex`, keys its store by
`id(obj)` instead — an opaque integer with no path back, a weak reference kept
alongside each value purely to verify identity and close the id-reuse hazard a
bare `id()` key would reopen — and exposes no `.keys()`, `.values()`,
`.items()` or `__iter__` at all. A round-eleven review found that public
surface was not the whole of the reach: `gc.get_referents(idx)`, stdlib, no
private name in the call, walks an object's own `__slots__` and hands back
whatever they hold — the live `(weakref, value)` dict itself, for
`__slots__ = ("_by_id",)`. One call recovered every judged medium the same way
`.keys()` had. The fix moves the store off the instance: `__slots__` now holds
only `__weakref__`, and the dict lives in a module-level `_INDEX_STORAGE`,
keyed by the index itself. `gc.get_referents` on an index now yields only its
type, and — since there is no such slot any more — an ordinary
`idx._by_id = …` and even `object.__setattr__(idx, "_by_id", …)` both raise
`AttributeError` rather than rebind anything. Reaching `_INDEX_STORAGE` by its
own name, or by walking this module's `__dict__`, is the same disclosed
"careless-caller defence, not a capability boundary" limit as `_MINTED_HERE`
two paragraphs up — not a new one, and not what either review found.

**A round-twelve review found the limit underneath that one, which no rename
reaches.** `gc.get_objects()` is a full heap walk and needs no name at all:
filtering it by `isinstance(x, weakref.WeakKeyDictionary)` finds
`_INDEX_STORAGE` directly, with no `import azazel_boot.snapshot` anywhere in
the attacking code. It is not even the shortest route — `weakref.ref`
instances are themselves walked by `gc.get_objects()`, and a live
`Quarantine` is a member of it in its *own* right: `[o for o in gc.
get_objects() if type(o).__name__ == "Quarantine"]` finds one with no weak
reference, no index, and nothing of this module in the chain at all. Moving
where `_WeakIdentityIndex` keeps its store cannot close this, because what
is found is never the store — it is any live object in the same OS process,
which `gc` exists to enumerate regardless of what holds it. This is not a
gap in `_WeakIdentityIndex`, and no further redesign of it would close
anything: the class's claim is narrowed to what a call to *this module's
own surface* — a method, a return value, an exception, a repr, a log line —
can hand back to a caller who does not already hold the object, which
remains true. It was never, and could not have been, a claim that a
`Quarantine` is hidden from other code sharing the interpreter; nothing
running inside one OS process can hide a live object's existence from `gc`
in that same process.

**"Once" counts judged snapshots, not write operations.** `may_migrate` is a
question and answers it as often as it is asked; `note_snapshot_written`
records once per `(medium, judged values)`. A caller that performs several
writes under one verdict gets one record, because one preflight judged one
snapshot — the contract is one write per judged snapshot, and this module
cannot see how many the caller actually made.

The refusal raised from `_raise_gate_refused` holds **nothing** in its frame —
no gate, no snapshot, no binding, no sitting. A stage asked for another
sitting is now **terminal and audited** (`recovery_foreign_sitting`) on the
module's own principle that a swap is an event rather than a typo — it used to
raise and leave the workflow untouched, so a foreign sitting could probe a live
`TRIAL_OPEN` workflow as often as it liked with nothing recording that it had.
`interrupt` takes a `session_id` like every other stage; it was the one
exempt, so any holder of the object could end a workflow mid-flight. The limit `session_mode` states
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
