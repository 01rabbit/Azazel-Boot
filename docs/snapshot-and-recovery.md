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

`SnapshotDescriptor` (four fields) and `SnapshotAuditEntry` (five fields) are
not dataclasses — a hand-written `__init__` doing what `__post_init__` did,
and an explicit `__eq__`/`__hash__`, for the reason `CapacityReport` gives for
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

**Not every dangerous byte is a line boundary.** A round-31 security review
pointed out that `ESC` (`\x1b`) is neither a forbidden character in
`_require_an_opaque_value`'s existing checks nor a `str.splitlines()`
boundary, so a fingerprint carrying raw ANSI/OSC terminal escape
sequences — cursor movement, conceal/colour codes, an OSC window-title or
clipboard-write sequence — passed the check unchanged, as a single "line",
and reached the one property this module deliberately leaves
unredacted: `fingerprint`, on both `SnapshotDescriptor` and
`SnapshotAuditEntry` (the latter is the object actually destined for a
log). Closed with `unicodedata.category` rather than enumerating escape
sequences by pattern — the same "checkable shape, not a guarantee about
meaning" framing the rest of the function already uses: category `Cc` is
the C0/C1 control bytes (`ESC` and the bytes every ANSI/OSC sequence is
built from), `Cf` is the invisible format characters (bidi overrides,
zero-width joiners) a spoofed or reordered-looking log line could be built
from the same way. A round-32 review found the fix itself was correctly
wired into every rendering path but undriven by any test — every existing
rejected case in `test_a_fingerprint_is_an_opaque_token_and_not_a_rendered_record`
was plain text, so a regression silently dropping the check would have
passed unnoticed. Closed the same way earlier gaps in that same test were
isolated: one case built from nothing but an ESC-led OSC sequence.

**ASCII is not the only way to spell a forbidden character.** A round-35
security review passed two values through unchanged: one joined by
IDEOGRAPHIC SPACE (`Zs`, not the literal `" "` already forbidden and not
`Cc`/`Cf` either) instead of an ordinary space, which an ordinary
`str.split()` still tokenized into the same discrete fields a rendered
record would; and one built from fullwidth compatibility variants of `=`
and `/` plus that same ideographic space, which
`unicodedata.normalize("NFKC", ...)` — an ordinary defensive normalization
step — turned back into exactly the `"capacity=17179869184
medium=usb-SN-AA11BB22 host=/dev/nvme0n1p3"` string this function's own
history names as the original finding. Closed two ways: `Zs` joined
`Cc`/`Cf` in the category check, since it is the general case the literal
`" "` check was only a specific instance of; and a value whose
NFKC-normalized form differs from itself is refused outright — a bound an
opaque token (akin to a hex digest) can afford that free text could not.
Each check was mutation-tested in isolation from the other: OGHAM SPACE
MARK (one of the only two `Zs` characters NFKC itself leaves unchanged)
isolates the category check, and a fullwidth-digit value isolates the NFKC
check, the same way earlier rounds isolated `"="` from space/slash.

**NFKC-stability is not NFD-stability.** A round-36 security review found
one character — `≠`, NOT EQUAL TO (U+2260) — that is `Sm`, not a forbidden
literal, and NFKC-stable, but whose canonical decomposition (what NFD and
NFKD use, not NFC/NFKC) is a literal `=` plus a combining overlay. It
passed every check above unchanged; normalising it with NFD reconstructs
the literal `=`, the same shape the round-11 `"generation=17"` case exists
to refuse. A brute-force sweep of every codepoint found `≠` to be the only
one with this exact shape, and found no codepoint that is NFKC-stable but
NFC-unstable — so checking NFD in addition to NFKC closes the whole
family without needing all four normal forms: NFC-stability already
follows from NFKC-stability, and an NFKD-only (compatibility-only)
decomposition is caught by the **NFKC** check itself, not the NFD one —
NFKC performs the same compatibility decomposition NFKD does, before
recomposing, and the brute force found no codepoint where that
recomposition restores stability while the decomposition it undid was
dangerous. (A round-37 doctrine review corrected this paragraph: an
earlier version credited NFD with catching NFKD-only decompositions
"because NFD is a strict subset of what NFKD decomposes" — true as a
general fact, but backwards as a mechanism, since NFD being a *subset* of
NFKD means NFD provably does **not** see everything NFKD does; U+00B2
SUPERSCRIPT TWO is NFD-stable and NFKD/NFKC-unstable, the exact shape
that reasoning should have ruled out rather than explained.) The same
review found lone surrogates (`Cs`) pass every check unchanged — not a
tokenization bypass, but ill-formed text a strict-UTF-8 downstream
consumer cannot serialise, breaking the "opaque token" contract a
different way. `Cs` joined the category tuple for the same reason `Zs`
did: the general case a specific instance was never asked to cover.

**Marks are the other mechanism for changing how a neighbouring character
renders.** A round-37 security review found that combining marks
(`Mn`/`Mc`/`Me`) passed every check unchanged, with or without a base
character: a base-less run attaches visually to whatever precedes it
wherever the value is rendered — the audit's own `=` delimiter, or an
adjacent field — and a full-length run produces "Zalgo" visual corruption.
The same family of concern round 31 closed with `Cf` for bidi
overrides and zero-width joiners, for Unicode's other rendering-only
mechanism. `Mn`/`Mc`/`Me` joined the category tuple for the same reason
`Cf` did.

**A third rendering-only mechanism, the same shape again.** A round-38
security review found the five `Emoji_Modifier` codepoints (U+1F3FB
through U+1F3FF, the Fitzpatrick skin-tone modifiers — category `Sk`)
pass every check unchanged too: following an `Emoji_Modifier_Base`
character, one of these forms a single extended grapheme cluster that
renders as one glyph with a chosen skin tone — narrower than the
combining-mark case (a fixed, Unicode-defined set of base characters, not
arbitrary neighbouring text), but the same "not really an opaque token"
violation. `Sk` joined the category tuple for the same reason `Mn`/`Mc`/
`Me` did.

**A different mechanism from every prior fix: confusables.** Every earlier
fix in this function closes a Unicode *equivalence* — a character that is
itself a control/format/space/mark/modifier, or that normalises to a
forbidden literal. A round-39 security review found a sixth mechanism with
no equivalence relationship at all: ordinary `Sm`/`So` mathematical-symbol
codepoints that render as a near-identical glyph to `/`, `\` or `=` in an
ordinary font, but that `unicodedata.normalize` leaves untouched, because
there is nothing to normalise — they are unrelated codepoints, not
decomposed or compatibility forms of the ASCII original. U+2215 DIVISION
SLASH in place of `/` passed every check and reconstructed exactly the "a
path... is not one" disclosure this function's own history names as its
founding case. No category-wide fix exists here — `Sm`/`So` are vast,
ordinary-content categories, unlike `Cf`/`Mn`/`Sk` — so this is closed with
a named, bounded denylist (`_CONFUSABLE_DELIMITERS`) instead, the same
"narrows, does not guarantee" trade-off `KNOWN_CONTAINER_VERSIONS` already
makes.

**"Named, bounded" is exactly as incomplete as it sounds.** A round-40
security review found two more instances the same mechanism reaches: VERY
HEAVY SOLIDUS and VERY HEAVY REVERSE SOLIDUS (the Ornamental Dingbats
block's own "Heavy" glyphs, outside round 39's search scope, the same
undecorated family as the already-listed HEAVY EQUALS SIGN), and BRAILLE
PATTERN BLANK — a Braille cell with no dots raised, a well-known
real-world "invisible space" character, confusable with the space literal
rather than slash/backslash/equals, `So` rather than `Zs`, and just as
NFKC/NFD-stable and decomposition-unrelated as every other confusable in
this set. Both closed the same way: named entries added to
`_CONFUSABLE_DELIMITERS`, not a new mechanism.

**Round 41 found the denylist itself had a gap — a pair added half-complete
— and a coverage gap in what tested it, independently of each other.** A
round-41 security review noticed round 39 had named BIG SOLIDUS (U+29F8,
confusable with `/`) but never its immediate sibling in the same block, BIG
REVERSE SOLIDUS (U+29F9, confusable with `\`) — even though round 40 had
added the analogous VERY HEAVY SOLIDUS/VERY HEAVY REVERSE SOLIDUS pair
*complete*. `"C:⧹Users⧹admin⧹.ssh⧹id_rsa"` reconstructed a Windows-style
path with the missing half alone. Closed the same way as every entry
before it: the missing half added to `_CONFUSABLE_DELIMITERS`. A
round-41 test-suite review, working independently on its own copy, found
that the set — twelve entries after the security fix above — had only ever
been exercised by five of them; FRACTION SLASH, SET MINUS, MATHEMATICAL
RISING DIAGONAL and MATHEMATICAL FALLING DIAGONAL had no driving test
anywhere in the file, and deleting all four from the set left the whole
suite green. Both fixes were produced independently in separate isolated
copies, verified not to conflict, and merged together; each was
mutation-tested on its own after merging (deleting the newly-added entry
or the newly-tested entries and confirming the corresponding new test
case, and only that case, fails).

**Round 42, security: another block, not another literal.** Every
confusable named through round 41 came from a symbol block (Mathematical
Operators, Miscellaneous Symbols and Arrows, Ornamental Dingbats,
Miscellaneous Mathematical Symbols-B). Box Drawing (U+2500–U+257F) is a
different block with its own diagonal pair — U+2571/U+2572 — in ordinary
use as ASCII-art slash/backslash stand-ins, arguably a more plausible
bypass than the lower-frequency glyphs already listed. Closed the same
way: two more named entries.

**Round 42, test-suite: the same "sealed backstop reached one call-frame
later" shape round 39/40 found, recurring a third time.** `open_trial()`
and `commit()` each re-asked `_require_this_sitting(session_id)` and
`_require_the_same_snapshot(snapshot)` immediately before calling
`_require_the_gates(...)`, which itself asks the identical two,
unconditionally, at its own top. `self._session_id` and `self._pinned`
are each written exactly once (at construction and at `start()`
respectively) and never again, so nothing between the outer call and the
inner one can make them disagree — unlike `_require_the_gates`'s other
duplicated inputs (the snapshot/observation *type* checks), which its own
docstring keeps deliberately doubled as a defence against a *direct* call
to `_require_the_gates` bypassing the three entrances entirely (the
round-14 finding). That rationale never applied to these two, since they
only ever ran on the entrance path itself. Removed from both methods,
mutation-tested by deleting both lines from each and confirming the full
suite — including the foreign-sitting and snapshot-substitution tests
parametrised over every stage — stays green with the identical
`Refusal`, stage and audit event returned either way. This is unrelated
to `commit()`'s *second* `_require_the_same_snapshot` re-check, a few
lines further down, which guards the genuine gap `attempt()`'s wait
opens and was untouched.

**Round 42, doctrine and test-suite, independently: round 41's own
coverage-gap fix miscounted by two.** "Exercised by five, four more
added" is nine, not the twelve the set held at the time. BIG SOLIDUS
(U+29F8) and REVERSE SOLIDUS OPERATOR (U+29F5), both named by round 39,
had no driving test anywhere — plausibly missed because round 41's own
new case for the *sibling* entry, BIG REVERSE SOLIDUS, names "BIG
SOLIDUS" in its comment while building a string confusable with `\`, not
`/`. Both were already correctly refused — a coverage gap, not a live
bypass — closed with two more isolated cases, produced independently by
the test-suite review (which wrote the fix) and the doctrine review
(which found the same arithmetic error and recommended the identical
fix without touching test code, per its own remit).

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
| 8 | binding, generation, image digest | re-asks, before a migration's write, ADR-0008 D4.1.1 elements D8 gate 1 re-asks before a recovery's write — undisclosed in D7's own four-item text; whether it is really the *same* shape D8 gate 1 asks is itself unverified (round 34); see ADR-0010's "four further facts" note and the D8 gate-1 entry below |

**Check 7's own function is now guarded on its own terms, not only by its one
caller's.** `schema_is_compatible(*, current, target)` is public and
independently importable, and its body compared both operands with `in`/`>` —
the exact caller-controlled-operand shape this file guards against everywhere
else. `preflight()` already pins `current_schema`/`target_schema` to exactly
`int` before ever reaching it, so no path through this file was ever exposed —
but a round-28 security review built an object whose `__eq__`/`__gt__` both
always answer favorably and found this was the one function left that would
still walk past it, were a future caller ever to reach it directly. Pinned the
same way as every other numeric boundary in the file.

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
   report, `media_binding_holds`, asked again at every stage. D7's own
   `binding`/`generation`/`image digest` row (table above) is often described
   as asking "the same" ADR-0008 D4.1.1 elements as this gate — a round-34
   review found that claim unverified rather than false: this gate is one
   opaque bool over all five bound elements, deliberately, to avoid becoming
   an oracle over which element failed, while D7's three are independently
   settable, and no caller-side implementation of D7's three exists in this
   repository to say which shape they actually are. See ADR-0010's fourth
   further fact.
6. **key acquisition** (`KEY_ACQUISITION`) — `session_mode`'s `KeyAcquisition`
   Protocol, reused rather than reimplemented, so what crosses back is the
   same single enum and this module never sees a passphrase. `commit`
   **requires** one: `None` used to skip the gate entirely and leave an audit
   byte-identical to a legitimate commit, so nothing downstream could tell a
   recovery that unlocked the volume from one where nobody was ever prompted
7. **integrity verification** (`INTEGRITY_VERIFICATION`) — one gate for two
   facts: an unverified snapshot and an unrecognised container version both
   refuse under this same name, where D7's preflight keeps them as two
   separate `PreflightCheck` members. D8 has eight gates, not ten, and does
   not split this one further; an operator told `INTEGRITY_VERIFICATION`
   at recovery time cannot tell which of the two it was without the
   preflight's own, earlier classification.
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

**And that gap between the two writes is real, not only theoretical.** Every
re-check named above closes a *single-threaded* reentrancy window — caller
code invoked back from inside this module, such as `attempt()`. A
round-seventeen review found a different one: nothing single-threaded runs
between `commit`'s two final writes at all, so the only way into that gap is
a genuine second OS thread — an `interrupt()` call racing a `commit()` in
progress on the same `RecoveryWorkflow`, plausible for this module's own
documented domain (an operator screen, a device-pull handler, both acting on
one workflow object). Landing there moved `_stage` to `INTERRUPTED` first,
and `commit`'s own final `_sealed_assign` then met the seal's terminal-stage
guard and raised a bare `AttributeError` — the same "outside `RecoveryRefused`"
shape every other re-check in this section exists to close, reopened for the
one window none of them reach. Round seventeen closed it with a
`_require_stage(TRIAL_OPEN)` re-check immediately before that last write.

**A round-eighteen review proved a re-check of that shape can never fully
close the gap, and found three more instances of it.** A re-check and the
write it guards are still two separate statements, so the identical race
just re-opens one call-frame narrower, forever — reproduced directly against
round seventeen's own fix. The same shape exists wherever this module writes
`_stage` or `_candidate` without a lock around the read-then-write: `commit`'s
candidate write (one statement earlier than the gap round seventeen closed),
`start`'s and `open_trial`'s own stage writes, and `interrupt` racing a second,
equally legitimate call to itself. All four are closed by one change instead
of four narrower re-checks: `_sealed_assign`'s own terminal-stage guard now
answers `RecoveryRefused(WORKFLOW_ALREADY_FINISHED)` rather than a bare
`AttributeError`, at the one place every one of these writes passes through
regardless of how many statements precede it. Round seventeen's re-check is
removed rather than kept alongside the general fix — a guard that cannot fail
is not a guard.

**And that claim — "no write these races contest is ever returned to a
caller" — was itself wrong, for the one pairing round eighteen never
considered: two calls to the *same* method, both legitimate.** Round
eighteen's fix answers a *losing* thread's write correctly; it says nothing
about whether two winners can exist. A round-nineteen review drove two
genuinely concurrent, entirely legitimate `commit()` calls on one
`TRIAL_OPEN` workflow — no `interrupt()`, no hostile input — and got a real
double commit: both calls returned, each with its own honestly minted
`RecoveryCandidate`, and the audit held two `RECOVERY_COMPLETED` entries for
a workflow whose whole design is one-way and audited exactly once. Worse,
one of the two legitimately *returned* candidates then failed `holds()`,
because the other thread's write landed on top of it after the first had
already read its own value back to return. This is not the "wrong
exception type" class round eighteen closes; the race itself, not merely
which vocabulary a loser meets, needed closing. Every `RecoveryWorkflow`
now holds a per-instance `_lock` (a `threading.RLock`, reentrant because
`_refuse_gate` calls back into `_sealed_assign` on the same thread while
`start`/`open_trial` still hold the lock for their own whole body) for the
whole body of `start`, `open_trial`, `interrupt` and `_sealed_assign`
itself, and for all of `commit` except one call — see below. `attempt()`
calling back into `interrupt()` is not an instance of this reentrancy: by
the time `attempt()` runs, `commit` has already released the lock (see
below), so that `interrupt()` call is an ordinary acquisition of a lock
nobody is holding — it would succeed even with a plain, non-reentrant
`Lock`. No second call on the
same workflow — this method or a different one, `interrupt` racing in
included — can begin while the lock is held, so there is no window left
for either to observe state the other is mid-write on. `_sealed_assign`
takes the *same* `self._lock`, not a different one and not none: a caller
who reaches it directly does not bypass the lock, only the business-logic
checks (`_require_stage`, `_require_this_sitting`, and the rest) the
public methods run before ever calling it — round eighteen's fix inside
`_sealed_assign` is the backstop for *that* reach, the same one this
module has never claimed a capability boundary against, only "the
accidental reach". (A round-twenty doctrine review caught an earlier draft
of this paragraph, and the matching source comment, saying "bypassing the
lock" — both were wrong the same way, and are corrected here.)

**A round-seven re-check survived 32 rounds after the fix that made it
redundant, and a round-39 review found it.** Before the candidate write
above, `commit()` re-checks the same snapshot and — until this round — the
stage, added in round 7 so an `attempt()`-triggered interruption raised
`WORKFLOW_ALREADY_FINISHED` rather than the seal's bare `AttributeError`.
From `TRIAL_OPEN`, `_STAGE_EDGES` only reaches a terminal stage, so by the
time that re-check ran, the workflow was either still `TRIAL_OPEN` or
already terminal — and every statement between it and the candidate write
already has an identical backstop: `_require_an_unfenced_medium()` refuses
through `_refuse_gate`, which at the time carried its own terminal-stage
guard (originally built, per its own docstring, for exactly the rows this
re-check did *not* cover — round 40 later found that guard itself
redundant too, see below), and the candidate write itself goes through
`_sealed_assign`'s own guard. A mutation deleting the re-check passed the
whole suite. A test built specifically to distinguish it — racing a fence
and an interruption together, to reach `_refuse_gate` with a different
classification available — still answered `WORKFLOW_ALREADY_FINISHED`,
confirming the redundancy is total rather than a common-case coincidence.
Removed, the same way round eighteen removed its sibling one write later:
a guard that cannot fail is not a guard.

**The same shape recurred one call-frame deeper, and a round-40 review
found two more instances.** `_refuse_gate`'s own `if self._stage in
TERMINAL_STAGES:` guard — the very one the paragraph above leaned on as
`commit()`'s backstop — turned out to be exactly as redundant with
`_sealed_assign`'s guard as the re-check round 39 removed. `_refuse_gate`
calls `self._sealed_assign("_stage", RecoveryStage.REFUSED)`
unconditionally, with no statement between here and there, under the same
reentrant `self._lock` — one uninterrupted critical section, not two
separate reads a race could land between. Verified across all roughly
fifteen call sites into `_refuse_gate` (direct and via
`_require_an_unfenced_medium`), and confirmed by a new test that races an
interruption against `OPERATOR_CONFIRMATION` specifically — a gate
`_require_the_gates` refuses from inside itself, not through
`_require_an_unfenced_medium` — rather than only the `MEDIUM_FENCED` gate
round 39's own race test happened to exercise; both land on
`WORKFLOW_ALREADY_FINISHED` either way. Removed, with the same doctrine
comment discipline as round 39's removal: a guard that cannot fail is not
a guard, one call-frame later.

`interrupt()`'s own top-of-function `if self._stage in TERMINAL_STAGES:`
check was the third instance, and redundant for a different, more subtle
reason than the other two: not a shared critical section, but
`_require_this_sitting`'s write-then-raise shape. A same-sitting caller on
an already-terminal workflow falls through `_require_this_sitting`
untouched and meets `_sealed_assign`'s own terminal guard on the write
below instead. A foreign-sitting caller meets the identical guard one
statement earlier still, inside `_require_this_sitting` itself, before its
own `NOT_THIS_SITTING` raise — `_require_this_sitting` calls
`_sealed_assign` and only then raises, so the terminal guard is reached,
and refused, before `NOT_THIS_SITTING` ever fires. Every row lands on
`WORKFLOW_ALREADY_FINISHED` either way, same-sitting or foreign. A new test
covers the foreign-sitting case specifically — the row `interrupt()`'s
removed check and `_require_this_sitting`'s own guard could in principle
have disagreed on, and don't. Both new tests were mutation-tested against
`_sealed_assign`'s own guard (the real backstop underneath all three
instances) and fail correctly when it, rather than the already-removed
checks, is deleted — confirming they anchor to the invariant that remains,
not to the ones removed. A doctrine review independently re-derived both
redundancy proofs from `_STAGE_EDGES` and the call graph, not trusting the
test-suite reviewer's own reasoning, and found no third error the way
round 37 found a second one in round 36's work.

**`commit` does not hold `self._lock` across its call into
`_require_the_gates`, and a round-twenty review is why.** `_require_the_
gates` is where `acquisition.attempt()` lives — "the one step in this
workflow that blocks on a human." Holding `self._lock` across a
human-speed wait turns an operator screen into a lock an unrelated
`interrupt()` call queues behind, and a round-twenty security review built
a genuine circular wait out of exactly that: a device-pull handler that
calls `interrupt()` first, to record the interruption before tearing
anything down, and only afterwards releases whatever `attempt()` was
blocked on. `commit()`'s thread sits inside `attempt()` holding the lock,
waiting for a signal that only arrives after `interrupt()` returns;
`interrupt()`'s thread sits blocked on the lock `commit()` holds. Neither
moves. `commit` now releases the lock before calling `_require_the_gates`
and reacquires it only afterward, for the mint and the two final writes.
This does not reopen the double-commit race above: gates 1-4 only read the
quarantine, the binding and the sitting — none of which `self._lock` ever
protected (`Quarantine.fence()` is that object's own method, called from
device monitoring, entirely outside this lock) — and `_require_the_gates`'s
one write, `_cleared`, is the same sentinel for identical inputs
regardless of which of two racing threads' writes lands, so two threads
disagreeing about it is not a shape that can occur. What can genuinely
change while the lock is released — the snapshot, the stage — is exactly
what the "again, after the prompt" re-checks immediately after
`_require_the_gates` returns exist to catch, the same pattern round 7
built for the single-threaded case this reopens nothing in.

**A sibling of the same shape existed one step upstream, in
`_remember_the_medium`** (called from every `preflight()`, which this
document calls "free, read-only and unlimited" — an explicit invitation to
call it as often and as concurrently as a caller likes). Its own
check-then-record over `_JUDGED_BY` — "has this medium been judged before;
if not, start a fresh record" — had the identical unlocked shape
`_SNAPSHOTS_RECORDED`'s did before round eighteen. Two real threads
preflighting the *same* medium concurrently, the first time it is judged,
could each see no prior record, each build their own, and the second write
silently discard the first thread's verdict from the index — not from
`_MINTED_HERE`, so `verdict_was_minted_here` still answers correctly for
it, but `_medium_was_judged` then answers falsely for a verdict that
genuinely did judge this exact medium, and `may_migrate`/
`note_snapshot_written` refuse it with `MEDIUM_MOVED_SINCE_THE_PREFLIGHT` —
fails closed, since nothing illegitimate is ever granted, but still a real
misclassification of the kind D7's checks exist to get right. Fixed the
same way: `_JUDGED_LOCK`, a lock of its own rather than sharing
`_WRITE_LOCK`, since the two guard independent state reached from
independent call paths and sharing one lock would serialise two unrelated
operations against each other for no reason this module's state needs.

**Both locks' own two-thread race tests had a coverage gap only found in
round 30, and closed the same way round 21 closed the identical gap for
`RecoveryWorkflow._lock`.** A mutant that keeps the lock but narrows it —
covering only the `.get()` read, releasing before the write that
follows — reopens the exact TOCTOU each lock exists to close, one
statement later. The two-thread race tests could not see it: their second
thread stays blocked acquiring the still-present (just narrower) lock for
its whole grace period, never getting the chance to interleave with the
first thread's now-unprotected tail, so the outcome the race test checks
comes out identical either way. Closed by asking the question directly
instead of racing for it — the `_CountingRLock` technique — swapping each
module-level lock for a release-counting wrapper.

**Round 30's own first version of that technique did not reach far enough,
and a round-31 doctrine review found the gap.** It recorded a checkpoint
from inside `_WeakIdentityIndex.__setitem__`, on the theory that this was
"the write." But `__setitem__` fires when the index entry is first created
(`_SNAPSHOTS_RECORDED[quarantine] = written` / `_JUDGED_BY[quarantine] =
judged`) — one statement *before* the mutation the lock actually exists to
protect (`written.append(fields)` / `judged.add(verdict)` plus
`_JUDGED_SOMETHING.add(verdict)`). A mutant that narrows the lock to
release right after that assignment, leaving the append/add itself
unprotected, satisfied round 30's checkpoint and passed undetected — the
gap the two-thread race test already had, reopened one layer down inside
its own replacement. `list.append` and the weak set's `add` are ordinary
built-in-type methods and cannot be patched per-instance the way
`_WeakIdentityIndex.get`/`__setitem__` can, so hooking the mutation call
itself was not available as a fix.

Closed instead by moving the checkpoint to the one place guaranteed to run
exactly once, synchronously, at the true end of the critical section: the
counting lock's own `release()`. Patching `release()` to check the
protected data structure's actual final state — `fields in written` for
`_WRITE_LOCK`, `judged is not None and len(judged) >= 1` for
`_JUDGED_LOCK` — before forwarding to the real release proves the claim
directly, with no dependence on which internal method happens to run when:
under the correct implementation the append/add has already happened by
the time release is first called, so the check is `True`; under either
shape of narrowed-lock mutant, release fires before the mutation runs, and
the check is `False`. Re-verified by mutation: narrowing either lock to
release before its append/add is now caught, where round 30's version let
it through.

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

**A candidate written through `_sealed_assign` directly still has to agree
with the pin.** `_require_the_gates`/`_sealed_assign` are bound methods at
`commit`'s own reach, and a round-fourteen review used that reach to write a
`_candidate` naming a schema version `_pinned` never judged — in one case
with `_pinned` never even set, `start` skipped entirely, reaching
`COMMITTED` with `holds()` true and the audit empty. `_sealed_assign` now
refuses a `_candidate` write when `_pinned is None`, and refuses one whose
`schema_version` disagrees with `_pinned.schema_version`. Not the
fingerprint: `RecoveryCandidate._fingerprint` is set once, in `__init__`,
and read by nothing anywhere in this module — comparing it would be this
class's first read of a field the whole design keeps deliberately
write-only, and `schema_version` is the field a caller can act on. A
round-fifteen review found the comparison itself repeated the same
container-type/field-type gap as `binding`'s and `quarantine`'s fields:
`value.schema_version` was compared with `!=` before its type was pinned,
and a genuine `RecoveryCandidate` built with an `int` subclass whose
`__ne__` always answers `False` defeated the check the round-fourteen fix
had just added. `value.schema_version` is now pinned to exactly `int`
immediately before that comparison, the same way `binding`'s and
`quarantine`'s fields are pinned before theirs.

**And the pin itself, not only the candidate written against it.** The
`_pinned` write path checked *when* it could be written (only from
`NOT_STARTED`) but never *what* was written — a round-fifteen review wrote
a `_pinned` that was not a `SnapshotDescriptor` at all, through the same
bound-method reach `start` itself has, and the workflow accepted it
silently; the crash landed several calls later, inside the substitution
check's own field-reading helper, as a bare `AttributeError` from ordinary
attribute lookup rather than a refusal at the write. `_sealed_assign` now
runs `_require_a_real_snapshot` on a `_pinned` write — the identical check
every legitimate entrance already runs on its own `snapshot` argument,
reused rather than reimplemented.

**And `_stage` itself — the sharpest instance of the pattern yet.** Every
check `_sealed_assign` runs on a `_stage` write — the edge table, whether
the value is one reached without gates, whether it is exactly `COMMITTED`
— reads `value` before a round-sixteen review found its type was never
pinned. A stand-in answering `==`/`in`/`.value` like
`RecoveryStage.COMMITTED` while failing `is` it slid through the
*permissive* clearance branch — the one `open_trial`'s own transition
already satisfies — without D8's gates ever being asked. `holds()` and
`candidate_applies_to()` ask `is`, which a stand-in cannot spoof, so no
accepted `RecoveryCandidate` and no touch on the `Quarantine` followed —
but `flow.stage` then answered `== RecoveryStage.COMMITTED` for any caller
who wrote the ordinary comparison rather than this module's own
insisted-on `is`, while the audit stayed at `RECOVERY_TRIAL_OPENED`
forever and the workflow became permanently stuck. `_sealed_assign` now
pins `type(value) is RecoveryStage` before any of those checks read it.

**And the seal itself, at the one moment before it existed at all.** Every
gap above assumed a `RecoveryWorkflow` that had finished constructing —
`_sealed_assign`'s guards, the pin checks, all of it runs against an object
`__init__` already returned. A round-24 security review asked what happens
*during* construction: `__init__` validated `quarantine`, `binding` and
`session_id` — checks any caller of this public constructor can fail on
purpose — and only set `_sealed = False` (`__setattr__`'s "not yet sealed,
writes permitted" state) **after** all of that validation had already run.
A `TypeError` raised by any of those checks left a genuinely-typed, live
`RecoveryWorkflow` with no `_sealed` slot at all — and `__setattr__` gates
on `getattr(self, "_sealed", False)`, which defaults to `False`, meaning
unsealed, exactly when the slot was never set. Anyone holding that
half-built `self` — the same reach this document's own confidentiality
section treats as real for a half-built `SnapshotDescriptor`/
`SnapshotAuditEntry` (a debugger, or code shaped like the test suite's own
`_half_built` helper) — could write `_stage`, `_candidate` and
`_quarantine` by ordinary assignment: no gate, no stage graph, no audit
entry. `candidate_applies_to`/`holds` check `type(flow) is RecoveryWorkflow`
and then read `_stage`/`_candidate` straight off the instance, with nothing
to tell a forged-by-write workflow from a genuinely minted one — the same
"rebuild the object a legitimate caller holds" attack this document names
for `PreflightVerdict` and `MigrationLedger`, reached through construction
failure instead of through a hand-built stand-in. `_sealed` is now the very
first thing `__init__` sets, before any validation runs, and every field
write after it uses `object.__setattr__` directly rather than plain
assignment — the same idiom `SnapshotDescriptor` already used, for the
same reason: validate with plain functions first, then assign past a seal
that is already up.

The same review found two narrower instances of caller-supplied content
reaching a `__repr__` unchecked. `PreflightVerdict.__init__` validated
nothing about `refused_by` at all, though `preflight()` itself only ever
passes `None` or a genuine `PreflightCheck` member — a caller-built
`PreflightVerdict("nonsense")` constructed cleanly and then crashed
`__repr__`'s `self._refused_by.value` with a bare `AttributeError`, and an
object whose own `.value` returns chosen text rendered that text verbatim,
the same disclosure class `_require_an_exact_str`/`_require_an_opaque_value`
exist elsewhere to refuse. `refused_by` is now pinned to `None` or an exact
`PreflightCheck` member, the same treatment every other field in this file
gets. And `RecoveryCandidate.__repr__`'s f-string interpolated
`schema_version` — deliberately unvalidated at construction, by this
class's own design, so anyone can build `RecoveryCandidate(99, …)` and read
`99` back — through plain `str`/`format()`, so an object whose own
`__format__` returns chosen text rendered through the one place this class
exists to keep opaque. The repr now renders `schema_version` only when it
is genuinely `int`, without touching the intentionally permissive
constructor at all.

**Round 24's own fix opened one more window of this exact shape, found in
round 25.** Before round 24, `PreflightVerdict.__init__` performed no
validation at all, so it could never raise partway through construction —
a half-built `PreflightVerdict` was structurally impossible, and its
`__repr__` never needed a guard. The moment round 24 gave `refused_by` its
first-ever type check, a rejected constructor call became reachable for
the first time, and `__repr__` had not received the same canary-field
guard `SnapshotDescriptor`/`SnapshotAuditEntry`/`RecoveryWorkflow` already
carry. Closed the same way — `getattr(self, "_refused_by", <sentinel>)` —
except the sentinel is not `None`: `None` is `_refused_by`'s own
legitimate "the preflight passed" value, so a distinct module-level object
is what tells "unbuilt" and "built and passed" apart.

**Round 26 closed the remaining two instances pre-emptively, before either
had a live crash to point to.** `RecoveryCandidate.__init__` still cannot
raise — it validates nothing, deliberately, by this class's own design —
so no public caller can reach a half-built one; its `__repr__` gained the
same canary guard anyway (sentinel, not `None`, for the identical reason
`_refused_by`'s does), reachable only through `object.__new__` today. And
`MigrationLedger.__init__` — the only other class in the file gating
`__setattr__` on a `_sealed` flag besides `RecoveryWorkflow` — still set
`_sealed = False` first and `True` last, the exact pre-round-24 ordering,
even though it takes no argument and `list()` cannot raise, so there was
never a live gap. Both were reordered/guarded purely so a future round
that adds validation to either constructor inherits the safe shape by
default, rather than reopening the same crash a validation-adding round
already reopened once, in `PreflightVerdict`, the round before this one.

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
equality**, so a builtin that is not one of the nineteen is unreachable by any
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

**Both reprs also survive being called on a half-built instance, the same way
`RecoveryWorkflow.__repr__` already did.** `SnapshotDescriptor.__init__` and
`SnapshotAuditEntry.__init__` validate every field before assigning any of
them, so a rejected constructor call — a caller's malformed fingerprint,
among the shapes each `__init__`'s own docstring already describes finding —
leaves an object with none of its slots set. A round-22 security review
asked `traceback.TracebackException.from_exception(..., capture_locals=True)`
for exactly that `TypeError` — the ordinary shape of `pytest --showlocals`
and most crash reporters, and a code path this module's own test suite
already relies on elsewhere — and found it called the unguarded, redacting
`__repr__` and died a second time inside it with an `AttributeError`: a
clean, message-only refusal became a crash in the code written to keep
refusals clean. Each repr now reads one canary field — the first one its
own `__init__` assigns — with `getattr(self, "<field>", None)`, and returns
a plain `"<ClassName>(unbuilt)"` when it is absent, before touching anything
that construction never reached.

**`__eq__` and `__hash__` on the same two classes shared the identical gap,
found in the following round.** They are the only two classes in this file
that define either, and both read every field unconditionally through
`_fields_of(self)`/`self._fields()` — the same crash `__repr__` had, one
call deeper, just not reachable through `pytest --showlocals` (that
machinery only ever calls `repr()` on frame locals, never `==` or
`hash()`). It needs a caller that already holds a reference to the
half-built instance by some other means — a debugger evaluating an
expression at a breakpoint, or identity-set dedup over caught construction
failures — which is a narrower reach than `__repr__`'s, but the module had
just finished hardening this exact shape and left these two dunders behind.
Each class now has a `_fields_if_built()` method that returns `None`
instead of the field tuple when its canary is absent; `__eq__` returns
`False` for either operand missing it — a half-built instance carries no
value, so it is never equal to anything, itself included — and `__hash__`
raises a deliberate `TypeError` naming the class, rather than crash with
the same bare `AttributeError` the fields read would otherwise produce.

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

**`_JUDGED_BY` and `_SNAPSHOTS_RECORDED` can be found holding a live
`Quarantine`, for as long as one is alive elsewhere in the process** — not
for the life of the process itself: both are weak, so a medium nobody else
holds any more is not kept alive by having been judged (R14 doctrine
review: an earlier wording of this sentence said "for the life of the
process", which is the opposite of what `_SNAPSHOTS_RECORDED`'s own module
comment states and what round 10 built the weak indexing to guarantee —
corrected). Each is a two-round history of the same lesson landing
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

**And "once" needs the check and the record to be one act, not two.** The
module-wide spent-ness record was, until round eighteen, a check —
`_a_write_is_recorded` — and a record — `_remember_a_write` — as two separate
module functions called one after the other, with nothing between them but
ordinary Python statements. This is not the vocabulary-break class the
previous section closes: no exception raced here, the *state itself* went
wrong. A round-eighteen review drove two real threads through
`note_snapshot_written` for the same verdict, the same medium and the same
judged values, and both reached the check before either reached the record —
both saw "not yet recorded", and both recorded, producing two
`SNAPSHOT_WRITTEN` audit entries for the one preflight this verdict
authorised. A re-check cannot fix a defect in the state itself, only in which
exception a caller meets, so the fix is different in kind from the rest of
this section: the check and the record are merged into one function,
`_remember_a_write_if_new`, and its one `dict`-then-`list` critical section
runs under a module-level `threading.Lock`. The rule is unchanged — one
preflight, one recordable write — only how it is enforced.

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
