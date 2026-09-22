# ADR-0011: Where the passphrase is typed, and what may cross back

Status: **accepted (2026-09-22) — nothing implemented.** The owner decided
D1–D11 below. No helper exists, no `cryptsetup` has been invoked, no LUKS
volume has been opened on any device, and
[#40](https://github.com/01rabbit/Azazel-Boot/issues/40) stays
`hardware-unverified`.

Related: [ADR-0010 D1/D2/D3](0010-persistence-key-and-migration.md) ·
[ADR-0008 D4.1.1](0008-debian-13-live-baseline.md) ·
[Session mode](../session-mode.md) ·
[Quarantine policy](../quarantine-policy.md) §2 ·
[Threat model](../threat-model.md) §4–§5

## Context

[ADR-0010](0010-persistence-key-and-migration.md) D1 decided that no key means
an ephemeral session, D2 that five attempts end a boot's chance, and D3 that
the mode is fixed once. [`azazel_boot.session_mode`](../session-mode.md)
implements all three around one deliberate absence: **the passphrase never
reaches it.** A `KeyAcquisition` prompts and attempts the unlock somewhere
else and returns exactly one member of `AttemptOutcome`.

**No such acquisition exists.** `src/azazel_boot/` may not drive a console
([#1](https://github.com/01rabbit/Azazel-Boot/issues/1), enforced by
`tests/unit/test_boundary_static.py`), so the shipped default reports that
there is no channel and *every session is currently ephemeral*. That is the
gap reported rather than papered over, and this record decides the shape of
the thing that closes it.

The difficulty is the obvious one: **the helper is the one component that does
hold the secret.** Every other part of this design achieves confidentiality by
never receiving the value. The helper cannot. So the decisions below are not
about hiding a secret inside the helper — they are about what the helper is
permitted to be handed, and what is permitted to come back out, so that the
part which holds it is as small as possible and everything downstream keeps
the property it already has.

**No key material, passphrase, device identity, mapper path or `cryptsetup`
output appears in this record, in an issue, in a pull request, in a fixture, on
a terminal, in a journal or in an audit** — ADR-0010 D10, unchanged and
extended to this component.

## D1 — The helper lives in the initramfs, not in the product package

The unlock helper is an **initramfs hook helper**, invoked during early boot
and never afterwards. It is not part of `azazel_boot`, is not importable by it,
and is not on the package's dependency graph in either direction.

Two reasons, and the second is the load-bearing one:

1. `src/azazel_boot/` may not touch a device, a console or a process, and that
   constraint is what makes the existing static guards meaningful. Putting a
   `cryptsetup` call inside it would not be a small exception; it would end the
   guard.
2. **A boot-time-only component cannot be called later.** A helper that lives
   in the running system is a helper an operator, a script or an attacker can
   run at any point in the session — which would re-open, in a different file,
   exactly the mid-session unlock that D3 exists to refuse.

The hook order in [quarantine policy](../quarantine-policy.md) §2 is unchanged
by this record: the quarantine stays first. Where the unlock helper sits
relative to `az-mark-boot-medium` is **not decided here** (see below).

## D2 — The helper attempts **once** per invocation. The budget stays where it is.

One invocation is one prompt and one unlock attempt, reporting one outcome.
The helper holds **no counter**.

ADR-0010 D2's budget of five is already implemented in
`azazel_boot.session_mode`, pinned by tests and verified by mutation. A helper
that looped would be a second implementation of the same limit, in a component
that is harder to test, with no way to keep the two in agreement — and the
first time they disagreed, the looser one would be the one that ran.

So the helper's contract is exactly `KeyAcquisition.attempt()`: prompt once,
try once, say what happened. **This record adds no outcome to
`AttemptOutcome`.** If a condition cannot be expressed in the existing five
members, that is a finding to bring back here, not a value to invent at the
boundary.

## D3 — The helper has exactly two inputs, and neither is a string a caller chose

| Input | Where it comes from |
| --- | --- |
| The passphrase | Typed by the operator at a **local hidden console prompt**, with echo off. Nowhere else. |
| The bound volume identity | Re-derived by the helper from the **commissioning record on the boot medium**, per [ADR-0008 D4.1.1](0008-debian-13-live-baseline.md). |

**Not `argv`. Not the environment. Not a configuration file. Not a network
source, a remote API, the host's disk, or anything exported to a USB device.**
Each of those is a place a value is read by something other than the person
holding it, and each leaves it somewhere afterwards — a process listing, a
shell history, a backup, a log.

**The commissioning record is not a configuration file, and the difference is
worth writing down** because this is precisely the distinction that erodes. A
configuration file tells the helper what to do; the commissioning record *is
the identity being checked*, and the helper **re-derives** the binding from the
medium in front of it rather than believing a value it was handed. A helper
handed `--volume-uuid=…` would check a number against itself, which is the
tautology [`azazel_boot.persistence`](../persistence.md) was rebuilt to stop
making.

A record that does not match the medium the helper was started from is a
refusal, not a prompt: the operator is not asked to type into a mismatch.

## D4 — What comes back is an exit status, and the channel is that small on purpose

The helper reports its outcome as a **process exit status**: one small integer
from a fixed, enumerated set, each member mapping to exactly one
`AttemptOutcome`.

Not JSON on a pipe, not a line of text, not a file. **An exit status cannot
carry a passphrase.** A pipe can, a temporary file can, and a log line can; the
question then becomes whether anyone remembered to keep them clean, on every
path, including the error paths. An eight-bit channel removes the question
rather than answering it — the same reason `PassphraseChannel` has one member
and `AuditEntry` has no free-text field.

The mapping from status to outcome is fixed in one place and **pinned by a
test against `AttemptOutcome`**, so an outcome added on one side and not the
other is a red test rather than a status nobody handles.

## D5 — What never crosses back

The helper returns **none** of:

- the passphrase, in any encoding, at any length;
- a derived key, a key slot, a keyfile path, or a handle to any of them;
- the device-mapper path, the device node, or any raw media identity;
- `cryptsetup`'s standard output or standard error, in whole or in part;
- an errno, a return code from `cryptsetup`, or any message derived from one.

The last is not padding. `cryptsetup`'s diagnostics are the obvious thing to
forward when a failure is confusing, they name devices and slots, and forwarding
them is a one-line change that looks like an improvement. **The helper's
standard error is discarded, not captured** — captured means stored, and stored
means it reaches whatever renders it.

## D6 — The mapper name is a constant, not something the helper reports

The opened volume appears at a **fixed, non-secret device-mapper name**,
identical on every medium and every laptop.

A returned path is an identity: it names which device was opened, and it
travels into whatever logs or renders the return value. A constant names
nothing — anything that needs the volume already knows where it is, and if the
volume is not there, that is the `unlock-unavailable` classification rather
than a path to inspect.

## D7 — The helper does not log, and the audit may hold four words

The helper writes **no log of its own**: not to a console, not to a file, not
to the kernel ring buffer, not to a journal that survives the boot.

What may reach Boot's audit is a **classification**, from exactly this
vocabulary, and nothing beside it:

| Classification | Meaning |
| --- | --- |
| `unlock-succeeded` | the volume opened |
| `unlock-unavailable` | no key material, or no local hidden prompt to type into |
| `unlock-refused` | a passphrase was tried and did not open the volume; or the medium, the header or the binding refused before one was |
| `attempt-budget-exhausted` | recorded by `session_mode`, which owns the count |

No attempt number, no remaining count, no user identifier, no device identity,
no error detail, no timing. ADR-0010 D2 is explicit that a counter on a screen
is a counter in a photograph of a screen; a counter in a boot log is a counter
in every copy of that log.

**`unlock-refused` deliberately does not distinguish a wrong passphrase from a
bad header from a binding mismatch.** Separating them would tell whoever reads
the log which of those it was, which is the one piece of information an
attacker holding the medium does not already have.

## D8 — Every failure is fail-closed, and the session becomes ephemeral

There is no repair, no retry loop, no degraded open and no operator override.
Each of the following ends in an **ephemeral session**:

1. no TTY, or no hidden local prompt available;
2. the operator interrupted the prompt;
3. the LUKS header is missing, unreadable or inconsistent;
4. the commissioning binding does not match the medium in front of the helper;
5. the medium is fenced ([quarantine policy](../quarantine-policy.md) §4);
6. the attempt budget is exhausted (ADR-0010 D2).

Cases 1 and 2 map to outcomes that ADR-0010 already distinguishes: an
interruption verified nothing and so costs nothing, while an absent channel
settles the mode immediately. Cases 3, 4 and 5 are refusals *before* a prompt —
an operator is not asked to type a passphrase into a volume that will not be
opened whatever they type.

**A failed unlock does not quarantine the volume.** ADR-0010 D2 fixed that a
mistyped passphrase and a hostile guess are indistinguishable and that both
degrade to ephemeral; this record does not change it. Volume-wide quarantine is
D4's, for a suspected torn write, and
[#41](https://github.com/01rabbit/Azazel-Boot/issues/41)'s to implement.

## D9 — Nothing is kept, and nothing about keeping is claimed

**No secret is written into the initramfs, at build time or at run time.** No
keyfile, no key slot copy, no cached passphrase, no "just until the next hook"
file, no swap, no hibernation image. The initramfs is built by the image
builder, is signed, and is identical on every medium; a secret in it is a
secret in every copy of the image.

**What is not claimed:**

- **Not complete erasure from memory.** The helper holds the passphrase for the
  duration of one attempt. Python cannot guarantee erasure — strings are
  immutable, the interpreter copies them, the allocator and `gc` do as they
  please — and neither this record nor any implementation of it will claim
  otherwise. What is done is to minimise how long and how widely it is held, by
  keeping the holder to one short-lived process.
- **Not TPM protection.** Nothing here seals anything to a platform. On a
  borrowed laptop, platform-sealed material is absent by definition
  (ADR-0010 D1).
- **Not resistance to offline attack.** That is a property of the key
  derivation, which ADR-0010 does not decide and this record does not either.
- **Not protection from code in the same process.** A helper that has the
  passphrase can do anything with it; what bounds the damage is that it is one
  small, signed, boot-time component with the surface D3 and D11 describe.

## D10 — The acceptance criteria are tests that no secret crosses the boundary

An implementation of this record is not accepted on review alone. It is
accepted when:

1. **A static test** asserts the helper's return channel is the enumerated
   status set and nothing else, that the status-to-`AttemptOutcome` mapping is
   total on both sides, and that no code path writes the passphrase, a derived
   key, a mapper path or `cryptsetup` output to any file, stream or log.
2. **A static test** asserts the helper reads no `argv`, no environment, no
   configuration file, no network and no host-disk path, in the allowlist form
   `tests/unit/test_session_mode.py` and `tests/unit/test_boundary_static.py`
   now use — an exact set of permitted imports, with `__import__`, `eval`,
   `exec` and `compile` refused by name. A denylist of module names is one
   `__import__` wide, which an adversarial review demonstrated against the
   previous version of both guards.
3. **An integration test** drives every path in D8 against a fake `cryptsetup`
   and asserts that the passphrase, a derived key, a mapper path and the
   fake's own diagnostics appear in no returned value, no audit entry, no
   exception, no `repr` and no captured-locals traceback of the helper's own
   frames. The fake's `__repr__` **renders its secret deliberately**, because a
   double with the default `object.__repr__` renders an address and makes such
   an assertion pass against any implementation at all.
4. **A mutation run**, with the baseline asserted green first, shows that
   removing each of the above is caught.
5. **A targeted independent adversarial review** is completed before merge, as
   a storage and confidentiality change.

## D11 — What the helper may not reach, at all

No network. No host disk. No USB export. No snapshot, migration or recovery —
those are ADR-0010 D6–D8 and
[#42](https://github.com/01rabbit/Azazel-Boot/issues/42), and a component that
can open a volume is not also the component that can copy one. No capability
change, no fence clearing, no re-opening of a session that required a reboot
(ADR-0010 D8's closing rule, which applies here too).

The helper runs with the **narrowest privilege that can open a LUKS volume**
and is not granted more for convenience. What that privilege is in concrete
terms — user, capabilities, mount namespace — is **not decided here**; see
below.

## Consequences

- The gap is closable: something can now be built that makes a session
  persistent, and `session_mode` needs no change to accept it.
- Closing it requires an initramfs, which this repository has never produced.
  Until then every session stays ephemeral, and that remains true in the README
  rather than being quietly dropped once a helper exists on paper.
- `AttemptOutcome` becomes a shared contract across a process boundary. The
  test pinning the mapping is what keeps it one contract rather than two.
- Diagnosing a failed unlock in the field is deliberately hard. An operator
  learns that persistence did not open, not why. That cost is accepted here
  rather than discovered later by someone adding a helpful message.

## What this record does not decide

- **The key-derivation function, parameters, slot layout or credential
  format.** ADR-0010 left these open and they stay open; offline-attack
  resistance is a property of that choice.
- **The helper's implementation language.** If it is Python, D9's
  no-erasure-claimed applies as written; if it is not, the claim still is not
  made, because a `memset` in a language with one does not cover the kernel's
  copies, the tty buffer or the pages the allocator already released.
- **The helper's concrete privilege** — user, capability set, namespace — and
  **its position in the hook order** relative to `az-mark-boot-medium`. Both
  need the initramfs that does not exist. The trigger that settles them is the
  first built initramfs against which
  [quarantine policy](../quarantine-policy.md) §2's `verify_initramfs` runs on
  a real manifest rather than a filled-in structure.
- **Where the recovery credential of ADR-0010 D1 is presented.** It is a third
  source in a fixed order; whether it reaches the same helper or another one is
  the recovery workflow's question (D8 there, #42 here).

## What this record does not establish

**Nothing here is implemented.** No helper exists. No `cryptsetup` has been
invoked by anything in this repository, no LUKS header has been read, no
passphrase has been typed, and no volume has been opened, on any device. There
is no initramfs to put a hook into.

Every claim above is about a shape. The hardware record that
[threat model](../threat-model.md) §3.3 requires does not exist, and until a
real USB SSD and a real laptop say otherwise this record and everything built
from it carry `hardware-unverified`.
