# Persistent or ephemeral: decided once, and the secret never arrives

Status: **decision logic only.** `azazel_boot.session_mode` decides which mode a
boot is in and refuses to change it afterwards. It **opens no volume, derives no
key, shows no prompt and reads no input** — a `KeyAcquisition` supplied from
outside does that and reports one enum value back. Nothing here has run on
hardware. No passphrase has been attempted and no volume has been opened,
sealed or created on any device.

Implements [ADR-0010](adr/0010-persistence-key-and-migration.md) D1, D2 and D3.
D4–D8 are implemented in software elsewhere in this package and
hardware-unverified (see below); D9 and D10 are held by static and runtime
checks only.

Related: [ADR-0011](adr/0011-unlock-helper-boundary.md) — the shape of the
acquisition that does not yet exist ·
[Persistence](persistence.md) · [Threat model](threat-model.md) §5 ·
[Quarantine policy](quarantine-policy.md) §4 ·
[Confirmation flow](confirmation-flow.md) ·
[#40](https://github.com/01rabbit/Azazel-Boot/issues/40)

## The one property this is built around

**The passphrase does not reach this module.** Not as an argument, not inside a
wrapper, not behind a `disclose()` that a reviewer is asked to trust.

Every earlier round of this work redacted a value that some module was holding —
a `repr`, a pickle, a traceback frame — and each time the next weakness found
was the container itself. So the container was removed. `KeyAcquisition.attempt()`
prompts and tries the unlock **elsewhere** and returns exactly one member of
`AttemptOutcome`. The Protocol has no `passphrase()`, no `key()`, no `read()`
and no `material()`, and a test asserts the public surface is precisely
`{channel, attempt}`.

A module that never receives the secret has no container to weaken.

What that buys and what it does not: the secret still exists in the process that
performs the prompt. This does not make the passphrase unreachable to code
running in the same interpreter — nothing in Python does. It removes this
module's own vocabulary, reprs, audit entries and exception messages from the
set of places the secret can be found. It does **not** remove the acquisition
object from `commission`'s stack frame; see the note on tracebacks below.

## D1 — No key, no persistence

Three things follow from "no key means ephemeral, and there is no other answer":

- There is no unprotected-volume path. Not behind an operator acceptance, not
  behind a policy flag, not behind a state. The refusal is not enforced by a
  check; there is nothing to check, because no code path constructs one.
- `PassphraseChannel` has **one** member, `LOCAL_HIDDEN_PROMPT`. There is no
  member for an environment variable, a command-line argument, a configuration
  file, a network source or a file on disk. A caller cannot name what the type
  does not contain.
- The module imports `os`, `sys`, `pathlib`, `subprocess`, `socket`, `urllib`
  and `ctypes` **not at all**, and a test walks the module's AST to keep it that
  way.

The default acquisition, `NoLocalPrompt`, reports `NO_LOCAL_INPUT_CHANNEL` and
nothing else. That is the same shape `inventory.no_permanent_mac` uses for the
ioctl this package may not perform: prompting on a console is an act, `src/`
may not perform one (#1, enforced by `tests/unit/test_boundary_static.py`), and
so the honest default is the gap reported rather than papered over. Until a
component permitted to drive a console injects a real acquisition, **every
session is ephemeral**.

## D2 — Five attempts, and what that is not

`ATTEMPT_BUDGET` is `5`. `REJECTED` and `OPENED` each spend one because each is
one passphrase attempt. `INTERRUPTED` spends nothing and decides nothing — the
operator stopped before trying anything, and the session is left with no mode
at all, which is the fail-closed state. The two `NO_…` outcomes do not retry,
because asking again asks the same question of the same absent thing. A
provider exception or invalid response is charged conservatively: without an
explicit non-attempt outcome, the caller cannot know whether verification
already ran.

On the fifth rejection the mode is fixed to ephemeral for this boot.

`BootSession` owns the shared budget for commissioning and recovery. Creating
another `RecoveryWorkflow` does not reset it **when the same `BootSession`
owner is retained and supplied**. The prototype `azazel_boot.runtime` service
retains one owner for the running boot and selects ephemeral mode because no
safe persistence/key path exists; it does not expose key acquisition. A
per-owner lock admits only
one commissioning/recovery acquisition at a time and refuses overlapping
requests, so concurrent callers cannot both consume the same last attempt. If
commissioning already fixed the mode as persistent, a later fifth attempt
stops further prompts but does not mutate that fixed mode; the volume remains
quarantined and ordinary use continues to be refused. Recovery cannot prompt
from an undecided or ephemeral session.

**This is not brute-force resistance, and is not claimed as any.** An attacker
holding the medium reboots and gets five more. What the limit buys is that a
*running* session cannot be ground down in place while the operator is
elsewhere, and that a mistyped passphrase degrades to ephemeral rather than
quarantining the volume. Resistance to offline attack is a property of the key
derivation, which ADR-0010 does not decide and this module does not implement.

**It is not TPM protection.** Nothing here seals anything to a platform.

**It is not erasure of secrets from memory.** Python cannot guarantee that:
strings are immutable, the interpreter copies them, and the allocator and `gc`
do as they please. So no erasure is claimed. What is done instead is to never
accept the secret here, and to audit only transitions that contain none.

**A mistake and an attack are the same thing here.** A mistyped passphrase and a
hostile guess are indistinguishable, and treating them identically is the point:
a test drives five rejections and asserts every quarantine verdict is exactly
what it was before, and that the medium is not fenced.

## D3 — The mode is an object one boot minted

`CommissionedMode` is checked with `is`, not `==`. What makes it this boot's
mode is that the `BootSession` that decided it holds that exact object; a copy,
a rebuild and an unpickle are not it, and `__reduce__` raises rather than
letting one exist. `mode_applies_to(session, mode)` is how a caller asks,
instead of reading `mode.mode` and believing it.

There is no promotion and no demotion. A session that starts ephemeral stays
ephemeral until the machine reboots, and a second `commission()` refuses with
`mode_already_fixed`. There is deliberately no `SessionMode` member meaning
"undecided" — an undecided session is the **absence** of a `CommissionedMode`,
because a third value is something later code would compare against and proceed
on.

**Reading `mode.is_persistent` is not asking whether this boot decided it.**
Anyone can construct a `CommissionedMode(PERSISTENT, …)` and it will answer
`True`, because that property reads the two fields it was handed. The rule for
a caller is `mode_applies_to(session, mode)` first, the capability second. The
accessor is kept rather than removed because a mode that cannot say what it is
would be answered by reading `_mode` instead, which is worse.

`CommissionedMode.authority` is `()` in both modes. A mode is a capability
statement, never an authority; Azazel-Edge's deterministic arbiter holds the
same and only authority before and after. A test drives the quarantine through
a full commissioning in both modes and asserts no verdict moves.

## The order of the gates

`commission()` settles everything that costs nothing **before** an operator is
asked to type, and **re-checks the fence on every iteration** — the loop spans
an operator typing up to five passphrases, which is as much wall-clock time as
they take, and the medium can be pulled during it. Checking once meant a medium
removed after the first prompt still commissioned a persistent mode over a
fence, which an adversarial review drove and nothing caught.

The gates, in order:

1. a mode already decided → `mode_already_fixed`
2. a record made on another machine or in another sitting → `not_this_host_or_session`
3. a fenced medium → `medium_fenced`
4. a channel that is not a hidden local prompt → `channel_not_a_local_hidden_prompt`

Only then is `attempt()` called. A removed medium therefore never produces a
prompt, and the binding is **re-derived** from the supplied inventory by
`commissioning.binding_applies` rather than compared against the session's own
constructor arguments — the tautology fixed in
[`azazel_boot.persistence`](persistence.md) and not reintroduced here.

The two refusals that could otherwise render something are raised from helper
functions whose frames hold **one boolean each**.

**That is narrower than it first looks, and the first draft of this page
overstated it.** It said a captured-locals traceback "has no acquisition and no
inventory in it to print". It does: `commission` is still on the stack and
still holds the parameter it was handed, and a frame cannot forget its own
argument. If an acquisition's `__repr__` renders what it is holding, a crash
reporter shows it from that frame. The test that was supposed to catch this
passed because the test double used the default `object.__repr__`, which
renders an address — it would have passed against any implementation at all.
The double now leaks deliberately, and the assertion is scoped to this module's
own frames, which is the only thing this module can be held to.

The same is true of the **session id**. `commission` and `_require_this_host`
were handed it, so their frames hold it and a captured-locals traceback renders
it in clear. The frame that raises holds one boolean, and no refusal *message*
carries it — that much is tested on all six refusal paths. Beyond that, a
sitting's id is visible to anything that renders a traceback of this module,
and this page says so rather than leaving it to be found.

## What the audit may hold

Three classifications, and nothing else:

| Event | When |
| --- | --- |
| `mode_selected` | a mode was fixed; carries the mode, which the operator is told anyway |
| `persistence_unavailable` | no key material, or no local input channel |
| `attempt_budget_exhausted` | the fifth passphrase attempt |

`AuditEntry` has two fields and no third. There is no `detail`, `message`,
`reason`, `attempts`, `remaining`, `identity`, `error` or `passphrase` field —
a free-text field is how a secret or a host identity reaches an audit, and a
test scans every dataclass this module defines for a field name matching any of
them.

**The attempt count reaches no audit, no journal and no screen**, and is not in
`BootSession.__repr__` either: a counter on a screen is a counter in a
photograph of a screen, and a counter in a `repr` is one in every traceback.

## What cannot be reached from here

Host storage, a USB write, a VM, the network, an export, a snapshot and a
recovery. The module's imports are pinned to an **exact set** —
`__future__`, `dataclasses`, `enum`, `typing`, `azazel_boot` — and it names none
of those things in code, asserted over the AST rather than over the file's text
so that the paragraph you are reading is not mistaken for a violation of itself.

An allowlist rather than a denylist, because a denylist of module names is one
`__import__` wide. An adversarial review appended a function that ran `dd`
against a raw block device and sent the bytes over TCP, assembling every module
name from fragments — `__import__("sub" + "process")`, `__import__("soc" +
"ket")`, `__import__("io")` — and the entire suite stayed green, here and in
the repository-wide guard in `tests/unit/test_boundary_static.py`. Both now
refuse `__import__`, `eval`, `exec` and `compile` by name across
`src/azazel_boot/`, and both see relative imports, which they previously did
not.

Docstrings are excluded from that scan **by node identity, not by value**:
excluding them by value meant a function whose entire body was the one-word
docstring `"mount"` silently whitelisted that literal everywhere else in the
file, which the same review armed and walked four forbidden tokens through.

## What this does not establish

- **No hardware.** No USB SSD, no laptop, no volume, no LUKS header, no prompt.
  #40 is `software implementation complete / hardware-unverified` and stays
  open.
- **No acquisition exists.** Nothing in this repository can prompt for a
  passphrase, so nothing can return `OPENED` outside a test.
  [ADR-0011](adr/0011-unlock-helper-boundary.md) decides what one would look
  like — an initramfs hook helper reporting a process exit status — and decides
  it only; no helper is written, and there is no initramfs to put one in.
- **D4–D8 are implemented in software and hardware-unverified; D9 and D10 are
  held by static and runtime checks only.** Dirty-write detection and
  volume-wide quarantine ([#41](https://github.com/01rabbit/Azazel-Boot/issues/41))
  are `azazel_boot.dirty_write` with `azazel_boot.persistence`; the
  in-partition snapshot, preflight and recovery workflow
  ([#42](https://github.com/01rabbit/Azazel-Boot/issues/42)) are
  `azazel_boot.snapshot` — see [snapshot and recovery](snapshot-and-recovery.md).
  None of it has run on a device.
- **Boot still cannot represent a commissioning record.** `SessionBinding` binds
  a session to an inventory; the record shapes live in
  `azazel_fabric.provisioning_contracts`.
