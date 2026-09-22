"""What a suspected torn write is called, and why the whole volume goes.

[ADR-0010](../../docs/adr/0010-persistence-key-and-migration.md) D4 and D5,
implemented. Azazel-Boot#41.

**This module classifies. It does not read a device, repair anything, or decide
what happens next** — the caller performs the IO and reports what it saw in the
vocabulary below, and `azazel_boot.persistence` turns a classification into a
refusal. Nothing here opens, mounts, repairs, writes or exports.

## Why the whole volume

[Threat model](../../docs/threat-model.md) §4 fixes the write order —
*prepare-and-sync, apply, verify, persist receipt* — with a prepare or sync
failure producing zero changes. So **a missing receipt is the signal**. What it
does not tell you is *how much* is affected, and there is no way to find out
from this side: the records that were already there are the same bytes whether
the interrupted write touched them or not, and the only thing that could say
otherwise is the volume being judged.

Per-record salvage would therefore be a guess presented as a finding. D5
refuses it, so the unit is the volume.

## Nothing here is called erased

Boot **will not use** the volume in ordinary operation. It does not say the
volume was wiped, cleared, erased, destroyed, shredded or deleted, because it
was not — the data is on the medium, and
[quarantine policy](../../docs/quarantine-policy.md) §4 still offers an export
of it **unmodified** for offline examination. The distinction is what an
operator may later truthfully tell someone about the evidence, so
`tests/unit/test_dirty_write.py` scans every rendered string for those six
words.

## Ambiguity is not a third answer

A receipt that cannot be read, a verification that errored, a continuity nobody
established: each resolves **to quarantine**. There is no vocabulary for "probably
fine" and no path that treats an unknown as a clean write. That is why the three
inputs are three-valued enums rather than booleans — a `bool` has no room for
"nobody established this", so the caller would have to pick one of the two
answers it does have, and under time pressure that is `True`.

Nothing here has run on hardware. No USB SSD has been pulled mid-write, no
receipt has been read, and no volume has been quarantined on any device.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ReceiptState(Enum):
    """Whether the receipt that ends a write is there.

    Three values, not a `bool`. `UNREADABLE` is a different fact from `MISSING`
    — one says the write did not finish, the other says nobody can tell — and
    collapsing them means choosing which lie to tell.
    """

    PERSISTED = "persisted"
    MISSING = "missing"
    UNREADABLE = "unreadable"


class MediumContinuity(Enum):
    """Whether the medium stayed put for the whole write."""

    PRESENT_THROUGHOUT = "present_throughout"
    REMOVED_DURING_WRITE = "removed_during_write"
    #: Nobody watched, or the watcher itself failed. Not "probably fine".
    NOT_ESTABLISHED = "not_established"


class Verification(Enum):
    """The *verify* step of the write order, and whether it reached an answer."""

    VERIFIED = "verified"
    FAILED = "failed"
    #: The check could not be completed. Distinct from a check that said no.
    INDETERMINATE = "indeterminate"


class DirtySignal(Enum):
    """The closed detection vocabulary, and the whole of the audit's payload.

    A member is a **classification**: which condition was observed, from a fixed
    set. ADR-0010 D4 is explicit that the classification is the whole payload —
    not what was being written, not which record was in flight, not an offset, a
    size, a count or a timestamp.
    """

    RECEIPT_MISSING = "receipt_missing"
    RECEIPT_UNREADABLE = "receipt_unreadable"
    REMOVAL_DURING_WRITE = "removal_during_write"
    CONTINUITY_NOT_ESTABLISHED = "continuity_not_established"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_INDETERMINATE = "verification_indeterminate"


@dataclass(frozen=True)
class WriteObservation:
    """What the caller saw, in three closed vocabularies and nothing else.

    There is no field for the record, the offset, the size, the byte count, the
    device, the time or the content. A free-text or numeric field here is how
    that reaches an audit, and D4 says the classification is the payload.
    """

    receipt: ReceiptState
    continuity: MediumContinuity
    verification: Verification


#: The one observation out of twenty-seven that is a clean write.
#:
#: Written out rather than derived, so that widening it is a visible edit to a
#: literal rather than a condition someone loosened.
CLEAN = WriteObservation(
    receipt=ReceiptState.PERSISTED,
    continuity=MediumContinuity.PRESENT_THROUGHOUT,
    verification=Verification.VERIFIED,
)


def classify(observation: WriteObservation) -> DirtySignal | None:
    """The signal, or `None` when the write was clean.

    **The order is fixed and is part of the contract**, because several faults
    usually arrive together and the audit records one word. A removal explains a
    missing receipt, so reporting `receipt_missing` for a medium that was pulled
    would name the symptom instead of the event; continuity is therefore asked
    first, then whether the verify step reached an answer, then the receipt.

    `None` is returned rather than a `CLEAN` member so that no caller can write
    `if signal is DirtySignal.CLEAN` and have it mean "safe" — there is nothing
    to compare against. Callers do not branch on this at all: they hand the
    observation to `PersistenceSession.report_write`, which refuses or does not.
    """

    if observation.continuity is MediumContinuity.REMOVED_DURING_WRITE:
        return DirtySignal.REMOVAL_DURING_WRITE
    if observation.continuity is MediumContinuity.NOT_ESTABLISHED:
        return DirtySignal.CONTINUITY_NOT_ESTABLISHED
    if observation.verification is Verification.FAILED:
        return DirtySignal.VERIFICATION_FAILED
    if observation.verification is Verification.INDETERMINATE:
        return DirtySignal.VERIFICATION_INDETERMINATE
    if observation.receipt is ReceiptState.MISSING:
        return DirtySignal.RECEIPT_MISSING
    if observation.receipt is ReceiptState.UNREADABLE:
        return DirtySignal.RECEIPT_UNREADABLE
    return None
