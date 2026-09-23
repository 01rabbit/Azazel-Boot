"""One base class for every refusal these modules raise.

A caller that means "do not write unless everything is in order" has to be able
to express that in one `except`. With three unrelated exception types, a CLI
catching the writer's refusal lets the media session's refusal escape as an
unhandled traceback — and a traceback carries captured locals into whatever is
logging it, which is how a redacted value reaches a log anyway.

The sentence above was written for three of them and read as though it covered
every refusal in the package, which is worse than either: six —
`ConfirmationRefused`, `PersistenceRefused`, `ImageRefused`, `ExportRefused`,
`ModeRefused` and `RecoveryRefused` — derived straight from `Exception`, so the
one `except` this module promises let each of them past. They all derive from
`Refused` now, and `tests/unit/test_refusals.py` derives the list from the
package rather than repeating it here, so a tenth *class named like a refusal*
is covered on the day it is written instead of on the day somebody remembers
this paragraph.

**"Named like a refusal" is the actual mechanism, and it is narrower than "one
base class for every refusal these modules raise" reads.** The test asks which
classes are *spelled* `...Refused`; a refusal that is not spelled that way is
invisible to it by construction, however the rule is written. One exists:
`azazel_boot.commissioning.UnidentifiedHost` is a `ValueError`, raised where a
host presents no identity to bind to, and it is not a `Refused` — an unhandled
`UnidentifiedHost` escapes the single `except` this module promises, captured
locals included, which is exactly the harm this docstring names. Bringing it
under this hierarchy is a public-contract change to a module this file does
not own, and is tracked separately rather than made here without its own
review.
"""

from __future__ import annotations


class Refused(Exception):
    """An operation did not happen, and the reason is a value, not a message.

    Subclasses carry a `refusal` enum member and a `detail` string. The detail
    never carries a device identity, a capacity, or a host path.
    """
