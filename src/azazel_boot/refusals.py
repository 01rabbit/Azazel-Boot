"""One base class for every refusal these modules raise.

A caller that means "do not write unless everything is in order" has to be able
to express that in one `except`. With three unrelated exception types, a CLI
catching the writer's refusal lets the media session's refusal escape as an
unhandled traceback — and a traceback carries captured locals into whatever is
logging it, which is how a redacted value reaches a log anyway.
"""

from __future__ import annotations


class Refused(Exception):
    """An operation did not happen, and the reason is a value, not a message.

    Subclasses carry a `refusal` enum member and a `detail` string. The detail
    never carries a device identity, a capacity, or a host path.
    """
