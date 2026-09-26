"""Resolve a symbolic profile ID into a closed, pinned set of build inputs — or refuse.

This is the gate the contract's input closure
(`docs/builder-writer-contract.md` section 5) is enforced at. Two properties
matter more than anything else this module does:

*Nothing an operator types becomes a source.* An input is named by a symbolic
ID that must already exist in versioned configuration. A URL, a mirror, an apt
line, a package name or a path does not match the identifier grammar, so it
cannot be smuggled in as an input name; and an input that configuration does
not name is not resolved at all.

*An unpinned input is refused, not resolved later.* `ADR-0002` D3 C2 is
explicit that a build which can silently resolve something mutable "fails C1
eventually and fails it invisibly". The failure has to be loud and it has to be
at resolution time, because by build time the mutable thing has already been
fetched.

The configuration this repository ships pins **nothing**, so every profile in it
refuses. That is the honest state — no snapshot has been chosen, no toolchain
has been pinned, and no builder has been selected — and
`tests/unit/test_build_closure.py` asserts it rather than letting it drift.

Resolution reads the two configuration files and nothing else: no environment
variable, no network, no subprocess, no wall clock.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

#: A symbolic input or profile ID. Lowercase, dot- or dash-separated, and
#: deliberately unable to express a URL (`://`), a path (`/`), a shell fragment
#: or an apt line. The grammar is the first half of the input closure.
SYMBOLIC_ID = re.compile(r"^[a-z0-9]+(?:[-.][a-z0-9]+)*$")

#: The only two immutable pin forms. A tag, a branch, a codename or a bare
#: version string is mutable in the sense C2 cares about: the same name can
#: later mean different bytes.
PIN_FORMS = (
    re.compile(r"^sha256:[0-9a-f]{64}$"),
    re.compile(r"^snapshot:[0-9]{8}T[0-9]{6}Z$"),
)

PROFILES_FILE = "profiles.json"
PINS_FILE = "pins.json"

PROFILES_SCHEMA = "azazel-boot/build-profiles@1"
PINS_SCHEMA = "azazel-boot/build-pins@1"


class Refusal(Enum):
    """Why a resolution did not happen. One value per distinguishable cause."""

    BAD_SCHEMA = "bad_schema"
    UNKNOWN_PROFILE = "unknown_profile"
    NOT_SYMBOLIC = "not_symbolic"
    EMPTY_PROFILE = "empty_profile"
    DUPLICATE_INPUT = "duplicate_input"
    UNPINNED_INPUT = "unpinned_input"
    MUTABLE_PIN = "mutable_pin"
    ORPHAN_PIN = "orphan_pin"
    UNPINNED_QUARANTINE_POLICY = "unpinned_quarantine_policy"


class ClosureRefused(Exception):
    """A closure could not be produced. Carries the cause, never a partial result."""

    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclass(frozen=True)
class Configuration:
    """The versioned configuration, parsed but not yet resolved."""

    profiles: dict[str, dict]
    pins: dict[str, str]

    @property
    def profile_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.profiles))


@dataclass(frozen=True)
class Closure:
    """A closed set of pinned inputs. Every field is an input to the digest."""

    profile_id: str
    quarantine_policy: str
    inputs: tuple[tuple[str, str], ...]

    def canonical_bytes(self) -> bytes:
        """The exact bytes the digest is taken over.

        Sorted, separator-fixed, newline-terminated: two hosts that resolved the
        same configuration produce the same bytes, whatever their locale, dict
        ordering or filesystem order happens to be.
        """

        document = {
            "profile_id": self.profile_id,
            "quarantine_policy": self.quarantine_policy,
            "inputs": [list(pair) for pair in self.inputs],
        }
        return (
            json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        ).encode("ascii")

    def digest(self) -> str:
        """The `build_input_digest` the contract's record carries."""

        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()


def load_configuration(config_dir: Path) -> Configuration:
    """Read `profiles.json` and `pins.json` from a versioned configuration directory."""

    profiles_document = _read_json(config_dir / PROFILES_FILE)
    pins_document = _read_json(config_dir / PINS_FILE)

    if profiles_document.get("schema") != PROFILES_SCHEMA:
        raise ClosureRefused(
            Refusal.BAD_SCHEMA, f"{PROFILES_FILE} is not {PROFILES_SCHEMA}"
        )
    if pins_document.get("schema") != PINS_SCHEMA:
        raise ClosureRefused(Refusal.BAD_SCHEMA, f"{PINS_FILE} is not {PINS_SCHEMA}")

    profiles = profiles_document.get("profiles", {})
    pins = pins_document.get("pins", {})
    if not isinstance(profiles, dict) or not isinstance(pins, dict):
        raise ClosureRefused(Refusal.BAD_SCHEMA, "profiles and pins must be objects")
    return Configuration(profiles=profiles, pins=pins)


def resolve(configuration: Configuration, profile_id: str) -> Closure:
    """Resolve one profile, or raise `ClosureRefused` with the reason.

    There is no partial resolution and no warning path: a profile resolves
    completely or not at all.
    """

    if not SYMBOLIC_ID.match(profile_id):
        raise ClosureRefused(
            Refusal.NOT_SYMBOLIC,
            f"{profile_id!r} is not a symbolic ID; a URL, path or package name "
            "cannot name a profile",
        )
    if profile_id not in configuration.profiles:
        raise ClosureRefused(Refusal.UNKNOWN_PROFILE, profile_id)

    profile = configuration.profiles[profile_id]
    names = profile.get("inputs") or []
    if not names:
        raise ClosureRefused(Refusal.EMPTY_PROFILE, profile_id)

    seen: set[str] = set()
    resolved: list[tuple[str, str]] = []
    for name in names:
        if not isinstance(name, str) or not SYMBOLIC_ID.match(name):
            raise ClosureRefused(Refusal.NOT_SYMBOLIC, repr(name))
        if name in seen:
            raise ClosureRefused(Refusal.DUPLICATE_INPUT, name)
        seen.add(name)
        pin = configuration.pins.get(name)
        if pin is None:
            raise ClosureRefused(
                Refusal.UNPINNED_INPUT,
                f"{name} has no pin; an input resolved at build time is not an input",
            )
        if not isinstance(pin, str) or not any(form.match(pin) for form in PIN_FORMS):
            raise ClosureRefused(
                Refusal.MUTABLE_PIN,
                f"{name} is pinned to {pin!r}, which is not an immutable form",
            )
        resolved.append((name, pin))

    orphans = sorted(set(configuration.pins) - seen)
    if orphans:
        raise ClosureRefused(
            Refusal.ORPHAN_PIN,
            f"pins name inputs this profile does not use: {orphans}",
        )

    policy = profile.get("quarantine_policy_ref")
    if not isinstance(policy, str) or not SYMBOLIC_ID.match(policy):
        raise ClosureRefused(
            Refusal.UNPINNED_QUARANTINE_POLICY,
            f"{profile_id} does not pin a quarantine policy; the payload's "
            "defining safety property is not an implicit default",
        )

    return Closure(
        profile_id=profile_id,
        quarantine_policy=policy,
        inputs=tuple(sorted(resolved)),
    )


def _read_json(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ClosureRefused(Refusal.BAD_SCHEMA, f"{path.name} is unreadable: {error}") from None
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise ClosureRefused(Refusal.BAD_SCHEMA, f"{path.name} is not JSON: {error}") from None
    if not isinstance(document, dict):
        raise ClosureRefused(Refusal.BAD_SCHEMA, f"{path.name} is not an object")
    return document
