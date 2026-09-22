"""A denylist parametrized over itself shrinks with itself, silently.

This shape has slipped through three times in this repository — `VOLUME_MANAGERS`,
`VOLUME_MANAGER_MEMBERS` and `FORBIDDEN_ASSURANCE_WORDS` — each found by mutation
rather than by review, and each fixed one at a time. The pattern is always the
same:

    @pytest.mark.parametrize("item", SOME_DENYLIST)
    def test_each_item_is_refused(item): ...

Emptying `SOME_DENYLIST` leaves that test with zero cases, which is a pass. The
test measures the constant against itself and cannot notice it shrinking.

So the shape gets a test of its own rather than a fourth correction. A
constant imported from `azazel_boot` or `tools` and parametrized over must also
be asserted **literally** somewhere — as an exact tuple, or as a superset
assertion naming its members — so that shrinking it goes red.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent

#: Names that look like a closed set whose shrinking would matter. A constant
#: parametrized over that is *not* one of these — a list of fixtures, a set of
#: inputs — is a different thing and is not in scope.
CLOSED_SET_HINTS = ("FORBIDDEN", "PERMITTED", "REQUIRED", "MANAGERS", "MEMBERS", "NEVER")


def _module_constants_parametrized(path: Path) -> set[str]:
    """Constants imported from the product and then parametrized over."""

    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith(("azazel_boot", "tools")):
                imported.update(a.asname or a.name for a in node.names)

    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "parametrize"):
            continue
        for argument in node.args[1:]:
            if isinstance(argument, ast.Name) and argument.id in imported:
                found.add(argument.id)
    return found


def _literally_asserted(path: Path, name: str) -> bool:
    """Whether the file also pins the constant against written-out members.

    An exact-tuple assertion or a superset assertion both count: either fails
    when a member disappears. A bare `assert item in CONSTANT` does not.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        sides = [node.left, *node.comparators]
        mentions = any(isinstance(s, ast.Name) and s.id == name for s in sides)
        literal = any(isinstance(s, ast.Tuple | ast.List | ast.Set) and s.elts for s in sides)
        literal = literal or any(
            isinstance(s, ast.Call)
            and isinstance(s.func, ast.Name)
            and s.func.id == "set"
            and s.args
            and isinstance(s.args[0], ast.Tuple | ast.List | ast.Set)
            for s in sides
        )
        if mentions and literal:
            return True
    return False


@pytest.mark.parametrize(
    "path", sorted(TESTS.glob("test_*.py")), ids=lambda p: p.name
)
def test_no_denylist_is_parametrized_over_itself_without_being_pinned(path: Path) -> None:
    """The shape, caught repo-wide, instead of a fourth one-at-a-time fix."""

    for name in _module_constants_parametrized(path):
        if not any(hint in name for hint in CLOSED_SET_HINTS):
            continue
        assert _literally_asserted(path, name), (
            f"{path.name} parametrizes over {name} without also pinning its "
            "members literally; emptying the constant would leave this suite "
            "green with zero cases"
        )
