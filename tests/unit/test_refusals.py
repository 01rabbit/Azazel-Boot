"""The two promises a refusal makes, asked of every class that makes them.

Both are claims this repository writes down and then does not check, which is
the shape of finding that survives a review: a sentence in a docstring is not
a property, and a property nothing asks is a property that holds until the
next edit.

1. `azazel_boot.refusals` says it is "one base class for every refusal these
   modules raise", and gives the reason: a caller that means "do not write
   unless everything is in order" writes one `except`. Six of the nine
   refusals did not derive from it, so that `except` let three of them through
   as unhandled tracebacks — carrying captured locals into whatever is logging.

2. A class that refuses `__reduce__` is refusing to hand its fields back.
   `object.__getstate__` is a public method on every object since 3.11 and
   hands back exactly the same state with no pickling involved, so refusing
   one door and not the other refuses neither. Eight classes refused one.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
from pathlib import Path

import pytest

import azazel_boot
from azazel_boot.refusals import Refused

PACKAGE = Path(azazel_boot.__file__).parent


def _modules():
    for entry in sorted(pkgutil.iter_modules([str(PACKAGE)])):
        yield importlib.import_module(f"azazel_boot.{entry.name}")


def _classes():
    """Every class **defined** in this package, once, by identity."""

    seen: dict[int, type] = {}
    for module in _modules():
        for _, value in inspect.getmembers(module, inspect.isclass):
            if value.__module__.startswith("azazel_boot."):
                seen[id(value)] = value
    return list(seen.values())


def test_every_refusal_in_this_package_shares_the_one_base_class() -> None:
    refusals = [value for value in _classes() if value.__name__.endswith("Refused")]

    assert len(refusals) >= 9, sorted(value.__name__ for value in refusals)
    assert not [value for value in refusals if not issubclass(value, Refused)]


def test_a_class_that_refuses_to_be_pickled_refuses_to_hand_its_fields_back() -> None:
    """Derived from the source, so a ninth class inherits the rule for free.

    Written out as a list, this test would have passed on the day it was
    written and said nothing on every day after it.
    """

    refuse_reduce: list[tuple[str, str]] = []
    refuse_getstate: list[tuple[str, str]] = []
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            defined = {
                body.name for body in node.body if isinstance(body, ast.FunctionDef)
            }
            if "__reduce__" in defined:
                refuse_reduce.append((path.name, node.name))
            if "__getstate__" in defined:
                refuse_getstate.append((path.name, node.name))

    assert len(refuse_reduce) >= 15, refuse_reduce
    assert not sorted(set(refuse_reduce) - set(refuse_getstate))


def test_both_refusals_are_refusals_and_not_merely_definitions() -> None:
    """And they raise, rather than existing.

    `object.__new__` rather than a constructor, because the question is about
    the class's answer and not about building a legitimate instance of each of
    fifteen different things.
    """

    asked = 0
    for value in _classes():
        if "__reduce__" not in vars(value):
            continue
        blank = object.__new__(value)
        with pytest.raises(TypeError):
            value.__reduce__(blank)
        with pytest.raises(TypeError):
            value.__getstate__(blank)
        asked += 1
    assert asked >= 15, asked
