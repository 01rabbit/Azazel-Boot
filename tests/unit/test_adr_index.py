"""The ADR index must describe the ADRs that exist.

`docs/adr/README.md` is where a reader looks to find out what has been decided.
It is hand-maintained, so it can fall behind the directory it indexes — an ADR
added without a row is invisible to anyone who reads the index, and a row left
behind after a rename points at nothing. Either way the reader is told
something false about what this project has decided.

This repository already states the principle these tests apply: "A rule that
lives only in prose is one review away from being gone" (`test_boundary_static`
docstring). The ADR index is such a rule.

These tests check the correspondence only. They say nothing about whether a
decision is good, implemented, or verified — the directory's rule 4 governs
that, and no test can enforce it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ADR_DIR = Path(__file__).resolve().parents[2] / "docs" / "adr"
INDEX = ADR_DIR / "README.md"

#: `0003-immutable-ab-update.md` -> ("0003", "0003-immutable-ab-update.md")
_ADR_FILE = re.compile(r"^(?P<number>\d{4})-[a-z0-9_-]+\.md$")
#: A Records row: `| [0003](0003-immutable-ab-update.md) | question | status |`
_INDEX_ROW = re.compile(r"^\|\s*\[(?P<number>\d{4})\]\((?P<href>[^)]+)\)\s*\|")
_TITLE = re.compile(r"^# ADR-(?P<number>\d{4}):\s+\S")


def _adr_files() -> dict[str, Path]:
    found: dict[str, Path] = {}
    for path in sorted(ADR_DIR.glob("*.md")):
        match = _ADR_FILE.match(path.name)
        if match:
            found[match.group("number")] = path
    return found


def _index_rows() -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in INDEX.read_text(encoding="utf-8").splitlines():
        match = _INDEX_ROW.match(line)
        if match:
            rows[match.group("number")] = match.group("href")
    return rows


@pytest.fixture(scope="module")
def files() -> dict[str, Path]:
    found = _adr_files()
    assert found, f"no ADR files matched under {ADR_DIR}; the naming changed"
    return found


@pytest.fixture(scope="module")
def rows() -> dict[str, str]:
    found = _index_rows()
    assert found, f"parsed no Records rows from {INDEX}; the table format changed"
    return found


def test_every_adr_has_a_row_in_the_index(files, rows) -> None:
    missing = sorted(set(files) - set(rows))
    assert not missing, (
        f"ADRs with no row in {INDEX.name}: {missing} — a decision nobody "
        "reading the index would find"
    )


def test_every_index_row_points_at_an_adr_that_exists(files, rows) -> None:
    phantom = sorted(set(rows) - set(files))
    assert not phantom, f"index rows for ADRs that do not exist: {phantom}"
    for number, href in rows.items():
        assert href == files[number].name, (
            f"row {number} links to {href!r}, the file is {files[number].name!r}"
        )


def test_adr_numbers_are_contiguous_from_one(files) -> None:
    """A gap is either a deleted decision or a typo; both need explaining."""

    numbers = sorted(int(n) for n in files)
    assert numbers == list(range(1, len(numbers) + 1)), (
        f"ADR numbers are not 1..{len(numbers)} with no gaps: {numbers}"
    )


def test_each_adr_titles_itself_with_its_own_number(files) -> None:
    for number, path in files.items():
        first_line = path.read_text(encoding="utf-8").splitlines()[0]
        match = _TITLE.match(first_line)
        assert match, f"{path.name}: first line is not '# ADR-NNNN: <title>': {first_line!r}"
        assert match.group("number") == number, (
            f"{path.name} is titled ADR-{match.group('number')}"
        )


def test_each_adr_states_a_status(files) -> None:
    """Rule 4: an ADR never promotes status — but it must declare one."""

    for path in files.values():
        head = path.read_text(encoding="utf-8").splitlines()[:12]
        assert any(line.startswith("Status:") for line in head), (
            f"{path.name} has no 'Status:' line in its first 12 lines"
        )
