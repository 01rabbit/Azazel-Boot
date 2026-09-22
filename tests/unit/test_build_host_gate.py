"""An evaluation build runs on the Debian 13 / amd64 build host, or not at all.

An evaluation is a build, so it inherits every constraint a build has. A build
that ran somewhere else would be evidence about that somewhere else — and the
first thing anyone would do with it is quote it as evidence about the candidate.

The candidate registry is checked here too, for what it cannot say: `live-build`
is listed because `ADR-0008` D2 makes it a constraint on the still-open
selection, and `Candidate` has no field that could record adoption.
"""

from __future__ import annotations

import sys
from dataclasses import fields
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.builder.candidates import (  # noqa: E402
    CANDIDATES,
    LIVE_BUILD,
    Candidate,
    HostRefusal,
    check_build_host,
)

DEBIAN_13 = 'PRETTY_NAME="Debian GNU/Linux 13"\nID=debian\nVERSION_ID="13"\n'


def os_release(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "os-release"
    path.write_text(text, encoding="utf-8")
    return path


def test_the_debian_13_amd64_host_with_the_tool_present_is_permitted(tmp_path: Path) -> None:
    check = check_build_host(os_release(tmp_path, DEBIAN_13), "x86_64", tool_present=True)
    assert check.permitted is True
    assert check.refusal is None


@pytest.mark.parametrize(
    "text",
    [
        'ID=ubuntu\nVERSION_ID="24.04"\n',
        'ID=debian\nVERSION_ID="12"\n',
        'ID=debian\nVERSION_ID="trixie"\n',
        "",
    ],
)
def test_a_host_that_is_not_debian_13_is_refused(tmp_path: Path, text: str) -> None:
    check = check_build_host(os_release(tmp_path, text), "x86_64", tool_present=True)
    assert check.permitted is False
    assert check.refusal is HostRefusal.NOT_THE_BUILD_HOST


@pytest.mark.parametrize("architecture", ["aarch64", "armv7l", "riscv64", ""])
def test_another_architecture_is_refused(tmp_path: Path, architecture: str) -> None:
    check = check_build_host(os_release(tmp_path, DEBIAN_13), architecture, tool_present=True)
    assert check.permitted is False
    assert check.refusal is HostRefusal.NOT_THE_BUILD_HOST


def test_the_refusal_names_what_the_host_is_without_guessing(tmp_path: Path) -> None:
    check = check_build_host(
        os_release(tmp_path, 'ID=ubuntu\nVERSION_ID="24.04"\n'), "x86_64", tool_present=True
    )
    assert "ubuntu" in check.detail and "24.04" in check.detail


def test_an_unreadable_os_release_is_refused_rather_than_assumed(tmp_path: Path) -> None:
    check = check_build_host(tmp_path / "absent", "x86_64", tool_present=True)
    assert check.permitted is False
    assert check.refusal is HostRefusal.OS_RELEASE_UNREADABLE


def test_the_right_host_without_the_candidate_installed_is_refused(tmp_path: Path) -> None:
    check = check_build_host(os_release(tmp_path, DEBIAN_13), "x86_64", tool_present=False)
    assert check.permitted is False
    assert check.refusal is HostRefusal.TOOL_ABSENT


def test_a_candidate_cannot_record_that_it_was_adopted() -> None:
    """`ADR-0002` D2 leaves the builder open; a registry entry is not a choice."""

    names = {field.name for field in fields(Candidate)}
    for forbidden in ("selected", "preferred", "chosen", "adopted", "rank", "default"):
        assert forbidden not in names


def test_live_build_is_listed_as_a_constraint_not_a_selection() -> None:
    assert LIVE_BUILD in CANDIDATES
    assert "not a selection" in LIVE_BUILD.standing
    assert "ADR-0008 D2" in LIVE_BUILD.standing


def test_the_registry_says_what_an_inspector_must_read() -> None:
    """C5 is decided from the image, so the requirements are on the inspector."""

    requirements = " ".join(LIVE_BUILD.inspection_requirements)
    for needed in ("ordered list of hooks", "digest", "where each hook came from"):
        assert needed in requirements
