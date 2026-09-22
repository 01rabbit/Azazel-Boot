"""The candidates under evaluation, and the host an evaluation build may run on.

A candidate is a tool someone proposed. It is **not** a selection: `ADR-0002` D2
leaves the builder open and `ADR-0009` D8 P7 says a selection happens in an ADR.
Nothing in this module adopts anything, and `Candidate` has no field that could
say it did.

`live-build` is here because `ADR-0008` D2 records it as the builder the Debian
13 Live baseline is written against — a **constraint on** the eventual
selection, not the selection. Listing it is what lets C5 be measured against it,
which is the step that would eliminate it if it cannot pin the initramfs.

The build-host gate exists because the owner fixed where an evaluation build may
run: inside a dedicated Debian 13 / amd64 build environment, and nowhere else.
An evaluation is a build, so it inherits every constraint a build has. A host
that is not that host produces an `inconclusive` result, not a build.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

#: The only host an evaluation build may run on (owner's decision, 2026-09-22;
#: `ADR-0009` D3 for the same profile applied to a release build).
REQUIRED_OS_ID = "debian"
REQUIRED_OS_VERSION_ID = "13"
REQUIRED_ARCHITECTURE = "x86_64"


class HostRefusal(Enum):
    NOT_THE_BUILD_HOST = "not_the_build_host"
    OS_RELEASE_UNREADABLE = "os_release_unreadable"
    TOOL_ABSENT = "tool_absent"


@dataclass(frozen=True)
class Candidate:
    """A tool proposed for evaluation.

    There is deliberately no `selected` field, no `preferred` field and no
    ranking. A record that cannot express adoption cannot be read as adopting.
    """

    name: str
    #: What `ADR-0008` D2 says about it, quoted rather than paraphrased.
    standing: str
    #: The command an evaluation would drive, for the record. Nothing here runs
    #: it: this package executes no subprocess, by design and by test.
    invocation: str
    #: What an inspector must read out of the built image for C5 to be decided.
    inspection_requirements: tuple[str, ...]


LIVE_BUILD = Candidate(
    name="live-build",
    standing=(
        "the builder the Debian 13 Live baseline is written against "
        "(ADR-0008 D2) — a constraint on ADR-0002's open selection, not a "
        "selection"
    ),
    invocation="lb config && lb build, inside the Debian 13 build environment",
    inspection_requirements=(
        "the ordered list of hooks that run in the initramfs",
        "a digest for each hook's contents",
        "where each hook came from: pinned by Boot, a builder default, or "
        "derived from the build host",
        "every path and argument a hook carries, so host dependence and shell "
        "fragments are visible",
    ),
)

CANDIDATES = (LIVE_BUILD,)


@dataclass(frozen=True)
class HostCheck:
    """Whether this host may run an evaluation build, and why not when it may not."""

    permitted: bool
    refusal: HostRefusal | None
    detail: str


def check_build_host(
    os_release: Path, architecture: str, *, tool_present: bool
) -> HostCheck:
    """Refuse a host that is not the Debian 13 / amd64 build environment.

    Reading `/etc/os-release` is enough to answer this, and it is the whole
    check: an evaluation build that ran somewhere else would be evidence about
    that somewhere else.
    """

    try:
        text = os_release.read_text(encoding="utf-8")
    except OSError as error:
        return HostCheck(False, HostRefusal.OS_RELEASE_UNREADABLE, str(error))

    fields: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            name, _, value = line.partition("=")
            fields[name.strip()] = value.strip().strip('"')

    if (
        fields.get("ID") != REQUIRED_OS_ID
        or fields.get("VERSION_ID") != REQUIRED_OS_VERSION_ID
        or architecture != REQUIRED_ARCHITECTURE
    ):
        return HostCheck(
            False,
            HostRefusal.NOT_THE_BUILD_HOST,
            f"this host is {fields.get('ID', '?')} {fields.get('VERSION_ID', '?')} "
            f"/ {architecture}; an evaluation build runs on "
            f"{REQUIRED_OS_ID} {REQUIRED_OS_VERSION_ID} / {REQUIRED_ARCHITECTURE} "
            "or not at all",
        )
    if not tool_present:
        return HostCheck(
            False, HostRefusal.TOOL_ABSENT, "the candidate is not installed on this host"
        )
    return HostCheck(True, None, "")
