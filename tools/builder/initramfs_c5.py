"""Measure a candidate builder against C5: deterministic control of the initramfs.

`ADR-0002` D3 names C5 as "the criterion most likely to eliminate an otherwise
attractive tool", and D4.1 requires it to be **measured**, never read from a
tool's documentation. This module is the instrument: it takes what an inspector
found inside a **built** initramfs and decides whether that build satisfies C5.

The shape follows from what C5 is actually about. Boot's quarantine has to be the
first thing the initramfs does (`docs/threat-model.md` §3.1), which means Boot
must be able to pin *what is in there*, *in what order*, and *where each piece
came from*. A builder that cannot answer those three questions has not failed a
test — it has made the product's defining property unverifiable.

So a build is refused when any hook cannot be pinned:

- a hook Boot did not pin entered the image;
- the order could not be established at all;
- a hook depends on a path outside the build root, so the image is a function of
  the machine it was built on;
- a hook carries a shell fragment, which is an input nobody reviewed;
- a hook's origin cannot be named, or it has no digest — in both cases there is
  nothing to pin it *to*.

The verdict vocabulary is `pass`, `fail`, `inconclusive`, and every result
carries **how it was established**. `inconclusive` is a first-class answer: no
build host, an inspector that could not read the image, a run that never
happened. Recording that honestly is the difference between an evaluation and a
formality.

**One build host never establishes reproducibility.** `C5Result` will not
describe a single-host result as reproduced, and there is no `SUPPORTED` verdict
for a caller to reach for. That is `ADR-0002` D1.3 applied to this criterion.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from enum import Enum

from azazel_boot.quarantine import EARLY_HOOKS

#: Boot's pinned hooks, in order. Imported rather than restated: a second copy
#: would be a second source of truth for the one thing C5 is about.
PINNED_HOOKS = EARLY_HOOKS

#: A hook entry's digest form. Anything else is not something to pin to.
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

#: A path that leaves the build root makes the image a function of the machine
#: it was built on.
_ABSOLUTE_OR_ESCAPING = re.compile(r"^/|(^|/)\.\.(/|$)")

#: Characters that turn a hook argument into a shell fragment.
_SHELL = re.compile(r"[;&|`$><\n]|\$\(")


class Provenance(Enum):
    """Where a hook in the built image came from.

    `UNKNOWN` is the value that matters: a builder that cannot say where a hook
    came from cannot let Boot pin it, whatever else it does well.
    """

    PINNED_BY_BOOT = "pinned_by_boot"
    BUILDER_DEFAULT = "builder_default"
    HOST_DERIVED = "host_derived"
    UNKNOWN = "unknown"


class Verdict(Enum):
    """The C5 answer. There is no `SUPPORTED` and no `SELECTED`.

    A criterion is met or not met by a build; a tool is selected by an ADR
    (`ADR-0009` D8 P7).
    """

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class EvidenceType(Enum):
    """How the verdict was established. `ADR-0002` D4.1 forbids the third one
    from standing in for the first."""

    MEASURED_ON_A_BUILT_INITRAMFS = "measured_on_a_built_initramfs"
    READ_FROM_TOOL_DOCUMENTATION = "read_from_tool_documentation"
    NOT_MEASURED = "not_measured"


class Fault(Enum):
    UNPINNED_HOOK = "unpinned_hook"
    HOOK_MISSING = "hook_missing"
    ORDER_NOT_DETERMINED = "order_not_determined"
    ORDER_CHANGED = "order_changed"
    QUARANTINE_NOT_FIRST = "quarantine_not_first"
    HOST_PATH_DEPENDENCE = "host_path_dependence"
    SHELL_FRAGMENT = "shell_fragment"
    PROVENANCE_UNKNOWN = "provenance_unknown"
    DIGEST_MISSING = "digest_missing"


@dataclass(frozen=True)
class HookEntry:
    """One hook as an inspector found it inside the built image."""

    name: str
    digest: str | None
    provenance: Provenance
    #: Paths and arguments the hook carries, as read out of the image.
    arguments: tuple[str, ...] = ()


@dataclass(frozen=True)
class InitramfsInspection:
    """What an inspector could establish about a built initramfs.

    `order_established` is separate from the order itself: an inspector that
    lists hooks but cannot say when each runs has found contents, not control,
    and C5 is about control.
    """

    candidate: str
    build_host_id: str
    hooks: tuple[HookEntry, ...]
    order_established: bool


@dataclass(frozen=True)
class C5Result:
    """A verdict, how it was reached, and what it does not establish."""

    candidate: str
    verdict: Verdict
    evidence_type: EvidenceType
    faults: tuple[Fault, ...]
    build_host_count: int
    detail: str

    @property
    def reproducibility_established(self) -> bool:
        """Always false below two independent hosts, whatever the verdict.

        C5 is about one build's determinism. Reproducibility is C1, it needs two
        independent builders (`ADR-0002` D1.3), and a passing C5 on one host says
        nothing about it.
        """

        return False

    @property
    def selects_a_builder(self) -> bool:
        """Never. A selection is an ADR, not a measurement."""

        return False

    def to_json(self) -> str:
        document = asdict(self)
        document["verdict"] = self.verdict.value
        document["evidence_type"] = self.evidence_type.value
        document["faults"] = [fault.value for fault in self.faults]
        document["reproducibility_established"] = False
        document["selects_a_builder"] = False
        return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def not_measured(candidate: str, detail: str) -> C5Result:
    """The honest result when no build happened.

    An evaluation that cannot run produces this, not a blank and not a pass.
    """

    return C5Result(
        candidate=candidate,
        verdict=Verdict.INCONCLUSIVE,
        evidence_type=EvidenceType.NOT_MEASURED,
        faults=(),
        build_host_count=0,
        detail=detail,
    )


def evaluate(inspection: InitramfsInspection) -> C5Result:
    """Decide C5 for one built initramfs on one build host."""

    faults: list[Fault] = []
    names = tuple(hook.name for hook in inspection.hooks)

    if not inspection.order_established:
        # Contents without order is not control. Everything else is secondary,
        # because a hook set whose ordering is unknown cannot be pinned at all.
        faults.append(Fault.ORDER_NOT_DETERMINED)
    else:
        missing = [name for name in PINNED_HOOKS if name not in names]
        if missing:
            faults.append(Fault.HOOK_MISSING)
        if not names or names[0] != PINNED_HOOKS[0]:
            faults.append(Fault.QUARANTINE_NOT_FIRST)
        elif names != PINNED_HOOKS:
            faults.append(Fault.ORDER_CHANGED)

    for hook in inspection.hooks:
        if hook.name not in PINNED_HOOKS:
            faults.append(Fault.UNPINNED_HOOK)
        if hook.provenance is Provenance.UNKNOWN:
            faults.append(Fault.PROVENANCE_UNKNOWN)
        if hook.provenance is Provenance.HOST_DERIVED:
            faults.append(Fault.HOST_PATH_DEPENDENCE)
        if hook.digest is None or not DIGEST.match(hook.digest):
            faults.append(Fault.DIGEST_MISSING)
        for argument in hook.arguments:
            if _ABSOLUTE_OR_ESCAPING.search(argument):
                faults.append(Fault.HOST_PATH_DEPENDENCE)
            if _SHELL.search(argument):
                faults.append(Fault.SHELL_FRAGMENT)

    ordered = tuple(sorted(set(faults), key=lambda fault: list(Fault).index(fault)))
    return C5Result(
        candidate=inspection.candidate,
        verdict=Verdict.PASS if not ordered else Verdict.FAIL,
        evidence_type=EvidenceType.MEASURED_ON_A_BUILT_INITRAMFS,
        faults=ordered,
        build_host_count=1,
        detail=(
            "one build host; C5 is a property of this build, and C1 is untouched"
            if not ordered
            else "the build could not be pinned"
        ),
    )
