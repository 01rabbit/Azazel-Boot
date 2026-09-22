"""C5 is measured, and `inconclusive` is an answer rather than a gap.

`ADR-0002` D3 calls C5 the criterion most likely to eliminate a tool, and D4.1
forbids satisfying it from a tool's documentation. Two properties matter more
than the individual refusals below.

First, **a result carries how it was reached.** `EvidenceType.NOT_MEASURED` is a
value a result can hold, so an evaluation that could not run says so instead of
leaving a blank that later reads as a pass.

Second, **nothing here can promote anything.** There is no `SUPPORTED` verdict,
`reproducibility_established` is false whatever the verdict, and
`selects_a_builder` is false always. C5 is a property of one build on one host;
C1 needs two independent builders, and a selection is an ADR.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.builder.initramfs_c5 import (  # noqa: E402
    PINNED_HOOKS,
    C5Result,
    EvidenceType,
    Fault,
    HookEntry,
    InitramfsInspection,
    Provenance,
    Verdict,
    evaluate,
    not_measured,
)

DIGEST = "sha256:" + "a" * 64


def hook(name: str, **overrides) -> HookEntry:
    attributes = {
        "name": name,
        "digest": DIGEST,
        "provenance": Provenance.PINNED_BY_BOOT,
        "arguments": (),
    }
    attributes.update(overrides)
    return HookEntry(**attributes)


def inspection(**overrides) -> InitramfsInspection:
    attributes = {
        "candidate": "live-build",
        "build_host_id": "0123456789abcdef",
        "hooks": tuple(hook(name) for name in PINNED_HOOKS),
        "order_established": True,
    }
    attributes.update(overrides)
    return InitramfsInspection(**attributes)


def test_the_pinned_hooks_are_the_quarantines_own_list() -> None:
    """One source of truth: a second copy would be a second contract."""

    from azazel_boot.quarantine import EARLY_HOOKS

    assert PINNED_HOOKS is EARLY_HOOKS


def test_a_fully_pinned_build_passes_c5() -> None:
    result = evaluate(inspection())
    assert result.verdict is Verdict.PASS
    assert result.evidence_type is EvidenceType.MEASURED_ON_A_BUILT_INITRAMFS
    assert result.faults == ()


def test_an_unpinned_hook_fails() -> None:
    extra = (*[hook(name) for name in PINNED_HOOKS], hook("vendor-helpful-hook"))
    result = evaluate(inspection(hooks=extra))
    assert result.verdict is Verdict.FAIL
    assert Fault.UNPINNED_HOOK in result.faults


def test_an_order_that_could_not_be_established_fails() -> None:
    """Contents without order is not control, and C5 is about control."""

    result = evaluate(inspection(order_established=False))
    assert result.verdict is Verdict.FAIL
    assert Fault.ORDER_NOT_DETERMINED in result.faults


def test_a_quarantine_hook_that_does_not_run_first_fails() -> None:
    reordered = tuple(hook(name) for name in (PINNED_HOOKS[1], PINNED_HOOKS[0], *PINNED_HOOKS[2:]))
    result = evaluate(inspection(hooks=reordered))
    assert Fault.QUARANTINE_NOT_FIRST in result.faults


def test_a_reordered_build_fails_even_with_the_quarantine_first() -> None:
    reordered = tuple(
        hook(name)
        for name in (PINNED_HOOKS[0], PINNED_HOOKS[2], PINNED_HOOKS[1], *PINNED_HOOKS[3:])
    )
    assert Fault.ORDER_CHANGED in evaluate(inspection(hooks=reordered)).faults


def test_a_missing_hook_fails() -> None:
    assert Fault.HOOK_MISSING in evaluate(
        inspection(hooks=tuple(hook(name) for name in PINNED_HOOKS[1:]))
    ).faults


@pytest.mark.parametrize(
    "argument",
    ["/etc/live/build.conf", "../../outside/file", "a/../../escape", "/usr/lib/x"],
)
def test_a_hook_that_reaches_outside_the_build_root_fails(argument: str) -> None:
    """An image that is a function of the machine it was built on is not pinned."""

    hooks = (hook(PINNED_HOOKS[0], arguments=(argument,)), *[hook(n) for n in PINNED_HOOKS[1:]])
    assert Fault.HOST_PATH_DEPENDENCE in evaluate(inspection(hooks=hooks)).faults


@pytest.mark.parametrize(
    "argument",
    ["x; rm -rf /", "a && b", "a | b", "$(id)", "`id`", "a > b", "a\nb"],
)
def test_a_hook_carrying_a_shell_fragment_fails(argument: str) -> None:
    hooks = (hook(PINNED_HOOKS[0], arguments=(argument,)), *[hook(n) for n in PINNED_HOOKS[1:]])
    assert Fault.SHELL_FRAGMENT in evaluate(inspection(hooks=hooks)).faults


def test_a_hook_whose_origin_cannot_be_named_fails() -> None:
    """A builder that cannot say where a hook came from cannot let Boot pin it."""

    hooks = (
        hook(PINNED_HOOKS[0], provenance=Provenance.UNKNOWN),
        *[hook(name) for name in PINNED_HOOKS[1:]],
    )
    assert Fault.PROVENANCE_UNKNOWN in evaluate(inspection(hooks=hooks)).faults


def test_a_host_derived_hook_fails() -> None:
    hooks = (
        hook(PINNED_HOOKS[0], provenance=Provenance.HOST_DERIVED),
        *[hook(name) for name in PINNED_HOOKS[1:]],
    )
    assert Fault.HOST_PATH_DEPENDENCE in evaluate(inspection(hooks=hooks)).faults


@pytest.mark.parametrize("digest", [None, "", "sha1:" + "a" * 40, "a" * 64])
def test_a_hook_with_nothing_to_pin_to_fails(digest) -> None:
    hooks = (hook(PINNED_HOOKS[0], digest=digest), *[hook(n) for n in PINNED_HOOKS[1:]])
    assert Fault.DIGEST_MISSING in evaluate(inspection(hooks=hooks)).faults


def test_a_result_that_was_never_measured_says_so() -> None:
    result = not_measured("live-build", "no Debian 13 / amd64 build host")
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.evidence_type is EvidenceType.NOT_MEASURED
    assert result.build_host_count == 0


def test_no_verdict_means_supported() -> None:
    assert {member.value for member in Verdict} == {"pass", "fail", "inconclusive"}


def test_documentation_is_a_distinct_evidence_type_and_is_never_produced_here() -> None:
    """It exists so a documentation claim can be filed as one — and not mistaken
    for a measurement."""

    assert EvidenceType.READ_FROM_TOOL_DOCUMENTATION.value == "read_from_tool_documentation"
    assert evaluate(inspection()).evidence_type is not EvidenceType.READ_FROM_TOOL_DOCUMENTATION


def test_a_pass_on_one_host_establishes_neither_reproducibility_nor_a_selection() -> None:
    """C5 is one build's determinism; C1 needs two independent builders."""

    result = evaluate(inspection())
    assert result.verdict is Verdict.PASS
    assert result.build_host_count == 1
    assert result.reproducibility_established is False
    assert result.selects_a_builder is False


def test_a_filed_result_carries_what_it_does_not_establish() -> None:
    filed = json.loads(evaluate(inspection()).to_json())
    assert filed["evidence_type"] == "measured_on_a_built_initramfs"
    assert filed["reproducibility_established"] is False
    assert filed["selects_a_builder"] is False


def test_a_result_is_immutable() -> None:
    import dataclasses

    result = evaluate(inspection())
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.verdict = Verdict.PASS  # type: ignore[misc]
    assert isinstance(result, C5Result)
