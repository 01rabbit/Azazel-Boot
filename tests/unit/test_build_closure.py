"""The input closure must refuse everything it cannot pin.

`docs/builder-writer-contract.md` section 5 says nothing an operator types
becomes a source, and `ADR-0002` D3 C2 says an unpinned input fails the
reproducibility criterion invisibly. Both are properties of a refusal, so the
tests below are mostly about what does *not* resolve.

The most important one is `test_the_shipped_configuration_resolves_nothing`:
this repository has pinned no snapshot, no toolchain and no firmware set, and
the configuration it ships says so by refusing. A change that makes that test
pass by accident has pinned something, which is a decision, not a fix.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.builder.closure import (  # noqa: E402
    Closure,
    ClosureRefused,
    Configuration,
    Refusal,
    load_configuration,
    resolve,
)

CONFIG_DIR = ROOT / "config" / "builder"

PINNED = {
    "debian-snapshot": "snapshot:20260101T000000Z",
    "live-image-config": "sha256:" + "a" * 64,
    "firmware-set": "sha256:" + "b" * 64,
    "builder-toolchain": "sha256:" + "c" * 64,
}


def _configuration(*, inputs=None, pins=None, policy="quarantine.v2") -> Configuration:
    names = list(PINNED) if inputs is None else list(inputs)
    return Configuration(
        profiles={
            "responder-eval": {"quarantine_policy_ref": policy, "inputs": names},
        },
        pins=dict(PINNED) if pins is None else dict(pins),
    )


def test_the_shipped_configuration_parses_and_names_the_evaluation_profile() -> None:
    configuration = load_configuration(CONFIG_DIR)
    assert configuration.profile_ids == ("responder-eval",)


def test_the_shipped_configuration_resolves_nothing() -> None:
    """Nothing has been pinned, so no profile can be built. That is the state."""

    configuration = load_configuration(CONFIG_DIR)
    with pytest.raises(ClosureRefused) as refused:
        resolve(configuration, "responder-eval")
    assert refused.value.refusal is Refusal.UNPINNED_INPUT


def test_a_non_utf8_configuration_is_refused_not_crashed(tmp_path: Path) -> None:
    (tmp_path / "profiles.json").write_bytes(b"\xff")
    (tmp_path / "pins.json").write_text(
        json.dumps({"schema": "azazel-boot/build-pins@1", "pins": {}}), encoding="utf-8"
    )

    with pytest.raises(ClosureRefused) as refused:
        load_configuration(tmp_path)

    assert refused.value.refusal is Refusal.BAD_SCHEMA


def test_the_shipped_pins_file_is_empty() -> None:
    document = json.loads((CONFIG_DIR / "pins.json").read_text(encoding="utf-8"))
    assert document["pins"] == {}, (
        "a pin appeared in the shipped configuration; pinning a snapshot or a "
        "toolchain is a decision that belongs in a PR of its own"
    )


@pytest.mark.parametrize(
    "identifier",
    [
        "https://deb.debian.org/debian",
        "deb.debian.org/debian bookworm main",
        "../../etc/passwd",
        "/dev/sda",
        "live-build; rm -rf /",
        "Responder-Eval",
        "",
    ],
)
def test_a_profile_name_that_is_not_symbolic_is_refused(identifier: str) -> None:
    """A URL, an apt line, a path or a shell fragment cannot name a profile."""

    with pytest.raises(ClosureRefused) as refused:
        resolve(_configuration(), identifier)
    assert refused.value.refusal is Refusal.NOT_SYMBOLIC


def test_an_unknown_profile_is_refused_by_name() -> None:
    with pytest.raises(ClosureRefused) as refused:
        resolve(_configuration(), "responder-prod")
    assert refused.value.refusal is Refusal.UNKNOWN_PROFILE


def test_an_input_the_operator_invented_does_not_resolve() -> None:
    configuration = _configuration(inputs=[*PINNED, "extra-driver"])
    with pytest.raises(ClosureRefused) as refused:
        resolve(configuration, "responder-eval")
    assert refused.value.refusal is Refusal.UNPINNED_INPUT
    assert "extra-driver" in refused.value.detail


@pytest.mark.parametrize(
    "pin",
    ["v1.0", "latest", "bookworm", "main", "a" * 64, "sha1:" + "a" * 40, "snapshot:20260101"],
)
def test_a_pin_that_is_not_an_immutable_form_is_refused(pin: str) -> None:
    pins = dict(PINNED, **{"debian-snapshot": pin})
    with pytest.raises(ClosureRefused) as refused:
        resolve(_configuration(pins=pins), "responder-eval")
    assert refused.value.refusal is Refusal.MUTABLE_PIN


def test_a_pin_for_an_input_the_profile_does_not_use_is_refused() -> None:
    """An orphan pin means the configuration and the profile disagree."""

    pins = dict(PINNED, **{"unused-input": "sha256:" + "d" * 64})
    with pytest.raises(ClosureRefused) as refused:
        resolve(_configuration(pins=pins), "responder-eval")
    assert refused.value.refusal is Refusal.ORPHAN_PIN


def test_a_repeated_input_is_refused() -> None:
    with pytest.raises(ClosureRefused) as refused:
        resolve(_configuration(inputs=[*PINNED, "debian-snapshot"]), "responder-eval")
    assert refused.value.refusal is Refusal.DUPLICATE_INPUT


def test_a_profile_with_no_inputs_is_refused() -> None:
    with pytest.raises(ClosureRefused) as refused:
        resolve(_configuration(inputs=[], pins={}), "responder-eval")
    assert refused.value.refusal is Refusal.EMPTY_PROFILE


@pytest.mark.parametrize("policy", [None, "", "Quarantine V1", 1])
def test_a_profile_that_does_not_pin_a_quarantine_policy_is_refused(policy) -> None:
    """The payload's defining safety property is never an implicit default."""

    with pytest.raises(ClosureRefused) as refused:
        resolve(_configuration(policy=policy), "responder-eval")
    assert refused.value.refusal is Refusal.UNPINNED_QUARANTINE_POLICY


def test_a_resolved_closure_is_ordered_and_complete() -> None:
    closure = resolve(_configuration(), "responder-eval")
    assert closure.inputs == tuple(sorted(PINNED.items()))
    assert closure.quarantine_policy == "quarantine.v2"


def test_the_digest_does_not_depend_on_the_order_the_inputs_were_written_in() -> None:
    forward = resolve(_configuration(inputs=sorted(PINNED)), "responder-eval")
    backward = resolve(_configuration(inputs=sorted(PINNED, reverse=True)), "responder-eval")
    assert forward.digest() == backward.digest()


def test_the_digest_changes_when_a_pin_changes() -> None:
    before = resolve(_configuration(), "responder-eval")
    after = resolve(
        _configuration(pins=dict(PINNED, **{"firmware-set": "sha256:" + "e" * 64})),
        "responder-eval",
    )
    assert before.digest() != after.digest()


def test_the_canonical_form_is_ascii_and_newline_terminated() -> None:
    """Two hosts must produce the same bytes, whatever their locale."""

    canonical = resolve(_configuration(), "responder-eval").canonical_bytes()
    assert canonical.endswith(b"\n")
    canonical.decode("ascii")


def test_a_closure_is_immutable() -> None:
    closure = resolve(_configuration(), "responder-eval")
    with pytest.raises(dataclasses.FrozenInstanceError):
        closure.profile_id = "something-else"  # type: ignore[misc]
    assert isinstance(closure, Closure)
