"""The initramfs contract, checked against the built artifact rather than hoped for.

`ADR-0002` C5 — deterministic control of the initramfs — is the criterion most
likely to eliminate a build tool, and the reason is in `verify_initramfs`: the
quarantine has to be *first*, the hook set has to be exactly what Boot pinned,
and a tool that injects its own hook or reorders them produces an image that is
not a Boot image. Expressing that as a check on the artifact means a builder
cannot satisfy it by documentation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from azazel_boot.quarantine import (
    EARLY_HOOKS,
    EXCLUDED_FROM_THE_ZERO_WRITE_CLAIM,
    POLICY_VERSION,
    ImageRefused,
    InitramfsManifest,
    Refusal,
    verify_initramfs,
)

POLICY_FILE = Path(__file__).resolve().parents[2] / "config" / "quarantine" / "policy-v1.json"


def manifest(**overrides) -> InitramfsManifest:
    attributes = {
        "policy_version": POLICY_VERSION,
        "hooks": EARLY_HOOKS,
        "resume_enabled": False,
        "automount_rules": (),
    }
    attributes.update(overrides)
    return InitramfsManifest(**attributes)


def test_the_pinned_policy_file_and_the_module_agree() -> None:
    """A build pins the file; the running code implements it. They cannot drift."""

    document = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
    assert document["version"] == POLICY_VERSION
    assert tuple(document["early_hooks"]) == EARLY_HOOKS
    assert tuple(document["excluded_from_the_zero_write_claim"]) == (
        EXCLUDED_FROM_THE_ZERO_WRITE_CLAIM
    )


def test_the_quarantine_hook_is_the_first_one() -> None:
    assert EARLY_HOOKS[0] == "az-quarantine-block-devices"


def test_a_conforming_manifest_is_accepted() -> None:
    verify_initramfs(manifest())


def test_a_manifest_that_runs_something_before_the_quarantine_is_refused() -> None:
    """A quarantine that starts second has already lost."""

    reordered = (EARLY_HOOKS[1], EARLY_HOOKS[0], *EARLY_HOOKS[2:])
    with pytest.raises(ImageRefused) as refused:
        verify_initramfs(manifest(hooks=reordered))
    assert refused.value.refusal is Refusal.QUARANTINE_NOT_FIRST


def test_a_reordered_manifest_is_refused_even_when_the_quarantine_is_first() -> None:
    reordered = (EARLY_HOOKS[0], EARLY_HOOKS[2], EARLY_HOOKS[1], *EARLY_HOOKS[3:])
    with pytest.raises(ImageRefused) as refused:
        verify_initramfs(manifest(hooks=reordered))
    assert refused.value.refusal is Refusal.HOOK_ORDER_CHANGED


def test_a_hook_the_builder_added_is_refused() -> None:
    """This is C5: an unpinned hook runs before any Boot policy code."""

    with pytest.raises(ImageRefused) as refused:
        verify_initramfs(manifest(hooks=(*EARLY_HOOKS, "vendor-helpful-hook")))
    assert refused.value.refusal is Refusal.UNPINNED_HOOK


@pytest.mark.parametrize("index", range(len(EARLY_HOOKS)))
def test_a_missing_hook_is_refused(index: int) -> None:
    hooks = tuple(hook for position, hook in enumerate(EARLY_HOOKS) if position != index)
    with pytest.raises(ImageRefused) as refused:
        verify_initramfs(manifest(hooks=hooks))
    assert refused.value.refusal is Refusal.HOOK_MISSING


def test_an_image_built_against_another_policy_version_is_refused() -> None:
    with pytest.raises(ImageRefused) as refused:
        verify_initramfs(manifest(policy_version="quarantine.v0"))
    assert refused.value.refusal is Refusal.WRONG_POLICY_VERSION


def test_resume_is_refused_unconditionally() -> None:
    """Resuming consumes the owner's hibernation image. That is their session."""

    with pytest.raises(ImageRefused) as refused:
        verify_initramfs(manifest(resume_enabled=True))
    assert refused.value.refusal is Refusal.RESUME_ENABLED


def test_an_automount_rule_in_the_image_is_refused() -> None:
    with pytest.raises(ImageRefused) as refused:
        verify_initramfs(manifest(automount_rules=("99-helpful.rules",)))
    assert refused.value.refusal is Refusal.AUTOMOUNT_RULE_PRESENT


def test_firmware_nvram_changes_are_named_as_excluded_rather_than_prevented() -> None:
    """The threat model reports them; it never promises to stop them."""

    assert EXCLUDED_FROM_THE_ZERO_WRITE_CLAIM
    assert all("nvram" in item for item in EXCLUDED_FROM_THE_ZERO_WRITE_CLAIM)
