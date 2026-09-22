"""The initramfs contract, and the pinned artifact a build consumes.

`ADR-0002` C5 — deterministic control of the initramfs — is the criterion most
likely to eliminate a build tool, and the reason is in `verify_initramfs`: the
quarantine has to be *first*, the hook set has to be exactly what Boot pinned,
and it has to survive into userspace.

An adversarial review found two things this file now checks. The policy file's
action list was asserted by nothing and had already drifted from the module, so
a reader of the pinned artifact would have drawn the wrong conclusion about what
is blocked. And the first refusal masked the rest, so a version-string typo hid
resume being enabled — the fault that consumes the owner's hibernation image.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from azazel_boot.quarantine import (
    EARLY_HOOKS,
    EXCLUDED_FROM_THE_ZERO_WRITE_CLAIM,
    IMAGE_REFUSAL_SEVERITY,
    NEVER_ALLOWED_ANYWHERE,
    POLICY_VERSION,
    UNBLOCKABLE_BY_APPROVAL,
    WRITING_ACTIONS,
    Action,
    ImageRefused,
    InitramfsManifest,
    Refusal,
    verify_initramfs,
)

POLICY_FILE = Path(__file__).resolve().parents[2] / "config" / "quarantine" / "policy-v1.json"


@pytest.fixture(scope="module")
def policy() -> dict:
    return json.loads(POLICY_FILE.read_text(encoding="utf-8"))


def manifest(**overrides) -> InitramfsManifest:
    attributes = {
        "policy_version": POLICY_VERSION,
        "hooks": EARLY_HOOKS,
        "resume_enabled": False,
        "automount_rules": (),
        "quarantine_persists_into_userspace": True,
    }
    attributes.update(overrides)
    return InitramfsManifest(**attributes)


# --- the pinned artifact and the module may not drift ----------------------


def test_the_pinned_policy_file_and_the_module_agree_on_every_field(policy: dict) -> None:
    assert policy["version"] == POLICY_VERSION
    assert tuple(policy["early_hooks"]) == EARLY_HOOKS
    assert tuple(policy["excluded_from_the_zero_write_claim"]) == (
        EXCLUDED_FROM_THE_ZERO_WRITE_CLAIM
    )
    assert {member.value for member in Action} == set(policy["actions"])
    assert {member.value for member in NEVER_ALLOWED_ANYWHERE} == set(
        policy["never_allowed_anywhere"]
    )
    assert {member.value for member in UNBLOCKABLE_BY_APPROVAL} == set(
        policy["unblockable_by_approval"]
    )


def test_the_policy_file_states_the_initramfs_requirements_the_module_checks(
    policy: dict,
) -> None:
    requirements = policy["initramfs_requirements"]
    assert requirements["quarantine_hook_runs_first"] is True
    assert requirements["quarantine_persists_into_userspace"] is True
    assert requirements["resume_enabled"] is False
    assert requirements["automount_rules"] == []


def test_every_action_but_read_is_a_writing_action() -> None:
    """Dropping a member from this set would silently delete its tests."""

    assert {member.value for member in WRITING_ACTIONS} == {
        member.value for member in Action
    } - {"read"}
    assert len(WRITING_ACTIONS) == len(Action) - 1


def test_assembly_is_refused_everywhere_because_it_is_not_per_device() -> None:
    """A volume group scanned from the medium can pull in host physical volumes.

    `evaluate(device, action)` cannot express a cross-device write at all, so
    assembly is refused everywhere rather than adjudicated per device.
    """

    assert {
        Action.LVM_ASSEMBLY,
        Action.MD_ASSEMBLY,
        Action.ZFS_IMPORT,
        Action.FIRMWARE_UPDATE,
        Action.RESUME_FROM_HIBERNATION,
    } == set(NEVER_ALLOWED_ANYWHERE)


def test_the_severity_order_covers_every_refusal_an_image_check_can_raise() -> None:
    """Derived from the function, not restated from the constant.

    A second copy of the constant would pass while the defect it is named for —
    someone adds a fault to `verify_initramfs` and forgets the order, and the
    build gate crashes past every `except` — went straight through. Two
    manifests raise every fault the function can raise between them.
    """

    everything_wrong = manifest(
        policy_version="typo",
        hooks=("vendor-hook", *EARLY_HOOKS[1:]),
        resume_enabled=True,
        automount_rules=("99-helpful.rules",),
        quarantine_persists_into_userspace=False,
    )
    merely_reordered = manifest(
        hooks=(EARLY_HOOKS[0], EARLY_HOOKS[2], EARLY_HOOKS[1], *EARLY_HOOKS[3:])
    )

    raised: set[Refusal] = set()
    for candidate in (everything_wrong, merely_reordered):
        with pytest.raises(ImageRefused) as refused:
            verify_initramfs(candidate)
        raised |= {fault[0] for fault in refused.value.faults}

    assert raised == set(IMAGE_REFUSAL_SEVERITY), (
        "a fault `verify_initramfs` can raise is missing from the severity "
        "order, or the order names one it cannot"
    )


def test_a_refusal_outside_the_severity_order_does_not_crash_the_gate() -> None:
    refused = ImageRefused(((Refusal.NOT_CONFIRMED, "not an image fault"),))
    assert refused.refusal is Refusal.NOT_CONFIRMED
    with pytest.raises(ValueError):
        ImageRefused(())


def test_the_quarantine_hook_is_the_first_one() -> None:
    assert EARLY_HOOKS[0] == "az-quarantine-block-devices"


# --- what a built image must satisfy ---------------------------------------


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
    assert Refusal.HOOK_MISSING in {fault[0] for fault in refused.value.faults}


def test_an_empty_hook_list_is_refused_without_an_index_error() -> None:
    with pytest.raises(ImageRefused) as refused:
        verify_initramfs(manifest(hooks=()))
    assert Refusal.HOOK_MISSING in {fault[0] for fault in refused.value.faults}


def test_a_duplicated_hook_is_refused() -> None:
    with pytest.raises(ImageRefused):
        verify_initramfs(manifest(hooks=(EARLY_HOOKS[0], *EARLY_HOOKS)))


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


def test_a_quarantine_that_does_not_survive_into_userspace_is_refused() -> None:
    """Threat model section 3.1: re-establishing it in userspace starts too late."""

    with pytest.raises(ImageRefused) as refused:
        verify_initramfs(manifest(quarantine_persists_into_userspace=False))
    assert refused.value.refusal is Refusal.QUARANTINE_NOT_PERSISTENT


def test_a_trivial_fault_does_not_mask_a_dangerous_one() -> None:
    """A version typo must not hide resume being enabled."""

    with pytest.raises(ImageRefused) as refused:
        verify_initramfs(
            manifest(
                policy_version="typo",
                resume_enabled=True,
                automount_rules=("99-helpful.rules",),
            )
        )
    found = {fault[0] for fault in refused.value.faults}
    assert {
        Refusal.RESUME_ENABLED,
        Refusal.AUTOMOUNT_RULE_PRESENT,
        Refusal.WRONG_POLICY_VERSION,
    } <= found
    assert refused.value.refusal is Refusal.RESUME_ENABLED


def test_firmware_nvram_changes_are_named_as_excluded_rather_than_prevented() -> None:
    """The threat model reports them; it never promises to stop them."""

    assert EXCLUDED_FROM_THE_ZERO_WRITE_CLAIM
    assert all("nvram" in item for item in EXCLUDED_FROM_THE_ZERO_WRITE_CLAIM)
