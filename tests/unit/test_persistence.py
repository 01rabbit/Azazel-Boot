"""Persistence decisions, on synthetic media, with no device anywhere near them.

Every test uses a constructed layout and a constructed disposition. **No real
USB SSD, no real laptop, no loop device and no `/dev` path is involved**, and
nothing here is evidence that a volume can be created, unlocked or repaired on
hardware.

The tests are grouped by the four things that must not happen: persistence
reaching host storage, a volume manager reaching the medium, a failure moving
authority, and a secret reaching a field that could be rendered.
"""

from __future__ import annotations

import pytest

from azazel_boot.commissioning import SessionBinding
from azazel_boot.persistence import (
    DEGRADED_CAPABILITY,
    PARTITION_ROLES,
    VOLUME_MANAGERS,
    MediumLayout,
    Partition,
    PersistenceRefused,
    PersistenceState,
    PersistenceTarget,
    Refusal,
    UnlockOutcome,
    absent,
    check_layout,
    create,
    fence_after_removal,
    recovery_options,
    status_field_names,
    unlock,
)
from azazel_boot.quarantine import Disposition

HOST = "sha256:" + "a" * 64
SESSION = "s1"

#: Names that must not exist on the status model.
CONFIDENTIAL_NAMES = (
    "passphrase",
    "key",
    "recovery_key",
    "key_material",
    "operator",
    "operator_id",
    "identity",
    "serial",
    "device_path",
)


def layout(**overrides) -> MediumLayout:
    partitions = overrides.pop(
        "partitions",
        (
            Partition(role="esp", filesystem="vfat"),
            Partition(role="boot_root", filesystem="squashfs", read_only=True),
            Partition(role="persistence", filesystem="ext4", mappings=("dm-crypt",)),
        ),
    )
    return MediumLayout(
        partition_table=overrides.pop("partition_table", "gpt"), partitions=partitions
    )


def target(**overrides) -> PersistenceTarget:
    return PersistenceTarget(
        disposition=overrides.pop("disposition", Disposition.BOOT_MEDIUM),
        layout=overrides.pop("layout", layout()),
    )


def binding(**overrides) -> SessionBinding:
    return SessionBinding(
        host_fingerprint=overrides.pop("host_fingerprint", HOST),
        session_id=overrides.pop("session_id", SESSION),
    )


def unlock_arguments(**overrides) -> dict:
    arguments = {
        "unlocked": True,
        "integrity_verified": True,
        "stored_generation": 7,
        "last_seen_generation": 7,
        "dirty": False,
        "repairable": True,
    }
    arguments.update(overrides)
    return arguments


# --- persistence never reaches host storage --------------------------------


def test_persistence_is_created_only_on_the_booted_medium() -> None:
    status = create(target(), binding(), session_id=SESSION, host_fingerprint=HOST)
    assert status.state is PersistenceState.LOCKED


def test_host_storage_is_never_a_persistence_target() -> None:
    with pytest.raises(PersistenceRefused) as refused:
        create(
            target(disposition=Disposition.QUARANTINED),
            binding(),
            session_id=SESSION,
            host_fingerprint=HOST,
        )
    assert refused.value.refusal is Refusal.HOST_STORAGE_TARGET


def test_an_unobserved_target_is_refused_rather_than_assumed() -> None:
    with pytest.raises(PersistenceRefused) as refused:
        create(
            target(disposition=None), binding(), session_id=SESSION, host_fingerprint=HOST
        )
    assert refused.value.refusal is Refusal.UNOBSERVED_TARGET


def test_unlocking_also_refuses_a_target_that_is_not_the_medium() -> None:
    """The check is on every act, not only on creation."""

    with pytest.raises(PersistenceRefused):
        unlock(target(disposition=Disposition.QUARANTINED), **unlock_arguments())


# --- the layout is the simple one ------------------------------------------


def test_the_agreed_layout_passes() -> None:
    check_layout(layout())


@pytest.mark.parametrize("manager", VOLUME_MANAGERS)
def test_a_volume_manager_on_the_medium_is_refused(manager: str) -> None:
    """Assembly is not per-device: a group scanned here can reach host disks."""

    partitions = (
        Partition(role="esp", filesystem="vfat"),
        Partition(role="boot_root", filesystem="squashfs", read_only=True),
        Partition(role="persistence", filesystem="ext4", mappings=("dm-crypt", manager)),
    )
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(partitions=partitions))
    assert refused.value.refusal is Refusal.VOLUME_MANAGER_PRESENT


def test_persistence_must_be_a_luks2_volume() -> None:
    partitions = (
        Partition(role="esp", filesystem="vfat"),
        Partition(role="boot_root", filesystem="squashfs", read_only=True),
        Partition(role="persistence", filesystem="ext4"),
    )
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(partitions=partitions))
    assert refused.value.refusal is Refusal.NOT_LUKS2


def test_a_read_write_boot_root_is_refused() -> None:
    partitions = (
        Partition(role="esp", filesystem="vfat"),
        Partition(role="boot_root", filesystem="ext4", read_only=False),
    )
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(partitions=partitions))
    assert refused.value.refusal is Refusal.ROOT_NOT_READ_ONLY


@pytest.mark.parametrize("missing", ["esp", "boot_root"])
def test_a_missing_required_partition_is_refused(missing: str) -> None:
    partitions = tuple(p for p in layout().partitions if p.role != missing)
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(partitions=partitions))
    assert refused.value.refusal is Refusal.MISSING_PARTITION_ROLE


def test_an_extra_partition_is_refused_rather_than_ignored() -> None:
    """"Ignored" is how a volume nobody reviewed ends up on the medium."""

    partitions = (*layout().partitions, Partition(role="scratch", filesystem="ext4"))
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(partitions=partitions))
    assert refused.value.refusal is Refusal.UNKNOWN_PARTITION_ROLE


@pytest.mark.parametrize("table", ["mbr", "dos", "apm", ""])
def test_a_medium_that_is_not_gpt_is_refused(table: str) -> None:
    with pytest.raises(PersistenceRefused):
        check_layout(layout(partition_table=table))


def test_persistence_is_optional() -> None:
    """A medium handed out in an emergency may simply not carry it."""

    partitions = tuple(p for p in layout().partitions if p.role != "persistence")
    check_layout(layout(partitions=partitions))
    assert absent().state is PersistenceState.ABSENT


def test_the_agreed_roles_are_the_three_of_adr_0008_d4_1() -> None:
    assert PARTITION_ROLES == ("esp", "boot_root", "persistence")


# --- the record binds to this host and this session -------------------------


def test_a_record_bound_to_another_machine_is_refused() -> None:
    with pytest.raises(PersistenceRefused) as refused:
        create(
            target(),
            binding(host_fingerprint="sha256:" + "b" * 64),
            session_id=SESSION,
            host_fingerprint=HOST,
        )
    assert refused.value.refusal is Refusal.NOT_THIS_HOST


def test_a_record_from_another_session_is_refused() -> None:
    with pytest.raises(PersistenceRefused) as refused:
        create(target(), binding(session_id="s0"), session_id=SESSION, host_fingerprint=HOST)
    assert refused.value.refusal is Refusal.NOT_THIS_SESSION


# --- degradation is safe, and never a repair-into-use -----------------------


def test_a_verified_volume_opens() -> None:
    status = unlock(target(), **unlock_arguments())
    assert status.state is PersistenceState.OPEN
    assert status.outcome is UnlockOutcome.OPENED
    assert status.writable is True


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"unlocked": False}, UnlockOutcome.UNLOCK_FAILED),
        ({"integrity_verified": False}, UnlockOutcome.INTEGRITY_UNVERIFIED),
        ({"stored_generation": 6, "last_seen_generation": 7}, UnlockOutcome.ROLLBACK_DETECTED),
        ({"dirty": True, "repairable": False}, UnlockOutcome.UNRECOVERABLE_DIRTY_VOLUME),
    ],
)
def test_every_failure_quarantines_rather_than_repairs_into_use(overrides, expected) -> None:
    status = unlock(target(), **unlock_arguments(**overrides))
    assert status.state is PersistenceState.QUARANTINED
    assert status.outcome is expected
    assert status.writable is False
    assert status.capability == DEGRADED_CAPABILITY


def test_a_dirty_volume_repaired_within_bounds_opens_and_says_so() -> None:
    status = unlock(target(), **unlock_arguments(dirty=True, repairable=True))
    assert status.state is PersistenceState.OPEN
    assert "within bounds" in " ".join(status.reasons)


def test_there_is_no_outcome_meaning_opened_with_warnings() -> None:
    assert {member.value for member in UnlockOutcome} == {
        "opened",
        "unlock_failed",
        "integrity_unverified",
        "rollback_detected",
        "unrecoverable_dirty_volume",
    }


def test_a_surprise_removal_fences_without_reading_the_medium() -> None:
    """A fence that needed the medium could not fire when the medium is gone."""

    import inspect

    assert inspect.signature(fence_after_removal).parameters == {}
    status = fence_after_removal()
    assert status.state is PersistenceState.FENCED
    assert status.writable is False
    assert "reboot" in " ".join(status.reasons)


# --- nothing here moves authority ------------------------------------------


@pytest.mark.parametrize(
    "status",
    [
        absent(),
        fence_after_removal(),
        unlock(target(), **unlock_arguments()),
        unlock(target(), **unlock_arguments(unlocked=False)),
        unlock(target(), **unlock_arguments(integrity_verified=False)),
        create(target(), binding(), session_id=SESSION, host_fingerprint=HOST),
    ],
)
def test_no_persistence_state_changes_edge_authority(status) -> None:
    """Every state is a capability. Edge's arbiter decides in all of them."""

    assert status.authority == ()
    assert status.capability in {"CORE", "LITE"}


# --- recovery never touches the host ---------------------------------------


@pytest.mark.parametrize("state", list(PersistenceState))
def test_no_recovery_option_repairs_the_host(state: PersistenceState) -> None:
    from azazel_boot.persistence import RECOVERY_OPTIONS

    offered = " ".join(RECOVERY_OPTIONS[state]).lower()
    for forbidden in ("host", "internal disk", "laptop", "fsck", "repair the machine"):
        assert forbidden not in offered


def test_a_fenced_session_is_offered_a_reboot_and_nothing_else() -> None:
    assert recovery_options(fence_after_removal()) == ("reboot; the session cannot continue",)


def test_a_quarantined_volume_is_offered_export_and_rewrite_not_repair() -> None:
    status = unlock(target(), **unlock_arguments(integrity_verified=False))
    offered = " ".join(recovery_options(status))
    assert "unmodified" in offered
    assert "repair" not in offered


# --- nothing here can hold a secret ----------------------------------------


def test_the_status_model_cannot_carry_a_secret_or_an_identity() -> None:
    names = status_field_names()
    for confidential in CONFIDENTIAL_NAMES:
        assert confidential not in names, (
            f"PersistenceStatus grew a {confidential!r} field; a value the model "
            "cannot hold is a value no rendering can leak"
        )


def test_no_refusal_message_names_a_device_a_host_or_a_secret() -> None:
    attempts = [
        lambda: create(
            target(disposition=Disposition.QUARANTINED),
            binding(),
            session_id=SESSION,
            host_fingerprint=HOST,
        ),
        lambda: create(
            target(), binding(host_fingerprint="sha256:" + "b" * 64),
            session_id=SESSION, host_fingerprint=HOST,
        ),
        lambda: create(
            target(), binding(session_id="s0"), session_id=SESSION, host_fingerprint=HOST
        ),
    ]
    for attempt in attempts:
        with pytest.raises(PersistenceRefused) as refused:
            attempt()
        rendered = str(refused.value)
        assert HOST not in rendered
        assert "b" * 64 not in rendered
        assert SESSION not in rendered
