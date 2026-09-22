"""Persistence decisions, on synthetic media, with no device anywhere near them.

Every test uses a constructed layout and a real `Quarantine` driven with
synthetic devices. **No real USB SSD, no real laptop, no loop device and no
`/dev` path is involved**, and nothing here is evidence that a volume can be
created, unlocked or repaired on hardware.

Several tests exist because an adversarial review defeated the first version,
and each names what it defeated:

- a `Disposition` obtained for the internal disk — or typed by hand with no
  quarantine in existence — opened persistence on anything;
- `unlock` was bound to no host and no session, and opened a medium with no
  persistence partition at all;
- the layout check was reachable only by calling it directly, so deleting it
  from both entry points left the suite green;
- a repaired volume was byte-identical to a verified one in everything but a
  free-text string;
- a checked layout could be appended to afterwards;
- `float("nan")` as a generation waved the rollback check through.
"""

from __future__ import annotations

import dataclasses
import json
import traceback

import pytest

from azazel_boot.commissioning import SessionBinding
from azazel_boot.persistence import (
    DEGRADED_CAPABILITY,
    PARTITION_ROLES,
    RECOVERY_OPTIONS,
    VOLUME_MANAGER_MEMBERS,
    VOLUME_MANAGERS,
    Capability,
    MediumLayout,
    Partition,
    PersistenceRefused,
    PersistenceSession,
    PersistenceState,
    PersistenceStatus,
    Refusal,
    UnlockOutcome,
    check_layout,
    recovery_options,
    status_field_names,
)
from azazel_boot.quarantine import Device, DeviceClass, Quarantine

HOST = "sha256:" + "a" * 64
SESSION = "s1"
MEDIUM_ID = "usb-boot-medium"
MEDIUM = Device(identity=MEDIUM_ID, device_class=DeviceClass.BOOT_MEDIUM)
HOST_DISK = Device(identity="host-nvme-SN-1", device_class=DeviceClass.HOST_STORAGE)
NEVER_SEEN = Device(identity="late-arrival", device_class=DeviceClass.HOST_STORAGE)

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

ESP = Partition(role="esp", filesystem="vfat")
ROOT = Partition(role="boot_root", filesystem="squashfs", read_only=True)
PERSISTENCE = Partition(role="persistence", filesystem="ext4", mappings=("dm-crypt",))


def layout(*partitions: Partition, table: str = "gpt") -> MediumLayout:
    return MediumLayout(
        partition_table=table, partitions=partitions or (ESP, ROOT, PERSISTENCE)
    )


def session(**overrides) -> PersistenceSession:
    quarantine = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM_ID)
    quarantine.observe(MEDIUM)
    quarantine.observe(HOST_DISK)
    return PersistenceSession(
        quarantine=quarantine,
        binding=SessionBinding(
            host_fingerprint=overrides.pop("host_fingerprint", HOST),
            session_id=overrides.pop("session_id", SESSION),
        ),
        session_id=SESSION,
        host_fingerprint=HOST,
    )


def unlock_arguments(**overrides) -> dict:
    arguments = {
        "unlocked": True,
        "integrity_verified": True,
        "stored_generation": 7,
        "last_seen_generation": 7,
        "dirty": False,
        "repairable": True,
        "reverified_after_repair": False,
    }
    arguments.update(overrides)
    return arguments


# --- the medium is asked about, never asserted ------------------------------


def test_persistence_is_created_only_on_the_booted_medium() -> None:
    assert session().create(MEDIUM, layout()).state is PersistenceState.LOCKED


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_host_storage_is_never_a_persistence_target(act: str) -> None:
    """A disposition obtained for the internal disk used to open anything."""

    live = session()
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(HOST_DISK, layout())
        else:
            live.unlock(HOST_DISK, layout(), **unlock_arguments())
    assert refused.value.refusal is Refusal.NOT_THE_BOOT_MEDIUM


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_an_unobserved_target_is_refused_rather_than_assumed(act: str) -> None:
    live = session()
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(NEVER_SEEN, layout())
        else:
            live.unlock(NEVER_SEEN, layout(), **unlock_arguments())
    assert refused.value.refusal is Refusal.UNOBSERVED_TARGET


def test_the_session_asks_the_quarantine_rather_than_taking_a_disposition() -> None:
    """The decision is made here, not handed in: a caller has nothing to assert."""

    import inspect

    from azazel_boot import persistence

    for name in ("create", "unlock"):
        parameters = inspect.signature(getattr(PersistenceSession, name)).parameters
        assert "disposition" not in parameters
        assert parameters["device"].annotation in (Device, "Device")
    assert "PersistenceTarget" not in dir(persistence)


def test_a_medium_demoted_by_the_quarantine_stops_being_a_target() -> None:
    live = session()
    live.create(MEDIUM, layout())
    live.quarantine._dispositions[MEDIUM_ID] = __import__(
        "azazel_boot.quarantine", fromlist=["Disposition"]
    ).Disposition.QUARANTINED  # noqa: SLF001 - forcing the state the quarantine owns
    with pytest.raises(PersistenceRefused) as refused:
        live.unlock(MEDIUM, layout(), **unlock_arguments())
    assert refused.value.refusal is Refusal.NOT_THE_BOOT_MEDIUM


# --- the layout check is applied by the acts, not only by itself ------------


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_both_acts_apply_the_layout_check(act: str) -> None:
    """Deleting the call from the acts used to leave every layout test green."""

    live = session()
    bad = layout(ESP, ROOT, Partition("persistence", "ext4", mappings=("dm-crypt", "lvm")))
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(MEDIUM, bad)
        else:
            live.unlock(MEDIUM, bad, **unlock_arguments())
    assert refused.value.refusal is Refusal.VOLUME_MANAGER_PRESENT


def test_the_agreed_layout_passes() -> None:
    check_layout(layout())


@pytest.mark.parametrize("manager", VOLUME_MANAGERS)
def test_a_volume_manager_on_the_medium_is_refused(manager: str) -> None:
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(
            layout(
                ESP, ROOT, Partition("persistence", "ext4", mappings=("dm-crypt", manager))
            )
        )
    assert refused.value.refusal is Refusal.VOLUME_MANAGER_PRESENT


@pytest.mark.parametrize("member", VOLUME_MANAGER_MEMBERS)
def test_a_partition_that_is_a_volume_manager_member_is_refused(member: str) -> None:
    """It assembles something even with nothing stacked on it today."""

    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(Partition("esp", member), ROOT))
    assert refused.value.refusal is Refusal.VOLUME_MANAGER_PRESENT


@pytest.mark.parametrize("role", ["esp", "boot_root"])
def test_a_mapping_under_the_esp_or_the_root_is_refused(role: str) -> None:
    partitions = tuple(
        Partition(p.role, p.filesystem, p.read_only, ("dm-crypt",)) if p.role == role else p
        for p in (ESP, ROOT)
    )
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(*partitions))
    assert refused.value.refusal is Refusal.MAPPING_ON_A_PLAIN_PARTITION


def test_two_partitions_with_the_same_role_are_refused() -> None:
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(ESP, ROOT, PERSISTENCE, PERSISTENCE))
    assert refused.value.refusal is Refusal.DUPLICATE_PARTITION_ROLE


def test_the_roles_must_be_in_the_fixed_order() -> None:
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(PERSISTENCE, ROOT, ESP))
    assert refused.value.refusal is Refusal.PARTITION_ORDER_CHANGED


def test_persistence_must_be_a_luks2_volume() -> None:
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(ESP, ROOT, Partition("persistence", "ext4")))
    assert refused.value.refusal is Refusal.NOT_LUKS2


def test_anything_between_the_encrypted_partition_and_its_filesystem_is_refused() -> None:
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(
            layout(ESP, ROOT, Partition("persistence", "ext4", mappings=("dm-crypt", "dm-cache")))
        )
    assert refused.value.refusal is Refusal.PERSISTENCE_NOT_DIRECTLY_FORMATTED


def test_a_read_write_boot_root_is_refused() -> None:
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(ESP, Partition("boot_root", "ext4", read_only=False)))
    assert refused.value.refusal is Refusal.ROOT_NOT_READ_ONLY


@pytest.mark.parametrize("missing", ["esp", "boot_root"])
def test_a_missing_required_partition_is_refused(missing: str) -> None:
    partitions = tuple(p for p in (ESP, ROOT, PERSISTENCE) if p.role != missing)
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(*partitions))
    assert refused.value.refusal is Refusal.MISSING_PARTITION_ROLE


def test_an_extra_partition_is_refused_rather_than_ignored() -> None:
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(ESP, ROOT, PERSISTENCE, Partition("scratch", "ext4")))
    assert refused.value.refusal is Refusal.UNKNOWN_PARTITION_ROLE


@pytest.mark.parametrize("table", ["mbr", "dos", "apm", ""])
def test_a_medium_that_is_not_gpt_is_refused(table: str) -> None:
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(table=table))
    assert refused.value.refusal is Refusal.NOT_GPT


def test_persistence_is_optional_but_cannot_be_unlocked_when_absent() -> None:
    """A medium handed out in an emergency may simply not carry it."""

    check_layout(layout(ESP, ROOT))
    live = session()
    assert live.create(MEDIUM, layout(ESP, ROOT)).state is PersistenceState.LOCKED
    with pytest.raises(PersistenceRefused) as refused:
        live.unlock(MEDIUM, layout(ESP, ROOT), **unlock_arguments())
    assert refused.value.refusal is Refusal.NO_PERSISTENCE_PARTITION


def test_a_layout_cannot_be_appended_to_after_it_is_checked() -> None:
    """A review checked a target and then grew the list it was built from."""

    partitions = [ESP, ROOT]
    medium = MediumLayout(partition_table="gpt", partitions=partitions)
    check_layout(medium)
    partitions.append(Partition("persistence", "ext4", mappings=("lvm",)))
    assert [p.role for p in medium.partitions] == ["esp", "boot_root"]


def test_the_agreed_roles_are_the_three_of_adr_0008_d4_1() -> None:
    assert PARTITION_ROLES == ("esp", "boot_root", "persistence")


# --- every act is bound to this host and this session -----------------------


@pytest.mark.parametrize("act", ["create", "unlock"])
@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"host_fingerprint": "sha256:" + "b" * 64}, Refusal.NOT_THIS_HOST),
        ({"session_id": "s0"}, Refusal.NOT_THIS_SESSION),
    ],
)
def test_every_act_re_checks_the_binding(act: str, overrides: dict, expected) -> None:
    """The first version bound at creation and never again."""

    live = session(**overrides)
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(MEDIUM, layout())
        else:
            live.unlock(MEDIUM, layout(), **unlock_arguments())
    assert refused.value.refusal is expected


# --- degradation is safe, and never a repair-into-use -----------------------


def test_a_verified_volume_opens() -> None:
    status = session().unlock(MEDIUM, layout(), **unlock_arguments())
    assert status.state is PersistenceState.OPEN
    assert status.outcome is UnlockOutcome.OPENED
    assert status.writable is True
    assert status.capability is Capability.LITE


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"unlocked": False}, UnlockOutcome.UNLOCK_FAILED),
        ({"integrity_verified": False}, UnlockOutcome.INTEGRITY_UNVERIFIED),
        ({"stored_generation": 6, "last_seen_generation": 7}, UnlockOutcome.ROLLBACK_DETECTED),
        ({"dirty": True, "repairable": False}, UnlockOutcome.UNRECOVERABLE_DIRTY_VOLUME),
        (
            {"dirty": True, "repairable": True, "reverified_after_repair": False},
            UnlockOutcome.REPAIR_NOT_REVERIFIED,
        ),
    ],
)
def test_every_failure_quarantines_rather_than_repairs_into_use(overrides, expected) -> None:
    status = session().unlock(MEDIUM, layout(), **unlock_arguments(**overrides))
    assert status.state is PersistenceState.QUARANTINED
    assert status.outcome is expected
    assert status.writable is False
    assert status.capability is DEGRADED_CAPABILITY


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        # Several faults at once: the earlier suite varied one flag from a
        # good baseline, so nothing pinned precedence and a repair could be
        # moved ahead of the integrity check without a test noticing.
        (
            {"unlocked": False, "integrity_verified": False, "dirty": True},
            UnlockOutcome.UNLOCK_FAILED,
        ),
        (
            {"integrity_verified": False, "dirty": True, "repairable": True,
             "reverified_after_repair": True},
            UnlockOutcome.INTEGRITY_UNVERIFIED,
        ),
        (
            {"integrity_verified": False, "stored_generation": 1, "last_seen_generation": 9},
            UnlockOutcome.INTEGRITY_UNVERIFIED,
        ),
        (
            {"stored_generation": 1, "last_seen_generation": 9, "dirty": True,
             "repairable": True, "reverified_after_repair": True},
            UnlockOutcome.ROLLBACK_DETECTED,
        ),
    ],
)
def test_the_first_fault_in_the_fixed_order_is_the_one_reported(overrides, expected) -> None:
    assert session().unlock(MEDIUM, layout(), **unlock_arguments(**overrides)).outcome is expected


def test_a_repaired_volume_is_distinguishable_from_a_verified_one() -> None:
    """The earlier version returned plain `opened`, identical but for a string."""

    status = session().unlock(
        MEDIUM, layout(), **unlock_arguments(dirty=True, reverified_after_repair=True)
    )
    assert status.state is PersistenceState.OPEN
    assert status.outcome is UnlockOutcome.OPENED_AFTER_BOUNDED_REPAIR
    assert status.outcome is not UnlockOutcome.OPENED


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), "7", 7.0, 7.5, -1, True, None]
)
def test_a_generation_that_is_not_a_count_is_refused(value) -> None:
    """`nan` compares false against everything, so it used to pass as no rollback."""

    with pytest.raises(PersistenceRefused) as refused:
        session().unlock(MEDIUM, layout(), **unlock_arguments(stored_generation=value))
    assert refused.value.refusal is Refusal.GENERATION_NOT_A_COUNT


def test_there_is_no_outcome_meaning_opened_with_warnings() -> None:
    assert {member.value for member in UnlockOutcome} == {
        "opened",
        "opened_after_bounded_repair",
        "unlock_failed",
        "integrity_unverified",
        "rollback_detected",
        "unrecoverable_dirty_volume",
        "repair_not_reverified",
    }


# --- a fence revokes, rather than announcing -------------------------------


def test_a_surprise_removal_fences_without_reading_the_medium() -> None:
    import inspect

    parameters = inspect.signature(PersistenceSession.fence_after_removal).parameters
    assert set(parameters) == {"self"}


def test_a_fence_revokes_the_session_rather_than_returning_a_new_value() -> None:
    """A component holding the earlier status used to keep reading `open`."""

    live = session()
    live.unlock(MEDIUM, layout(), **unlock_arguments())
    assert live.status().writable is True

    live.fence_after_removal()
    assert live.status().state is PersistenceState.FENCED
    assert live.status().writable is False
    for act in (
        lambda: live.create(MEDIUM, layout()),
        lambda: live.unlock(MEDIUM, layout(), **unlock_arguments()),
    ):
        with pytest.raises(PersistenceRefused) as refused:
            act()
        assert refused.value.refusal is Refusal.SESSION_FENCED


# --- nothing here moves authority, and capability is a closed vocabulary ----


def test_capability_is_an_enum_with_two_members() -> None:
    """A bare string let a review construct a status claiming FULL and ADMIN."""

    assert {member.value for member in Capability} == {"CORE", "LITE"}


@pytest.mark.parametrize(
    ("build", "state", "capability"),
    [
        (lambda live: live.status(), PersistenceState.ABSENT, Capability.CORE),
        (lambda live: live.create(MEDIUM, layout()), PersistenceState.LOCKED, Capability.CORE),
        (
            lambda live: live.unlock(MEDIUM, layout(), **unlock_arguments()),
            PersistenceState.OPEN,
            Capability.LITE,
        ),
        (
            lambda live: live.unlock(
                MEDIUM, layout(), **unlock_arguments(integrity_verified=False)
            ),
            PersistenceState.QUARANTINED,
            Capability.CORE,
        ),
        (lambda live: live.fence_after_removal(), PersistenceState.FENCED, Capability.CORE),
    ],
)
def test_each_state_carries_exactly_its_capability_and_no_authority(
    build, state, capability
) -> None:
    status = build(session())
    assert status.state is state
    assert status.capability is capability
    assert status.authority == ()


def test_only_an_open_volume_is_writable() -> None:
    live = session()
    assert live.status().writable is False
    assert live.create(MEDIUM, layout()).writable is False
    assert live.unlock(MEDIUM, layout(), **unlock_arguments()).writable is True


# --- recovery never touches the host ---------------------------------------


@pytest.mark.parametrize("state", list(PersistenceState))
def test_the_offered_options_are_exactly_these_and_no_others(state: PersistenceState) -> None:
    """A denylist of four nouns missed "mount it read-write to salvage the session"."""

    expected = {
        PersistenceState.ABSENT: (
            "continue without persistence, at CORE",
            "create persistence on this medium as a separate explicit act",
        ),
        PersistenceState.LOCKED: (
            "continue without persistence, at CORE",
            "attempt an unlock with the documented portable passphrase or recovery path",
        ),
        PersistenceState.OPEN: (),
        PersistenceState.QUARANTINED: (
            "continue without persistence, at CORE",
            "export the quarantined volume for offline examination, unmodified",
            "rewrite the medium from a verified image on another machine",
        ),
        PersistenceState.FENCED: ("reboot; the session cannot continue",),
    }
    assert RECOVERY_OPTIONS[state] == expected[state]


def test_a_fenced_session_is_offered_a_reboot_and_nothing_else() -> None:
    live = session()
    assert recovery_options(live.fence_after_removal()) == (
        "reboot; the session cannot continue",
    )


# --- nothing here can hold a secret ----------------------------------------


def test_the_status_model_cannot_carry_a_secret_or_an_identity() -> None:
    names = status_field_names()
    for confidential in CONFIDENTIAL_NAMES:
        assert confidential not in names


def test_no_refusal_names_a_value_the_medium_supplied() -> None:
    """A partition table is attacker-supplied input on borrowed hardware."""

    hostile = Partition(role="/dev/nvme0n1p3 SERIAL=S4EVNF0N\x1b[2J", filesystem="ext4")
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(ESP, ROOT, hostile))
    rendered = str(refused.value)
    assert "/dev" not in rendered
    assert "SERIAL" not in rendered
    assert "\x1b" not in rendered


def test_no_traceback_of_a_binding_refusal_carries_the_binding() -> None:
    """`pytest --showlocals` and most crash reporters capture frame locals."""

    live = session(session_id="s-secret-99", host_fingerprint="sha256:" + "b" * 64)
    try:
        live.create(MEDIUM, layout())
    except PersistenceRefused as error:
        captured = "".join(
            traceback.TracebackException.from_exception(
                error, capture_locals=True
            ).format()
        )
    assert "s-secret-99" not in captured
    assert "b" * 64 not in captured
    assert HOST not in captured


def test_a_status_renders_and_serialises_without_a_secret() -> None:
    status = session().unlock(MEDIUM, layout(), **unlock_arguments())
    document = dataclasses.asdict(status)
    document["state"] = status.state.value
    document["outcome"] = status.outcome.value
    document["capability"] = status.capability.value
    rendered = repr(status) + json.dumps(document, default=str)
    for secret in (HOST, SESSION, MEDIUM_ID):
        assert secret not in rendered


def test_a_status_is_immutable() -> None:
    status = session().create(MEDIUM, layout())
    with pytest.raises(dataclasses.FrozenInstanceError):
        status.state = PersistenceState.OPEN  # type: ignore[misc]
    assert isinstance(status, PersistenceStatus)
