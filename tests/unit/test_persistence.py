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
from conftest import mac_reader

from azazel_boot.commissioning import SessionBinding, host_fingerprint
from azazel_boot.inventory import collect_interfaces
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
    status_field_names,
)
from azazel_boot.quarantine import Device, DeviceClass, Quarantine

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


TWO_NIC_MACS = {"enp3s0": "a0:b1:c2:d3:e4:f5", "enx001122334455": "00:11:22:33:44:55"}


@pytest.fixture
def observations(sysfs_two_nics):
    """The live read-only inventory this host presents.

    Synthetic, built by the shared sysfs fixtures, and the thing the host
    fingerprint is derived from — which is what makes the binding check a check
    rather than a comparison of the session with itself.
    """

    return collect_interfaces(sysfs_two_nics, permanent_mac_reader=mac_reader(TWO_NIC_MACS))


@pytest.fixture
def another_laptop(sysfs_single_nic):
    """A different machine. Its fingerprint differs, so a binding stops applying."""

    return collect_interfaces(
        sysfs_single_nic, permanent_mac_reader=mac_reader({"wlp2s0": "12:34:56:78:9a:bc"})
    )


def session(observations, **overrides) -> PersistenceSession:
    quarantine = overrides.pop(
        "quarantine", Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM_ID)
    )
    quarantine.observe(MEDIUM)
    quarantine.observe(HOST_DISK)
    return PersistenceSession(
        quarantine=quarantine,
        binding=SessionBinding(
            host_fingerprint=overrides.pop(
                "host_fingerprint", host_fingerprint(observations)
            ),
            session_id=overrides.pop("session_id", SESSION),
        ),
        session_id=SESSION,
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


def test_persistence_is_created_only_on_the_booted_medium(observations) -> None:
    status = session(observations).create(MEDIUM, layout(), observations)
    assert status.state is PersistenceState.LOCKED


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_host_storage_is_never_a_persistence_target(act: str, observations) -> None:
    """A disposition obtained for the internal disk used to open anything."""

    live = session(observations)
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(HOST_DISK, layout(), observations)
        else:
            live.unlock(HOST_DISK, layout(), observations, **unlock_arguments())
    assert refused.value.refusal is Refusal.NOT_THE_BOOT_MEDIUM


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_an_unobserved_target_is_refused_rather_than_assumed(act: str, observations) -> None:
    live = session(observations)
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(NEVER_SEEN, layout(), observations)
        else:
            live.unlock(NEVER_SEEN, layout(), observations, **unlock_arguments())
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


def test_a_medium_demoted_by_the_quarantine_stops_being_a_target(observations) -> None:
    live = session(observations)
    live.create(MEDIUM, layout(), observations)
    live.quarantine._dispositions[MEDIUM_ID] = __import__(
        "azazel_boot.quarantine", fromlist=["Disposition"]
    ).Disposition.QUARANTINED  # noqa: SLF001 - forcing the state the quarantine owns
    with pytest.raises(PersistenceRefused) as refused:
        live.unlock(MEDIUM, layout(), observations, **unlock_arguments())
    assert refused.value.refusal is Refusal.NOT_THE_BOOT_MEDIUM


# --- the layout check is applied by the acts, not only by itself ------------


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_both_acts_apply_the_layout_check(act: str, observations) -> None:
    """Deleting the call from the acts used to leave every layout test green."""

    live = session(observations)
    bad = layout(ESP, ROOT, Partition("persistence", "ext4", mappings=("dm-crypt", "lvm")))
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(MEDIUM, bad, observations)
        else:
            live.unlock(MEDIUM, bad, observations, **unlock_arguments())
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
        check_layout(layout(ESP, Partition("boot_root", "squashfs", read_only=False)))
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


def test_persistence_is_optional_but_cannot_be_unlocked_when_absent(observations) -> None:
    """A medium handed out in an emergency may simply not carry it."""

    check_layout(layout(ESP, ROOT))
    live = session(observations)
    assert live.create(MEDIUM, layout(ESP, ROOT), observations).state is PersistenceState.LOCKED
    with pytest.raises(PersistenceRefused) as refused:
        live.unlock(MEDIUM, layout(ESP, ROOT), observations, **unlock_arguments())
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
    "overrides",
    [
        {"host_fingerprint": "sha256:" + "b" * 64},
        {"session_id": "s0"},
    ],
)
def test_a_binding_that_does_not_apply_refuses_every_act(
    act: str, overrides: dict, observations
) -> None:
    live = session(observations, **overrides)
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(MEDIUM, layout(), observations)
        else:
            live.unlock(MEDIUM, layout(), observations, **unlock_arguments())
    assert refused.value.refusal is Refusal.NOT_THIS_HOST_OR_SESSION


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_the_same_session_on_a_different_laptop_is_refused(
    act: str, observations, another_laptop
) -> None:
    """The check that matters, and the one the previous version could not make.

    It compared the binding against the session's own constructor arguments —
    both supplied by the same object, so a self-consistent session passed
    forever, on any machine. The fingerprint is now re-derived from the live
    inventory, so another laptop refuses even though nothing was forged.
    """

    live = session(observations)
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(MEDIUM, layout(), another_laptop)
        else:
            live.unlock(MEDIUM, layout(), another_laptop, **unlock_arguments())
    assert refused.value.refusal is Refusal.NOT_THIS_HOST_OR_SESSION


# --- degradation is safe, and never a repair-into-use -----------------------


def test_a_verified_volume_opens(observations) -> None:
    status = session(observations).unlock(MEDIUM, layout(), observations, **unlock_arguments())
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
def test_every_failure_quarantines_rather_than_repairs_into_use(
    overrides, expected, observations
) -> None:
    status = session(observations).unlock(
        MEDIUM, layout(), observations, **unlock_arguments(**overrides)
    )
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
def test_the_first_fault_in_the_fixed_order_is_the_one_reported(
    overrides, expected, observations
) -> None:
    status = session(observations).unlock(
        MEDIUM, layout(), observations, **unlock_arguments(**overrides)
    )
    assert status.outcome is expected


def test_a_repaired_volume_is_distinguishable_from_a_verified_one(observations) -> None:
    """The earlier version returned plain `opened`, identical but for a string."""

    status = session(observations).unlock(
        MEDIUM, layout(), observations, **unlock_arguments(dirty=True, reverified_after_repair=True)
    )
    assert status.state is PersistenceState.OPEN
    assert status.outcome is UnlockOutcome.OPENED_AFTER_REPAIR
    assert status.outcome is not UnlockOutcome.OPENED


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), "7", 7.0, 7.5, -1, True, None]
)
def test_a_generation_that_is_not_a_count_is_refused(value, observations) -> None:
    """`nan` compares false against everything, so it used to pass as no rollback."""

    with pytest.raises(PersistenceRefused) as refused:
        session(observations).unlock(
            MEDIUM, layout(), observations, **unlock_arguments(stored_generation=value)
        )
    assert refused.value.refusal is Refusal.GENERATION_NOT_A_COUNT


def test_there_is_no_outcome_meaning_opened_with_warnings() -> None:
    assert {member.value for member in UnlockOutcome} == {
        "opened",
        "opened_after_repair",
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


def test_a_fence_revokes_the_session_rather_than_returning_a_new_value(observations) -> None:
    """A component holding the earlier status used to keep reading `open`."""

    live = session(observations)
    live.unlock(MEDIUM, layout(), observations, **unlock_arguments())
    assert live.status().writable is True

    live.fence_after_removal()
    assert live.status().state is PersistenceState.FENCED
    assert live.status().writable is False
    for act in (
        lambda: live.create(MEDIUM, layout(), observations),
        lambda: live.unlock(MEDIUM, layout(), observations, **unlock_arguments()),
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
        (lambda live, seen: live.status(), PersistenceState.UNEXAMINED, Capability.CORE),
        (
            lambda live, seen: live.create(MEDIUM, layout(), seen),
            PersistenceState.LOCKED,
            Capability.CORE,
        ),
        (
            lambda live, seen: live.unlock(MEDIUM, layout(), seen, **unlock_arguments()),
            PersistenceState.OPEN,
            Capability.LITE,
        ),
        (
            lambda live, seen: live.unlock(
                MEDIUM, layout(), seen, **unlock_arguments(integrity_verified=False)
            ),
            PersistenceState.QUARANTINED,
            Capability.CORE,
        ),
        (
            lambda live, seen: live.fence_after_removal(),
            PersistenceState.FENCED,
            Capability.CORE,
        ),
    ],
)
def test_each_state_carries_exactly_its_capability_and_no_authority(
    build, state, capability
, observations) -> None:
    status = build(session(observations), observations)
    assert status.state is state
    assert status.capability is capability
    assert status.authority == ()


def test_only_an_open_volume_is_writable(observations) -> None:
    live = session(observations)
    assert live.status().writable is False
    assert live.create(MEDIUM, layout(), observations).writable is False
    assert live.unlock(MEDIUM, layout(), observations, **unlock_arguments()).writable is True


# --- recovery never touches the host ---------------------------------------


@pytest.mark.parametrize("state", list(PersistenceState))
def test_the_offered_options_are_exactly_these_and_no_others(state: PersistenceState) -> None:
    """A denylist of four nouns missed "mount it read-write to salvage the session"."""

    expected = {
        PersistenceState.UNEXAMINED: (
            "continue without persistence, at CORE",
            "examine the medium: no act has run in this session yet",
        ),
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


def test_recovery_options_read_the_current_state_not_a_held_snapshot(
    observations,
) -> None:
    """A caller holding `unlock`'s return value got no reboot instruction."""

    live = session(observations)
    live.unlock(MEDIUM, layout(), observations, **unlock_arguments())
    live.fence_after_removal()
    assert live.recovery_options() == ("reboot; the session cannot continue",)


def test_the_module_offers_no_way_to_ask_a_stale_snapshot(observations) -> None:
    from azazel_boot import persistence

    assert not hasattr(persistence, "recovery_options")


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


def test_no_traceback_of_a_binding_refusal_carries_the_binding(observations) -> None:
    """`pytest --showlocals` and most crash reporters capture frame locals."""

    live = session(
        observations, session_id="s-secret-99", host_fingerprint="sha256:" + "b" * 64
    )
    try:
        live.create(MEDIUM, layout(), observations)
    except PersistenceRefused as error:
        captured = "".join(
            traceback.TracebackException.from_exception(
                error, capture_locals=True
            ).format()
        )
    assert "s-secret-99" not in captured
    assert "b" * 64 not in captured
    assert host_fingerprint(observations) not in captured


def test_no_traceback_of_any_refusal_carries_the_device_or_the_layout(
    observations,
) -> None:
    """A device and a layout are arguments of every act, so they were in every
    frame — including for a crafted partition role."""

    live = session(observations)
    hostile = Partition(role="/dev/nvme0n1p3 SERIAL=S4EVNF0N", filesystem="ext4")
    try:
        live.create(MEDIUM, layout(ESP, ROOT, hostile), observations)
    except PersistenceRefused as error:
        captured = "".join(
            traceback.TracebackException.from_exception(
                error, capture_locals=True
            ).format()
        )
    assert MEDIUM_ID not in captured
    assert "/dev/nvme0n1p3" not in captured
    assert "SERIAL" not in captured


def test_a_status_renders_and_serialises_without_a_secret(observations) -> None:
    status = session(observations).unlock(MEDIUM, layout(), observations, **unlock_arguments())
    document = dataclasses.asdict(status)
    document["state"] = status.state.value
    document["outcome"] = status.outcome.value
    document["capability"] = status.capability.value
    rendered = repr(status) + json.dumps(document, default=str)
    for secret in (host_fingerprint(observations), SESSION, MEDIUM_ID):
        assert secret not in rendered


def test_the_session_is_sealed_and_the_fence_is_one_way(observations) -> None:
    """A review substituted a forged quarantine into a public field and cleared
    the fence with one assignment."""

    live = session(observations)
    live.unlock(MEDIUM, layout(), observations, **unlock_arguments())
    live.fence_after_removal()

    with pytest.raises(AttributeError):
        live._fenced = False  # noqa: SLF001 - the attack
    for name, value in (
        ("_quarantine", Quarantine(session_id=SESSION, boot_medium_identity="other")),
        ("_binding", SessionBinding(host_fingerprint="x", session_id=SESSION)),
        ("_session_id", "s-other"),
    ):
        with pytest.raises(AttributeError):
            setattr(live, name, value)
    assert live.status().state is PersistenceState.FENCED


def test_a_session_refuses_to_be_serialised(observations) -> None:
    """`asdict` and `pickle` walked past the redacted repr when it was a dataclass."""

    import pickle

    live = session(observations)
    with pytest.raises(TypeError):
        pickle.dumps(live)
    assert not dataclasses.is_dataclass(live)
    assert host_fingerprint(observations) not in repr(live)


def test_a_quarantine_from_another_session_is_refused(observations) -> None:
    """Two sessions sharing one quarantine let a fenced medium be opened again."""

    foreign = Quarantine(session_id="s-other", boot_medium_identity=MEDIUM_ID)
    foreign.observe(MEDIUM)
    with pytest.raises(PersistenceRefused) as refused:
        PersistenceSession(
            quarantine=foreign,
            binding=SessionBinding(
                host_fingerprint=host_fingerprint(observations), session_id=SESSION
            ),
            session_id=SESSION,
        )
    assert refused.value.refusal is Refusal.QUARANTINE_FROM_ANOTHER_SESSION


def test_an_unobserved_device_claiming_to_be_the_medium_is_refused(observations) -> None:
    """The quarantine's cardinal rule: a device's own claim decides nothing."""

    impostor = Device(identity="another-usb", device_class=DeviceClass.BOOT_MEDIUM)
    with pytest.raises(PersistenceRefused) as refused:
        session(observations).create(impostor, layout(), observations)
    assert refused.value.refusal is Refusal.UNOBSERVED_TARGET


def test_a_partitions_mappings_cannot_be_appended_to_after_it_is_built() -> None:
    mappings = ["dm-crypt"]
    partition = Partition("persistence", "ext4", mappings=mappings)
    mappings.append("lvm")
    assert partition.mappings == ("dm-crypt",)


@pytest.mark.parametrize("member", VOLUME_MANAGER_MEMBERS)
def test_the_member_denylist_is_pinned_literally(member: str) -> None:
    """Parametrizing over the constant shrinks with it; this does not."""

    assert member in VOLUME_MANAGER_MEMBERS
    assert {"lvm2_member", "zfs_member", "linux_raid_member", "vdo", "drbd"} <= set(
        VOLUME_MANAGER_MEMBERS
    )


def test_each_role_carries_one_of_a_named_set_of_filesystems() -> None:
    from azazel_boot.persistence import PERMITTED_FILESYSTEMS

    assert PERMITTED_FILESYSTEMS == {
        "esp": ("vfat",),
        "boot_root": ("squashfs", "erofs"),
        "persistence": ("ext4", "xfs", "f2fs"),
    }
    with pytest.raises(PersistenceRefused) as refused:
        check_layout(layout(ESP, ROOT, Partition("persistence", "btrfs", ("dm-crypt",))))
    assert refused.value.refusal is Refusal.FILESYSTEM_NOT_PERMITTED


def test_a_status_is_immutable(observations) -> None:
    status = session(observations).create(MEDIUM, layout(), observations)
    with pytest.raises(dataclasses.FrozenInstanceError):
        status.state = PersistenceState.OPEN  # type: ignore[misc]
    assert isinstance(status, PersistenceStatus)


# --------------------------------------------------------------------------
# Round three: four holes the 555 tests above did not see
#
# Every test below was written after an adversarial review reproduced the
# defect, and every one of them is red against the module as it stood at
# `d36834c` — which passed all 555.
# --------------------------------------------------------------------------


def test_a_host_that_presents_no_identity_gets_no_binding_at_all(
    sysfs_mac_only,
) -> None:
    """The empty digest was one constant, shared by every such machine.

    `host_fingerprint` hashed only commissionable identities, so a laptop with
    none hashed the empty string: `sha256:e3b0c442…`, the same value everywhere.
    A binding made on one unidentifiable host therefore applied to every other
    unidentifiable host — and those are precisely the hosts Boot is lent.

    There is no fingerprint for such a host now, so there is no binding and
    nothing that needs one runs. That is the safe degradation: `assess` already
    calls this state `COMMISSIONING_REQUIRED`.
    """

    from azazel_boot.commissioning import UnidentifiedHost, bind_session

    unidentifiable = collect_interfaces(
        sysfs_mac_only, permanent_mac_reader=mac_reader({"eth0": "de:ad:be:ef:00:01"})
    )
    assert not any(o.is_commissionable for o in unidentifiable)

    with pytest.raises(UnidentifiedHost):
        host_fingerprint(unidentifiable)
    with pytest.raises(UnidentifiedHost):
        bind_session(unidentifiable, session_id=SESSION)


#: The SHA-256 of the empty string, which is what the fingerprint used to be on
#: a host with no commissionable interface. Written out because it is the whole
#: of the defect: one literal constant, identical on every machine on earth.
EMPTY_DIGEST = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)


def test_a_record_carrying_the_empty_digest_applies_to_nothing(
    observations, sysfs_mac_only, sysfs_single_nic
) -> None:
    """The record still exists on a USB SSD carried from a previous session.

    Refusing to *make* one is only half the fix. A binding holding the empty
    digest — written by an earlier build, or by anyone who can put a constant in
    a file — matched every host that could not identify itself, which is the
    condition the product meets whenever it is lent a machine whose NICs it
    cannot read. `binding_applies` now fails closed there rather than comparing
    two absences and finding them equal.
    """

    from azazel_boot.commissioning import binding_applies

    unidentifiable = collect_interfaces(
        sysfs_mac_only, permanent_mac_reader=mac_reader({"eth0": "de:ad:be:ef:00:01"})
    )
    other_unidentifiable = collect_interfaces(
        sysfs_single_nic, permanent_mac_reader=mac_reader({"wlp2s0": None})
    )
    for inventory in (unidentifiable, other_unidentifiable, ()):
        assert not any(o.is_commissionable for o in inventory)

    carried = SessionBinding(host_fingerprint=EMPTY_DIGEST, session_id=SESSION)
    for inventory in (unidentifiable, other_unidentifiable, ()):
        assert not binding_applies(carried, inventory, session_id=SESSION)

    live = session(observations, host_fingerprint=EMPTY_DIGEST)
    with pytest.raises(PersistenceRefused) as refused:
        live.create(MEDIUM, layout(), unidentifiable)
    assert refused.value.refusal is Refusal.NOT_THIS_HOST_OR_SESSION


def test_no_traceback_carries_the_host_identities_the_fingerprint_is_taken_over(
    observations,
) -> None:
    """The fix for the self-comparison put the pre-images into every frame.

    Making the binding a real check meant passing the live inventory into every
    act. `InterfaceObservation` had a generated repr, so the borrowed machine's
    permanent MACs, NIC serials, PCI ids and kernel names appeared in the
    captured locals of every refusal — the values the fingerprint is a hash of.
    Three sibling reprs had been redacted; the fourth, holding the pre-images,
    had not.
    """

    live = session(observations, session_id="s-secret-99")
    try:
        live.create(MEDIUM, layout(), observations)
    except PersistenceRefused as error:
        captured = "".join(
            traceback.TracebackException.from_exception(
                error, capture_locals=True
            ).format()
        )

    for observation in observations:
        assert observation.permanent_mac
        assert observation.permanent_mac not in captured
        assert observation.interface_key not in captured
        assert observation.kernel_name_observed not in captured
        for value in (observation.bus_path, observation.pci_id, observation.serial):
            if value:
                assert value not in captured


def test_rebuilding_a_session_over_a_fenced_medium_does_not_unfence_it(
    observations,
) -> None:
    """The fence was per-object, and the object could simply be rebuilt.

    No forgery: the same quarantine, the same binding and the same session id
    are three arguments the legitimate caller already holds. The second session
    opened persistence on a medium that was no longer there and offered no
    reboot. Threat-model §4's deliberate removal is served by whichever object
    was not the one that got fenced, so the flag moved to the quarantine.
    """

    quarantine = Quarantine(session_id=SESSION, boot_medium_identity=MEDIUM_ID)
    binding = SessionBinding(
        host_fingerprint=host_fingerprint(observations), session_id=SESSION
    )
    first = session(observations, quarantine=quarantine)
    first.unlock(MEDIUM, layout(), observations, **unlock_arguments())
    first.fence_after_removal()

    second = PersistenceSession(
        quarantine=quarantine, binding=binding, session_id=SESSION
    )
    with pytest.raises(PersistenceRefused) as refused:
        second.unlock(MEDIUM, layout(), observations, **unlock_arguments())
    assert refused.value.refusal is Refusal.SESSION_FENCED
    assert second.status().state is PersistenceState.FENCED
    assert second.recovery_options() == ("reboot; the session cannot continue",)
    assert quarantine.is_fenced


def test_the_fence_survives_the_seal_being_bypassed(observations) -> None:
    """`object.__setattr__` clears the slot; the fence must not depend on it."""

    live = session(observations)
    live.unlock(MEDIUM, layout(), observations, **unlock_arguments())
    live.fence_after_removal()

    object.__setattr__(live, "_fenced", False)
    assert live.status().state is PersistenceState.FENCED
    with pytest.raises(PersistenceRefused) as refused:
        live.create(MEDIUM, layout(), observations)
    assert refused.value.refusal is Refusal.SESSION_FENCED


def test_the_seal_is_defence_against_a_careless_caller_and_says_no_more(
    observations,
) -> None:
    """The limit is asserted, so the claim cannot outlive the mechanism.

    `__setattr__` is a hook, not access control. `object.__setattr__` writes the
    slot, `__new__` yields an instance that never ran `__init__` and is
    therefore never sealed — skipping the quarantine's session check with it —
    and a subclass can override the hook outright. An adversarial review used
    all three; the third opened persistence on the host's internal disk.

    Python cannot close attribute assignment, and `azazel_boot.quarantine` says
    so in the same words. The two modules now make the same claim, which is the
    true one. This test records the limit **as an assertion**: a future seal
    that actually holds turns it red, and whoever writes that seal must then
    correct the docstrings rather than leave a stale claim standing.
    """

    live = session(observations)
    with pytest.raises(AttributeError):
        live._binding = None  # noqa: SLF001 - the guard that does work

    object.__setattr__(live, "_session_id", "s-other")
    assert live.session_id == "s-other"

    raw = PersistenceSession.__new__(PersistenceSession)
    assert not getattr(raw, "_sealed", False)

    from pathlib import Path

    from azazel_boot import persistence, quarantine

    for module in (persistence, quarantine):
        # Whitespace-normalised: the sentence wraps differently in the two
        # files, and a test that a reflow can break is a test nobody keeps.
        source = " ".join(Path(module.__file__).read_text(encoding="utf-8").split())
        assert "code already running in the process" in source


def test_the_volume_manager_denylist_is_pinned_literally() -> None:
    """The sole mutation survivor of 53: shrinking the constant stayed green.

    `test_a_volume_manager_on_the_medium_is_refused` parametrizes over
    `VOLUME_MANAGERS`, so a version keeping only `("lvm", "md")` passed every
    test. Its sibling `VOLUME_MANAGER_MEMBERS` was pinned; this one was not, and
    `docs/persistence.md` claimed both were.
    """

    assert {
        "lvm",
        "lvm2",
        "mdraid",
        "md",
        "zfs",
        "bcache",
        "dm-raid",
        "dm-thin",
        "stratis",
    } <= set(VOLUME_MANAGERS)


def test_the_two_constant_tables_cannot_be_widened_by_assignment() -> None:
    """Read-only for the reason `azazel_boot.artifact`'s field maps are.

    The allowlist is the whole of `check_layout`'s structural authority, and the
    recovery table is what an operator is offered after a failure. A `dict`
    hands a caller both with one assignment. Careless-caller defence, on the
    terms stated above — not a seal.
    """

    from azazel_boot.persistence import PERMITTED_FILESYSTEMS

    with pytest.raises(TypeError):
        PERMITTED_FILESYSTEMS["persistence"] = ("btrfs",)  # type: ignore[index]
    with pytest.raises(TypeError):
        RECOVERY_OPTIONS[PersistenceState.FENCED] = ()  # type: ignore[index]
