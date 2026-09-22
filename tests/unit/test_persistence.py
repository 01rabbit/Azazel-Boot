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
import hashlib
import hmac
import json
import traceback

import pytest
from conftest import mac_reader

from azazel_boot.commissioning import SessionBinding, host_fingerprint
from azazel_boot.inventory import collect_interfaces
from azazel_boot.persistence import (
    DEGRADED_CAPABILITY,
    KNOWN_PLACEHOLDER_IDENTITIES,
    PARTITION_ROLES,
    RECOVERY_OPTIONS,
    VOLUME_MANAGER_MEMBERS,
    VOLUME_MANAGERS,
    BindingKey,
    Capability,
    MediaAssertion,
    MediaBinding,
    MediaClaim,
    MediaIdentity,
    MediaIdentitySource,
    MediumLayout,
    Partition,
    PersistenceRefused,
    PersistenceSession,
    PersistenceState,
    PersistenceStatus,
    Refusal,
    UnlockOutcome,
    bind_media,
    check_layout,
    encodable,
    identity_is_stable,
    media_binding_applies,
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


#: The medium's own identity, and the key the binding is protected with.
#:
#: Synthetic, like everything else here. A real one is read from the device's
#: USB serial descriptor, SCSI VPD page or NVMe identify data by a component
#: permitted to query hardware, and a real key is derived from the TPM or the
#: commissioning secret. `azazel_boot.persistence` reads neither.
MEDIA_IDENTITY = MediaIdentity(
    "SYNTHETIC-MEDIA-0001", MediaIdentitySource.USB_SERIAL_DESCRIPTOR
)
BINDING_KEY = BindingKey(b"synthetic-test-key-not-a-real-one")
PERSISTENCE_UUID = "9f2a41c8-0000-4000-8000-synthetic01"
BOOT_IMAGE_DIGEST = "sha256:" + "a" * 64
COMMISSIONING_GENERATION = 3


def claim(**overrides) -> MediaClaim:
    return MediaClaim(
        identity=overrides.pop("identity", MEDIA_IDENTITY),
        device_identity=overrides.pop("device_identity", MEDIUM_ID),
        persistence_uuid=overrides.pop("persistence_uuid", PERSISTENCE_UUID),
        boot_image_digest=overrides.pop("boot_image_digest", BOOT_IMAGE_DIGEST),
        commissioning_generation=overrides.pop(
            "commissioning_generation", COMMISSIONING_GENERATION
        ),
    )


def assertion(**overrides) -> MediaAssertion:
    """A claim and a binding minted for it. The honest, matching pair."""

    made = claim(**overrides)
    return MediaAssertion(claim=made, binding=bind_media(made, BINDING_KEY))


MEDIA = assertion()

#: The two arguments every act now requires, for the call sites whose subject is
#: something else. The tests that are *about* the media binding pass them
#: explicitly, which is where naming them earns its space.
MEDIA_ARGS = {"media": MEDIA, "binding_key": BINDING_KEY}


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
    }
    arguments.update(overrides)
    return arguments


# --- the medium is asked about, never asserted ------------------------------


def test_persistence_is_created_only_on_the_booted_medium(observations) -> None:
    status = session(observations).create(MEDIUM, layout(), observations, **MEDIA_ARGS)
    assert status.state is PersistenceState.LOCKED


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_host_storage_is_never_a_persistence_target(act: str, observations) -> None:
    """A disposition obtained for the internal disk used to open anything."""

    live = session(observations)
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(HOST_DISK, layout(), observations, **MEDIA_ARGS)
        else:
            live.unlock(HOST_DISK, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
    assert refused.value.refusal is Refusal.NOT_THE_BOOT_MEDIUM


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_an_unobserved_target_is_refused_rather_than_assumed(act: str, observations) -> None:
    live = session(observations)
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(NEVER_SEEN, layout(), observations, **MEDIA_ARGS)
        else:
            live.unlock(NEVER_SEEN, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
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
    live.create(MEDIUM, layout(), observations, **MEDIA_ARGS)
    live.quarantine._dispositions[MEDIUM_ID] = __import__(
        "azazel_boot.quarantine", fromlist=["Disposition"]
    ).Disposition.QUARANTINED  # noqa: SLF001 - forcing the state the quarantine owns
    with pytest.raises(PersistenceRefused) as refused:
        live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
    assert refused.value.refusal is Refusal.NOT_THE_BOOT_MEDIUM


# --- the layout check is applied by the acts, not only by itself ------------


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_both_acts_apply_the_layout_check(act: str, observations) -> None:
    """Deleting the call from the acts used to leave every layout test green."""

    live = session(observations)
    bad = layout(ESP, ROOT, Partition("persistence", "ext4", mappings=("dm-crypt", "lvm")))
    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(MEDIUM, bad, observations, **MEDIA_ARGS)
        else:
            live.unlock(MEDIUM, bad, observations, **MEDIA_ARGS, **unlock_arguments())
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
    created = live.create(MEDIUM, layout(ESP, ROOT), observations, **MEDIA_ARGS)
    assert created.state is PersistenceState.LOCKED
    with pytest.raises(PersistenceRefused) as refused:
        live.unlock(MEDIUM, layout(ESP, ROOT), observations, **MEDIA_ARGS, **unlock_arguments())
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
            live.create(MEDIUM, layout(), observations, **MEDIA_ARGS)
        else:
            live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
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
            live.create(MEDIUM, layout(), another_laptop, **MEDIA_ARGS)
        else:
            live.unlock(
                MEDIUM,
                layout(),
                another_laptop,
                **MEDIA_ARGS,
                **unlock_arguments(),
            )
    assert refused.value.refusal is Refusal.NOT_THIS_HOST_OR_SESSION


# --- degradation is safe, and never a repair-into-use -----------------------


def test_a_verified_volume_opens(observations) -> None:
    status = session(observations).unlock(
        MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments()
    )
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
        ({"dirty": True}, UnlockOutcome.DIRTY_VOLUME),
    ],
)
def test_every_failure_quarantines_rather_than_repairs_into_use(
    overrides, expected, observations
) -> None:
    status = session(observations).unlock(
        MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments(**overrides)
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
            {"integrity_verified": False, "dirty": True},
            UnlockOutcome.INTEGRITY_UNVERIFIED,
        ),
        (
            {"integrity_verified": False, "stored_generation": 1, "last_seen_generation": 9},
            UnlockOutcome.INTEGRITY_UNVERIFIED,
        ),
        (
            {"stored_generation": 1, "last_seen_generation": 9, "dirty": True},
            UnlockOutcome.ROLLBACK_DETECTED,
        ),
    ],
)
def test_the_first_fault_in_the_fixed_order_is_the_one_reported(
    overrides, expected, observations
) -> None:
    status = session(observations).unlock(
        MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments(**overrides)
    )
    assert status.outcome is expected


def test_there_is_no_way_to_open_a_dirty_volume(observations) -> None:
    """The repair path is gone, not merely refused — ADR-0010 D4.

    This test replaces `test_a_repaired_volume_is_distinguishable_from_a_verified_one`,
    which asserted that a repaired open was *labelled* differently from a clean
    one. That was the right fix for the problem as it then stood, and it is not
    a substitute for not having the path: a caller who can report "repaired and
    re-verified" can open a torn volume by saying so twice.

    So the check is on the signature as well as the behaviour. `unlock` has no
    parameter a caller could set to reach `OPEN` with `dirty=True`, which is
    stronger than every combination of parameters being refused.
    """

    import inspect

    parameters = set(inspect.signature(PersistenceSession.unlock).parameters)
    assert not parameters & {"repairable", "reverified_after_repair", "repair"}
    assert not any("repair" in name for name in parameters)

    status = session(observations).unlock(
        MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments(dirty=True)
    )
    assert status.state is PersistenceState.QUARANTINED
    assert status.outcome is UnlockOutcome.DIRTY_VOLUME
    assert status.writable is False
    assert status.capability is DEGRADED_CAPABILITY


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), "7", 7.0, 7.5, -1, True, None]
)
def test_a_generation_that_is_not_a_count_is_refused(value, observations) -> None:
    """`nan` compares false against everything, so it used to pass as no rollback."""

    with pytest.raises(PersistenceRefused) as refused:
        session(observations).unlock(
            MEDIUM,
            layout(),
            observations,
            **MEDIA_ARGS,
            **unlock_arguments(stored_generation=value),
        )
    assert refused.value.refusal is Refusal.GENERATION_NOT_A_COUNT


def test_there_is_no_outcome_meaning_opened_with_warnings() -> None:
    assert {member.value for member in UnlockOutcome} == {
        "opened",
        "unlock_failed",
        "integrity_unverified",
        "rollback_detected",
        "dirty_volume",
    }
    # And no member whose name suggests one: `opened_after_repair` was real.
    assert not any("repair" in member.value for member in UnlockOutcome)


# --- a fence revokes, rather than announcing -------------------------------


def test_a_surprise_removal_fences_without_reading_the_medium() -> None:
    import inspect

    parameters = inspect.signature(PersistenceSession.fence_after_removal).parameters
    assert set(parameters) == {"self"}


def test_a_fence_revokes_the_session_rather_than_returning_a_new_value(observations) -> None:
    """A component holding the earlier status used to keep reading `open`."""

    live = session(observations)
    live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
    assert live.status().writable is True

    live.fence_after_removal()
    assert live.status().state is PersistenceState.FENCED
    assert live.status().writable is False
    for act in (
        lambda: live.create(MEDIUM, layout(), observations, **MEDIA_ARGS),
        lambda: live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments()),
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
            lambda live, seen: live.create(
                MEDIUM, layout(), seen, **MEDIA_ARGS
            ),
            PersistenceState.LOCKED,
            Capability.CORE,
        ),
        (
            lambda live, seen: live.unlock(
                MEDIUM, layout(), seen, **MEDIA_ARGS,
                **unlock_arguments(),
            ),
            PersistenceState.OPEN,
            Capability.LITE,
        ),
        (
            lambda live, seen: live.unlock(
                MEDIUM,
                layout(),
                seen,
                **MEDIA_ARGS,
                **unlock_arguments(integrity_verified=False),
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
    assert live.create(MEDIUM, layout(), observations, **MEDIA_ARGS).writable is False
    opened = live.unlock(
        MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments()
    )
    assert opened.writable is True


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
            "attempt an unlock with an operator-carried passphrase or recovery "
            "procedure, where the site has established one",
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
    live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
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
        live.create(MEDIUM, layout(), observations, **MEDIA_ARGS)
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
        live.create(MEDIUM, layout(ESP, ROOT, hostile), observations, **MEDIA_ARGS)
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
    status = session(observations).unlock(
        MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments()
    )
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
    live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
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
        session(observations).create(impostor, layout(), observations, **MEDIA_ARGS)
    assert refused.value.refusal is Refusal.UNOBSERVED_TARGET


def test_a_partitions_mappings_cannot_be_appended_to_after_it_is_built() -> None:
    mappings = ["dm-crypt"]
    partition = Partition("persistence", "ext4", mappings=mappings)
    mappings.append("lvm")
    assert partition.mappings == ("dm-crypt",)


def test_the_member_denylist_is_pinned_literally() -> None:
    """A five-element subset of fifteen is not a pin.

    The first version asserted `{lvm2_member, zfs_member, linux_raid_member,
    vdo, drbd} <= set(...)`, so ten entries — `lvm1_member`, the whole
    firmware-RAID family, `bcache`, `stratis` — could be dropped with the suite
    green. Mutation testing replaced `lvm1_member` with an unused string and
    nothing noticed. Those ten are precisely the ones added to close an earlier
    finding, and `docs/persistence.md` claimed the list was pinned.

    The exact tuple, in order, as `PERMITTED_FILESYSTEMS` already is.
    """

    assert VOLUME_MANAGER_MEMBERS == (
        "lvm1_member",
        "lvm2_member",
        "zfs_member",
        "linux_raid_member",
        "ddf_raid_member",
        "isw_raid_member",
        "promise_fasttrack_raid_member",
        "via_raid_member",
        "silicon_medley_raid_member",
        "adaptec_raid_member",
        "jmicron_raid_member",
        "bcache",
        "stratis",
        "vdo",
        "drbd",
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
    status = session(observations).create(MEDIUM, layout(), observations, **MEDIA_ARGS)
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
        live.create(
            MEDIUM, layout(), unidentifiable, **MEDIA_ARGS
        )
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
        live.create(MEDIUM, layout(), observations, **MEDIA_ARGS)
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
    first.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
    first.fence_after_removal()

    second = PersistenceSession(
        quarantine=quarantine, binding=binding, session_id=SESSION
    )
    with pytest.raises(PersistenceRefused) as refused:
        second.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
    assert refused.value.refusal is Refusal.SESSION_FENCED
    assert second.status().state is PersistenceState.FENCED
    assert second.recovery_options() == ("reboot; the session cannot continue",)
    assert quarantine.is_fenced


def test_the_fence_survives_the_seal_being_bypassed(observations) -> None:
    """`object.__setattr__` clears the slot; the fence must not depend on it."""

    live = session(observations)
    live.unlock(MEDIUM, layout(), observations, **MEDIA_ARGS, **unlock_arguments())
    live.fence_after_removal()

    object.__setattr__(live, "_fenced", False)
    assert live.status().state is PersistenceState.FENCED
    with pytest.raises(PersistenceRefused) as refused:
        live.create(MEDIUM, layout(), observations, **MEDIA_ARGS)
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

    assert VOLUME_MANAGERS == (
        "lvm",
        "lvm2",
        "mdraid",
        "md",
        "zfs",
        "bcache",
        "dm-raid",
        "dm-thin",
        "stratis",
    )


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


# --------------------------------------------------------------------------
# The medium's own identity (F32, option b)
#
# The host binding alone was defeated: a laptop whose onboard NICs cannot be
# identified takes its whole fingerprint from whatever identifiable NIC is
# present, so an adversary supplying a USB dongle supplied the host identity,
# and three laptops sharing one dongle shared one fingerprint. Opening
# persistence now requires a hardware-provided stable media identity as well,
# bound under a key-protected HMAC together with the LUKS volume UUID, the
# signed Boot image digest and the commissioning generation.
# --------------------------------------------------------------------------


def test_the_identity_source_vocabulary_has_no_word_for_where_it_is_plugged_in() -> None:
    """Topology is not identity, and the type cannot express it.

    A bus path, a device node, a port or an enumeration order says where a
    thing is plugged in. All four change when the operator uses a different
    socket, and none of them is reported by the device. The same discipline as
    `Device` having no `kernel_name` and the interface key excluding it.
    """

    values = {source.value for source in MediaIdentitySource}
    assert values == {
        "usb_serial_descriptor",
        "scsi_vpd_wwn",
        "nvme_eui64",
        "nvme_nguid",
        "ata_serial",
    }
    for forbidden in ("bus", "path", "port", "node", "slot", "hub", "index", "order"):
        assert not any(forbidden in value for value in values)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "0000000000000000",
        "aaaaaaaaaaaa",
        "0123456789abcdef",
        "123456789012",
        "unknown",
        "short",
    ],
)
def test_an_identity_every_device_of_its_kind_reports_is_not_an_identity(value) -> None:
    """The `_NULL_MAC` rule, for media.

    Cheap USB-SATA and USB-NVMe bridges ship a whole production run with one
    serial descriptor. Treating that as an identity gives every medium of that
    model the same one — which is the failure this whole change exists to
    close, arrived at from the other direction.
    """

    assert not identity_is_stable(value)


def test_a_medium_with_no_usable_identity_gets_no_binding_and_no_persistence(
    observations,
) -> None:
    unusable = MediaIdentity("", MediaIdentitySource.USB_SERIAL_DESCRIPTOR)
    with pytest.raises(PersistenceRefused) as refused:
        bind_media(claim(identity=unusable), BINDING_KEY)
    assert refused.value.refusal is Refusal.MEDIA_IDENTITY_UNAVAILABLE

    placeholder = MediaIdentity("0123456789abcdef", MediaIdentitySource.SCSI_VPD_WWN)
    with pytest.raises(PersistenceRefused) as refused:
        bind_media(claim(identity=placeholder), BINDING_KEY)
    assert refused.value.refusal is Refusal.MEDIA_IDENTITY_NOT_STABLE


def test_without_a_key_there_is_no_binding_and_therefore_no_persistence() -> None:
    """A plain digest is recomputable by anyone who learns the five inputs.

    The standing rule is a key-protected HMAC bound to the platform or the
    commissioning secret. A caller with neither has no key, and the answer is
    a refusal rather than a weaker binding.
    """

    with pytest.raises(PersistenceRefused) as refused:
        bind_media(claim(), BindingKey(b"tooshort"))
    assert refused.value.refusal is Refusal.MEDIA_BINDING_KEY_UNAVAILABLE


@pytest.mark.parametrize(
    "changed",
    [
        # The identity's **value**, with the source held constant, and the
        # **source**, with the value held constant. They were one case once —
        # `MediaIdentity("ANOTHER-MEDIUM-0002", NVME_EUI64)` against a default
        # of `("SYNTHETIC-MEDIA-0001", USB_SERIAL_DESCRIPTOR)` — so both moved
        # together and the source alone made the digest differ. A review
        # removed the identity *value* from the HMAC and the suite stayed
        # green: the central property of this whole change was passing for the
        # wrong reason. Two cases, one variable each.
        {
            "identity": MediaIdentity(
                "ANOTHER-MEDIUM-0002", MediaIdentitySource.USB_SERIAL_DESCRIPTOR
            )
        },
        {
            "identity": MediaIdentity(
                "SYNTHETIC-MEDIA-0001", MediaIdentitySource.NVME_EUI64
            )
        },
        {"persistence_uuid": "00000000-1111-4000-8000-recreated01"},
        {"boot_image_digest": "sha256:" + "b" * 64},
        {"commissioning_generation": COMMISSIONING_GENERATION - 1},
    ],
)
def test_any_of_the_bound_inputs_changing_refuses(changed, observations) -> None:
    """A different medium, a re-created volume, a different image, a rollback.

    All of them are one refusal on purpose. A refusal naming *which* input was
    wrong is an oracle: it tells an attacker holding the rest which one to keep
    working on.
    """

    live = session(observations)
    tampered = MediaAssertion(claim=claim(**changed), binding=MEDIA.binding)

    assert not media_binding_applies(MEDIA.binding, claim(**changed), BINDING_KEY)
    with pytest.raises(PersistenceRefused) as refused:
        live.unlock(
            MEDIUM,
            layout(),
            observations,
            media=tampered,
            binding_key=BINDING_KEY,
            **unlock_arguments(),
        )
    assert refused.value.refusal is Refusal.MEDIA_BINDING_MISMATCH


def test_a_binding_minted_under_another_key_does_not_match() -> None:
    """Key-protected means the key is what makes it unforgeable."""

    other = BindingKey(b"a-different-synthetic-test-key!!")
    minted = bind_media(claim(), other)
    assert minted.digest != MEDIA.binding.digest
    assert not media_binding_applies(minted, claim(), BINDING_KEY)
    assert media_binding_applies(minted, claim(), other)


def test_persistence_does_not_open_when_the_media_binding_is_absent_or_wrong(
    observations,
) -> None:
    """The check runs in both acts, before the layout is even read.

    A review deleted the layout call from both entry points once and every
    layout test stayed green because they all called the checker directly. The
    same shape of mistake is possible here, so both acts are exercised.
    """

    live = session(observations)
    forged = MediaAssertion(claim=claim(), binding=MediaBinding(digest="0" * 64))

    for act in ("create", "unlock"):
        with pytest.raises(PersistenceRefused) as refused:
            if act == "create":
                live.create(
                    MEDIUM,
                    layout(),
                    observations,
                    media=forged,
                    binding_key=BINDING_KEY,
                )
            else:
                live.unlock(
                    MEDIUM,
                    layout(),
                    observations,
                    media=forged,
                    binding_key=BINDING_KEY,
                    **unlock_arguments(),
                )
        assert refused.value.refusal is Refusal.MEDIA_BINDING_MISMATCH
    assert live.status().state is PersistenceState.UNEXAMINED


def test_the_media_binding_is_checked_before_the_layout_is_read(observations) -> None:
    """A medium that is not ours is refused without parsing what it presents.

    A partition table is attacker-supplied input, and reading it to decide
    whether to refuse a medium we have already failed to recognise is work done
    on the adversary's behalf.
    """

    live = session(observations)
    hostile = Partition(role="/dev/nvme0n1p3 SERIAL=S4EVNF0N", filesystem="ext4")
    forged = MediaAssertion(claim=claim(), binding=MediaBinding(digest="0" * 64))

    with pytest.raises(PersistenceRefused) as refused:
        live.create(
            MEDIUM,
            layout(ESP, ROOT, hostile),
            observations,
            media=forged,
            binding_key=BINDING_KEY,
        )
    assert refused.value.refusal is Refusal.MEDIA_BINDING_MISMATCH


def _tampered_media() -> tuple[MediaAssertion, BindingKey]:
    """A claim whose identity does not match `MEDIA.binding`, and a key.

    The raw strings live only here. This frame has returned by the time any
    refusal is raised, so they are in no traceback the caller captures.
    """

    return (
        MediaAssertion(
            claim=claim(
                identity=MediaIdentity(
                    "S4EVNF0NSECRET999", MediaIdentitySource.USB_SERIAL_DESCRIPTOR
                )
            ),
            binding=MEDIA.binding,
        ),
        BindingKey(b"the-key-material-must-never-render"),
    )


def _unencodable_media() -> tuple[MediaClaim, BindingKey]:
    """Values that cannot be encoded, built where they will not be a local."""

    return (
        MediaClaim(
            identity=MediaIdentity(
                "SNSECRET\ud800", MediaIdentitySource.USB_SERIAL_DESCRIPTOR
            ),
            device_identity=MEDIUM_ID,
            persistence_uuid="uuid-SECRETVALUE-A",
            boot_image_digest="sha256:secretimagedigest",
            commissioning_generation=COMMISSIONING_GENERATION,
        ),
        BindingKey(b"another-key-that-must-never-render"),
    )


def test_nothing_renders_the_raw_media_identity_or_the_key(observations) -> None:
    """The owner's hardware, and key material. Neither may be rendered anywhere.

    The standing rule is that a raw serial, WWN or EUI-64 lives in the
    encrypted commissioning record and nowhere else — not the audit, not a
    journal, not a terminal, not an issue or a pull request, not an external
    report. Key material goes nowhere at all.

    A captured-locals traceback is every one of those at once, so it is what is
    measured.
    """

    # Built in a helper so the raw values are **not locals of this frame** when
    # the refusal is raised. The first version bound them here and the test
    # failed on its own scaffolding — which is the measurement working: a
    # captured-locals traceback renders every frame on the stack, the test's
    # included.
    tampered, secret_key_holder = _tampered_media()
    live = session(observations)

    try:
        live.unlock(
            MEDIUM,
            layout(),
            observations,
            media=tampered,
            binding_key=secret_key_holder,
            **unlock_arguments(),
        )
    except PersistenceRefused as error:
        captured = "".join(
            traceback.TracebackException.from_exception(
                error, capture_locals=True
            ).format()
        )

    # Disclosed only now, after the traceback has been rendered.
    secret_identity = tampered.claim.identity.disclose()
    secret_key = secret_key_holder.disclose().decode()

    assert secret_identity not in captured
    assert secret_key not in captured
    assert MEDIA.binding.digest not in captured
    assert PERSISTENCE_UUID not in captured

    for rendered in (
        repr(tampered),
        repr(tampered.claim),
        repr(MEDIA.binding),
        repr(secret_key_holder),
        str(tampered.claim.identity),
    ):
        assert secret_identity not in rendered
        assert secret_key not in rendered


def test_neither_the_identity_nor_the_key_can_be_serialised_or_reassigned() -> None:
    """A redacted repr is not a redacted object; both lessons already learned."""

    import copy
    import pickle

    identity = MediaIdentity("SYNTHETIC-MEDIA-0001", MediaIdentitySource.ATA_SERIAL)
    key = BindingKey(b"synthetic-test-key-not-a-real-one")

    for held in (identity, key):
        for attempt in (pickle.dumps, copy.copy, copy.deepcopy):
            with pytest.raises(TypeError):
                attempt(held)

    with pytest.raises(AttributeError):
        identity._value = "SOMETHING-ELSE-0002"  # noqa: SLF001 - the attack
    with pytest.raises(AttributeError):
        key._key = b"another-key"  # noqa: SLF001 - the attack
    assert identity.disclose() == "SYNTHETIC-MEDIA-0001"


def test_the_binding_carries_no_field_that_could_hold_the_identity_or_a_key() -> None:
    """Absent vocabulary: what the model cannot hold, it cannot leak."""

    names = {field_.name for field_ in dataclasses.fields(MediaBinding)}
    assert names == {"digest"}
    for forbidden in (
        "media_identity",
        "identity",
        "serial",
        "wwn",
        "key",
        "key_material",
        "secret",
        "passphrase",
    ):
        assert forbidden not in names


def test_the_canonical_encoding_cannot_confuse_two_different_media() -> None:
    """Length-prefixed, so field boundaries are not a matter of luck.

    **Two cases, because one was not enough.** The first version used only the
    boundary shift below, which kills plain concatenation and nothing else: a
    review rewrote `_canonical` as `b"|".join(...)` and the suite stayed green,
    because shifting a boundary in content that carries no delimiter produces
    different strings under a delimiter join.

    The second case is content that carries the delimiter. It is not contrived:
    the identity comes from hardware and the rest from a caller, so neither can
    be assumed free of any separator a future encoding might pick. Both
    identities below pass every stability check, so nothing upstream rejects
    them.
    """

    shifted_left = bind_media(
        claim(persistence_uuid="aaaa", boot_image_digest="bbbbbb"), BINDING_KEY
    )
    shifted_right = bind_media(
        claim(persistence_uuid="aaaabb", boot_image_digest="bbbb"), BINDING_KEY
    )
    assert shifted_left.digest != shifted_right.digest

    for separator in ("|", ":", "\x00", "/"):
        head = f"AAAAAAAB{separator}B"
        assert identity_is_stable(head)
        carrying_left = bind_media(
            claim(
                identity=MediaIdentity(head, MediaIdentitySource.USB_SERIAL_DESCRIPTOR),
                device_identity="C",
            ),
            BINDING_KEY,
        )
        carrying_right = bind_media(
            claim(
                identity=MediaIdentity(
                    "AAAAAAAB", MediaIdentitySource.USB_SERIAL_DESCRIPTOR
                ),
                device_identity=f"B{separator}C",
            ),
            BINDING_KEY,
        )
        assert carrying_left.digest != carrying_right.digest


def test_an_absent_device_identity_is_refused_like_its_two_siblings() -> None:
    """`""` is the same value on every machine, which is the whole family.

    The volume UUID and the image digest were guarded by a presence check and
    the device identity was not, so an empty one minted a binding and opened a
    volume end to end. Same shape as the host fingerprint taken over nothing.
    """

    for field in ("device_identity", "persistence_uuid", "boot_image_digest"):
        with pytest.raises(PersistenceRefused) as refused:
            bind_media(claim(**{field: ""}), BINDING_KEY)
        assert refused.value.refusal is Refusal.MEDIA_BINDING_INCOMPLETE
        with pytest.raises(PersistenceRefused):
            bind_media(claim(**{field: "   "}), BINDING_KEY)


def test_a_negative_or_non_integer_commissioning_generation_is_refused() -> None:
    for bad in (-1, 1.5, float("nan"), True, "3"):
        with pytest.raises(PersistenceRefused) as refused:
            bind_media(claim(commissioning_generation=bad), BINDING_KEY)
        assert refused.value.refusal is Refusal.GENERATION_NOT_A_COUNT


def test_the_limit_of_the_media_binding_is_stated_rather_than_implied() -> None:
    """It does not defeat a clone made together with the hardware identity.

    Nor an enclosure that reports an identity of the adversary's choosing.
    Those are hardware substitution, which the threat model already excludes —
    and the escalation that produced this change rested on the limit being
    written down, so the statement gets an assertion of its own.
    """

    from pathlib import Path

    from azazel_boot import persistence as module

    source = " ".join(Path(module.__file__).read_text(encoding="utf-8").split())
    assert "does not defeat a full byte-for-byte clone" in source

    threat_model = Path(__file__).resolve().parents[2] / "docs" / "threat-model.md"
    text = " ".join(threat_model.read_text(encoding="utf-8").split())
    assert "hardware-provided stable media identity" in text


# --------------------------------------------------------------------------
# Round seven: the seven mutations that survived, and why they could
#
# A mutation harness whose copied tree was already red reported every mutation
# as caught, including the one that removed the medium's identity from the
# digest. The numbers it produced were not evidence. These tests exist because
# a harness that establishes its own baseline found seven live holes.
# --------------------------------------------------------------------------


def test_a_claim_for_one_device_does_not_open_persistence_on_another(
    observations,
) -> None:
    """Two identity systems were checked independently, so both could be satisfied.

    `_require_the_medium` asks the quarantine about `Device.identity`, which
    this session assigned from what the initramfs marked.
    `_require_the_media_binding` checks `MediaClaim.identity`, which the
    hardware reports. Nothing related them, so a valid binding for a medium the
    caller owns, presented alongside the booted medium as `device`, opened
    persistence. The claim must be *about* the device being acted on, and the
    device's identity is inside the HMAC so the pair cannot be swapped.
    """

    elsewhere = assertion(device_identity="a-medium-the-caller-owns")
    live = session(observations)

    with pytest.raises(PersistenceRefused) as refused:
        live.unlock(
            MEDIUM,
            layout(),
            observations,
            media=elsewhere,
            binding_key=BINDING_KEY,
            **unlock_arguments(),
        )
    assert refused.value.refusal is Refusal.MEDIA_BINDING_MISMATCH
    assert live.status().state is PersistenceState.UNEXAMINED


def test_an_identity_that_cannot_be_encoded_is_refused_rather_than_raised(
    observations,
) -> None:
    """It used to escape as `UnicodeEncodeError`, from the worst possible frame.

    A lone surrogate passed every stability check — long enough, not uniform,
    not a listed placeholder — and then failed the strict encode inside the
    canonical encoding, whose frame holds the disclosed identity, the volume
    UUID and the image digest. All three were in the traceback, and the
    exception escaped both public functions, which no caller is told about.

    The route is ordinary: Python decodes OS-provided strings with
    `surrogateescape`, so a sysfs attribute whose bytes are not valid UTF-8
    produces exactly this.
    """

    assert not identity_is_stable("SNSECRET\ud800")
    assert not encodable("SNSECRET\ud800")
    assert encodable("SYNTHETIC-MEDIA-0001", "")

    surrogate = MediaIdentity("SNSECRET\ud800", MediaIdentitySource.USB_SERIAL_DESCRIPTOR)
    with pytest.raises(PersistenceRefused) as refused:
        bind_media(claim(identity=surrogate), BINDING_KEY)
    assert refused.value.refusal is Refusal.MEDIA_IDENTITY_NOT_STABLE

    with pytest.raises(PersistenceRefused) as refused:
        bind_media(claim(persistence_uuid="uuid-\ud800"), BINDING_KEY)
    assert refused.value.refusal is Refusal.MEDIA_BINDING_INCOMPLETE

    # And it does not escape the boolean-answering function either.
    assert not media_binding_applies(
        MEDIA.binding, claim(identity=surrogate), BINDING_KEY
    )


def test_no_traceback_of_an_unencodable_identity_carries_it(observations) -> None:
    """The frame that held it has returned before anything raises."""

    hostile, key = _unencodable_media()
    try:
        bind_media(hostile, key)
    except PersistenceRefused as error:
        captured = "".join(
            traceback.TracebackException.from_exception(
                error, capture_locals=True
            ).format()
        )
    secret = hostile.identity.disclose()
    assert secret not in captured
    assert hostile.persistence_uuid not in captured
    assert key.disclose().decode() not in captured


def test_a_uniform_identity_is_refused_even_when_it_is_not_on_the_denylist() -> None:
    """The denylist was doing the work the uniformity rule is credited with.

    Every uniform value the parametrized list happened to use — `aaaaaaaaaaaa`,
    `0000000000000000` — is *also* a known placeholder, so deleting the
    uniformity check left the suite green.
    """

    for uniform in ("11111111", "ffffffffff", "zzzzzzzzzzzz", "--------"):
        assert uniform not in KNOWN_PLACEHOLDER_IDENTITIES
        assert not identity_is_stable(uniform)


def test_the_binding_is_domain_separated() -> None:
    """Claimed in the docstring, pinned by nothing until now."""

    from azazel_boot.persistence import _BINDING_DOMAIN, _canonical

    assert _BINDING_DOMAIN
    encoded = _canonical("a", "bb")
    assert encoded.startswith(_BINDING_DOMAIN)
    assert hmac.new(
        BINDING_KEY.disclose(), encoded[len(_BINDING_DOMAIN):], hashlib.sha256
    ).hexdigest() != hmac.new(
        BINDING_KEY.disclose(), encoded, hashlib.sha256
    ).hexdigest()


def test_the_digest_comparison_is_constant_time_and_whole() -> None:
    """A prefix comparison passed every test, which is the point of pinning it.

    Timing is not observable from a unit test, so the mechanism is asserted at
    the source — the same shape as the seal-limit test. A reviewer replaced
    `hmac.compare_digest` with a truncated `==` and nothing noticed.
    """

    from pathlib import Path

    from azazel_boot import persistence as module

    source = " ".join(Path(module.__file__).read_text(encoding="utf-8").split())
    assert "hmac.compare_digest(recomputed.digest, media.binding.digest)" in source
    assert source.count("hmac.compare_digest") >= 2

    last = MEDIA.binding.digest[-1]
    near = MediaBinding(digest=MEDIA.binding.digest[:-1] + ("0" if last != "0" else "1"))
    assert not media_binding_applies(near, claim(), BINDING_KEY)


def test_media_binding_applies_fails_closed_on_a_claim_it_cannot_bind() -> None:
    """The public function's refusal path had no caller in the suite.

    Returning True there would make every unbindable medium — no identity, a
    placeholder identity, no key — match whatever binding was presented.
    """

    unusable = MediaIdentity("", MediaIdentitySource.USB_SERIAL_DESCRIPTOR)
    assert not media_binding_applies(MEDIA.binding, claim(identity=unusable), BINDING_KEY)
    assert not media_binding_applies(
        MEDIA.binding, claim(identity=MEDIA_IDENTITY), BindingKey(b"tooshort")
    )
    assert not media_binding_applies(
        MEDIA.binding, claim(persistence_uuid="  "), BINDING_KEY
    )


@pytest.mark.parametrize("act", ["create", "unlock"])
def test_the_media_binding_is_checked_before_the_layout_in_both_acts(
    act: str, observations
) -> None:
    """A caller with a wrong binding must not learn layout facts first.

    The earlier test exercised `create` only, so moving the check after
    `check_layout` in `unlock` alone survived. The partition table is
    attacker-supplied input, and parsing it on behalf of a medium already known
    not to be ours is work done for the adversary.
    """

    live = session(observations)
    hostile = Partition(role="/dev/nvme0n1p3 SERIAL=S4EVNF0N", filesystem="ext4")
    forged = MediaAssertion(claim=claim(), binding=MediaBinding(digest="0" * 64))
    bad = layout(ESP, ROOT, hostile)

    with pytest.raises(PersistenceRefused) as refused:
        if act == "create":
            live.create(MEDIUM, bad, observations, media=forged, binding_key=BINDING_KEY)
        else:
            live.unlock(
                MEDIUM,
                bad,
                observations,
                media=forged,
                binding_key=BINDING_KEY,
                **unlock_arguments(),
            )
    assert refused.value.refusal is Refusal.MEDIA_BINDING_MISMATCH


def test_a_length_is_not_key_material() -> None:
    """`bytes(16)` is sixteen zero bytes, and `BindingKey(16)` accepted it."""

    for wrong in (16, "a-passphrase", None, 3.0):
        with pytest.raises(TypeError):
            BindingKey(wrong)
    assert BindingKey(bytearray(b"x" * 32)).is_usable


def test_a_binding_cannot_be_reused_under_a_different_device_identity(
    observations,
) -> None:
    """The cross-check alone is not the same as binding the device in.

    With `device_identity` compared but **not** inside the HMAC, a binding
    minted while the quarantine called the medium one thing matches a claim
    naming another — the digest does not move — and the comparison then passes
    because the claim agrees with the device in front of it. The binding
    becomes reusable across device identities, which is the property the
    comparison was supposed to establish.

    Mutation found it: removing `claim.device_identity` from the canonical
    message left the suite green when the cross-check was the only test.
    """

    minted_elsewhere = bind_media(
        claim(device_identity="a-different-device-identity"), BINDING_KEY
    )
    here = claim(device_identity=MEDIUM_ID)

    # The claim agrees with the device being acted on, so only the HMAC can
    # refuse this.
    assert here.device_identity == MEDIUM.identity
    assert not media_binding_applies(minted_elsewhere, here, BINDING_KEY)

    live = session(observations)
    with pytest.raises(PersistenceRefused) as refused:
        live.create(
            MEDIUM,
            layout(),
            observations,
            media=MediaAssertion(claim=here, binding=minted_elsewhere),
            binding_key=BINDING_KEY,
        )
    assert refused.value.refusal is Refusal.MEDIA_BINDING_MISMATCH
