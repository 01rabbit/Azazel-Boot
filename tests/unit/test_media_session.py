"""What may be offered as a write target, and what a code can and cannot carry.

Every test here is about a refusal or an absence. That is the shape of the
problem: the writer's job is to not erase the wrong thing, and the way that goes
wrong is never a missing feature — it is a device that should not have been
offered, a code that outlived the listing that issued it, or an identifier that
reached a screen and then a screenshot.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import pickle

import pytest

from azazel_boot.media import (
    SCREEN_FIELDS,
    DeviceIdentity,
    Eligibility,
    MediaCandidate,
    MediaSession,
    Refusal,
    SelectionRefused,
    assess,
    candidate_field_names,
)

#: Names that must not exist on the model, so that nothing downstream can print
#: them (contract section 7.6).
CONFIDENTIAL_NAMES = ("model", "serial", "serial_number", "wwn", "device_path", "dev_node")


def candidate(**overrides) -> MediaCandidate:
    attributes = {
        "identity": "stable-identity-1",
        "capacity_bytes": 64 * 1000**3,
        "partition_table": "gpt",
        "bus_path": "usb-0:1.2",
        "physical_label": "blue tag",
        "removable": True,
        "mounted": False,
        "internal": False,
        "holds_running_root": False,
    }
    attributes.update(overrides)
    return MediaCandidate(**attributes)


def test_the_model_cannot_carry_a_model_or_a_serial() -> None:
    names = candidate_field_names()
    for confidential in CONFIDENTIAL_NAMES:
        assert confidential not in names, (
            f"MediaCandidate grew a {confidential!r} field; a value the model "
            "cannot hold is a value no rendering can leak"
        )


def test_a_removable_unmounted_external_disk_is_eligible() -> None:
    assert assess(candidate()) is Eligibility.ELIGIBLE


def test_an_internal_disk_is_refused() -> None:
    assert assess(candidate(internal=True)) is Eligibility.INTERNAL_DISK


def test_the_disk_holding_the_running_root_is_refused() -> None:
    assert assess(candidate(holds_running_root=True)) is Eligibility.HOLDS_RUNNING_ROOT


@pytest.mark.parametrize("removable", [None, False])
def test_a_disk_whose_removability_is_not_established_is_refused(removable) -> None:
    """Unknown is not removable. Treating it as removable is the writer deciding."""

    assert assess(candidate(removable=removable)) is Eligibility.REMOVABILITY_UNKNOWN


def test_a_mounted_volume_is_refused() -> None:
    assert assess(candidate(mounted=True)) is Eligibility.MOUNTED


def test_an_internal_disk_is_refused_as_internal_even_if_it_is_also_mounted() -> None:
    """The most consequential mistake is the one the operator is told about."""

    assert assess(candidate(internal=True, mounted=True)) is Eligibility.INTERNAL_DISK


def test_an_ineligible_device_is_listed_without_a_code() -> None:
    session = MediaSession("m1")
    offers = session.offer([candidate(identity=DeviceIdentity("internal"), internal=True)])
    assert offers[0].eligibility is Eligibility.INTERNAL_DISK
    assert offers[0].target_code is None
    with pytest.raises(SelectionRefused):
        session.claim("m1-1-01")


def test_only_eligible_devices_consume_a_code() -> None:
    session = MediaSession("m1")
    offers = session.offer(
        [
            candidate(identity=DeviceIdentity("internal"), internal=True),
            candidate(identity=DeviceIdentity("usb-a")),
            candidate(identity=DeviceIdentity("mounted"), mounted=True),
            candidate(identity=DeviceIdentity("usb-b")),
        ]
    )
    codes = [offer.target_code for offer in offers]
    assert codes == [None, "m1-1-01", None, "m1-1-02"]


def test_a_code_resolves_to_the_device_as_enumerated() -> None:
    session = MediaSession("m1")
    session.offer([candidate(identity=DeviceIdentity("usb-a"))])
    assert session.claim("m1-1-01").identity == DeviceIdentity("usb-a")


def test_a_code_is_single_use() -> None:
    session = MediaSession("m1")
    session.offer([candidate(identity=DeviceIdentity("usb-a"))])
    session.claim("m1-1-01")
    with pytest.raises(SelectionRefused) as refused:
        session.claim("m1-1-01")
    assert refused.value.refusal is Refusal.ALREADY_USED


def test_a_code_from_an_earlier_listing_does_not_resolve() -> None:
    """Re-enumerating invalidates the previous view of the world.

    An adversarial review found the first version of this module reissuing the
    same positional code, so a code an operator had written down for a blank
    stick resolved, after a re-listing, to an evidence disk. The substitution
    happened here — upstream of every check the writer performs.
    """

    session = MediaSession("m1")
    session.offer([candidate(identity=DeviceIdentity("usb-a"))])
    session.offer([candidate(identity=DeviceIdentity("usb-b"))])
    with pytest.raises(SelectionRefused) as refused:
        session.claim("m1-1-01")
    assert refused.value.refusal is Refusal.UNKNOWN_CODE
    assert session.claim("m1-2-01").identity == DeviceIdentity("usb-b")


def test_a_spent_code_stays_spent_across_a_re_listing() -> None:
    """Re-enumeration must not hand a used code back."""

    session = MediaSession("m1")
    session.offer([candidate(identity=DeviceIdentity("usb-a"))])
    session.claim("m1-1-01")
    session.offer([candidate(identity=DeviceIdentity("usb-b"))])
    with pytest.raises(SelectionRefused) as refused:
        session.claim("m1-1-01")
    assert refused.value.refusal is Refusal.ALREADY_USED


def test_a_code_from_another_session_does_not_resolve() -> None:
    first = MediaSession("m1")
    first.offer([candidate(identity=DeviceIdentity("usb-a"))])
    second = MediaSession("m2")
    second.offer([candidate(identity=DeviceIdentity("usb-a"))])
    with pytest.raises(SelectionRefused) as refused:
        second.claim("m1-1-01")
    assert refused.value.refusal is Refusal.UNKNOWN_CODE


def test_the_operator_screen_carries_no_identity() -> None:
    session = MediaSession("m1")
    offers = session.offer([candidate(identity=DeviceIdentity("stable-identity-1"))])
    screen = offers[0].describe_for_screen()
    assert set(screen) == {*SCREEN_FIELDS, "eligibility", "target_code"}
    assert "stable-identity-1" not in repr(screen)


def test_no_default_rendering_prints_the_identity() -> None:
    """`describe_for_screen` is a discipline; `repr` is what a log actually calls."""

    session = MediaSession("m1")
    offers = session.offer([candidate(identity=DeviceIdentity("WWN-0x5001234"))])
    for rendered in (repr(offers[0]), repr(offers[0].candidate), f"{offers[0]}"):
        assert "WWN-0x5001234" not in rendered
    assert "WWN-0x5001234" not in repr(dataclasses.asdict(offers[0]))
    assert "WWN-0x5001234" not in json.dumps(
        dataclasses.asdict(offers[0]), default=str
    )


def test_an_identity_is_immutable_and_refuses_to_be_pickled() -> None:
    """A mutable write target let a port change what was opened after the checks."""

    identity = DeviceIdentity("WWN-0x5001234")
    with pytest.raises(AttributeError):
        identity._value = "something-else"  # noqa: SLF001 - the point of the test
    with pytest.raises(TypeError):
        pickle.dumps(identity)
    assert copy.deepcopy(identity) is identity
    assert identity.disclose() == "WWN-0x5001234"


@pytest.mark.parametrize(
    "raw_path", ["/dev/disk7", "/dev/sda", "dev\\disk7", "..", "C:disk"]
)
def test_a_device_path_cannot_be_used_as_a_public_identity(raw_path: str) -> None:
    with pytest.raises(ValueError, match="opaque token"):
        DeviceIdentity(raw_path)


def test_the_screen_carries_what_a_human_needs_to_pick_the_right_object() -> None:
    session = MediaSession("m1")
    screen = session.offer([candidate()])[0].describe_for_screen()
    assert screen["physical_label"] == "blue tag"
    assert screen["bus_path"] == "usb-0:1.2"
    assert screen["capacity_bytes"] == 64 * 1000**3
