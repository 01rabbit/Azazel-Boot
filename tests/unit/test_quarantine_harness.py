"""A whole session against synthetic block devices, with no machine involved.

The harness below is a sequence of events a real session produces — boot, a
hotplug, a dock, a resume from suspend, the USB being pulled — driven against
the quarantine's decision logic. It is **simulation**, and it is kept strictly
apart from hardware evidence: it can show that the rule blocks what it is meant
to block, and it can show nothing whatsoever about a laptop.

The program gate needs a hardware-in-the-loop record of zero content writes
across a full session (`docs/threat-model.md` section 3.3). Nothing here is that
record, and no document may describe the no-host-write property as verified
until that record exists.
"""

from __future__ import annotations

import pytest

from azazel_boot.quarantine import (
    WRITING_ACTIONS,
    Action,
    Device,
    DeviceClass,
    Disposition,
    ExportApproval,
    ExportRefused,
    Quarantine,
    Refusal,
    Verdict,
)

BOOT_MEDIUM = Device(identity="usb-boot-medium", device_class=DeviceClass.BOOT_MEDIUM)
INTERNAL_NVME = Device(identity="internal-nvme", device_class=DeviceClass.HOST_STORAGE)
DOCKED_DISK = Device(identity="dock-sata", device_class=DeviceClass.HOST_STORAGE)
UNCLASSIFIABLE = Device(identity="unknown-bridge", device_class=DeviceClass.UNKNOWN)


def a_quarantine() -> Quarantine:
    quarantine = Quarantine(session_id="s1", boot_medium_identity=BOOT_MEDIUM.identity)
    quarantine.observe(BOOT_MEDIUM)
    return quarantine


def test_the_boot_medium_is_recognised_by_identity() -> None:
    assert a_quarantine().disposition(BOOT_MEDIUM) is Disposition.BOOT_MEDIUM


def test_a_device_claiming_to_be_the_boot_medium_is_quarantined() -> None:
    """Identity decides. A class an impostor sets on itself does not."""

    quarantine = a_quarantine()
    impostor = Device(identity="another-usb", device_class=DeviceClass.BOOT_MEDIUM)
    assert quarantine.observe(impostor) is Disposition.QUARANTINED


def test_an_internal_disk_present_at_boot_is_quarantined() -> None:
    quarantine = a_quarantine()
    assert quarantine.observe(INTERNAL_NVME) is Disposition.QUARANTINED


@pytest.mark.parametrize("action", sorted(WRITING_ACTIONS, key=lambda a: a.value))
def test_every_writing_action_against_an_internal_disk_is_blocked(action: Action) -> None:
    quarantine = a_quarantine()
    quarantine.observe(INTERNAL_NVME)
    assert quarantine.evaluate(INTERNAL_NVME, action) is Verdict.BLOCKED


@pytest.mark.parametrize("action", sorted(WRITING_ACTIONS, key=lambda a: a.value))
def test_an_unobserved_device_is_blocked_rather_than_guessed_at(action: Action) -> None:
    """An unobserved device is not a device with no rule."""

    assert a_quarantine().evaluate(UNCLASSIFIABLE, action) is Verdict.BLOCKED


def test_a_device_that_appears_after_boot_is_quarantined_on_appearance() -> None:
    """The threat model calls a one-time scan explicitly wrong here."""

    quarantine = a_quarantine()
    assert quarantine.observe(DOCKED_DISK) is Disposition.QUARANTINED
    assert quarantine.evaluate(DOCKED_DISK, Action.AUTOMOUNT) is Verdict.BLOCKED


def test_a_full_session_writes_nothing_to_anything_that_is_not_the_medium() -> None:
    """The simulation the hardware record will later have to confirm."""

    quarantine = a_quarantine()
    allowed_writes: list[tuple[str, str]] = []

    # Boot: the internal disk is there from the start.
    quarantine.observe(INTERNAL_NVME)
    # A dock arrives mid-session, then a bridge nobody can classify.
    for device in (DOCKED_DISK, UNCLASSIFIABLE):
        quarantine.observe(device)
    # Resume from suspend: the same devices re-appear, plus one that never
    # announced itself at all.
    never_observed = Device(identity="late-arrival", device_class=DeviceClass.HOST_STORAGE)

    for device in (INTERNAL_NVME, DOCKED_DISK, UNCLASSIFIABLE, never_observed):
        for action in WRITING_ACTIONS:
            if quarantine.evaluate(device, action) is Verdict.ALLOWED:
                allowed_writes.append((device.identity, action.value))

    assert allowed_writes == [], (
        f"the quarantine allowed writes it must refuse: {allowed_writes}"
    )


def test_the_medium_itself_is_writable() -> None:
    """A quarantine that blocked its own medium would be a broken product."""

    assert a_quarantine().evaluate(BOOT_MEDIUM, Action.WRITABLE_MOUNT) is Verdict.ALLOWED


def test_an_approved_export_writes_to_its_target_and_nothing_else() -> None:
    quarantine = a_quarantine()
    quarantine.observe(INTERNAL_NVME)
    quarantine.observe(DOCKED_DISK)
    quarantine.approve_export(
        ExportApproval(
            session_id="s1",
            target_identity=INTERNAL_NVME.identity,
            reason="hand the incident record to the machine's owner",
            confirmed=True,
        )
    )
    assert quarantine.evaluate(INTERNAL_NVME, Action.EXPORT_WRITE) is Verdict.ALLOWED
    assert quarantine.evaluate(DOCKED_DISK, Action.EXPORT_WRITE) is Verdict.BLOCKED


def test_an_approval_does_not_widen_to_other_actions() -> None:
    """Approving an export approves an export, not a mount."""

    quarantine = a_quarantine()
    quarantine.observe(INTERNAL_NVME)
    quarantine.approve_export(
        ExportApproval(
            session_id="s1",
            target_identity=INTERNAL_NVME.identity,
            reason="export",
            confirmed=True,
        )
    )
    assert quarantine.evaluate(INTERNAL_NVME, Action.WRITABLE_MOUNT) is Verdict.BLOCKED
    assert quarantine.evaluate(INTERNAL_NVME, Action.FSCK) is Verdict.BLOCKED


def test_an_approval_from_another_session_is_refused() -> None:
    """Never a persisted preference: it does not outlive the sitting."""

    quarantine = a_quarantine()
    with pytest.raises(ExportRefused) as refused:
        quarantine.approve_export(
            ExportApproval(
                session_id="s0",
                target_identity=INTERNAL_NVME.identity,
                reason="export",
                confirmed=True,
            )
        )
    assert refused.value.refusal is Refusal.NOT_THIS_SESSION


def test_a_new_session_starts_with_no_approval() -> None:
    quarantine = a_quarantine()
    quarantine.observe(INTERNAL_NVME)
    quarantine.approve_export(
        ExportApproval(
            session_id="s1",
            target_identity=INTERNAL_NVME.identity,
            reason="export",
            confirmed=True,
        )
    )
    assert quarantine.evaluate(INTERNAL_NVME, Action.EXPORT_WRITE) is Verdict.ALLOWED

    next_session = Quarantine(session_id="s2", boot_medium_identity=BOOT_MEDIUM.identity)
    next_session.observe(BOOT_MEDIUM)
    next_session.observe(INTERNAL_NVME)
    assert next_session.evaluate(INTERNAL_NVME, Action.EXPORT_WRITE) is Verdict.BLOCKED


@pytest.mark.parametrize(
    ("approval", "expected"),
    [
        (
            ExportApproval(
                session_id="s1", target_identity="internal-nvme", reason="  ", confirmed=True
            ),
            Refusal.NO_REASON_GIVEN,
        ),
        (
            ExportApproval(
                session_id="s1",
                target_identity="internal-nvme",
                reason="export",
                confirmed=False,
            ),
            Refusal.NOT_CONFIRMED,
        ),
        (
            ExportApproval(
                session_id="s1",
                target_identity="usb-boot-medium",
                reason="export",
                confirmed=True,
            ),
            Refusal.BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET,
        ),
    ],
)
def test_an_incomplete_approval_authorises_nothing(approval, expected) -> None:
    quarantine = a_quarantine()
    with pytest.raises(ExportRefused) as refused:
        quarantine.approve_export(approval)
    assert refused.value.refusal is expected


def test_a_replacement_approval_does_not_accumulate() -> None:
    quarantine = a_quarantine()
    quarantine.observe(INTERNAL_NVME)
    quarantine.observe(DOCKED_DISK)
    for target in (INTERNAL_NVME.identity, DOCKED_DISK.identity):
        quarantine.approve_export(
            ExportApproval(
                session_id="s1", target_identity=target, reason="export", confirmed=True
            )
        )
    assert quarantine.evaluate(DOCKED_DISK, Action.EXPORT_WRITE) is Verdict.ALLOWED
    assert quarantine.evaluate(INTERNAL_NVME, Action.EXPORT_WRITE) is Verdict.BLOCKED


def test_the_audit_records_classifications_and_no_device_identity() -> None:
    """Audit is for traceability; it is not a place to keep identifiers."""

    quarantine = a_quarantine()
    quarantine.observe(INTERNAL_NVME)
    quarantine.evaluate(INTERNAL_NVME, Action.AUTOMOUNT)
    quarantine.evaluate(BOOT_MEDIUM, Action.READ)
    entries = quarantine.audit()
    assert [entry.verdict for entry in entries] == ["blocked", "allowed"]
    rendered = repr(entries)
    for identity in (INTERNAL_NVME.identity, BOOT_MEDIUM.identity):
        assert identity not in rendered
