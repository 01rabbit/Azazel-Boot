"""A whole session against synthetic block devices, with no machine involved.

The harness is a sequence of events a real session produces — boot, a hotplug, a
dock, a device pulled and replaced, a device that never announced itself —
driven against the quarantine's decision logic. It is **simulation**, and it is
kept strictly apart from hardware evidence: it can show that the rule blocks
what it is meant to block, and it can show nothing whatsoever about a laptop.

The program gate needs a hardware-in-the-loop record of zero content writes
across a full session (`docs/threat-model.md` section 3.3). Nothing here is that
record, and no document may describe the no-host-write property as verified
until that record exists.

Several tests exist because an adversarial review defeated the first version:
an approval survived the device being replaced; an approval could be armed for a
device that had never appeared; the medium was allowed to run a firmware
updater; and every check could be skipped through the generated constructor.
"""

from __future__ import annotations

import inspect

import pytest

from azazel_boot.quarantine import (
    NEVER_ALLOWED_ANYWHERE,
    UNBLOCKABLE_BY_APPROVAL,
    WRITING_ACTIONS,
    Action,
    AuditEntry,
    Device,
    DeviceClass,
    Disposition,
    ExportApproval,
    ExportRefused,
    Quarantine,
    Refusal,
    Verdict,
)

MEDIUM_ID = "usb-boot-medium"
BOOT_MEDIUM = Device(identity=MEDIUM_ID, device_class=DeviceClass.BOOT_MEDIUM)
HOST_NVME = Device(identity="host-nvme-SN-1", device_class=DeviceClass.HOST_STORAGE)
DOCKED_DISK = Device(identity="dock-sata", device_class=DeviceClass.HOST_STORAGE)
UNCLASSIFIABLE = Device(identity="unknown-bridge", device_class=DeviceClass.UNKNOWN)

WRITING = sorted(WRITING_ACTIONS, key=lambda action: action.value)


def a_quarantine() -> Quarantine:
    quarantine = Quarantine(session_id="s1", boot_medium_identity=MEDIUM_ID)
    quarantine.observe(BOOT_MEDIUM)
    return quarantine


def approval(target: str, **overrides) -> ExportApproval:
    attributes = {
        "session_id": "s1",
        "target_identity": target,
        "reason": "hand the incident record to the machine's owner",
        "confirmed": True,
    }
    attributes.update(overrides)
    return ExportApproval(**attributes)


# --- classification --------------------------------------------------------


def test_the_boot_medium_is_recognised_by_identity() -> None:
    assert a_quarantine().disposition(BOOT_MEDIUM) is Disposition.BOOT_MEDIUM


def test_a_device_claiming_to_be_the_boot_medium_is_quarantined_and_recorded() -> None:
    """Identity decides. A class an impostor sets on itself does not — and it is
    a deliberate assertion, so it is written down."""

    quarantine = a_quarantine()
    impostor = Device(identity="another-usb", device_class=DeviceClass.BOOT_MEDIUM)
    assert quarantine.observe(impostor) is Disposition.QUARANTINED
    assert [entry.action for entry in quarantine.audit()] == ["identity_claim_mismatch"]


@pytest.mark.parametrize("claimed", list(DeviceClass), ids=lambda c: c.value)
def test_what_a_device_says_about_itself_changes_no_outcome(claimed: DeviceClass) -> None:
    """The class is untrusted input, so nothing consults it.

    A first version did, and one hostile observation could then demote the
    medium for the rest of the session — an input that cannot promote anything
    but can destroy the only writable volume.
    """

    quarantine = Quarantine(session_id="s1", boot_medium_identity=MEDIUM_ID)
    assert quarantine.observe(Device(MEDIUM_ID, claimed)) is Disposition.BOOT_MEDIUM
    assert quarantine.observe(Device("host-disk", claimed)) is Disposition.QUARANTINED


def test_the_medium_survives_a_hostile_observation_of_its_identity() -> None:
    quarantine = a_quarantine()
    quarantine.observe(Device(identity=MEDIUM_ID, device_class=DeviceClass.HOST_STORAGE))
    assert quarantine.evaluate(BOOT_MEDIUM, Action.WRITABLE_MOUNT) is Verdict.ALLOWED
    assert quarantine.medium_is_bound() is True


def test_a_caller_can_ask_whether_the_medium_has_appeared() -> None:
    """Otherwise "no medium" is indistinguishable from "a host disk was refused"."""

    quarantine = Quarantine(session_id="s1", boot_medium_identity=MEDIUM_ID)
    assert quarantine.medium_is_bound() is False
    quarantine.observe(HOST_NVME)
    assert quarantine.medium_is_bound() is False
    quarantine.observe(BOOT_MEDIUM)
    assert quarantine.medium_is_bound() is True


def test_host_storage_present_at_boot_is_quarantined() -> None:
    quarantine = a_quarantine()
    assert quarantine.observe(HOST_NVME) is Disposition.QUARANTINED


def test_a_device_that_appears_after_boot_is_quarantined_on_appearance() -> None:
    """The threat model calls a one-time scan explicitly wrong here."""

    quarantine = a_quarantine()
    assert quarantine.observe(DOCKED_DISK) is Disposition.QUARANTINED
    assert quarantine.evaluate(DOCKED_DISK, Action.AUTOMOUNT) is Verdict.BLOCKED


# --- what is blocked -------------------------------------------------------


@pytest.mark.parametrize("action", WRITING, ids=lambda action: action.value)
def test_every_writing_action_against_host_storage_is_blocked(action: Action) -> None:
    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    assert quarantine.evaluate(HOST_NVME, action) is Verdict.BLOCKED


def test_reading_host_storage_is_blocked_too() -> None:
    """The operator-initiated read the threat model permits has no implementation."""

    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    quarantine.approve_export(approval(HOST_NVME.identity))
    assert quarantine.evaluate(HOST_NVME, Action.READ) is Verdict.BLOCKED


@pytest.mark.parametrize("action", WRITING, ids=lambda action: action.value)
def test_an_unobserved_device_is_blocked_rather_than_guessed_at(action: Action) -> None:
    """An unobserved device is not a device with no rule."""

    assert a_quarantine().evaluate(UNCLASSIFIABLE, action) is Verdict.BLOCKED


@pytest.mark.parametrize(
    "action", sorted(NEVER_ALLOWED_ANYWHERE, key=lambda a: a.value), ids=lambda a: a.value
)
def test_some_actions_are_refused_on_the_medium_too(action: Action) -> None:
    """A firmware updater is forbidden without qualification, ours or not."""

    assert a_quarantine().evaluate(BOOT_MEDIUM, action) is Verdict.BLOCKED


def test_the_medium_is_otherwise_writable() -> None:
    """A quarantine that blocked its own medium would be a broken product."""

    assert a_quarantine().evaluate(BOOT_MEDIUM, Action.WRITABLE_MOUNT) is Verdict.ALLOWED


def test_a_full_session_writes_nothing_to_anything_that_is_not_the_medium() -> None:
    """The simulation the hardware record will later have to confirm."""

    quarantine = a_quarantine()
    allowed: list[tuple[str, str]] = []

    quarantine.observe(HOST_NVME)
    quarantine.observe(DOCKED_DISK)
    quarantine.observe(UNCLASSIFIABLE)
    never_observed = Device(identity="late-arrival", device_class=DeviceClass.HOST_STORAGE)

    # The dock is pulled and something else arrives reporting the same identity.
    quarantine.observe(DOCKED_DISK)
    # Resume from suspend: everything re-appears.
    for device in (HOST_NVME, UNCLASSIFIABLE):
        quarantine.observe(device)

    for device in (HOST_NVME, DOCKED_DISK, UNCLASSIFIABLE, never_observed):
        for action in Action:
            if quarantine.evaluate(device, action) is Verdict.ALLOWED:
                allowed.append((device.identity, action.value))

    assert allowed == [], f"the quarantine allowed what it must refuse: {allowed}"


# --- the export approval ---------------------------------------------------


def test_an_approved_export_writes_to_its_target_and_nothing_else() -> None:
    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    quarantine.observe(DOCKED_DISK)
    quarantine.approve_export(approval(HOST_NVME.identity))
    assert quarantine.evaluate(HOST_NVME, Action.EXPORT_WRITE) is Verdict.ALLOWED
    assert quarantine.evaluate(DOCKED_DISK, Action.EXPORT_WRITE) is Verdict.BLOCKED


def test_an_approval_does_not_widen_to_other_actions() -> None:
    """Approving an export approves an export, not a mount."""

    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    quarantine.approve_export(approval(HOST_NVME.identity))
    for action in set(WRITING_ACTIONS) - set(UNBLOCKABLE_BY_APPROVAL):
        assert quarantine.evaluate(HOST_NVME, action) is Verdict.BLOCKED


def test_an_approval_does_not_survive_the_device_reappearing() -> None:
    """A device pulled and replaced is not the device that was approved."""

    quarantine = a_quarantine()
    quarantine.observe(DOCKED_DISK)
    quarantine.approve_export(approval(DOCKED_DISK.identity))
    assert quarantine.evaluate(DOCKED_DISK, Action.EXPORT_WRITE) is Verdict.ALLOWED
    quarantine.observe(DOCKED_DISK)
    assert quarantine.evaluate(DOCKED_DISK, Action.EXPORT_WRITE) is Verdict.BLOCKED


def test_an_approval_cannot_be_armed_for_a_device_that_never_appeared() -> None:
    quarantine = a_quarantine()
    with pytest.raises(ExportRefused) as refused:
        quarantine.approve_export(approval(HOST_NVME.identity))
    assert refused.value.refusal is Refusal.UNOBSERVED_DEVICE
    quarantine.observe(HOST_NVME)
    assert quarantine.evaluate(HOST_NVME, Action.EXPORT_WRITE) is Verdict.BLOCKED


def test_an_approval_naming_a_device_with_no_disposition_still_blocks() -> None:
    """Defence in depth for a state the public API can no longer reach.

    `approve_export` refuses an unobserved target, so this cannot arise through
    the API. The check in `evaluate` is the second line, and a second line that
    no test exercises is a line someone deletes: an adversarial review's
    mutation removed exactly this guard and the suite stayed green.
    """

    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    quarantine.approve_export(approval(HOST_NVME.identity))
    quarantine._dispositions.pop(HOST_NVME.identity)  # noqa: SLF001 - forced state
    assert quarantine.evaluate(HOST_NVME, Action.EXPORT_WRITE) is Verdict.BLOCKED


def test_an_operator_can_withdraw_an_approval() -> None:
    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    quarantine.approve_export(approval(HOST_NVME.identity))
    quarantine.withdraw_export()
    assert quarantine.evaluate(HOST_NVME, Action.EXPORT_WRITE) is Verdict.BLOCKED


def test_an_approval_from_another_session_is_refused() -> None:
    """Never a persisted preference: it does not outlive the sitting."""

    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    with pytest.raises(ExportRefused) as refused:
        quarantine.approve_export(approval(HOST_NVME.identity, session_id="s0"))
    assert refused.value.refusal is Refusal.NOT_THIS_SESSION


def test_a_new_session_starts_with_no_approval() -> None:
    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    quarantine.approve_export(approval(HOST_NVME.identity))
    assert quarantine.evaluate(HOST_NVME, Action.EXPORT_WRITE) is Verdict.ALLOWED

    next_session = Quarantine(session_id="s2", boot_medium_identity=MEDIUM_ID)
    next_session.observe(BOOT_MEDIUM)
    next_session.observe(HOST_NVME)
    assert next_session.evaluate(HOST_NVME, Action.EXPORT_WRITE) is Verdict.BLOCKED


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"reason": "  "}, Refusal.NO_REASON_GIVEN),
        ({"confirmed": False}, Refusal.NOT_CONFIRMED),
    ],
)
def test_an_incomplete_approval_authorises_nothing(overrides: dict, expected) -> None:
    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    with pytest.raises(ExportRefused) as refused:
        quarantine.approve_export(approval(HOST_NVME.identity, **overrides))
    assert refused.value.refusal is expected


def test_the_medium_is_not_an_export_target() -> None:
    quarantine = a_quarantine()
    with pytest.raises(ExportRefused) as refused:
        quarantine.approve_export(approval(MEDIUM_ID))
    assert refused.value.refusal is Refusal.BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET


def test_the_medium_identity_is_never_an_export_target_whatever_its_disposition() -> None:
    """A review approved an export to the medium's identity after a demotion."""

    quarantine = a_quarantine()
    quarantine.observe(Device(identity=MEDIUM_ID, device_class=DeviceClass.HOST_STORAGE))
    with pytest.raises(ExportRefused) as refused:
        quarantine.approve_export(approval(MEDIUM_ID))
    assert refused.value.refusal is Refusal.BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET


def test_a_structural_fault_is_reported_before_an_operator_slip() -> None:
    """Naming the medium is a mistake about the target; an unticked box is not."""

    quarantine = a_quarantine()
    with pytest.raises(ExportRefused) as refused:
        quarantine.approve_export(approval(MEDIUM_ID, confirmed=False))
    assert refused.value.refusal is Refusal.BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET


def test_a_replacement_approval_does_not_accumulate() -> None:
    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    quarantine.observe(DOCKED_DISK)
    for target in (HOST_NVME.identity, DOCKED_DISK.identity):
        quarantine.approve_export(approval(target))
    assert quarantine.evaluate(DOCKED_DISK, Action.EXPORT_WRITE) is Verdict.ALLOWED
    assert quarantine.evaluate(HOST_NVME, Action.EXPORT_WRITE) is Verdict.BLOCKED


# --- the state cannot be handed to the constructor -------------------------


def test_the_running_state_is_not_a_constructor_argument() -> None:
    """A ready-made approval through the generated `__init__` skipped every check."""

    parameters = set(inspect.signature(Quarantine).parameters)
    assert parameters == {"session_id", "boot_medium_identity"}
    with pytest.raises(TypeError):
        Quarantine(  # type: ignore[call-arg]
            session_id="s1",
            boot_medium_identity=MEDIUM_ID,
            _approval=approval(HOST_NVME.identity),
        )


def test_the_medium_identity_is_read_only() -> None:
    """Identity-only classification makes this field the whole of the authority."""

    quarantine = a_quarantine()
    with pytest.raises(AttributeError):
        quarantine.boot_medium_identity = HOST_NVME.identity  # type: ignore[misc]


def test_an_approval_for_the_medium_is_refused_before_it_has_ever_been_observed() -> None:
    """The identity check is the live one; the disposition check cannot see this.

    A review showed the two checks had become two spellings of one, and that
    deleting either left the suite green. This is the state that separates them.
    """

    quarantine = Quarantine(session_id="s1", boot_medium_identity=MEDIUM_ID)
    with pytest.raises(ExportRefused) as refused:
        quarantine.approve_export(approval(MEDIUM_ID))
    assert refused.value.refusal is Refusal.BOOT_MEDIUM_IS_NOT_AN_EXPORT_TARGET


def test_a_device_disagreeing_with_the_medium_identity_is_recorded() -> None:
    """Identity decides; the disagreement is still information.

    Duplicate or blank serials on USB and NVMe bridges are a known class of
    hardware, and nothing here yet constrains how an identity is constructed. A
    collision nobody notices is worse than one that is merely allowed.
    """

    quarantine = Quarantine(session_id="s1", boot_medium_identity=MEDIUM_ID)
    quarantine.observe(Device(MEDIUM_ID, DeviceClass.HOST_STORAGE))
    assert [
        entry.action for entry in quarantine.audit()
    ] == ["identity_claim_mismatch"]
    quarantine.observe(BOOT_MEDIUM)
    assert [entry.action for entry in quarantine.audit()] == ["identity_claim_mismatch"]


def test_the_quarantine_itself_renders_no_identity() -> None:
    """A generated repr printed every observed identity into any traceback."""

    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    rendered = repr(quarantine)
    for identity in (MEDIUM_ID, HOST_NVME.identity):
        assert identity not in rendered
    assert "s1" not in rendered


# --- the audit -------------------------------------------------------------


def test_the_audit_records_the_quarantines_own_conclusion_not_the_device_claim() -> None:
    """A host disk that misreports itself must not choose how it appears."""

    quarantine = a_quarantine()
    impostor = Device(identity="host-disk", device_class=DeviceClass.BOOT_MEDIUM)
    quarantine.observe(impostor)
    quarantine.evaluate(impostor, Action.FSCK)
    assert quarantine.audit()[-1] == AuditEntry(
        disposition="quarantined", action="fsck", verdict="blocked"
    )


def test_an_unobserved_device_is_audited_as_unobserved() -> None:
    quarantine = a_quarantine()
    quarantine.evaluate(UNCLASSIFIABLE, Action.AUTOMOUNT)
    assert quarantine.audit()[-1].disposition == "unobserved"


def test_a_superseded_approval_and_an_empty_withdrawal_are_recorded() -> None:
    """The audit shows what happened to an approval, not only that one was made."""

    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    quarantine.observe(DOCKED_DISK)
    quarantine.approve_export(approval(HOST_NVME.identity))
    quarantine.approve_export(approval(DOCKED_DISK.identity))
    quarantine.withdraw_export()
    quarantine.withdraw_export()
    verdicts = [
        entry.verdict for entry in quarantine.audit() if entry.action == "export_approval"
    ]
    assert verdicts == ["granted", "superseded", "granted", "withdrawn", "nothing_to_withdraw"]


def test_an_approval_and_its_refusals_are_recorded() -> None:
    """The threat model requires the approval to be in the audit record."""

    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    with pytest.raises(ExportRefused):
        quarantine.approve_export(approval(HOST_NVME.identity, confirmed=False))
    quarantine.approve_export(approval(HOST_NVME.identity))
    quarantine.withdraw_export()
    verdicts = [entry.verdict for entry in quarantine.audit() if entry.action == "export_approval"]
    assert verdicts == ["not_confirmed", "granted", "withdrawn"]


def test_the_audit_keeps_no_device_identity() -> None:
    """Audit is for traceability; it is not a place to keep identifiers."""

    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    quarantine.approve_export(approval(HOST_NVME.identity))
    quarantine.evaluate(HOST_NVME, Action.EXPORT_WRITE)
    quarantine.evaluate(BOOT_MEDIUM, Action.READ)
    rendered = repr(quarantine.audit())
    for identity in (HOST_NVME.identity, MEDIUM_ID, DOCKED_DISK.identity):
        assert identity not in rendered


def test_a_refusal_message_names_no_device() -> None:
    """These strings reach a console and a log on media that travels."""

    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    for overrides in ({"reason": " "}, {"confirmed": False}, {"session_id": "s0"}):
        with pytest.raises(ExportRefused) as refused:
            quarantine.approve_export(approval(HOST_NVME.identity, **overrides))
        assert HOST_NVME.identity not in str(refused.value)
        assert HOST_NVME.identity not in refused.value.detail
    with pytest.raises(ExportRefused) as refused:
        quarantine.approve_export(approval("never-seen-SN-DEADBEEF"))
    assert "DEADBEEF" not in str(refused.value)


# --------------------------------------------------------------------------
# The fence: removal, and what the rule does afterwards
#
# `fence()` and `is_fenced` arrived with `azazel_boot.persistence` and were
# tested only from the persistence side. A review pointed out the asymmetry and
# then used it: the class's own primary consumer, `evaluate`, never consulted
# the flag, so every action on a fenced medium was still allowed.
# --------------------------------------------------------------------------


def test_a_fenced_medium_allows_nothing() -> None:
    """The fence decides; it is not a note attached to the decision.

    `_decide` short-circuited on `disposition is BOOT_MEDIUM` and returned
    ALLOWED without looking at the fence, so a writable mount, an fsck, a
    journal replay and a swap activation against a medium that had been pulled
    were all permitted — and the audit recorded them as permitted, on
    `boot_medium`. That is the threat model's "new actions taken after removal"
    with an audit path that says they were fine.
    """

    quarantine = a_quarantine()
    quarantine.observe(BOOT_MEDIUM)
    assert quarantine.evaluate(BOOT_MEDIUM, Action.WRITABLE_MOUNT) is Verdict.ALLOWED

    quarantine.fence()
    for action in Action:
        assert quarantine.evaluate(BOOT_MEDIUM, action) is Verdict.BLOCKED
        assert quarantine.evaluate(HOST_NVME, action) is Verdict.BLOCKED


def test_a_device_arriving_after_the_fence_on_the_mediums_identity_is_blocked() -> None:
    """The sharp case, and the one the fence exists for.

    A device presenting the medium's identity after the removal is the
    transient-physical-access adversary this module states it cannot tell apart.
    Classification is unchanged — identity decides, and that is deliberate — but
    the verdict is not: it used to be a writable mount.
    """

    quarantine = a_quarantine()
    quarantine.observe(BOOT_MEDIUM)
    quarantine.fence()

    impostor = Device(identity=MEDIUM_ID, device_class=DeviceClass.HOST_STORAGE)
    assert quarantine.observe(impostor) is Disposition.BOOT_MEDIUM
    assert quarantine.evaluate(impostor, Action.WRITABLE_MOUNT) is Verdict.BLOCKED
    assert quarantine.evaluate(impostor, Action.SWAP_ACTIVATION) is Verdict.BLOCKED
    assert quarantine.medium_is_bound() is False


def test_the_fence_is_one_way_and_idempotent() -> None:
    """Nothing tested the quarantine's own flag, so making it two-way was green.

    `fence()` twice is still fenced; a re-appearance of the medium does not
    clear it; and plain assignment raises, which is the guard the session had
    from the start and the quarantine did not have when the flag moved here.
    """

    quarantine = a_quarantine()
    quarantine.observe(BOOT_MEDIUM)
    assert quarantine.is_fenced is False

    quarantine.fence()
    quarantine.fence()
    assert quarantine.is_fenced is True

    quarantine.observe(BOOT_MEDIUM)
    assert quarantine.is_fenced is True

    with pytest.raises(AttributeError):
        quarantine._fenced = False  # noqa: SLF001 - the attack
    assert quarantine.is_fenced is True


def test_the_fence_is_audited_once_and_then_as_a_repeat() -> None:
    """`docs/quarantine-policy.md` documents these entries; nothing asserted them."""

    quarantine = a_quarantine()
    quarantine.observe(BOOT_MEDIUM)
    quarantine.fence()
    quarantine.fence()

    fences = [entry for entry in quarantine.audit() if entry.action == "medium_fenced"]
    assert [entry.verdict for entry in fences] == ["fenced", "already_fenced"]
    assert all(entry.disposition == "boot_medium" for entry in fences)


def test_a_sealed_quarantine_refuses_the_assignment_that_promotes_any_device() -> None:
    """Reading through a property stopped a generated setter, not an assignment.

    Identity-only classification makes `_boot_medium_identity` the whole of this
    module's authority, which the class docstring has said since a second review
    said it. Careless-caller defence, on the terms stated there: it is not a
    seal, and nothing here claims one.
    """

    quarantine = a_quarantine()
    quarantine.observe(HOST_NVME)
    for name, value in (
        ("_boot_medium_identity", "host-nvme-SN-1"),
        ("_session_id", "s-other"),
        ("_dispositions", {}),
        ("_audit", []),
    ):
        with pytest.raises(AttributeError):
            setattr(quarantine, name, value)
    assert quarantine.evaluate(HOST_NVME, Action.WRITABLE_MOUNT) is Verdict.BLOCKED
