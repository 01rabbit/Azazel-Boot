"""The screen says little, promises less, and buys nothing.

Azazel-Boot#9's confirmation flow. Three properties carry the file, and each
answers a threat [the threat model](../../docs/threat-model.md) §6 names:

*A confirmation is treated as an authorization.* The strongest test here takes a
**completed** confirmation and drives the quarantine, the persistence session
and the writer with it in hand, showing every answer is the one it was before.

*Rendering falls back to something plausible.* Nothing here infers. A role must
be one the assessment offered, a code must be one this screen issued, and both
refuse rather than defaulting.

*A stressed operator confirms a topology they do not understand.* The screen
carries no identifier they did not read off the hardware, and no word that
turns "this is what Boot could read" into a finding about the laptop.

No screen has been shown to anybody. Every test runs against captured sysfs
fixtures with an injected MAC reader. **No real laptop, no real NIC, no
operator.**
"""

from __future__ import annotations

import copy
import dataclasses
import pickle
from pathlib import Path

import pytest
from conftest import mac_reader

from azazel_boot.commissioning import INTERFACE_ROLES, ROLES, assess, describe_for_operator
from azazel_boot.confirmation import (
    FORBIDDEN_ASSURANCE_WORDS,
    NOT_OFFERED_BY_THE_ASSESSMENT,
    PERMITTED_AFTER_CONFIRMATION,
    REFUSED_REGARDLESS,
    TRUST_WORDING,
    Confirmation,
    ConfirmationRefused,
    ConfirmationScreen,
    OfferedInterface,
    PlatformTrust,
    ScreenRefusal,
    rendered_words,
    restatement_for,
)
from azazel_boot.inventory import collect_interfaces

SESSION = "s1"
TWO_NIC_MACS = {"enp3s0": "a0:b1:c2:d3:e4:f5", "enx001122334455": "00:11:22:33:44:55"}


def observe(root, macs):
    return collect_interfaces(root, permanent_mac_reader=mac_reader(macs))


@pytest.fixture
def two_nics(sysfs_two_nics):
    return observe(sysfs_two_nics, TWO_NIC_MACS)


def screen_for(observations, trust=PlatformTrust.UNVERIFIED_PLATFORM):
    screen = ConfirmationScreen(SESSION, trust)
    first = screen.first_stage(observations, assess(observations))
    return screen, first


def first_offerable(first):
    return next(row for row in first.offered if row.is_offerable)


def complete(observations, role="observation"):
    """Walk the whole flow and return the confirmation it produced."""

    screen, first = screen_for(observations)
    row = first_offerable(first)
    screen.second_stage(row.code, role)
    return screen, screen.confirm(row.code, role, restatement_for(row, role))


# --------------------------------------------------------------------------
# A confirmation authorises nothing. This is the one that matters.
# --------------------------------------------------------------------------


def test_a_confirmation_cannot_be_handed_to_anything_that_decides() -> None:
    """The three modules that act have nowhere to put one.

    Not "they ignore it" — their signatures have no parameter it fits. A
    confirmation that could be passed would eventually be consulted.
    """

    import ast
    import inspect

    from azazel_boot import persistence, quarantine, writer

    # Not "the word does not appear" — `writer` has its own two-stage
    # confirmation and legitimately uses it. What must be absent is **this
    # module**: nothing that acts may import it or name its type.
    for module in (persistence, quarantine, writer):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "confirmation" not in node.module
            if isinstance(node, ast.Import):
                assert all("confirmation" not in a.name for a in node.names)
            if isinstance(node, ast.Name):
                assert node.id != "Confirmation"

    for owner, names in (
        (persistence.PersistenceSession, ("create", "unlock")),
        (quarantine.Quarantine, ("evaluate", "approve_export", "observe")),
        (writer.WriteAuthority, ("plan", "execute")),
    ):
        for name in names:
            annotations = [
                str(p.annotation)
                for p in inspect.signature(getattr(owner, name)).parameters.values()
            ]
            assert not any("Confirmation" in a for a in annotations)


def test_a_completed_confirmation_changes_no_answer_anywhere(
    two_nics, sysfs_two_nics
) -> None:
    """Driven end to end with the confirmation in hand, and nothing moves.

    The threat is an operator — or a caller — reasoning "the interface was
    approved, therefore the action is approved". Every gate is asked before and
    after, and both answers are recorded here rather than argued about.
    """

    from azazel_boot.quarantine import Action, Device, DeviceClass, Quarantine, Verdict

    host_disk = Device(identity="host-nvme-SN-1", device_class=DeviceClass.HOST_STORAGE)
    medium = Device(identity="usb-boot-medium", device_class=DeviceClass.BOOT_MEDIUM)
    rule = Quarantine(session_id=SESSION, boot_medium_identity="usb-boot-medium")
    rule.observe(host_disk)
    rule.observe(medium)

    before = {
        action: rule.evaluate(host_disk, action) for action in Action
    }
    _, confirmation = complete(two_nics)
    assert isinstance(confirmation, Confirmation)
    after = {action: rule.evaluate(host_disk, action) for action in Action}

    assert before == after
    assert all(verdict is Verdict.BLOCKED for verdict in after.values())
    assert confirmation.authority == ()


def test_a_confirmation_holds_nothing_that_could_be_read_as_a_grant() -> None:
    """Absent vocabulary: no device, no capability, no lease, no expiry."""

    names = {f.name for f in dataclasses.fields(Confirmation)}
    assert names == {"code", "role", "session_id"}
    for forbidden in (
        "device",
        "device_path",
        "capability",
        "lease",
        "expires_at",
        "granted",
        "allowed",
        "authorised",
        "authorized",
        "permission",
        "token",
        "identity",
        "interface_key",
    ):
        assert forbidden not in names

    # Fields are not class attributes on a dataclass without defaults, so the
    # public surface is checked separately: one property, and no method.
    public = {n for n in dir(Confirmation) if not n.startswith("_")}
    assert public == {"authority"}
    assert not any(callable(getattr(Confirmation, n)) for n in public)


# --------------------------------------------------------------------------
# The screen never overstates
# --------------------------------------------------------------------------


@pytest.mark.parametrize("trust", list(PlatformTrust))
def test_no_screen_in_any_state_contains_an_assurance_word(trust, two_nics) -> None:
    """The promotion `UNVERIFIED_PLATFORM` exists to prevent, checked as words.

    A stressed operator reading "verified" takes it as a finding about the
    laptop. There is no such finding, in any class.
    """

    # The list is pinned as an exact tuple, not parametrized over itself.
    # Mutation emptied it and the suite stayed green — the **third** time that
    # shape has slipped through in this repository, after `VOLUME_MANAGERS` and
    # `VOLUME_MANAGER_MEMBERS`. `test_no_denylist_is_parametrized_over_itself`
    # now catches the shape repo-wide.
    assert FORBIDDEN_ASSURANCE_WORDS == (
        "safe",
        "secure",
        "verified",
        "trusted",
        "compatible",
        "supported",
        "certified",
        "guaranteed",
        "protected",
        "validated",
        "approved",
    )

    screen, first = screen_for(two_nics, trust)
    row = first_offerable(first)
    second = screen.second_stage(row.code, "observation")

    for rendered in (first, second):
        words = rendered_words(rendered)
        for forbidden in FORBIDDEN_ASSURANCE_WORDS:
            assert forbidden not in words, f"{trust.value} screen says {forbidden!r}"


def test_the_unverified_wording_says_what_cannot_be_claimed(two_nics) -> None:
    """Not merely "unverified" — what that means for what is on the screen."""

    _, first = screen_for(two_nics, PlatformTrust.UNVERIFIED_PLATFORM)
    rendered = "\n".join(first.lines)
    assert TRUST_WORDING[PlatformTrust.UNVERIFIED_PLATFORM] in rendered
    assert "not a finding about this laptop" in rendered
    assert "nothing checked Boot on this machine" in rendered


def test_the_trust_classes_are_the_threat_models_three() -> None:
    """A mirror that cannot drift from what it mirrors."""

    document = (
        Path(__file__).resolve().parents[2] / "docs" / "threat-model.md"
    ).read_text(encoding="utf-8")
    for trust in PlatformTrust:
        assert f"`{trust.value}`" in document
    assert {t.value for t in PlatformTrust} == {
        "VERIFIED_FIRMWARE",
        "EXTERNALLY_VERIFIED_MEDIA",
        "UNVERIFIED_PLATFORM",
    }


def test_no_path_raises_a_trust_class(two_nics) -> None:
    """Never silently upgraded. There is no setter and no upgrade function."""

    screen = ConfirmationScreen(SESSION, PlatformTrust.UNVERIFIED_PLATFORM)
    with pytest.raises(AttributeError):
        screen._trust = PlatformTrust.VERIFIED_FIRMWARE  # noqa: SLF001 - the attack
    assert screen.trust is PlatformTrust.UNVERIFIED_PLATFORM

    source = Path(
        __file__
    ).resolve().parents[2] / "src" / "azazel_boot" / "confirmation.py"
    text = source.read_text(encoding="utf-8")
    assert "VERIFIED_FIRMWARE" not in text.split("class PlatformTrust")[1].split(
        "TRUST_WORDING = {"
    )[1].split("}")[1]


def test_the_screen_states_what_is_permitted_and_what_stays_refused(two_nics) -> None:
    """Both halves, because "I approved it" is the mistake §6 names."""

    _, first = screen_for(two_nics)
    rendered = "\n".join(first.lines)
    for item in PERMITTED_AFTER_CONFIRMATION:
        assert item in rendered
    for item in REFUSED_REGARDLESS:
        assert item in rendered
    assert "writing anything to this laptop's own disks" in rendered
    assert "Azazel-Edge does that" in rendered


# --------------------------------------------------------------------------
# Nothing the operator did not read off the hardware
# --------------------------------------------------------------------------


def test_no_screen_carries_a_mac_a_serial_or_a_composite_identity(
    sysfs_two_nics,
) -> None:
    """`interface_key` is `bus_path|permanent_mac`, so it is absent too."""

    observations = observe(sysfs_two_nics, TWO_NIC_MACS)
    screen, first = screen_for(observations)
    row = first_offerable(first)
    second = screen.second_stage(row.code, "observation")

    rendered = "\n".join(first.lines + second.lines)
    for observation in observations:
        assert observation.permanent_mac
        assert observation.permanent_mac not in rendered
        assert observation.interface_key not in rendered
        assert observation.kernel_name_observed not in rendered
        for value in (observation.serial, observation.pci_id, observation.usb_vid_pid):
            if value:
                assert value not in rendered


def test_an_offered_row_has_no_field_that_could_hold_an_identifier() -> None:
    names = {f.name for f in dataclasses.fields(OfferedInterface)}
    assert names == {
        "code",
        "locator",
        "locator_is_a_label",
        "connection",
        "unavailable_because",
    }
    for forbidden in (
        "identity",
        "interface_key",
        "permanent_mac",
        "mac",
        "serial",
        "asset_id",
        "asset_tag",
        "tpm",
        "bus_path",
        "path",
        "operator",
    ):
        assert forbidden not in names


def test_the_bus_position_appears_only_when_there_is_no_label(
    sysfs_two_nics, sysfs_single_nic
) -> None:
    """The one judgement, asserted so it cannot widen quietly.

    Showing it always would disclose more than the question needs; never
    showing it would leave an operator facing two bare sockets unable to
    answer.
    """

    observations = observe(sysfs_two_nics, TWO_NIC_MACS)
    _, first = screen_for(observations)

    for observation, row in zip(observations, first.offered, strict=True):
        described = describe_for_operator(observation)
        if described["physical_label"] == "unlabelled":
            assert not row.locator_is_a_label
            assert row.locator == described["bus_position"]
            assert "carries no label" in "\n".join(first.lines)
        else:
            assert row.locator_is_a_label
            assert row.locator == described["physical_label"]
            assert described["bus_position"] not in "\n".join(first.lines)


def test_a_refusal_never_echoes_what_the_caller_supplied(two_nics) -> None:
    """Refusals reach a terminal and a journal."""

    screen, first = screen_for(two_nics)
    row = first_offerable(first)

    with pytest.raises(ConfirmationRefused) as refused:
        screen.second_stage("zz-99-secret-code", "observation")
    assert "zz-99-secret-code" not in str(refused.value)

    with pytest.raises(ConfirmationRefused) as refused:
        screen.second_stage(row.code, "a-role-nobody-registered")
    assert "a-role-nobody-registered" not in str(refused.value)
    assert row.locator not in str(refused.value)


def test_the_screen_and_the_confirmation_redact_their_reprs(two_nics) -> None:
    screen, confirmation = complete(two_nics)
    assert SESSION not in repr(confirmation)
    assert confirmation.code not in repr(confirmation)
    assert "observation" in repr(confirmation)
    assert SESSION not in repr(screen)

    # The message, not just the type. `__slots__` happens to make this class
    # unpicklable today, so `pytest.raises(TypeError)` passed against a version
    # with `__reduce__` deleted — it was Python's incidental refusal, not ours.
    # A `__getstate__` or a `__dict__` added later would remove that accident.
    for attempt in (lambda: pickle.dumps(screen), lambda: copy.deepcopy(screen)):
        with pytest.raises(TypeError, match="not serialisable"):
            attempt()


# --------------------------------------------------------------------------
# Two stages, and neither is skippable
# --------------------------------------------------------------------------


def test_the_restating_screen_must_actually_be_shown(two_nics) -> None:
    """Otherwise the second stage is a step a caller can skip."""

    screen, first = screen_for(two_nics)
    row = first_offerable(first)

    with pytest.raises(ConfirmationRefused) as refused:
        screen.confirm(row.code, "observation", restatement_for(row, "observation"))
    assert refused.value.refusal is ScreenRefusal.FIRST_STAGE_NOT_SHOWN


def test_the_phrase_is_built_from_the_port_and_the_role(two_nics) -> None:
    """One answer cannot stand for a different port or a different role."""

    screen, first = screen_for(two_nics)
    rows = [row for row in first.offered if row.is_offerable]
    assert len(rows) >= 2

    screen.second_stage(rows[0].code, "observation")
    for wrong in (
        "yes",
        "y",
        restatement_for(rows[1], "observation"),
        restatement_for(rows[0], "management"),
    ):
        with pytest.raises(ConfirmationRefused) as refused:
            screen.confirm(rows[0].code, "observation", wrong)
        assert refused.value.refusal in {
            ScreenRefusal.RESTATEMENT_DID_NOT_MATCH,
            ScreenRefusal.ROLE_NOT_OFFERED,
        }


def test_a_code_confirms_one_port_once(two_nics) -> None:
    screen, confirmation = complete(two_nics)
    with pytest.raises(ConfirmationRefused) as refused:
        screen.second_stage(confirmation.code, "observation")
    assert refused.value.refusal is ScreenRefusal.CHOICE_CODE_ALREADY_USED


def test_a_code_from_another_screen_does_not_resolve(two_nics) -> None:
    """A code names a port, not a position in whatever list exists now."""

    other = ConfirmationScreen("s2", PlatformTrust.UNVERIFIED_PLATFORM)
    other.first_stage(two_nics, assess(two_nics))
    screen, first = screen_for(two_nics)
    del screen

    fresh = ConfirmationScreen(SESSION, PlatformTrust.UNVERIFIED_PLATFORM)
    with pytest.raises(ConfirmationRefused) as refused:
        fresh.second_stage(first_offerable(first).code, "observation")
    assert refused.value.refusal is ScreenRefusal.UNKNOWN_CHOICE_CODE


# --------------------------------------------------------------------------
# Nothing is inferred
# --------------------------------------------------------------------------


def test_only_roles_the_assessment_offered_may_be_confirmed(two_nics) -> None:
    screen, first = screen_for(two_nics)
    row = first_offerable(first)
    offered = set(assess(two_nics).offerable_roles)
    assert offered == set(ROLES)

    for never in ("unassigned", "root", "internal", "external", "anything"):
        assert never not in offered
        with pytest.raises(ConfirmationRefused) as refused:
            screen.second_stage(row.code, never)
        assert refused.value.refusal is ScreenRefusal.ROLE_NOT_OFFERED


def test_a_single_nic_host_is_offered_observation_and_nothing_else(
    sysfs_single_nic,
) -> None:
    """Observe-only as the intended outcome, said in the operator's words."""

    observations = observe(sysfs_single_nic, {"wlp2s0": "12:34:56:78:9a:bc"})
    screen, first = screen_for(observations)
    rendered = "\n".join(first.lines)
    assert "one usable port" in rendered
    assert "not a fault" in rendered

    row = first_offerable(first)
    for never in set(ROLES) - {"observation"}:
        with pytest.raises(ConfirmationRefused):
            screen.second_stage(row.code, never)


def test_an_uncommissionable_interface_is_shown_and_cannot_be_chosen(
    sysfs_mac_only,
) -> None:
    """Shown, because the operator can see the port and will ask about it."""

    observations = observe(sysfs_mac_only, {"eth0": "de:ad:be:ef:00:01"})
    screen, first = screen_for(observations)
    (row,) = first.offered
    assert not row.is_offerable
    assert "no_discriminator_beyond_mac" in "\n".join(first.lines)
    assert "nothing is confirmed and nothing will be" in "\n".join(first.lines)

    with pytest.raises(ConfirmationRefused) as refused:
        screen.second_stage(row.code, "observation")
    assert refused.value.refusal is ScreenRefusal.UNKNOWN_CHOICE_CODE


def test_an_ambiguous_inventory_offers_nothing(sysfs_cloned_identity) -> None:
    observations = observe(
        sysfs_cloned_identity,
        {"enp1s0": "aa:bb:cc:dd:ee:01", "enp1s0f1": "aa:bb:cc:dd:ee:01"},
    )
    screen, first = screen_for(observations)
    rendered = "\n".join(first.lines)

    # Each interface is individually complete — the ambiguity is between them —
    # so a row that read `incomplete_reasons` alone said "choose me" while the
    # assessment had already refused. The row asks the assessment now.
    assert all(o.is_commissionable for o in observations)
    assert assess(observations).offerable_roles == ()
    assert not any(row.is_offerable for row in first.offered)
    assert NOT_OFFERED_BY_THE_ASSESSMENT in rendered
    assert "cannot tell these ports apart" in rendered

    for row in first.offered:
        with pytest.raises(ConfirmationRefused) as refused:
            screen.second_stage(row.code, "observation")
        assert refused.value.refusal is ScreenRefusal.UNKNOWN_CHOICE_CODE


def test_the_role_words_are_fabrics_registered_ones() -> None:
    """No second vocabulary; this module invents none."""

    source = (
        Path(__file__).resolve().parents[2] / "src" / "azazel_boot" / "confirmation.py"
    ).read_text(encoding="utf-8")
    import ast

    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in INTERFACE_ROLES:
                assert node.value in INTERFACE_ROLES
    assert "ROLES" in source


def test_the_module_performs_nothing(two_nics) -> None:
    """It renders text and records a word. It opens nothing and sends nothing."""

    import ast

    source = (
        Path(__file__).resolve().parents[2] / "src" / "azazel_boot" / "confirmation.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    assert not imported & {"os", "subprocess", "socket", "urllib", "pathlib", "shutil"}
    assert "open" not in calls
    assert "print" not in calls
