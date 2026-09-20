"""Roles stay unassigned, ambiguity fails closed, and a record does not travel.

Azazel-Boot#9. The assessment reports what an inventory *permits*. It confirms
nothing on an operator's behalf and grants no authority, so every test here is
about what is refused and what an operator would still have to settle.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from conftest import mac_reader

from azazel_boot.commissioning import (
    CommissioningState,
    assess,
    bind_session,
    binding_applies,
    describe_for_operator,
    host_fingerprint,
)
from azazel_boot.inventory import collect_interfaces

TWO_NIC_MACS = {"enp3s0": "a0:b1:c2:d3:e4:f5", "enx001122334455": "00:11:22:33:44:55"}


def _observe(root, macs):
    return collect_interfaces(root, permanent_mac_reader=mac_reader(macs))


def test_no_interfaces_requires_commissioning():
    assessment = assess(())
    assert assessment.state is CommissioningState.COMMISSIONING_REQUIRED
    assert assessment.offerable_roles == ()


def test_an_ambiguous_identity_fails_closed(sysfs_cloned_identity):
    """Two interfaces, one composite identity. Neither is guessed at."""

    observations = _observe(
        sysfs_cloned_identity,
        {"enp1s0": "aa:bb:cc:dd:ee:01", "enp1s0f1": "aa:bb:cc:dd:ee:01"},
    )
    assessment = assess(observations)

    assert assessment.state is CommissioningState.COMMISSIONING_REQUIRED
    assert assessment.commissionable_keys == ()
    assert assessment.offerable_roles == ()
    assert any("ambiguous identity fails closed" in r for r in assessment.reasons)


def test_an_interface_without_a_discriminator_cannot_be_commissioned(sysfs_mac_only):
    observations = _observe(sysfs_mac_only, {"eth0": "de:ad:be:ef:00:01"})
    assessment = assess(observations)

    assert assessment.state is CommissioningState.COMMISSIONING_REQUIRED
    assert any("no_discriminator_beyond_mac" in r for r in assessment.reasons)


def test_a_single_interface_host_is_observe_only_by_intent(sysfs_single_nic):
    """Stated as the intended outcome, not as a defect (#9).

    One port means no independent management path, so a two-stage commit for a
    high-impact change has nowhere to run. Enforcement eligibility is therefore
    absent by construction rather than withheld by policy.
    """

    observations = _observe(sysfs_single_nic, {"wlp2s0": "12:34:56:78:9a:bc"})
    assessment = assess(observations)

    assert assessment.state is CommissioningState.OBSERVE_ONLY
    assert assessment.offerable_roles == ("observation",)
    assert len(assessment.commissionable_keys) == 1
    assert any("intended outcome, not a defect" in r for r in assessment.reasons)


def test_two_distinct_interfaces_still_assign_no_role(sysfs_two_nics):
    """The state is *awaiting* confirmation. Nothing is confirmed here."""

    assessment = assess(_observe(sysfs_two_nics, TWO_NIC_MACS))

    assert assessment.state is CommissioningState.AWAITING_OPERATOR_CONFIRMATION
    assert len(assessment.commissionable_keys) == 2
    assert any("stay unassigned until an operator confirms" in r for r in assessment.reasons)


def test_every_assessment_gives_at_least_one_reason(
    sysfs_two_nics, sysfs_single_nic, sysfs_mac_only, sysfs_cloned_identity
):
    """An operator facing a refusal must be told what it was."""

    for root, macs in (
        (sysfs_two_nics, TWO_NIC_MACS),
        (sysfs_single_nic, {"wlp2s0": "12:34:56:78:9a:bc"}),
        (sysfs_mac_only, {"eth0": "de:ad:be:ef:00:01"}),
        (sysfs_cloned_identity, {"enp1s0": "aa:bb:cc:dd:ee:01", "enp1s0f1": "aa:bb:cc:dd:ee:01"}),
    ):
        assert assess(_observe(root, macs)).reasons


def test_a_record_does_not_apply_to_a_different_laptop(sysfs_two_nics, sysfs_single_nic):
    """Boot has no "the network", only "this host, this session" (#9)."""

    here = _observe(sysfs_two_nics, TWO_NIC_MACS)
    elsewhere = _observe(sysfs_single_nic, {"wlp2s0": "12:34:56:78:9a:bc"})

    binding = bind_session(here, session_id="session-1")
    assert binding_applies(binding, here, session_id="session-1")
    assert not binding_applies(binding, elsewhere, session_id="session-1")


def test_a_record_does_not_apply_to_a_later_session_on_the_same_host(sysfs_two_nics):
    here = _observe(sysfs_two_nics, TWO_NIC_MACS)
    binding = bind_session(here, session_id="session-1")

    assert not binding_applies(binding, here, session_id="session-2")


def test_the_fingerprint_ignores_interfaces_that_cannot_be_commissioned(
    sysfs_two_nics,
):
    """An unidentifiable NIC appearing must not invalidate a live binding."""

    full = _observe(sysfs_two_nics, TWO_NIC_MACS)
    partial_macs = dict(TWO_NIC_MACS)
    partial_macs["enx001122334455"] = None  # its identity can no longer be read

    assert host_fingerprint(full) != host_fingerprint(_observe(sysfs_two_nics, partial_macs))


def test_a_binding_requires_a_session_id(sysfs_two_nics):
    with pytest.raises(ValueError, match="session_id is required"):
        bind_session(_observe(sysfs_two_nics, TWO_NIC_MACS), session_id="   ")


def test_the_operator_is_never_shown_a_kernel_name(sysfs_two_nics):
    """They confirm "the port with the blue tag", not `enp3s0` (#9).

    A name they cannot check against the machine in front of them invites a
    confirmation that means nothing.
    """

    for observation in _observe(sysfs_two_nics, TWO_NIC_MACS):
        described = describe_for_operator(observation)
        rendered = " ".join(described.values())
        assert observation.kernel_name_observed
        assert observation.kernel_name_observed not in rendered
        assert described["physical_label"]
        assert described["connection"] in {"wired", "wireless"}


def test_the_operator_description_says_why_an_interface_is_unavailable(sysfs_mac_only):
    (observation,) = _observe(sysfs_mac_only, {"eth0": "de:ad:be:ef:00:01"})
    described = describe_for_operator(observation)
    assert "no_discriminator_beyond_mac" in described["unavailable_because"]


def test_the_assessment_is_deterministic(sysfs_two_nics):
    """No clock, no randomness: the same inventory gives the same answer."""

    first = assess(_observe(sysfs_two_nics, TWO_NIC_MACS))
    second = assess(_observe(sysfs_two_nics, TWO_NIC_MACS))
    assert first == second


def _string_values(path: Path) -> set[str]:
    """Every string this module *uses*, excluding prose.

    Comments and docstrings are skipped on purpose. Naming a retired word in
    order to record that it is retired is the opposite of using it, and a scan
    that could not tell the difference would push the correction's own
    explanation out of the file.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    }

# --------------------------------------------------------------------------
# The role vocabulary is Fabric's, and stays Fabric's
# --------------------------------------------------------------------------


#: What Boot held before adopting Fabric's list, copied literally.
#:
#: Kept so the correction stays legible rather than becoming invisible the
#: moment it is made. Boot, Fabric and Azazel-Nexus each had a different list;
#: `management` was the only value all three shared.
RETIRED_BOOT_ROLES = ("observe", "internal", "external", "management", "capture", "decoy")

#: Of those, the ones that actually went away. `management` did not: all three
#: vocabularies agree on it, so it is still a value this package uses.
#:
#: Filtered here rather than skipped inside the test. A skip that fires on
#: every run is a filter written in the wrong place -- and this repository's
#: CI refuses a run in which any test skipped, so the wrong place would have
#: been a red build.
RETIRED_AND_GONE = tuple(role for role in RETIRED_BOOT_ROLES if role != "management")


def test_the_role_mirror_still_matches_fabrics_registered_list():
    """Two statements of one list; this is what keeps them the same one.

    `commissioning.py` cannot import Fabric -- it is a CORE path and Fabric
    reaches this repository through one boundary module only (ADR-0004 D3) --
    so it names the roles itself. That is the shape that drifts, so that is the
    shape that gets a test.

    It skips without the optional extra, which is correct for a contributor
    with no network and useless as a gate; CI installs the extra.
    """

    pytest.importorskip(
        "azazel_fabric",
        reason="the Fabric extra is optional; commissioning must work without it",
    )
    from azazel_fabric.provisioning_contracts import INTERFACE_ROLES as FABRIC_ROLES

    from azazel_boot.commissioning import INTERFACE_ROLES

    assert INTERFACE_ROLES == FABRIC_ROLES


def test_unassigned_is_never_offered_as_something_to_confirm():
    """It is what an interface is before anyone confirms anything.

    Offering it would make "no role" a thing an operator actively chooses, and
    Boot's starting state would then depend on someone having chosen it.
    """

    from azazel_boot.commissioning import INTERFACE_ROLES, ROLES

    assert "unassigned" in INTERFACE_ROLES
    assert "unassigned" not in ROLES
    assert set(ROLES) == set(INTERFACE_ROLES) - {"unassigned"}


@pytest.mark.parametrize("retired", RETIRED_AND_GONE)
def test_no_retired_boot_role_word_survives_in_the_package(retired):
    """The near-misses are the dangerous ones.

    `observe` against `observation`, `decoy` against `deception_bridge`: both
    read as agreement to anyone skimming, and a reader who saw one and expected
    the other would not notice.
    """

    package = Path(__file__).resolve().parents[2] / "src" / "azazel_boot"
    offenders = [
        path.name
        for path in sorted(package.rglob("*.py"))
        if retired in _string_values(path)
    ]
    assert offenders == [], (
        f"{offenders} still use the retired role {retired!r} as a value; Boot "
        "uses Fabric's registered vocabulary"
    )


def test_topology_is_not_readmitted_as_a_role():
    """`internal` and `external` answered a different question.

    Which side of the boundary an interface faces is topology, it is Boot's
    own, and it never crosses a product boundary as a role. Putting either back
    into the role list would merge the two axes again -- which is how the three
    vocabularies diverged in the first place.
    """

    from azazel_boot.commissioning import INTERFACE_ROLES, ROLES

    for zone in ("internal", "external", "protected", "egress"):
        assert zone not in ROLES
        assert zone not in INTERFACE_ROLES
