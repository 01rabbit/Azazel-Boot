"""Nothing a Lite artifact does — or fails to do — may cost the Core anything.

Azazel-Boot#16, and the consumer half of the program's SO-06 objective. Every
test here checks one direction of the same rule: a missing, corrupt, expired or
unverifiable artifact degrades capability to `CORE` and **moves no authority**.

The cases are Boot's, not Nexus's. Absence is a normal configuration for an
emergency medium, expiry is the default state of a medium that is never
updated, and the medium can vanish while it is being read.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from azazel_boot.lite_cache import (
    DEGRADED_CAPABILITY,
    STAGING_RULE,
    Admission,
    Freshness,
    decide,
    refuse_everything,
)

MODULE = Path(__file__).resolve().parents[2] / "src" / "azazel_boot" / "lite_cache.py"

FUTURE = "2099-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"
NOW = "2026-09-19T00:00:00Z"


def accept(_artifact):
    return True, "signature verified by 2 of 3 active keys"


def reject(reason):
    return lambda _artifact: (False, reason)


def raiser(_artifact):
    raise RuntimeError("verifier exploded")


# --------------------------------------------------------------------------
# The shared rule: never a usable artifact, never a moved authority.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"artifact_present": False}, Admission.ABSENT),
        ({"artifact_present": True}, Admission.UNVERIFIABLE),
        (
            {"artifact_present": True, "verifier": reject("BUNDLE_SIGNATURE_MALFORMED")},
            Admission.REFUSED,
        ),
        (
            {"artifact_present": True, "verifier": reject("BUNDLE_FILE_HASH_MISMATCH")},
            Admission.REFUSED,
        ),
        (
            {"artifact_present": True, "verifier": reject("BUNDLE_ARCHIVE_UNREADABLE")},
            Admission.REFUSED,
        ),
        ({"artifact_present": True, "verifier": raiser}, Admission.REFUSED),
    ],
)
def test_every_failure_degrades_to_core_and_admits_nothing(kwargs, expected):
    decision = decide(**kwargs)

    assert decision.admission is expected
    assert decision.usable is False
    assert decision.capability == DEGRADED_CAPABILITY
    assert decision.freshness is None
    assert decision.reasons, "a refusal an operator cannot read is not a refusal"


def test_no_outcome_can_name_an_authority_level():
    """`CORE` is a capability state. No decision here may say otherwise."""

    authority_words = {"authority", "authorize", "authorized", "permit", "grant", "FULL"}
    for kwargs in (
        {"artifact_present": False},
        {"artifact_present": True},
        {"artifact_present": True, "verifier": reject("nope")},
        {"artifact_present": True, "verifier": accept, "expires_at": FUTURE, "as_of": NOW},
    ):
        decision = decide(**kwargs)
        assert decision.capability == DEGRADED_CAPABILITY
        assert not (authority_words & set(decision.capability.split()))


# --------------------------------------------------------------------------
# Boot-specific cases.
# --------------------------------------------------------------------------


def test_absence_is_reported_as_a_normal_configuration():
    """A medium handed out without Lite is not a fault (#16)."""

    decision = decide(artifact_present=False)
    assert decision.admission is Admission.ABSENT
    assert any("normal configuration" in r for r in decision.reasons)


def test_an_expired_artifact_is_admitted_with_its_label_intact():
    """Withholding the label would be worse than withholding the data.

    A consumer that lost the label would treat stale indicators as current,
    which is the one outcome worse than having none.
    """

    decision = decide(
        artifact_present=True, verifier=accept, expires_at=PAST, as_of=NOW
    )

    assert decision.admission is Admission.ADMITTED
    assert decision.usable is True
    assert decision.freshness is Freshness.EXPIRED
    assert any("expected state" in r for r in decision.reasons)


def test_a_current_artifact_is_admitted_and_labelled_current():
    decision = decide(
        artifact_present=True, verifier=accept, expires_at=FUTURE, as_of=NOW
    )
    assert decision.admission is Admission.ADMITTED
    assert decision.freshness is Freshness.CURRENT


def test_an_artifact_with_no_expiry_is_not_treated_as_current():
    decision = decide(artifact_present=True, verifier=accept, as_of=NOW)
    assert decision.freshness is Freshness.UNKNOWN


def test_freshness_that_was_never_evaluated_counts_as_expired():
    """No reference time is not evidence of currency."""

    decision = decide(artifact_present=True, verifier=accept, expires_at=FUTURE)
    assert decision.freshness is Freshness.EXPIRED


def test_admission_alone_does_not_raise_capability():
    """What a verified artifact enables is decided against more than itself.

    Capability is the intersection of resource, topology, verified assets and
    trust/health. A verified artifact is one input to one of those dimensions.
    """

    decision = decide(
        artifact_present=True, verifier=accept, expires_at=FUTURE, as_of=NOW
    )
    assert decision.capability == DEGRADED_CAPABILITY


# --------------------------------------------------------------------------
# The default refuses, and the refusal is distinguishable.
# --------------------------------------------------------------------------


def test_the_default_verifier_admits_nothing():
    """Knowledge signs with Ed25519; the bootstrap is standard-library only.

    A build that did not wire verification must end up with no data, never with
    unverified data.
    """

    accepted, detail = refuse_everything(object())
    assert accepted is False
    assert "no signature verifier" in detail

    decision = decide(artifact_present=True)
    assert decision.admission is Admission.UNVERIFIABLE


def test_unverifiable_is_distinguishable_from_refused():
    """"Never judged" and "judged and rejected" are different operator facts."""

    never_judged = decide(artifact_present=True)
    rejected = decide(artifact_present=True, verifier=reject("BUNDLE_REVOKED_SIGNER"))

    assert never_judged.admission is not rejected.admission
    assert never_judged.capability == rejected.capability == DEGRADED_CAPABILITY


def test_the_verifier_detail_is_passed_through_unchanged():
    """Knowledge owns the refusal vocabulary; Boot does not reinterpret it.

    A new Knowledge refusal code must need no change here, which is only true
    while Boot treats the text as opaque.
    """

    decision = decide(
        artifact_present=True, verifier=reject("BUNDLE_SECURITY_EPOCH_TOO_LOW")
    )
    assert decision.verifier_detail == "BUNDLE_SECURITY_EPOCH_TOO_LOW"


def test_boot_does_not_enumerate_knowledges_refusal_codes():
    """Enumerating them would fork a vocabulary Knowledge owns."""

    source = MODULE.read_text(encoding="utf-8")
    assert "BUNDLE_" not in source


def test_a_verifier_that_raises_is_a_refusal_not_a_crash():
    """An artifact that could not be judged is refused, never admitted."""

    decision = decide(artifact_present=True, verifier=raiser)
    assert decision.admission is Admission.REFUSED
    assert "RuntimeError" in decision.verifier_detail


# --------------------------------------------------------------------------
# Contracts the reader that does not exist yet has to meet.
# --------------------------------------------------------------------------


def test_the_staging_rule_is_stated_on_every_decision():
    """A contract written down can be implemented against; an implicit one cannot."""

    decision = decide(artifact_present=False)
    assert decision.staging_rule == STAGING_RULE
    assert "atomic rename" in STAGING_RULE
    assert "never a partially written state" in STAGING_RULE


def test_the_module_reads_no_artifact_and_writes_no_cache():
    """It decides admission. Acting on the decision is operational code.

    The medium can vanish mid-read (threat model §4), so an admission is a
    decision about bytes already verified — never a promise that a device still
    exists.
    """

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])

    assert "pathlib" not in roots and "os" not in roots and "shutil" not in roots
    assert "azazel_fabric" not in roots


def test_the_decision_is_deterministic():
    """`as_of` is supplied, never read from a clock, so a replay reproduces it."""

    first = decide(artifact_present=True, verifier=accept, expires_at=PAST, as_of=NOW)
    second = decide(artifact_present=True, verifier=accept, expires_at=PAST, as_of=NOW)
    assert first == second
