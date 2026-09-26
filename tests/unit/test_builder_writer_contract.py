"""The builder/writer contract must not be able to drift into a weaker one.

`docs/builder-writer-contract.md` is written before the builder exists, which
is the only time its awkward properties are cheap: a writer that takes no
device path, a build verb that cannot write, an artifact record with no
optional fields. Every one of those is the kind of rule that survives review
right up until the moment it is inconvenient.

These tests read the document as structure rather than prose. They check the
verb table, the artifact-record fields, the accepted options of `write`, and
the absence of the claims this repository is not entitled to make. They say
nothing about whether any of it is implemented: none of it is, and
`tests/unit/test_status.py` is what keeps that honest.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / "docs"
CONTRACT = DOCS / "builder-writer-contract.md"
ADR = DOCS / "adr" / "0009-builder-and-writer-contract.md"

#: The operator surface, in the order the contract lists it. `build` and
#: `write` appear once each and never together; see `test_no_verb_both_builds_and_writes`.
VERBS = ("doctor", "prepare-host", "build", "verify", "list-media", "write", "inspect")

#: One field per fact that is gone if the build does not record it. Revised with
#: ADR-0009 D2: the manifests and the SBOM are sidecars inside the artifact, so
#: the record carries a reference and a digest for each rather than the
#: documents themselves.
ARTIFACT_FIELDS = {
    "image_version",
    "git_revision",
    "builder_version",
    "debian_snapshot",
    "package_manifest_ref",
    "package_manifest_digest",
    "firmware_manifest_ref",
    "firmware_manifest_digest",
    "sbom_ref",
    "sbom_digest",
    "source_date_epoch",
    "build_input_digest",
    "partition_layout_digest",
    "root_filesystem_digest",
    "boot_chain_identity",
    "unsigned_payload_digest",
    "signed_artifact_digest",
    "signature",
    "build_time",
    "compatibility_claim",
    "quarantine_policy_version",
}

#: Only the build environment and the write service hold any privilege.
PRIVILEGES = {"unprivileged", "build environment only", "write service only"}

#: Claims no document in this repository may make today. Each one has a
#: specific reason: nothing has been built, written, selected, or booted.
FORBIDDEN_CLAIMS = (
    "boot ready",
    "no-host-write verified",
    "builder selected",
    "builder is selected",
    "live-build is selected",
    "ready for hardware",
    "hardware verified",
)

_HEADING = re.compile(r"^(#{2,6})\s+(?P<title>.+?)\s*$")


def _section(text: str, title: str) -> str:
    """Return one section's body, ending at the next heading of equal or higher level."""

    lines = text.splitlines()
    start = level = 0
    for number, line in enumerate(lines):
        match = _HEADING.match(line)
        if match and match.group("title") == title:
            start, level = number + 1, len(match.group(1))
            break
    assert level, f"no section titled {title!r} in the document"

    body: list[str] = []
    for line in lines[start:]:
        following = _HEADING.match(line)
        if following and len(following.group(1)) <= level:
            break
        body.append(line)
    return "\n".join(body)


def _rows(section: str) -> list[list[str]]:
    """Return the data rows of the first Markdown table in `section`."""

    rows: list[list[str]] = []
    seen_table = False
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            if seen_table and rows:
                break
            continue
        seen_table = True
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if all(set(cell) <= set("-: ") for cell in cells):  # the separator row
            continue
        rows.append(cells)
    assert rows, "parsed no table rows; the document's table format changed"
    return rows[1:]  # drop the header


@pytest.fixture(scope="module")
def contract() -> str:
    return CONTRACT.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def adr() -> str:
    return ADR.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def verb_rows(contract: str) -> list[list[str]]:
    return _rows(_section(contract, "2. The seven verbs"))


def _verb(cell: str) -> str:
    return cell.strip("`")


def test_the_operator_surface_is_exactly_the_six_verbs(verb_rows) -> None:
    assert tuple(_verb(row[0]) for row in verb_rows) == VERBS


def test_no_verb_both_builds_and_writes(verb_rows) -> None:
    """The separation is the point: a verb named for both would be the merge."""

    for row in verb_rows:
        verb = _verb(row[0])
        assert not ("build" in verb and "write" in verb), (
            f"{verb!r} names both halves; `build` and `write` are separated by "
            "an artifact, not by a flag (contract §2.1)"
        )


def test_only_the_build_environment_and_the_write_service_hold_privilege(verb_rows) -> None:
    privileges = {_verb(row[0]): row[2] for row in verb_rows}
    assert set(privileges.values()) <= PRIVILEGES, (
        f"a privilege outside {sorted(PRIVILEGES)} appeared: {sorted(set(privileges.values()))}"
    )
    assert privileges["write"] == "write service only"
    assert privileges["build"] == "build environment only"
    for verb in ("doctor", "verify", "list-media", "inspect"):
        assert privileges[verb] == "unprivileged", (
            f"{verb} claims privilege {privileges[verb]!r}; only `build` and "
            "`write` reach a privileged component (contract §8)"
        )


def test_only_write_touches_a_block_device_for_writing(verb_rows) -> None:
    writing = {_verb(row[0]) for row in verb_rows if row[3] == "yes"}
    assert writing == {"write"}, (
        f"verbs marked as touching a block device: {sorted(writing)} — the "
        "write service is the only component that opens one"
    )


def test_the_artifact_record_carries_exactly_the_agreed_fields(contract: str) -> None:
    rows = _rows(_section(contract, "3. The artifact record"))
    fields = {_verb(row[0]) for row in rows}
    assert fields == ARTIFACT_FIELDS, (
        f"missing: {sorted(ARTIFACT_FIELDS - fields)}; "
        f"unexpected: {sorted(fields - ARTIFACT_FIELDS)}"
    )


def test_the_record_references_its_manifests_rather_than_embedding_them() -> None:
    """ADR-0009 D2, revised: a record of scalars, and sidecars bound by digest."""

    for name in ("package_manifest", "firmware_manifest", "sbom"):
        assert name not in ARTIFACT_FIELDS, (
            f"{name!r} is back in the record; a fingerprint over a record "
            "containing a structured document cannot be computed identically twice"
        )
        assert {f"{name}_ref", f"{name}_digest"} <= ARTIFACT_FIELDS


def test_the_reproduced_subject_and_the_signed_artifact_are_separate_fields() -> None:
    """ADR-0002 D1.1: the reproduced subject is the *unsigned* payload."""

    assert {"unsigned_payload_digest", "signed_artifact_digest"} <= ARTIFACT_FIELDS
    assert "image_digest" not in ARTIFACT_FIELDS


def test_the_compatibility_claim_has_two_values_and_a_build_moves_neither(contract: str) -> None:
    rows = _rows(_section(contract, "3. The artifact record"))
    claim = next(row[1] for row in rows if _verb(row[0]) == "compatibility_claim")
    assert "`candidate`" in claim and "`hardware_verified`" in claim
    # Normalised, because a line wrap is not a change of meaning.
    section = " ".join(
        _section(contract, "3.2 `compatibility_claim` has two values").split()
    )
    assert "No third value exists" in section
    assert "only a hardware record moves it" in section


def test_write_accepts_no_device_path(contract: str) -> None:
    """A path is not a name an operator can be sure of (contract §7.1)."""

    rows = _rows(_section(contract, "7.1 There is no device path on the public surface"))
    for accepts, domain in ((row[0], row[1]) for row in rows):
        assert "/dev" not in domain, f"{accepts!r} takes a device path: {domain!r}"
        assert "path" not in domain.lower(), f"{accepts!r} takes a path: {domain!r}"


def test_no_document_offers_a_device_option(contract: str, adr: str) -> None:
    """`--device` may be named only where it is refused."""

    for name, text in (("contract", contract), ("ADR-0009", adr)):
        for line in text.splitlines():
            if "--device" in line:
                assert " no " in f" {line.lower()} ", (
                    f"{name} mentions --device outside a refusal: {line!r}"
                )


def test_the_writer_refuses_what_the_product_exists_to_protect(contract: str) -> None:
    refused = " ".join(
        row[0] for row in _rows(_section(contract, "7.3 What the writer refuses outright"))
    ).lower()
    for target in ("internal disk", "root filesystem", "removability", "mounted volume"):
        assert target in refused, f"the refusal table no longer covers {target!r}"


def test_the_adr_selects_no_builder(adr: str) -> None:
    head = "\n".join(adr.splitlines()[:12])
    assert "**No build tool is selected**" in head, (
        "ADR-0009's status no longer states that the builder question is open; "
        "ADR-0002 D2/D3/D4 stand until a selection ADR supersedes them"
    )


def test_the_selection_plan_requires_a_measured_digest_pair(adr: str) -> None:
    """ADR-0002 D4.1 wants an actual reproduction, not a citation of one."""

    plan = _section(adr, "D8 — This ADR selects no builder, and here is what would")
    steps = {row[0] for row in _rows(plan)}
    assert steps == {"P1", "P2", "P3", "P4", "P5", "P6", "P7"}
    reproduction = next(row for row in _rows(plan) if row[0] == "P4")
    assert reproduction[2] == "measured"
    assert "independent infrastructure" in reproduction[1]


def test_no_document_claims_more_than_this_repository_holds(contract: str, adr: str) -> None:
    for name, text in (("contract", contract), ("ADR-0009", adr)):
        lowered = text.lower()
        for claim in FORBIDDEN_CLAIMS:
            assert claim not in lowered, (
                f"{name} contains {claim!r}; nothing has been built, written, "
                "selected, or booted"
            )
