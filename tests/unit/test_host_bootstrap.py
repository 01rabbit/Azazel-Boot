"""The plan is shown, and it cannot perform itself.

`doctor` reports and changes nothing (ADR-0009 D1), and the owner's rule for P2
is that creating a build host, downloading anything externally, or escalating
privilege is shown as a plan **before** it runs. Both halves need pinning: the
classification that decides what must be shown, and the absence of any means of
running it.

Several tests here are about **absence** — what the module cannot express, what
it does not import, what a record cannot hold — because that is what survives a
future contributor who has not read this file.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest
from tools.builder.candidates import (
    REQUIRED_ARCHITECTURE,
    REQUIRED_OS_ID,
    REQUIRED_OS_VERSION_ID,
)
from tools.builder.host_bootstrap import (
    FORBIDDEN_EVIDENCE_FIELDS,
    NEEDS_APPROVAL_FIRST,
    REQUIRED_VM_EVIDENCE_FIELDS,
    STAMP,
    TARGET_ARCHITECTURE,
    TARGET_OS_ID,
    TARGET_OS_VERSION_ID,
    VM_BUILD_ROOT,
    BootstrapRefused,
    HostKind,
    Refusal,
    StepKind,
    VmEvidence,
    plan,
    require_build_io_inside_the_vm,
    require_isolated_host,
    require_vm_evidence,
)
from tools.builder.hostports import Backend, DigestCheck, Execution, SignatureCheck

MODULE = Path(__file__).resolve().parents[2] / "tools" / "builder" / "host_bootstrap.py"


def evidence(**overrides) -> VmEvidence:
    fields = {
        "image_source": "https://cdimage.debian.org/.../debian-13-amd64-netinst.iso",
        "image_digest": "sha512:" + "a" * 128,
        "signature_verification": SignatureCheck.VERIFIED,
        "digest_verification": DigestCheck.MATCHED,
        "created_at": "2026-09-22T00:00:00Z",
        "cpu_architecture": "x86_64",
        "debian_version_id": "13",
        "builder_tool_version": "live-build 1:2025.1",
        "host_kind": HostKind.DISPOSABLE_VM_ON_LINUX,
        "backend": Backend.QEMU_SYSTEM_X86_64,
        "execution": Execution.NATIVE_AMD64,
    }
    fields.update(overrides)
    return VmEvidence(**fields)


# --------------------------------------------------------------------------
# The plan runs nothing
# --------------------------------------------------------------------------


def test_the_module_imports_no_means_of_performing_a_step() -> None:
    """"Shown before it runs" must not be a property of whoever called it."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)

    assert not imported & {
        "subprocess",
        "os",
        "shutil",
        "pathlib",
        "socket",
        "urllib",
        "http",
        "requests",
        "ctypes",
    }
    assert not calls & {"open", "exec", "eval", "compile", "__import__"}


def test_a_step_is_data_and_carries_what_it_does_not_do() -> None:
    """A command line does not show the constraints being honoured."""

    for step in plan(HostKind.DISPOSABLE_VM_ON_LINUX).steps:
        assert isinstance(step.command, str)
        assert step.because
        assert step.does_not, f"{step.step_id} claims no constraint"


# --------------------------------------------------------------------------
# A chroot is not a build host, and the type cannot say otherwise
# --------------------------------------------------------------------------


def test_the_host_vocabulary_has_no_value_for_anything_sharing_a_kernel() -> None:
    """The refusal is structural: there is nothing to record a chroot with.

    A chroot, a container, a namespace and this session's own machine all share
    the kernel of whatever they run on, so a measurement taken in one is
    evidence about that kernel's environment. The owner decided a disposable VM,
    and a value the type cannot hold is one a caller cannot smuggle in.
    """

    values = {kind.value for kind in HostKind}
    assert values == {"disposable_vm_on_linux", "disposable_vm_on_macos"}
    for forbidden in ("chroot", "container", "namespace", "docker", "podman", "local"):
        assert not any(forbidden in value for value in values)


@pytest.mark.parametrize("passed", ["chroot", "disposable_vm_on_linux", None, 0, True])
def test_a_host_that_is_not_a_disposable_vm_is_refused(passed) -> None:
    """Including the string spelling of a value that does exist."""

    with pytest.raises(BootstrapRefused) as refused:
        require_isolated_host(passed)
    assert refused.value.refusal is Refusal.NOT_A_DISPOSABLE_VM


# --------------------------------------------------------------------------
# What must be shown first
# --------------------------------------------------------------------------


def test_creating_downloading_and_escalating_all_need_the_plan_shown_first() -> None:
    assert set(NEEDS_APPROVAL_FIRST) == {
        StepKind.CREATE_HOST,
        StepKind.EXTERNAL_DOWNLOAD,
        StepKind.PRIVILEGE_ESCALATION,
    }


@pytest.mark.parametrize("kind", list(HostKind))
def test_every_step_of_those_three_kinds_is_listed_as_needing_approval(kind) -> None:
    """The classification is what decides; nothing else may.

    A step added later with one of these kinds is caught by this, rather than by
    somebody remembering to add it to a second list.
    """

    made = plan(kind)
    listed = made.steps_needing_approval
    assert listed
    assert {step.step_id for step in listed} == {
        step.step_id for step in made.steps if step.kind in NEEDS_APPROVAL_FIRST
    }
    assert {step.kind for step in listed} <= set(NEEDS_APPROVAL_FIRST)


@pytest.mark.parametrize("kind", list(HostKind))
def test_the_plan_names_the_three_operations_that_actually_need_permission(kind) -> None:
    """Named individually, because "some steps need approval" is not a plan."""

    kinds = {step.kind for step in plan(kind).steps}
    assert StepKind.CREATE_HOST in kinds
    assert StepKind.EXTERNAL_DOWNLOAD in kinds
    assert StepKind.PRIVILEGE_ESCALATION in kinds


# --------------------------------------------------------------------------
# One VM is not evidence of anything but itself
# --------------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(HostKind))
def test_building_a_machine_is_not_a_measurement_a_support_claim_or_a_selection(
    kind,
) -> None:
    """Same three answers `C5Result` gives, for the same reason."""

    made = plan(kind)
    assert made.reproducibility_established is False
    assert made.supported is False
    assert made.selects_a_builder is False
    assert made.stamp == STAMP

    for name in ("reproducibility_established", "supported", "selects_a_builder"):
        assert not any(f.name == name for f in dataclasses.fields(made))


def test_the_evidence_cannot_hold_a_release_or_support_claim() -> None:
    names = {f.name for f in dataclasses.fields(VmEvidence)}
    for forbidden in FORBIDDEN_EVIDENCE_FIELDS:
        assert forbidden not in names


# --------------------------------------------------------------------------
# The evidence the owner requires
# --------------------------------------------------------------------------


def test_every_required_evidence_field_exists_on_the_model() -> None:
    """Image source, digest, both checks, creation time, architecture, version,
    tool, backend, execution — pinned as an exact tuple.

    The parametrized test below iterates this constant, so shrinking it would
    leave that test with fewer cases and the suite green.
    `test_denylist_shape.py` found this file doing exactly that, which is the
    fourth instance of the shape in this repository.
    """

    assert REQUIRED_VM_EVIDENCE_FIELDS == (
        "image_source",
        "image_digest",
        "signature_verification",
        "digest_verification",
        "created_at",
        "cpu_architecture",
        "debian_version_id",
        "builder_tool_version",
        "backend",
        "execution",
    )
    names = {f.name for f in dataclasses.fields(VmEvidence)}
    assert set(REQUIRED_VM_EVIDENCE_FIELDS) <= names
    require_vm_evidence(evidence())


@pytest.mark.parametrize("missing", REQUIRED_VM_EVIDENCE_FIELDS)
def test_a_missing_evidence_field_is_refused_rather_than_defaulted(missing) -> None:
    """A blank there reads as "any machine" three months later."""

    blank = {
        "signature_verification": SignatureCheck.NOT_ATTEMPTED,
        "digest_verification": DigestCheck.NOT_ATTEMPTED,
        "backend": None,
        "execution": None,
    }.get(missing, "")
    with pytest.raises(BootstrapRefused) as refused:
        require_vm_evidence(evidence(**{missing: blank}))
    assert refused.value.refusal in {
        Refusal.EVIDENCE_FIELD_MISSING,
        Refusal.UNSIGNED_IMAGE_SOURCE,
    }


def test_an_image_nobody_verified_the_signature_of_is_refused() -> None:
    """A digest says two files match; a signature says Debian published it."""

    for failing in (SignatureCheck.FAILED, SignatureCheck.NOT_ATTEMPTED):
        with pytest.raises(BootstrapRefused) as refused:
            require_vm_evidence(evidence(signature_verification=failing))
        assert refused.value.refusal is Refusal.UNSIGNED_IMAGE_SOURCE


def test_a_digest_that_did_not_match_is_refused_independently() -> None:
    """Checking one and reporting the other satisfied is the whole failure.

    A single boolean could not tell "not attempted" from "attempted and
    failed", and could not say which of the two checks had passed.
    """

    for failing in (DigestCheck.MISMATCHED, DigestCheck.NOT_ATTEMPTED):
        with pytest.raises(BootstrapRefused) as refused:
            require_vm_evidence(evidence(digest_verification=failing))
        assert refused.value.refusal is Refusal.UNSIGNED_IMAGE_SOURCE


def test_evidence_without_the_evaluation_stamp_is_refused() -> None:
    with pytest.raises(BootstrapRefused) as refused:
        require_vm_evidence(evidence(stamp="release"))
    assert refused.value.refusal is Refusal.STAMP_MISSING


def test_the_evidence_repr_does_not_carry_the_operators_machine() -> None:
    """A traceback gets pasted into an issue; a URL the operator typed should not."""

    rendered = repr(evidence(image_source="/Users/someone/Downloads/debian.iso"))
    assert "/Users/someone" not in rendered
    assert "a" * 128 not in rendered
    assert "2026-09-22T00:00:00Z" not in rendered
    assert "x86_64" in rendered


# --------------------------------------------------------------------------
# Build IO stays inside the VM
# --------------------------------------------------------------------------


def test_a_build_input_or_output_on_the_host_is_refused() -> None:
    """A shared folder is the ordinary way this constraint is broken."""

    require_build_io_inside_the_vm((VM_BUILD_ROOT + "config", VM_BUILD_ROOT + "out"))
    for outside in (
        "/Users/someone/Downloads",
        "/home/user/Azazel-Boot",
        "/tmp/build",
        "../escape",
        "/mnt/shared",
        "",
    ):
        with pytest.raises(BootstrapRefused) as refused:
            require_build_io_inside_the_vm((outside,))
        assert refused.value.refusal is Refusal.HOST_PATH_USED_FOR_BUILD_IO


@pytest.mark.parametrize("kind", list(HostKind))
def test_no_step_writes_to_a_medium_a_release_or_a_product_artifact(kind) -> None:
    """The four things P2 may not touch, checked against every command."""

    for step in plan(kind).steps:
        text = step.command.lower()
        for forbidden in ("/dev/sd", "/dev/nvme", "/dev/disk", "dd if=", "mkfs", "of="):
            assert forbidden not in text, f"{step.step_id}: {forbidden}"
        for forbidden in ("gpg --sign", "--detach-sign", "release channel"):
            assert forbidden not in text, f"{step.step_id}: {forbidden}"


@pytest.mark.parametrize("kind", list(HostKind))
def test_the_vm_is_created_without_a_shared_folder_or_usb_passthrough(kind) -> None:
    """The three constraints, asserted **exactly**, not by keyword.

    The first version asserted `"usb" in joined`. A mutation rewrote the line to
    "passes through the USB device under test" — the opposite claim, containing
    the same word — and the test passed. Searching for a noun cannot tell a
    constraint from its negation, so the strings are pinned whole.

    USB passthrough in particular would put a real device in reach of an
    evaluation build, which is the B5 boundary the owner has not opened.
    """

    (creation,) = [s for s in plan(kind).steps if s.kind is StepKind.CREATE_HOST]
    assert creation.does_not == (
        "does not pass through any USB device",
        "does not mount a host folder into the VM",
        "does not reuse an existing VM — a reused one is not disposable",
    )
    assert "--no-shared-folder" in creation.command
    assert "--no-usb-passthrough" in creation.command


@pytest.mark.parametrize("kind", list(HostKind))
def test_the_steps_are_the_nine_the_plan_page_documents_in_that_order(kind) -> None:
    """Ids and order pinned, because the page tabulates them.

    A mutation renumbered the last step and nothing noticed: the assertions
    about it looked at its title. Pinning the sequence catches a renumber, a
    reorder, a dropped step and a step added without updating
    `docs/p2-host-bootstrap-plan.md`.
    """

    made = plan(kind)
    assert tuple(step.step_id for step in made.steps) == (
        "P2-B1",
        "P2-B2",
        "P2-B3",
        "P2-B4",
        "P2-B5",
        "P2-B6",
        "P2-B7",
        "P2-B8",
        "P2-B9",
    )
    assert tuple(step.kind for step in made.steps) == (
        StepKind.INSPECT,
        StepKind.EXTERNAL_DOWNLOAD,
        StepKind.INSPECT,
        StepKind.CREATE_HOST,
        StepKind.INSPECT,
        StepKind.PRIVILEGE_ESCALATION,
        StepKind.INSPECT,
        StepKind.WRITE_INSIDE_THE_VM,
        StepKind.INSPECT,
    )

    page = (Path(__file__).resolve().parents[2] / "docs" / "p2-host-bootstrap-plan.md").read_text(
        encoding="utf-8"
    )
    for step in made.steps:
        assert step.step_id in page, f"{step.step_id} is not in the plan page"


# --------------------------------------------------------------------------
# The plan targets the host the existing gate requires
# --------------------------------------------------------------------------


def test_the_target_is_the_one_the_build_host_gate_already_enforces() -> None:
    """Two statements of one fact; this is what keeps them the same one."""

    assert TARGET_OS_ID == REQUIRED_OS_ID
    assert TARGET_OS_VERSION_ID == REQUIRED_OS_VERSION_ID
    assert TARGET_ARCHITECTURE == REQUIRED_ARCHITECTURE


@pytest.mark.parametrize("kind", list(HostKind))
def test_the_plan_ends_by_destroying_the_vm_and_not_before_the_result_is_written(
    kind,
) -> None:
    """Disposable means it goes, and the order is part of the meaning."""

    steps = plan(kind).steps
    assert "destroy" in steps[-1].title.lower()
    assert any("before the c5 result" in item.lower() for item in steps[-1].does_not)


def test_nothing_here_has_run() -> None:
    """The module says so, and the statement is pinned like any other claim."""

    source = " ".join(MODULE.read_text(encoding="utf-8").split())
    assert "Nothing here has run." in source
    assert "No VM has been created" in source
