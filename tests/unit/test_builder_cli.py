"""`doctor` reads, `prepare-host` asks, and neither does it by remembering to.

Two guarantees are under test, and both are structural rather than behavioural:

*`doctor` is read-only* because the Protocol it depends on has no method that
writes, and because the module imports no way around that. A test that only
watched `doctor` behave would pass on a version that had grown one convenient
`subprocess.run`.

*`prepare-host` does nothing before approval* because the executor — the object
that could download, create or install — is not in scope until the phase runs,
and because an approval is an object the session minted rather than a value a
caller can produce.

Every probe here is a fake. **No test touches a real machine**, no command is
run, and nothing is downloaded, created or installed.
"""

from __future__ import annotations

import ast
import copy
import pickle
from dataclasses import replace
from pathlib import Path

import pytest
from tools.builder.cli import NO_EXECUTOR_AVAILABLE, main, run_doctor, run_prepare_host
from tools.builder.doctor import (
    MINIMUM_FREE_BYTES,
    VM_NAME,
    Check,
    Reason,
    Status,
    examine,
    render,
    select_backend,
)
from tools.builder.host_bootstrap import STAMP, HostKind
from tools.builder.hostports import (
    Backend,
    DigestCheck,
    DownloadOutcome,
    Execution,
    HostFacts,
    HostProbe,
    SharedKernelMarker,
    SignatureCheck,
    VmSpec,
)
from tools.builder.prepare import (
    CONFIRMATION_PHRASE,
    PHASE_ORDER,
    Approval,
    Phase,
    PrepareRefused,
    PrepareSession,
    Refusal,
    execution_for,
    plan_lines,
    require_disposable,
    require_verified_image,
)

PACKAGE = Path(__file__).resolve().parents[2] / "tools" / "builder"

#: A host that passes every check. Overridden per test for the failing cases.
HEALTHY = {
    "os_id": "ubuntu",
    "os_version_id": "24.04",
    "machine": "x86_64",
    "available_backends": (Backend.QEMU_SYSTEM_X86_64,),
    "free_bytes": MINIMUM_FREE_BYTES,
    "network_reachable": True,
    "existing_vm_names": (),
    "can_escalate_privilege": True,
    "shared_kernel_markers": (),
    "shared_folders_configured": 0,
    "usb_passthrough_configured": 0,
}


class FakeProbe:
    """A `HostProbe` that reads nothing. Records how often it was asked."""

    def __init__(self, **overrides) -> None:
        self.calls = 0
        self._facts = HostFacts(**{**HEALTHY, **overrides})

    def facts(self) -> HostFacts:
        self.calls += 1
        return self._facts


class RecordingExecutor:
    """An executor that records rather than acts, so a test can prove it idle."""

    def __init__(self, *, signature=SignatureCheck.VERIFIED, digest=DigestCheck.MATCHED):
        self.downloads: list[str] = []
        self.created: list[VmSpec] = []
        self.installed: list[tuple[str, str]] = []
        self.removed: list[str] = []
        self._signature = signature
        self._digest = digest

    def download_and_verify(self, source: str, into: str) -> DownloadOutcome:
        self.downloads.append(source)
        return DownloadOutcome(
            stored_at=f"{into}/debian.iso",
            signature=self._signature,
            digest=self._digest,
            digest_value="sha512:" + "a" * 128,
        )

    def create_vm(self, spec: VmSpec) -> str:
        self.created.append(spec)
        return f"handle-{spec.name}"

    def install_in_vm(self, vm_handle: str, package: str) -> str:
        self.installed.append((vm_handle, package))
        return "live-build 1:2025.1"

    def remove_created_file(self, path: str) -> None:
        self.removed.append(path)

    @property
    def acted(self) -> bool:
        return bool(self.downloads or self.created or self.installed)


def lines_from(fn, *args, **kwargs) -> tuple[int, tuple[str, ...]]:
    captured: list[str] = []
    code = fn(*args, out=captured.append, **kwargs)
    return code, tuple(captured)


def approved(session: PrepareSession, phase: Phase) -> Approval:
    return session.approve(phase, CONFIRMATION_PHRASE[phase])


def ready_session(**overrides) -> PrepareSession:
    session = PrepareSession(
        host_kind=HostKind.DISPOSABLE_VM_ON_LINUX,
        backend=overrides.pop("backend", Backend.QEMU_SYSTEM_X86_64),
        host_machine=overrides.pop("host_machine", "x86_64"),
    )
    session.show_plan(plan_lines(session.backend, session.execution))
    return session


# --------------------------------------------------------------------------
# `doctor` is read-only, by the type it depends on
# --------------------------------------------------------------------------


DECISION_MODULES = ("doctor.py", "prepare.py", "hostports.py", "host_bootstrap.py", "cli.py")


@pytest.mark.parametrize("name", DECISION_MODULES)
def test_no_decision_module_imports_a_way_to_reach_the_machine(name: str) -> None:
    """`system_probe.py` is the one module allowed to, and it is not in this list.

    A guarantee about what `doctor` does is worth nothing if the next
    contributor can add one convenient `subprocess.run` to it. This is the
    check that turns that into a red test.
    """

    tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
    imported: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)

    forbidden = {
        "subprocess",
        "shutil",
        "socket",
        "urllib",
        "http",
        "requests",
        "ctypes",
        "multiprocessing",
    }
    # `cli.py` imports `system_probe` lazily inside `main`, which is how the
    # one operational module stays out of every other import graph.
    assert not imported & forbidden, f"{name} imports {imported & forbidden}"
    assert not calls & {"open", "exec", "eval", "compile", "__import__"}


def test_the_probe_protocol_has_no_method_that_could_change_anything() -> None:
    """Read-only as a property of the port, not a promise about the caller."""

    names = {n for n in dir(HostProbe) if not n.startswith("_")}
    assert names == {"facts"}
    for verb in ("run", "write", "create", "install", "download", "remove", "delete"):
        assert not any(verb in name for name in names)


def test_the_executor_protocol_offers_no_act_the_owner_excluded() -> None:
    """Absent, not guarded: a method that does not exist cannot be called."""

    from tools.builder.hostports import Executor

    names = {n for n in dir(Executor) if not n.startswith("_")}
    assert names == {
        "download_and_verify",
        "create_vm",
        "install_in_vm",
        "remove_created_file",
    }
    for excluded in ("delete_vm", "install_on_host", "attach_usb", "mount_host_disk"):
        assert excluded not in names


def test_doctor_asks_the_probe_and_nothing_else() -> None:
    probe = FakeProbe()
    code, printed = lines_from(run_doctor, probe)
    assert probe.calls == 1
    assert code == 0
    assert printed[-1] == "conclusion: prepare-host may run"


# --------------------------------------------------------------------------
# The report is a classification, and carries nothing from the host
# --------------------------------------------------------------------------


def test_a_doctor_report_carries_no_value_from_the_operators_machine() -> None:
    """It is the thing an operator pastes into an issue when asking for help."""

    probe = FakeProbe(
        existing_vm_names=("someones-private-vm", "client-forensics-2026"),
        free_bytes=123_456_789,
        machine="aarch64",
    )
    _, printed = lines_from(run_doctor, probe)
    rendered = "\n".join(printed)

    for secret in ("someones-private-vm", "client-forensics-2026", "123456789", "123,456,789"):
        assert secret not in rendered
    for line in printed:
        assert "/" not in line or line.startswith("backend:")


def test_a_finding_has_no_field_that_could_hold_such_a_value() -> None:
    import dataclasses

    from tools.builder.doctor import Finding

    names = {f.name for f in dataclasses.fields(Finding)}
    assert names == {"check", "status", "reason"}
    for forbidden in ("detail", "message", "path", "value", "host", "note"):
        assert forbidden not in names


def test_host_facts_redact_the_fields_that_are_about_the_operator() -> None:
    rendered = repr(FakeProbe(existing_vm_names=("private-vm",), free_bytes=999).facts())
    assert "private-vm" not in rendered
    assert "999" not in rendered
    assert "x86_64" in rendered


# --------------------------------------------------------------------------
# Every check, and the distinction between missing and refused
# --------------------------------------------------------------------------


def finding_for(probe: FakeProbe, check: Check):
    (found,) = [f for f in examine(probe).findings if f.check is check]
    return found


def test_a_shared_kernel_host_is_refused_not_merely_missing_something() -> None:
    """This session's own container is exactly this case.

    `MISSING` is something an operator can supply. `REFUSED` is something they
    cannot: no amount of installing makes a container a machine of its own.
    """

    probe = FakeProbe(shared_kernel_markers=(SharedKernelMarker.DOCKER_ENV_FILE,))
    found = finding_for(probe, Check.SHARED_KERNEL)
    assert found.status is Status.REFUSED
    assert found.reason is Reason.SHARED_KERNEL_HOST
    assert not examine(probe).can_prepare_a_host


def test_no_backend_installed_is_host_backend_unavailable() -> None:
    """Never inferred from the platform, never installed to fix it."""

    probe = FakeProbe(available_backends=())
    assert select_backend(probe.facts()) is None
    found = finding_for(probe, Check.VIRTUALISATION_BACKEND)
    assert found.status is Status.MISSING
    assert found.reason is Reason.HOST_BACKEND_UNAVAILABLE
    assert examine(probe).backend is None


def test_a_backend_is_chosen_only_from_what_the_host_already_has() -> None:
    """Preference breaks a tie between installed backends; it installs nothing."""

    assert select_backend(FakeProbe(available_backends=(Backend.UTM,)).facts()) is Backend.UTM
    assert (
        select_backend(
            FakeProbe(available_backends=(Backend.UTM, Backend.LIBVIRT)).facts()
        )
        is Backend.LIBVIRT
    )


def test_insufficient_free_space_is_missing() -> None:
    found = finding_for(FakeProbe(free_bytes=MINIMUM_FREE_BYTES - 1), Check.FREE_SPACE)
    assert found.status is Status.MISSING
    assert found.reason is Reason.INSUFFICIENT_FREE_SPACE


def test_an_unreachable_network_is_missing() -> None:
    found = finding_for(FakeProbe(network_reachable=False), Check.NETWORK_REACHABILITY)
    assert found.status is Status.MISSING
    assert found.reason is Reason.NETWORK_UNREACHABLE


def test_an_existing_vm_of_this_name_is_refused_because_this_tool_deletes_nothing() -> None:
    found = finding_for(FakeProbe(existing_vm_names=(VM_NAME,)), Check.EXISTING_VM_COLLISION)
    assert found.status is Status.REFUSED
    assert found.reason is Reason.VM_NAME_ALREADY_IN_USE


def test_unavailable_privilege_is_missing_and_is_never_exercised() -> None:
    found = finding_for(FakeProbe(can_escalate_privilege=False), Check.PRIVILEGE)
    assert found.status is Status.MISSING
    assert found.reason is Reason.PRIVILEGE_UNAVAILABLE


def test_a_configured_shared_folder_or_usb_passthrough_is_refused() -> None:
    """Both are the same rule wearing different clothes."""

    found = finding_for(FakeProbe(shared_folders_configured=1), Check.NO_SHARED_FOLDER)
    assert found.status is Status.REFUSED
    assert found.reason is Reason.SHARED_FOLDER_CONFIGURED

    found = finding_for(FakeProbe(usb_passthrough_configured=1), Check.NO_USB_PASSTHROUGH)
    assert found.status is Status.REFUSED
    assert found.reason is Reason.USB_PASSTHROUGH_CONFIGURED


def test_every_check_appears_in_every_report() -> None:
    """A check nobody runs is a check that passes."""

    assert {f.check for f in examine(FakeProbe()).findings} == set(Check)


def test_render_prints_only_this_modules_own_vocabulary() -> None:
    values = {c.value for c in Check} | {s.value for s in Status} | {r.value for r in Reason}
    for line in render(examine(FakeProbe(machine="aarch64"))):
        if line.startswith(("backend:", "conclusion:")):
            continue
        check, rest = line.split(": ", 1)
        status, reason = rest.split(" (", 1)
        assert check in values and status in values and reason.rstrip(")") in values


# --------------------------------------------------------------------------
# macOS on Apple silicon is emulation, and is recorded as such
# --------------------------------------------------------------------------


def test_an_amd64_guest_on_an_arm_host_is_emulation_and_is_named_that() -> None:
    assert execution_for("x86_64") is Execution.NATIVE_AMD64
    assert execution_for("amd64") is Execution.NATIVE_AMD64
    assert execution_for("arm64") is Execution.EMULATED_AMD64_ON_ARM64
    assert execution_for("aarch64") is Execution.EMULATED_AMD64_ON_ARM64


def test_the_plan_says_out_loud_that_an_emulated_run_supports_no_conclusion() -> None:
    """Otherwise a timing or a reproducibility reading looks available."""

    emulated = "\n".join(plan_lines(Backend.UTM, Execution.EMULATED_AMD64_ON_ARM64))
    assert "emulated" in emulated
    assert "no timing, reproducibility or support conclusion" in emulated

    native = "\n".join(plan_lines(Backend.LIBVIRT, Execution.NATIVE_AMD64))
    assert "emulated" not in native


def test_the_session_decides_the_execution_class_and_the_caller_cannot() -> None:
    """A record that took it as an argument could be written up as native."""

    session = ready_session(host_machine="arm64")
    assert session.execution is Execution.EMULATED_AMD64_ON_ARM64
    with pytest.raises(TypeError):
        session.evidence(execution=Execution.NATIVE_AMD64)  # type: ignore[call-arg]


# --------------------------------------------------------------------------
# Nothing happens before approval
# --------------------------------------------------------------------------


def test_prepare_host_shows_the_plan_and_performs_nothing() -> None:
    """The integration check, in both modes."""

    for dry_run in (True, False):
        probe = FakeProbe()
        code, printed = lines_from(run_prepare_host, probe, dry_run=dry_run)
        rendered = "\n".join(printed)
        assert "three acts, each confirmed on its own" in rendered
        for phrase in CONFIRMATION_PHRASE.values():
            assert phrase in rendered
        if dry_run:
            assert code == 0
            assert "nothing was downloaded, created or installed" in rendered
            assert STAMP in rendered
        else:
            assert code == 2
            assert NO_EXECUTOR_AVAILABLE in rendered


def test_prepare_host_refuses_before_the_plan_when_the_host_is_refused() -> None:
    probe = FakeProbe(shared_kernel_markers=(SharedKernelMarker.CGROUP_NAMESPACE,))
    code, printed = lines_from(run_prepare_host, probe, dry_run=True)
    rendered = "\n".join(printed)
    assert code == 2
    assert "refused" in rendered
    assert "three acts" not in rendered


def test_prepare_host_stops_on_host_backend_unavailable() -> None:
    """The name the owner asked for, printed as the reason."""

    code, printed = lines_from(
        run_prepare_host, FakeProbe(available_backends=()), dry_run=True
    )
    assert code == 2
    assert Reason.HOST_BACKEND_UNAVAILABLE.value in "\n".join(printed)


def test_a_session_cannot_be_built_without_a_backend() -> None:
    with pytest.raises(PrepareRefused) as refused:
        PrepareSession(HostKind.DISPOSABLE_VM_ON_LINUX, None, "x86_64")
    assert refused.value.refusal is Refusal.HOST_BACKEND_UNAVAILABLE


def test_approval_is_impossible_before_the_plan_is_shown() -> None:
    session = PrepareSession(
        HostKind.DISPOSABLE_VM_ON_LINUX, Backend.LIBVIRT, "x86_64"
    )
    with pytest.raises(PrepareRefused) as refused:
        session.approve(Phase.EXTERNAL_DOWNLOAD, CONFIRMATION_PHRASE[Phase.EXTERNAL_DOWNLOAD])
    assert refused.value.refusal is Refusal.PLAN_NOT_SHOWN


def test_each_phase_has_its_own_confirmation_phrase() -> None:
    """One "yes" must not stand for all three."""

    assert len(set(CONFIRMATION_PHRASE.values())) == len(PHASE_ORDER)
    session = ready_session()
    for phase in PHASE_ORDER:
        for other in PHASE_ORDER:
            if other is phase:
                continue
            with pytest.raises(PrepareRefused) as refused:
                session.approve(phase, CONFIRMATION_PHRASE[other])
            assert refused.value.refusal is Refusal.CONFIRMATION_DID_NOT_MATCH


# --------------------------------------------------------------------------
# An approval is issued, not asserted
# --------------------------------------------------------------------------


def test_an_approval_a_caller_built_is_not_an_approval() -> None:
    """The shape four earlier review rounds defeated, in its final form."""

    session = ready_session()
    executor = RecordingExecutor()
    forged = Approval(Phase.EXTERNAL_DOWNLOAD)

    with pytest.raises(PrepareRefused) as refused:
        session.run(Phase.EXTERNAL_DOWNLOAD, forged, executor, source="s", into="i")
    assert refused.value.refusal is Refusal.NOT_AN_ISSUED_APPROVAL
    assert not executor.acted


def test_a_copied_or_replaced_approval_is_not_the_one_that_was_issued() -> None:
    session = ready_session()
    executor = RecordingExecutor()
    real = approved(session, Phase.EXTERNAL_DOWNLOAD)

    with pytest.raises(TypeError):
        pickle.dumps(real)
    with pytest.raises(TypeError):
        copy.deepcopy(real)
    with pytest.raises(AttributeError):
        real._phase = Phase.CREATE_VM  # noqa: SLF001 - the attack
    with pytest.raises(TypeError):
        replace(real)  # type: ignore[type-var]
    assert not executor.acted


def test_an_approval_for_one_phase_does_not_permit_another() -> None:
    session = ready_session()
    executor = RecordingExecutor()
    download = approved(session, Phase.EXTERNAL_DOWNLOAD)

    with pytest.raises(PrepareRefused) as refused:
        session.run(Phase.CREATE_VM, download, executor, spec=_spec())
    assert refused.value.refusal is Refusal.APPROVAL_FOR_ANOTHER_PHASE
    assert not executor.acted


def test_an_approval_is_spent_once() -> None:
    session = ready_session()
    executor = RecordingExecutor()
    first = approved(session, Phase.EXTERNAL_DOWNLOAD)
    session.run(Phase.EXTERNAL_DOWNLOAD, first, executor, source="s", into="i")

    with pytest.raises(PrepareRefused) as refused:
        session.run(Phase.EXTERNAL_DOWNLOAD, first, executor, source="s", into="i")
    assert refused.value.refusal is Refusal.APPROVAL_ALREADY_SPENT
    assert len(executor.downloads) == 1


def test_the_phases_run_in_order_or_not_at_all() -> None:
    """A VM is created from a verified image; a package goes into a VM that exists."""

    session = ready_session()
    executor = RecordingExecutor()
    creation = approved(session, Phase.CREATE_VM)

    with pytest.raises(PrepareRefused) as refused:
        session.run(Phase.CREATE_VM, creation, executor, spec=_spec())
    assert refused.value.refusal is Refusal.PHASE_OUT_OF_ORDER
    assert not executor.acted


# --------------------------------------------------------------------------
# What each act refuses
# --------------------------------------------------------------------------


def _spec(**overrides) -> VmSpec:
    return VmSpec(
        name=VM_NAME,
        architecture="x86_64",
        disk_bytes=40 * 1024**3,
        iso_path="/srv/azazel-evaluation/debian.iso",
        **overrides,
    )


@pytest.mark.parametrize(
    "unsafe",
    [
        {"shared_folders": ("/Users/someone",)},
        {"usb_passthrough": ("0781:5583",)},
        {"host_disk_mounts": ("/dev/nvme0n1",)},
    ],
)
def test_a_vm_that_would_not_be_disposable_is_refused(unsafe) -> None:
    with pytest.raises(PrepareRefused) as refused:
        require_disposable(_spec(**unsafe))
    assert refused.value.refusal is Refusal.VM_WOULD_NOT_BE_DISPOSABLE

    session = ready_session()
    executor = RecordingExecutor()
    session.run(
        Phase.EXTERNAL_DOWNLOAD,
        approved(session, Phase.EXTERNAL_DOWNLOAD),
        executor,
        source="s",
        into="i",
    )
    with pytest.raises(PrepareRefused):
        session.run(
            Phase.CREATE_VM, approved(session, Phase.CREATE_VM), executor, spec=_spec(**unsafe)
        )
    assert not executor.created


@pytest.mark.parametrize(
    "outcome,expected",
    [
        (
            DownloadOutcome("p", SignatureCheck.FAILED, DigestCheck.MATCHED, "d"),
            Refusal.SIGNATURE_NOT_VERIFIED,
        ),
        (
            DownloadOutcome("p", SignatureCheck.NOT_ATTEMPTED, DigestCheck.MATCHED, "d"),
            Refusal.SIGNATURE_NOT_VERIFIED,
        ),
        (
            DownloadOutcome("p", SignatureCheck.VERIFIED, DigestCheck.MISMATCHED, "d"),
            Refusal.DIGEST_NOT_MATCHED,
        ),
        (
            DownloadOutcome("p", SignatureCheck.VERIFIED, DigestCheck.NOT_ATTEMPTED, "d"),
            Refusal.DIGEST_NOT_MATCHED,
        ),
    ],
)
def test_the_signature_and_the_digest_are_checked_independently(outcome, expected) -> None:
    """Checking one and reporting the other satisfied is the failure this prevents."""

    with pytest.raises(PrepareRefused) as refused:
        require_verified_image(outcome)
    assert refused.value.refusal is expected


def test_a_failed_verification_stops_the_run_and_leaves_the_file_for_cleanup() -> None:
    session = ready_session()
    executor = RecordingExecutor(digest=DigestCheck.MISMATCHED)

    with pytest.raises(PrepareRefused) as refused:
        session.run(
            Phase.EXTERNAL_DOWNLOAD,
            approved(session, Phase.EXTERNAL_DOWNLOAD),
            executor,
            source="s",
            into="/srv/azazel-evaluation",
        )
    assert refused.value.refusal is Refusal.DIGEST_NOT_MATCHED

    outcome = session.cleanup(executor)
    assert outcome.removed == ("/srv/azazel-evaluation/debian.iso",)
    assert executor.removed == ["/srv/azazel-evaluation/debian.iso"]


# --------------------------------------------------------------------------
# Cleanup never removes a VM
# --------------------------------------------------------------------------


def test_cleanup_leaves_a_half_created_vm_for_the_operator() -> None:
    """Deleting one is something this tool does not do, failure or not."""

    session = ready_session()
    executor = RecordingExecutor()
    session.run(
        Phase.EXTERNAL_DOWNLOAD,
        approved(session, Phase.EXTERNAL_DOWNLOAD),
        executor,
        source="s",
        into="/srv/azazel-evaluation",
    )
    handle = session.run(
        Phase.CREATE_VM, approved(session, Phase.CREATE_VM), executor, spec=_spec()
    )

    outcome = session.cleanup(executor)
    assert handle in outcome.left_for_the_operator
    assert handle not in outcome.removed
    assert all(not name.startswith("handle-") for name in executor.removed)


def test_cleanup_is_idempotent_and_removes_nothing_twice() -> None:
    session = ready_session()
    executor = RecordingExecutor()
    session.run(
        Phase.EXTERNAL_DOWNLOAD,
        approved(session, Phase.EXTERNAL_DOWNLOAD),
        executor,
        source="s",
        into="/srv/azazel-evaluation",
    )
    first = session.cleanup(executor)
    second = session.cleanup(executor)
    assert first.removed
    assert second.removed == ()
    assert len(executor.removed) == 1


# --------------------------------------------------------------------------
# The session is not a value a caller can edit
# --------------------------------------------------------------------------


def test_a_session_refuses_reassignment_and_serialisation() -> None:
    """Same limit `azazel_boot.quarantine` states: careless caller, not a seal."""

    session = ready_session()
    with pytest.raises(TypeError):
        pickle.dumps(session)
    for name in ("_issued", "_completed", "_backend", "_plan_shown"):
        with pytest.raises(AttributeError):
            setattr(session, name, [])


def test_main_wires_the_verbs_without_touching_a_machine() -> None:
    assert main(["doctor"], probe=FakeProbe()) == 0
    assert main(["doctor"], probe=FakeProbe(available_backends=())) == 1
    assert main(["prepare-host", "--dry-run"], probe=FakeProbe()) == 0
    assert main(["prepare-host"], probe=FakeProbe()) == 2
