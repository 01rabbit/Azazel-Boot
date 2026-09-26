"""`azazel-boot-builder` — safe host preparation and local verification verbs.

    azazel-boot-builder doctor
    azazel-boot-builder prepare-host [--dry-run]
    azazel-boot-builder build --profile PROFILE
    azazel-boot-builder verify --record RECORD --artifact ARTIFACT

`doctor` reports and changes nothing. `prepare-host` shows its plan, then asks
for a separate confirmation before the external download, before creating the
VM, and before installing a package inside it.

**`prepare-host` cannot currently perform anything, and says so rather than
pretending.** The executor half of `tools.builder.hostports` has no
implementation in this repository: `--dry-run` is the whole of what runs today,
and without it the command refuses with the reason `NO_EXECUTOR_AVAILABLE`.
That is deliberate — the owner's instruction was to finish `doctor`, the plan,
the refusal vocabulary, the evidence schema and the dry run first, and to
execute only once an eligible host exists. A command that silently did nothing
while reporting success would be the opposite of that.

None of these verbs installs a dependency, escalates privilege, deletes a VM or
touches a USB device. Those capabilities are absent from the `Executor`
Protocol entirely. `verify` reads a local record and payload only; it has no
key or signer and never authorizes a write by itself.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from azazel_boot.artifact import (
    RecordRefused,
    VerificationOutcome,
    VerificationRefusal,
    parse_json,
)
from azazel_boot.artifact import (
    verify as verify_artifact,
)

from .closure import ClosureRefused, load_configuration, resolve
from .doctor import VM_NAME, DoctorReport, Reason, Status, examine, render
from .host_bootstrap import STAMP, HostKind
from .hostports import Execution, HostProbe
from .prepare import PrepareRefused, PrepareSession, plan_lines

#: Returned when `prepare-host` is asked to do something for real and there is
#: nothing to do it with. Distinct from a refusal about the host: the host may
#: be perfect and this tool still cannot act yet.
NO_EXECUTOR_AVAILABLE = "no_executor_available"
BUILDER_SELECTION_REQUIRED = "builder_selection_required"

EXIT_OK = 0
EXIT_NOT_READY = 1
EXIT_REFUSED = 2


def _host_kind_for(machine: str, os_id: str) -> HostKind:
    """macOS or Linux — and nothing else is a build host.

    Chosen from what the probe measured rather than from what the operator
    says. `HostKind` has no third value, so a shared-kernel host cannot be
    named here; `doctor` refuses it before this is reached.
    """

    del machine
    return (
        HostKind.DISPOSABLE_VM_ON_MACOS
        if os_id in ("darwin", "macos")
        else HostKind.DISPOSABLE_VM_ON_LINUX
    )


def run_doctor(probe: HostProbe, out: Callable[[str], None]) -> int:
    """Print the classification and return an exit code. Changes nothing."""

    report = examine(probe)
    for line in render(report):
        out(line)
    if report.refusals:
        return EXIT_REFUSED
    return EXIT_OK if report.can_prepare_a_host else EXIT_NOT_READY


def run_prepare_host(
    probe: HostProbe,
    out: Callable[[str], None],
    *,
    dry_run: bool,
) -> int:
    """Show the plan, and — today — stop there.

    The order matters and is the point: the host is examined, the plan is
    shown, and only then would a confirmation be read. Nothing external has
    happened by the time this function returns, in either mode.
    """

    report: DoctorReport = examine(probe)
    if report.refusals:
        out("prepare-host: refused")
        for finding in report.refusals:
            out(f"  {finding.check.value}: {finding.reason.value}")
        return EXIT_REFUSED
    if report.backend is None:
        out(f"prepare-host: refused ({Reason.HOST_BACKEND_UNAVAILABLE.value})")
        out(
            "  no virtualisation backend is installed. one is never selected by "
            "inference and never installed by this tool"
        )
        return EXIT_REFUSED
    if report.missing:
        out("prepare-host: not ready")
        for finding in report.missing:
            out(f"  {finding.check.value}: {finding.reason.value}")
        return EXIT_NOT_READY

    facts = probe.facts()
    try:
        session = PrepareSession(
            host_kind=_host_kind_for(facts.machine, facts.os_id),
            backend=report.backend,
            host_machine=facts.machine,
        )
    except PrepareRefused as refused:
        out(f"prepare-host: refused ({refused.refusal.value})")
        out(f"  {refused.detail}")
        return EXIT_REFUSED

    for line in session.show_plan(plan_lines(session.backend, session.execution)):
        out(line)

    if not dry_run:
        out("")
        out(f"prepare-host: refused ({NO_EXECUTOR_AVAILABLE})")
        out(
            "  the acts are not implemented in this repository yet. the plan, "
            "the refusals and the evidence schema are; re-run with --dry-run to "
            "see exactly what would be asked"
        )
        return EXIT_REFUSED

    out("")
    out("dry run: nothing was downloaded, created or installed")
    out(f"  vm that would be created: {VM_NAME}")
    out(f"  every artifact would carry: {STAMP}")
    if session.execution is Execution.EMULATED_AMD64_ON_ARM64:
        out("  and would be marked as an emulated evaluation run")
    return EXIT_OK


def run_build(profile_id: str, out: Callable[[str], None], *, config_dir: Path) -> int:
    """Resolve a versioned input closure, then refuse until a builder is selected.

    The command intentionally has no URL, package, overlay, or output argument.
    A profile may name only configuration already committed to the repository;
    with the shipped empty pin set it refuses before any candidate builder could
    run. Even a future complete closure does not select a builder by inference.
    """

    try:
        closure = resolve(load_configuration(config_dir), profile_id)
    except ClosureRefused as refused:
        out(f"build: refused ({refused.refusal.value})")
        return EXIT_REFUSED

    out(f"build: closure={closure.digest()}")
    out(f"build: refused ({BUILDER_SELECTION_REQUIRED})")
    return EXIT_REFUSED


def _measure_digest(path: Path) -> str | None:
    """Measure a local artifact without treating the path as a build input.

    `verify` is an inspection verb, not `build`: it may read the operator's
    selected local artifact and record, but it neither fetches bytes nor passes
    either value to a builder. Read failures deliberately have no path in the
    result because command output is routinely copied into tickets.
    """

    digest = hashlib.sha256()
    try:
        with path.open("rb") as artifact:
            for block in iter(lambda: artifact.read(1 << 16), b""):
                digest.update(block)
    except OSError:
        return None
    return "sha256:" + digest.hexdigest()


def run_verify(record_path: Path, artifact_path: Path, out: Callable[[str], None]) -> int:
    """Verify one local artifact record and payload, without a signing key.

    Digest and signature verdicts are rendered independently. There is no
    bundled verifier or key, so even a matching signed record is deliberately
    not writable: `verify_artifact` reports ``no_verifier`` instead of
    pretending that a digest match authenticated an artifact.
    """

    try:
        record_text = record_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        out("verify: refused (record_unreadable)")
        return EXIT_REFUSED
    try:
        record = parse_json(record_text)
    except RecordRefused:
        out("verify: refused (record_invalid)")
        return EXIT_REFUSED

    measured_digest = _measure_digest(artifact_path)
    if measured_digest is None:
        out("verify: refused (artifact_unreadable)")
        return EXIT_REFUSED

    result = verify_artifact(record, measured_digest)
    digest_result = "matched" if result.outcome is not VerificationOutcome.REFUSED else "mismatched"
    signature_result = {
        VerificationRefusal.DIGEST_MISMATCH: "not_attempted",
        VerificationRefusal.UNSIGNED: "not_attempted",
        VerificationRefusal.NO_VERIFIER: "not_verified_no_verifier",
        VerificationRefusal.SIGNATURE_INVALID: "invalid",
        None: "verified",
    }[result.refusal]
    out(f"verify: digest={digest_result}")
    out(f"verify: signature={signature_result}")
    out(f"verify: write_authorized={result.may_be_written}")
    if result.refusal is not None:
        out(f"verify: refusal={result.refusal.value}")
    return EXIT_OK if result.may_be_written else EXIT_REFUSED


def main(argv: Sequence[str] | None = None, probe: HostProbe | None = None) -> int:
    """Entry point. `probe` is injectable so the tests never touch a machine."""

    parser = argparse.ArgumentParser(prog="azazel-boot-builder")
    verbs = parser.add_subparsers(dest="verb", required=True)
    verbs.add_parser("doctor", help="report whether this host can prepare a build host")
    prepare = verbs.add_parser(
        "prepare-host", help="show the plan and ask before each act"
    )
    prepare.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would be asked and performed, and perform nothing",
    )
    verify = verbs.add_parser(
        "verify", help="read a local artifact and record; never writes media"
    )
    verify.add_argument("--record", required=True, type=Path)
    verify.add_argument("--artifact", required=True, type=Path)
    build = verbs.add_parser(
        "build", help="resolve a pinned profile; never selects or runs a builder"
    )
    build.add_argument("--profile", required=True)
    arguments = parser.parse_args(argv)

    def out(line: str) -> None:
        print(line)

    if arguments.verb == "verify":
        return run_verify(arguments.record, arguments.artifact, out)
    if arguments.verb == "build":
        return run_build(
            arguments.profile,
            out,
            config_dir=Path(__file__).resolve().parents[2] / "config" / "builder",
        )
    if probe is None:  # pragma: no cover - exercised only on a real machine
        from tools.hostprobe.system_probe import SystemProbe

        probe = SystemProbe()
    if arguments.verb == "doctor":
        return run_doctor(probe, out)
    if arguments.verb == "prepare-host":
        return run_prepare_host(probe, out, dry_run=arguments.dry_run)
    raise AssertionError(f"unknown builder verb: {arguments.verb!r}")


def statuses_seen(report: DoctorReport) -> tuple[Status, ...]:
    """Helper for callers that want the classification without the text."""

    return tuple(finding.status for finding in report.findings)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
