"""`azazel-boot-builder` — two verbs, and the second one asks before each act.

    azazel-boot-builder doctor
    azazel-boot-builder prepare-host [--dry-run]

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

Neither verb installs a dependency, escalates privilege, deletes a VM or
touches a USB device. Those are not guarded here; they are absent from the
`Executor` Protocol entirely.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

from .doctor import VM_NAME, DoctorReport, Reason, Status, examine, render
from .host_bootstrap import STAMP, HostKind
from .hostports import Execution, HostProbe
from .prepare import PrepareRefused, PrepareSession, plan_lines

#: Returned when `prepare-host` is asked to do something for real and there is
#: nothing to do it with. Distinct from a refusal about the host: the host may
#: be perfect and this tool still cannot act yet.
NO_EXECUTOR_AVAILABLE = "no_executor_available"

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
    arguments = parser.parse_args(argv)

    if probe is None:  # pragma: no cover - exercised only on a real machine
        from tools.hostprobe.system_probe import SystemProbe

        probe = SystemProbe()

    def out(line: str) -> None:
        print(line)

    if arguments.verb == "doctor":
        return run_doctor(probe, out)
    return run_prepare_host(probe, out, dry_run=arguments.dry_run)


def statuses_seen(report: DoctorReport) -> tuple[Status, ...]:
    """Helper for callers that want the classification without the text."""

    return tuple(finding.status for finding in report.findings)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
