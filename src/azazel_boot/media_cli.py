"""Interactive, read-only Linux media console.

One console invocation is one target-code session. It accepts no device path,
artifact path, model, serial, or other device identifier as an argument.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from collections.abc import Callable
from typing import Protocol, TextIO

from azazel_boot.linux_media import LinuxMediaRefused, LinuxMediaSession
from azazel_boot.media import MediaOffer
from azazel_boot.writer import Inspection

_DIGEST = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{64}$")


class ReadOnlyMediaConsole(Protocol):
    def list_media(self) -> tuple[MediaOffer, ...]: ...

    def inspect(
        self, target_code: str, *, expected_digest: str, length: int
    ) -> Inspection: ...


def run_console(
    session: ReadOnlyMediaConsole,
    *,
    stdin: TextIO,
    stdout: TextIO,
) -> int:
    """Run list/inspect commands without ever accepting a device path."""

    def print_offers() -> None:
        offers = session.list_media()
        stdout.write(
            json.dumps(
                [offer.describe_for_screen() for offer in offers],
                sort_keys=True,
                ensure_ascii=True,
            )
            + "\n"
        )

    print_offers()
    stdout.write("Commands: list-media | inspect <target-code> <sha256> <bytes> | quit\n")
    while True:
        stdout.write("media> ")
        stdout.flush()
        line = stdin.readline()
        if not line:
            return 0
        try:
            parts = shlex.split(line)
        except ValueError:
            stdout.write("refused: invalid command syntax\n")
            continue
        if not parts:
            continue
        if parts == ["quit"]:
            return 0
        if parts == ["list-media"]:
            try:
                print_offers()
            except LinuxMediaRefused as error:
                stdout.write(f"refused: {error}\n")
            continue
        if len(parts) == 4 and parts[0] == "inspect":
            target_code, digest, length_text = parts[1:]
            if _DIGEST.fullmatch(digest) is None:
                stdout.write("refused: expected sha256 digest is malformed\n")
                continue
            try:
                length = int(length_text, 10)
                if length <= 0:
                    raise ValueError
                normalized_digest = digest if digest.startswith("sha256:") else f"sha256:{digest}"
                result = session.inspect(
                    target_code,
                    expected_digest=normalized_digest,
                    length=length,
                )
                stdout.write(
                    json.dumps(
                        {
                            "matches": result.matches,
                            "expected_digest": result.expected_digest,
                            "measured_digest": result.measured_digest,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
            except (ValueError, LinuxMediaRefused):
                stdout.write("refused: inspection could not be completed\n")
            continue
        stdout.write("refused: command not supported\n")


def main(
    argv: list[str] | None = None,
    *,
    session_factory: Callable[[], ReadOnlyMediaConsole] = LinuxMediaSession.from_system,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> int:
    if argv not in (None, []):
        (stdout or sys.stdout).write("refused: this command accepts no arguments\n")
        return 2
    output = stdout or sys.stdout
    input_stream = stdin or sys.stdin
    try:
        session = session_factory()
        return run_console(session, stdin=input_stream, stdout=output)
    except LinuxMediaRefused as error:
        output.write(f"refused: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
