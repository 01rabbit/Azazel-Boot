"""Read-only status command for the non-operational Boot scaffold."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from azazel_boot.status import current_status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="azazel-boot",
        description="Report Boot's declared scope and implementation state.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    status = sub.add_parser("status", help="show read-only implementation status")
    status.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    result = asdict(current_status())
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result['product']} ({result['product_code']})")
        print(f"  operational: {result['operational']}")
        print(f"  installer: {result['installer']}")
        print("  supported host environments: none declared")
        print("  authority: none; Azazel-Edge remains the decision/enforcement authority")
    return 0


if __name__ == "__main__":
    sys.exit(main())
