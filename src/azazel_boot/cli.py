"""`azazel-boot status` -- print what this repository is, and is not.

The CLI does nothing else on purpose. Issue #1's last acceptance criterion is
that the bootstrap contains no operational network, enforcement, installer,
model-fetch or container activation code, so there is no command that could
start, configure or touch anything.
"""

from __future__ import annotations

import argparse
import json
import sys

from azazel_boot.fabric_projection import FABRIC_PIN, project_status
from azazel_boot.status import current_status


def _status_payload() -> dict[str, object]:
    status = current_status()
    projection = project_status(status)
    return {
        "product": status.product,
        "product_code": status.product_code,
        "operational": status.is_operational(),
        "capability": status.capability,
        "authority": list(status.authority),
        "capability_reasons": dict(status.capability_reasons),
        "components": [
            {"name": c.name, "status": c.status, "detail": c.detail}
            for c in status.components
        ],
        "fabric": {
            "pin": FABRIC_PIN,
            "projection_available": projection.available,
            "reason": projection.reason,
            "version": projection.fabric_version,
            "missing_planned_modules": list(projection.missing_planned),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="azazel-boot",
        description="Report what Azazel-Boot is. It does nothing else.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    status_cmd = sub.add_parser("status", help="print the non-operational status")
    status_cmd.add_argument(
        "--json", action="store_true", help="emit JSON instead of text"
    )
    args = parser.parse_args(argv)

    payload = _status_payload()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"{payload['product']} ({payload['product_code']})")
    print(f"  operational: {payload['operational']}")
    print(f"  capability : {payload['capability']} (no dimension is assessed)")
    print("  authority  : none -- Azazel-Edge's arbiter decides and enforces")
    fabric = payload["fabric"]
    assert isinstance(fabric, dict)
    print(f"  fabric pin : {fabric['pin']}, projection={fabric['projection_available']}")
    if fabric["reason"]:
        print(f"               {fabric['reason']}")
    for name in fabric["missing_planned_modules"]:
        print(f"               planned but absent at the pin: {name}")
    print("  components :")
    for component in payload["components"]:
        assert isinstance(component, dict)
        print(f"    {component['name']:<24} {component['status']:<16} {component['detail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
