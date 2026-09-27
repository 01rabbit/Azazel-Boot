"""Plan PoC partition geometry for a regular-file image, without writing it.

No block device, filesystem, or cryptsetup interface is exposed here. The
privileged writer in #27 must independently verify its live target before it
uses any geometry, and must never trust a stale plan as media authorization.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass


MIB = 1024 * 1024
GIB = 1024 * MIB
SECTOR = 512
ALIGN = MIB // SECTOR
MIN_CAPACITY = 32 * GIB
ESP_SIZE = 512 * MIB
ROOT_SIZE = 16 * GIB
MIN_PERSIST = 8 * GIB


@dataclass(frozen=True)
class PartitionRange:
    role: str
    first_lba: int
    last_lba: int


def plan(capacity_bytes: int, sector_bytes: int = SECTOR) -> tuple[PartitionRange, ...]:
    """Return inclusive LBAs, reserving GPT headers and aligning to 1 MiB."""

    if type(capacity_bytes) is not int or type(sector_bytes) is not int:
        raise ValueError("capacity and sector size must be integers")
    if sector_bytes != SECTOR or capacity_bytes < MIN_CAPACITY:
        raise ValueError("unsupported logical sector size or capacity")
    if capacity_bytes % sector_bytes:
        raise ValueError("capacity is not a multiple of the logical sector")
    total = capacity_bytes // sector_bytes
    end = ((total - 34) // ALIGN) * ALIGN - 1  # backup GPT and alignment
    esp_start = ALIGN
    esp_end = esp_start + ESP_SIZE // SECTOR - 1
    root_start = esp_end + 1
    root_end = root_start + ROOT_SIZE // SECTOR - 1
    persist_start = root_end + 1
    if (end - persist_start + 1) * SECTOR < MIN_PERSIST:
        raise ValueError("persistence partition is smaller than 8 GiB")
    return (
        PartitionRange("esp", esp_start, esp_end),
        PartitionRange("boot_root", root_start, root_end),
        PartitionRange("persistence", persist_start, end),
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: poc_media_geometry.py CAPACITY_BYTES", file=sys.stderr)
        return 2
    try:
        ranges = plan(int(argv[1]))
    except ValueError:
        print("unsupported PoC image geometry", file=sys.stderr)
        return 1
    print(json.dumps([asdict(item) for item in ranges], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
