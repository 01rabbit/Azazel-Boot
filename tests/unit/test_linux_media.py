"""Linux media policy tests use injected inventories and regular files only."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_boot import linux_writer
from azazel_boot.linux_media import (
    LinuxLsblkInventory,
    LinuxMediaRefused,
    LinuxMediaSession,
    _Block,
)
from azazel_boot.media import Eligibility
from azazel_boot.media_cli import run_console

PAYLOAD = b"synthetic inspection payload"
DIGEST = "sha256:" + hashlib.sha256(PAYLOAD).hexdigest()


def block(**changes: object) -> _Block:
    values: dict[str, object] = {
        "node": "/dev/synthetic-not-opened",
        "kname": "synthetic0",
        "kind": "disk",
        "bytes": 4096,
        "removable": True,
        "transport": "usb",
        "partition_table": None,
        "major": 240,
        "minor": 0,
        "stable_key": "hashed-stable-id",
        "bus_position": "5-2.1",
        "mounted": False,
        "root": False,
        "root_unknown": False,
    }
    values.update(changes)
    return _Block(**values)  # type: ignore[arg-type]


class Inventory:
    def __init__(self, *snapshots: tuple[_Block, ...]) -> None:
        self.snapshots = list(snapshots)
        self.calls = 0

    def enumerate(self) -> tuple[_Block, ...]:
        index = min(self.calls, len(self.snapshots) - 1)
        self.calls += 1
        return self.snapshots[index]


class RegularFileReader:
    def __init__(self, content: bytes = PAYLOAD) -> None:
        self.content = content
        self.calls = 0

    def digest(self, _block: _Block, length: int) -> str | None:
        self.calls += 1
        return "sha256:" + hashlib.sha256(self.content[:length]).hexdigest()


def test_list_media_issues_opaque_code_and_screen_repr_hide_identifiers() -> None:
    inventory = Inventory((block(),))
    session = LinuxMediaSession(inventory, RegularFileReader(), session_id="test-session")

    offer = session.list_media()[0]
    rendered = json.dumps(offer.describe_for_screen()) + repr(offer)

    assert offer.eligibility is Eligibility.ELIGIBLE
    assert offer.target_code is not None
    assert "synthetic-not-opened" not in rendered
    assert "hashed-stable-id" not in rendered
    assert "5-2.1" not in rendered
    assert "bus_path" not in offer.describe_for_screen()
    assert offer.describe_for_screen()["target_code"] == offer.target_code


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"transport": "sata"}, Eligibility.INTERNAL_DISK),
        ({"root": True}, Eligibility.HOLDS_RUNNING_ROOT),
        ({"root_unknown": True}, Eligibility.HOLDS_RUNNING_ROOT),
        ({"mounted": True}, Eligibility.MOUNTED),
        ({"removable": None}, Eligibility.REMOVABILITY_UNKNOWN),
        ({"bus_position": None}, Eligibility.REMOVABILITY_UNKNOWN),
        ({"stable_key": None}, Eligibility.INTERNAL_DISK),
        ({"major": None}, Eligibility.INTERNAL_DISK),
    ],
)
def test_ineligible_or_unidentifiable_devices_never_get_a_target_code(
    changes: dict[str, object], expected: Eligibility
) -> None:
    session = LinuxMediaSession(Inventory((block(**changes),)), RegularFileReader())

    offer = session.list_media()[0]

    assert offer.eligibility is expected
    assert offer.target_code is None


def test_duplicate_stable_identity_fails_closed() -> None:
    first = block()
    second = block(node="/dev/another-synthetic", kname="synthetic1", major=241)
    session = LinuxMediaSession(Inventory((first, second)), RegularFileReader())

    assert all(offer.target_code is None for offer in session.list_media())


def test_lsblk_parser_marks_root_ancestor_and_mounted_descendant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    devices = tmp_path / "devices"
    usb = devices / "pci0000:00" / "usb5" / "5-2" / "5-2.1" / "host9" / "target9:0:0"
    usb.mkdir(parents=True)
    class_block = tmp_path / "class" / "block"
    (class_block / "sdb").mkdir(parents=True)
    (class_block / "sdb" / "device").symlink_to(usb)

    payload = {
        "blockdevices": [
            {
                "path": "/dev/sda",
                "kname": "sda",
                "type": "disk",
                "size": 100000,
                "rm": False,
                "tran": "sata",
                "wwn": "root-wwn",
                "serial": "root-serial",
                "maj:min": "8:0",
                "mountpoints": [None],
                "children": [
                    {
                        "path": "/dev/sda1",
                        "kname": "sda1",
                        "type": "part",
                        "size": 90000,
                        "pkname": "sda",
                        "mountpoints": ["/"],
                    }
                ],
            },
            {
                "path": "/dev/sdb",
                "kname": "sdb",
                "type": "disk",
                "size": 500000,
                "rm": True,
                "tran": "usb",
                "wwn": "target-wwn",
                "serial": "target-serial",
                "maj:min": "8:16",
                "mountpoints": [None],
                "children": [
                    {
                        "path": "/dev/sdb1",
                        "kname": "sdb1",
                        "type": "part",
                        "size": 499000,
                        "pkname": "sdb",
                        "mountpoints": ["/media/target"],
                    }
                ],
            },
        ]
    }
    monkeypatch.setattr("azazel_boot.linux_media.sys.platform", "linux")
    monkeypatch.setattr(
        "azazel_boot.linux_media.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=json.dumps(payload)),
    )

    blocks = LinuxLsblkInventory(sysfs_root=tmp_path).enumerate()

    assert blocks[0].root
    assert blocks[0].root_unknown is False
    assert blocks[1].mounted
    assert blocks[1].bus_position == "5-2.1"
    assert "root-serial" not in repr(blocks)
    assert "target-serial" not in repr(blocks)


def test_lsblk_parser_unknown_root_and_missing_mount_metadata_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "blockdevices": [
            {
                "path": "/dev/sdz",
                "kname": "sdz",
                "type": "disk",
                "size": 4096,
                "rm": True,
                "tran": "usb",
                "wwn": "synthetic-wwn",
                "serial": "synthetic-serial",
                "maj:min": "8:240",
                # A requested lsblk field missing from an entry is not proof
                # that the device is unmounted.
            },
            {
                "path": "/dev/dm-0",
                "kname": "dm-0",
                "type": "crypt",
                "size": 4096,
                "rm": False,
                "tran": None,
                "wwn": None,
                "serial": None,
                "maj:min": "253:0",
                "mountpoints": ["/"],
            },
        ]
    }
    monkeypatch.setattr("azazel_boot.linux_media.sys.platform", "linux")
    monkeypatch.setattr(
        "azazel_boot.linux_media.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=json.dumps(payload)),
    )

    parsed = LinuxLsblkInventory().enumerate()[0]
    offers = LinuxMediaSession(Inventory((parsed,)), RegularFileReader()).list_media()

    assert parsed.root_unknown
    assert parsed.mounted
    assert offers[0].target_code is None


def test_inspect_rechecks_identity_then_hashes_through_injected_reader() -> None:
    inventory = Inventory((block(),), (block(),))
    reader = RegularFileReader()
    session = LinuxMediaSession(inventory, reader, session_id="one-session")
    offer = session.list_media()[0]

    result = session.inspect(offer.target_code or "", expected_digest=DIGEST, length=len(PAYLOAD))

    assert result.matches
    assert reader.calls == 1
    assert inventory.calls == 2


@pytest.mark.parametrize(
    "changed",
    [
        {"stable_key": "different-stable-id"},
        {"bytes": 8192},
        {"removable": False},
        {"mounted": True},
        {"bus_position": "5-2.2"},
        {"major": 241, "minor": 1},
    ],
)
def test_inspect_refuses_if_identity_or_relevant_attributes_change(
    changed: dict[str, object],
) -> None:
    inventory = Inventory((block(),), (block(**changed),))
    reader = RegularFileReader()
    session = LinuxMediaSession(inventory, reader)
    offer = session.list_media()[0]

    with pytest.raises(LinuxMediaRefused):
        session.inspect(offer.target_code or "", expected_digest=DIGEST, length=len(PAYLOAD))
    assert reader.calls == 0


def test_target_code_is_single_use_and_bound_to_one_session() -> None:
    inventory = Inventory((block(),), (block(),))
    session = LinuxMediaSession(inventory, RegularFileReader())
    code = session.list_media()[0].target_code or ""
    session.list_media()

    with pytest.raises(LinuxMediaRefused):
        session.inspect(code, expected_digest=DIGEST, length=len(PAYLOAD))


def test_cli_list_and_inspect_never_render_device_identifiers() -> None:
    session = LinuxMediaSession(Inventory((block(),), (block(),)), RegularFileReader())
    offers = session.list_media()
    code = offers[0].target_code
    assert code is not None

    class ListedSession:
        def list_media(self):
            return offers

        def inspect(self, target_code: str, *, expected_digest: str, length: int):
            return session.inspect(
                target_code, expected_digest=expected_digest, length=length
            )

    output = io.StringIO()
    commands = io.StringIO(f"inspect {code} {DIGEST} {len(PAYLOAD)}\nquit\n")

    assert run_console(ListedSession(), stdin=commands, stdout=output) == 0

    rendered = output.getvalue()
    assert "synthetic-not-opened" not in rendered
    assert "hashed-stable-id" not in rendered
    assert "5-2.1" not in rendered
    assert '"matches": true' in rendered


def test_physical_writer_gate_refuses_before_any_inventory_or_port_operation(
    tmp_path: Path,
) -> None:
    inventory = Inventory((block(),))
    media = LinuxMediaSession(inventory, RegularFileReader())
    ports = linux_writer._LinuxBlockPorts(media, effective_uid=lambda: 0)  # noqa: SLF001
    offer = media.list_media()[0]
    identity = offer.candidate.identity
    artifact = tmp_path / "synthetic.iso"
    artifact.write_bytes(PAYLOAD)

    with pytest.raises(linux_writer.PhysicalWriterUnavailable):
        ports.reread(identity, _permit=object())
    with pytest.raises(linux_writer.PhysicalWriterUnavailable):
        ports.unmount(identity, _permit=object())
    with pytest.raises(linux_writer.PhysicalWriterUnavailable):
        ports.write(identity, str(artifact), DIGEST, len(PAYLOAD), _permit=object())
    with pytest.raises(linux_writer.PhysicalWriterUnavailable):
        ports.digest(identity, len(PAYLOAD), _permit=object())
    with pytest.raises(linux_writer.PhysicalWriterUnavailable):
        ports._open_target(block(), _permit=object())  # noqa: SLF001

    assert inventory.calls == 1
    assert artifact.read_bytes() == PAYLOAD


def test_artifact_snapshot_fd_is_detached_from_later_source_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "source.iso"
    path.write_bytes(PAYLOAD)
    fd = linux_writer._LinuxBlockPorts._open_artifact(  # noqa: SLF001
        str(path), DIGEST, len(PAYLOAD)
    )
    try:
        path.write_bytes(b"changed after snapshot")
        assert os.pread(fd, len(PAYLOAD), 0) == PAYLOAD
    finally:
        os.close(fd)


def test_non_root_cannot_construct_the_privileged_writer_service() -> None:
    media = LinuxMediaSession(Inventory((block(),)), RegularFileReader())

    with pytest.raises(linux_writer.PhysicalWriterUnavailable):
        linux_writer.LinuxPrivilegedWriteService(
            media,
            artifact_store=object(),  # type: ignore[arg-type]
            artifact_reader=object(),  # type: ignore[arg-type]
            effective_uid=lambda: 1000,
        )
