"""The inventory reads, and does not guess, write, or transmit.

Azazel-Boot#9. Three properties, each checked rather than asserted in prose:
the parser builds identity from the composite fields and never from the kernel
name; an identity it cannot establish is recorded incomplete with reasons; and
reading an inventory changes nothing on the host it was read from.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from conftest import mac_reader

from azazel_boot.inventory import (
    DISCRIMINATOR_FIELDS,
    REQUIRED_IDENTITY_FIELDS,
    collect_interfaces,
    duplicate_identity_keys,
)

MODULE = Path(__file__).resolve().parents[2] / "src" / "azazel_boot" / "inventory.py"


def _tree_digest(root: Path) -> str:
    """A digest over every path, its kind, and any file content beneath ``root``."""

    parts: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            parts.append(f"link {rel} -> {path.readlink()}")
        elif path.is_dir():
            parts.append(f"dir  {rel}")
        else:
            parts.append(f"file {rel} {path.read_bytes()!r}")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def test_identity_is_built_from_the_composite_fields(sysfs_two_nics):
    observations = collect_interfaces(
        sysfs_two_nics,
        permanent_mac_reader=mac_reader(
            {"enp3s0": "a0:b1:c2:d3:e4:f5", "enx001122334455": "00:11:22:33:44:55"}
        ),
    )

    assert len(observations) == 2, "loopback must be excluded"
    wired, usb = observations

    assert wired.bus_path == "devices/pci0000:00/0000:00:1f.6"
    assert wired.permanent_mac == "a0:b1:c2:d3:e4:f5"
    assert wired.pci_id == "0x8086:0x15bb"
    assert wired.driver == "e1000e"
    assert wired.physical_label == "Ethernet"
    assert wired.firmware_version == "0.2-4"
    assert wired.is_commissionable

    assert usb.usb_vid_pid == "0b95:1790"
    assert usb.serial == "A1B2C3D4"
    assert usb.physical_label == "blue tag"
    assert usb.is_commissionable


def test_the_kernel_name_is_recorded_but_is_not_part_of_the_identity(sysfs_two_nics):
    """It moves between boots; deriving identity from it is the AR-12 failure."""

    observations = collect_interfaces(
        sysfs_two_nics,
        permanent_mac_reader=mac_reader(
            {"enp3s0": "a0:b1:c2:d3:e4:f5", "enx001122334455": "00:11:22:33:44:55"}
        ),
    )
    for observation in observations:
        assert observation.kernel_name_observed
        assert observation.kernel_name_observed not in observation.interface_key


def test_the_current_address_is_never_used_as_the_permanent_one(sysfs_two_nics):
    """Every fixture interface carries 02:00:00:00:00:99 in `address`.

    A parser that fell back to it would let a randomized or cloned address
    resolve an assignment.
    """

    observations = collect_interfaces(
        sysfs_two_nics, permanent_mac_reader=mac_reader({})
    )
    for observation in observations:
        assert observation.permanent_mac != "02:00:00:00:00:99"
        assert observation.permanent_mac is None
        assert "permanent_mac_unavailable" in observation.incomplete_reasons
        assert not observation.is_commissionable


def test_an_interface_with_only_a_mac_is_incomplete(sysfs_mac_only):
    """MAC-only matching is structurally insufficient, so it is refused early."""

    observations = collect_interfaces(
        sysfs_mac_only, permanent_mac_reader=mac_reader({"eth0": "de:ad:be:ef:00:01"})
    )
    (observation,) = observations
    assert observation.permanent_mac == "de:ad:be:ef:00:01"
    assert "no_discriminator_beyond_mac" in observation.incomplete_reasons
    assert not observation.is_commissionable


def test_an_unidentifiable_interface_gets_a_key_that_cannot_pass_for_identity(
    sysfs_mac_only,
):
    observations = collect_interfaces(
        sysfs_mac_only, permanent_mac_reader=mac_reader({})
    )
    (observation,) = observations
    assert observation.interface_key.startswith("unidentified:")
    assert not observation.is_commissionable


def test_two_interfaces_presenting_one_identity_are_reported(sysfs_cloned_identity):
    observations = collect_interfaces(
        sysfs_cloned_identity,
        permanent_mac_reader=mac_reader(
            {"enp1s0": "aa:bb:cc:dd:ee:01", "enp1s0f1": "aa:bb:cc:dd:ee:01"}
        ),
    )
    duplicates = duplicate_identity_keys(observations)
    assert len(duplicates) == 1


def test_reading_the_inventory_changes_nothing_on_the_host(sysfs_two_nics):
    """The product's defining promise, at the smallest scale that can hold it."""

    before = _tree_digest(sysfs_two_nics)
    collect_interfaces(
        sysfs_two_nics,
        permanent_mac_reader=mac_reader({"enp3s0": "a0:b1:c2:d3:e4:f5"}),
    )
    assert _tree_digest(sysfs_two_nics) == before


def test_the_module_imports_nothing_that_could_transmit():
    """An inventory that phoned home would disclose a borrowed machine's hardware."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])

    forbidden = {
        "socket", "http", "urllib", "requests", "ftplib", "smtplib",
        "telnetlib", "asyncio", "ssl", "xmlrpc", "subprocess",
    }
    assert not (imported & forbidden), (
        f"{sorted(imported & forbidden)} can transmit or spawn"
    )


def test_the_module_does_not_import_fabric():
    """ADR-0004 D3: one boundary module imports Fabric, and this is not it.

    Checked against the import graph, not against the text: the module's
    docstring names Fabric on purpose, to say where the boundary is.
    """

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    assert "azazel_fabric" not in roots


def test_the_module_spawns_no_process():
    """The bootstrap may not run a process (issue #1), and this does not.

    An earlier draft of this module shelled out to `ethtool -P` for the
    permanent MAC. `test_boundary_static.py` rejected it, correctly: reading a
    driver is operational work and does not belong in the bootstrap. The reader
    is injected instead, and its default reads nothing — so an unread identity
    is reported as unread rather than filled in from the current address.
    """

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    spawns = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"run", "Popen", "call", "check_output", "system", "exec"}
    ]
    assert spawns == [], f"{len(spawns)} process spawns; the bootstrap may run none"


def test_the_default_reader_reads_nothing_and_fails_closed(sysfs_two_nics):
    """No injected reader means no identity, which means COMMISSIONING_REQUIRED."""

    from azazel_boot.inventory import no_permanent_mac

    assert no_permanent_mac("enp3s0") is None

    observations = collect_interfaces(sysfs_two_nics)  # default reader
    assert observations
    for observation in observations:
        assert not observation.is_commissionable
        assert "permanent_mac_unavailable" in observation.incomplete_reasons


def test_an_all_zero_permanent_mac_is_an_absence_not_an_address(sysfs_two_nics):
    """A driver with no permanent address reports 00:00:00:00:00:00.

    Accepting it would give every such interface the same identity, which is
    the ambiguity this whole module exists to refuse.
    """

    observations = collect_interfaces(
        sysfs_two_nics,
        permanent_mac_reader=mac_reader(
            {"enp3s0": "00:00:00:00:00:00", "enx001122334455": "00:00:00:00:00:00"}
        ),
    )
    for observation in observations:
        assert observation.permanent_mac is None
        assert not observation.is_commissionable


def test_a_permanent_mac_is_normalized_before_it_becomes_identity(sysfs_two_nics):
    """Case and stray whitespace must not produce two identities for one port."""

    lower = collect_interfaces(
        sysfs_two_nics, permanent_mac_reader=mac_reader({"enp3s0": "a0:b1:c2:d3:e4:f5"})
    )
    upper = collect_interfaces(
        sysfs_two_nics, permanent_mac_reader=mac_reader({"enp3s0": " A0:B1:C2:D3:E4:F5 "})
    )
    assert lower[0].interface_key == upper[0].interface_key
    assert upper[0].permanent_mac == "a0:b1:c2:d3:e4:f5"


def test_collection_order_is_stable(sysfs_two_nics):
    """Directory iteration order is not; an inventory digest must not move."""

    reader = mac_reader(
        {"enp3s0": "a0:b1:c2:d3:e4:f5", "enx001122334455": "00:11:22:33:44:55"}
    )
    first = collect_interfaces(sysfs_two_nics, permanent_mac_reader=reader)
    second = collect_interfaces(sysfs_two_nics, permanent_mac_reader=reader)
    assert [o.interface_key for o in first] == [o.interface_key for o in second]


def test_a_missing_sysfs_root_is_empty_not_an_error():
    assert collect_interfaces(Path("/nonexistent/class/net")) == ()


def test_the_required_and_discriminator_field_sets_match_fabrics_rule():
    """Fabric's selector requires bus_path + MAC + one of pci/usb/serial."""

    assert REQUIRED_IDENTITY_FIELDS == ("bus_path", "permanent_mac")
    assert DISCRIMINATOR_FIELDS == ("pci_id", "usb_vid_pid", "serial")
