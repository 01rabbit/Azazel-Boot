"""Captured sysfs trees, so the inventory parser can be exercised without a machine.

Each builder writes a directory that mirrors what Linux exposes under
`/sys/class/net`, including the `device` symlink whose target *is* the bus
position. They are built rather than committed as binary because a symlink's
target is the thing under test and a checked-in tree would not survive
`git archive` or a Windows checkout intact.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")


def make_interface(
    net_root: Path,
    kernel_name: str,
    *,
    bus: str,
    pci_id: tuple[str, str] | None = None,
    usb: tuple[str, str] | None = None,
    serial: str | None = None,
    driver: str = "e1000e",
    label: str | None = None,
    wireless_phy: str | None = None,
    firmware_version: str | None = None,
) -> None:
    """Create one interface directory shaped like the real thing."""

    interface = net_root / kernel_name
    interface.mkdir(parents=True, exist_ok=True)

    # The bus tree the `device` symlink points into.
    device_real = net_root.parent / "devices" / bus
    device_real.mkdir(parents=True, exist_ok=True)
    (interface / "device").symlink_to(Path("../../devices") / bus)

    # The current address is present on every interface and is deliberately
    # *not* what identity is built from.
    _write(interface / "address", "02:00:00:00:00:99")

    if pci_id:
        _write(device_real / "vendor", pci_id[0])
        _write(device_real / "device", pci_id[1])
    if usb:
        _write(device_real / "idVendor", usb[0])
        _write(device_real / "idProduct", usb[1])
    if serial:
        _write(device_real / "serial", serial)
    if label:
        _write(device_real / "label", label)
    if firmware_version:
        _write(device_real / "firmware_version", firmware_version)
    if wireless_phy:
        _write(interface / "phy80211" / "name", wireless_phy)

    driver_real = net_root.parent / "bus" / "drivers" / driver
    driver_real.mkdir(parents=True, exist_ok=True)
    # Two functions of one multi-port card share a bus directory, so the driver
    # symlink may already be there. That sharing is the point of the cloned
    # identity fixture, not an accident to work around.
    driver_link = device_real / "driver"
    if not driver_link.exists() and not driver_link.is_symlink():
        driver_link.symlink_to(Path("../../bus/drivers") / driver)


@pytest.fixture
def sysfs_two_nics(tmp_path: Path) -> Path:
    """A laptop with a built-in wired port and a USB adapter."""

    net = tmp_path / "two_nics" / "sys" / "class" / "net"
    net.mkdir(parents=True)
    (net / "lo").mkdir()  # excluded: not a port anyone commissions
    make_interface(
        net, "enp3s0", bus="pci0000:00/0000:00:1f.6",
        pci_id=("0x8086", "0x15bb"), label="Ethernet", driver="e1000e",
        firmware_version="0.2-4",
    )
    make_interface(
        net, "enx001122334455", bus="pci0000:00/0000:00:14.0/usb2/2-1",
        usb=("0b95", "1790"), serial="A1B2C3D4", driver="ax88179_178a",
        label="blue tag",
    )
    return net


@pytest.fixture
def sysfs_single_nic(tmp_path: Path) -> Path:
    """One usable port: no independent management path exists."""

    net = tmp_path / "single_nic" / "sys" / "class" / "net"
    net.mkdir(parents=True)
    (net / "lo").mkdir()
    make_interface(
        net, "wlp2s0", bus="pci0000:00/0000:02:00.0",
        pci_id=("0x8086", "0x2723"), driver="iwlwifi", wireless_phy="phy0",
    )
    return net


@pytest.fixture
def sysfs_mac_only(tmp_path: Path) -> Path:
    """An interface with no discriminator beyond its MAC."""

    net = tmp_path / "mac_only" / "sys" / "class" / "net"
    net.mkdir(parents=True)
    make_interface(net, "eth0", bus="virtual/net/eth0", driver="veth")
    return net


@pytest.fixture
def sysfs_cloned_identity(tmp_path: Path) -> Path:
    """Two interfaces presenting the same composite identity."""

    net = tmp_path / "cloned_identity" / "sys" / "class" / "net"
    net.mkdir(parents=True)
    for name in ("enp1s0", "enp1s0f1"):
        make_interface(
            net, name, bus="pci0000:00/0000:01:00.0",
            pci_id=("0x14e4", "0x1686"), driver="tg3",
        )
    return net


def mac_reader(mapping: dict[str, str | None]):
    """A stand-in for `ethtool -P`, so no driver is queried in a test."""

    return lambda kernel_name: mapping.get(kernel_name)
