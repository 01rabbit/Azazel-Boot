"""Read-only interface inventory: what this host *is*, never what it may do.

Azazel-Boot#9. An interface role comes from read-only inventory plus explicit
operator confirmation against a **composite identity**. It never comes from an
interface name, its link state, or the default route.

Three properties make this module what the threat model needs, and each is
tested rather than asserted:

*Read-only.* Every access here opens a file for reading or reads a symlink.
Nothing is written, no process is run, no device is probed into a different
state, and no subsystem is asked to activate anything. On borrowed hardware
that is not a preference, it is the product's reason to exist — and it is why
the permanent MAC, which needs an ioctl, is *injected* rather than read here
(see :func:`no_permanent_mac`).

*Transmits nothing.* This module imports no networking, opens no socket, and
resolves no name. An inventory that phoned home would be a disclosure of the
owner's hardware, made without their knowledge, on a machine Boot was lent.

*Incomplete is never guessed.* An interface whose composite identity cannot be
established is recorded as incomplete **with its reasons**, and a caller may
not commission it. `azazel_boot.commissioning` turns that into
`COMMISSIONING_REQUIRED`. Filling a gap by inference is exactly the failure the
program plan's AR-12 finding names.

The kernel name is recorded because an operator sees it on a screen, and is
deliberately **excluded from identity**: it moves between boots and driver
reloads. Fabric's `InterfaceIdentity` makes the same exclusion, and
`azazel_boot.fabric_projection` is where an observation here becomes one.

This module does not import `azazel_fabric` (ADR-0004 D3): one boundary module
does, so Fabric's absence fails in one known place. What is produced here is
plain data that a projection can shape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

#: Where a running Linux exposes its interfaces. Injectable so the parser can
#: be exercised against captured trees without a machine.
DEFAULT_SYSFS_NET = Path("/sys/class/net")

#: An interface must carry these before any role may be confirmed against it.
#: `bus_path` and `permanent_mac` are both required, and MAC alone is never
#: enough — a cloned or spoofed MAC must not resolve an assignment.
REQUIRED_IDENTITY_FIELDS = ("bus_path", "permanent_mac")

#: At least one of these must also be present, for the same reason.
DISCRIMINATOR_FIELDS = ("pci_id", "usb_vid_pid", "serial")

_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

#: A MAC of all zeroes is what a driver reports when it has no permanent
#: address to give. It is an absence, not an address.
_NULL_MAC = "00:00:00:00:00:00"


@dataclass(frozen=True)
class InterfaceObservation:
    """One interface as read, with no role and no judgement about it."""

    #: Stable key within one inventory. Derived from the composite identity,
    #: never from the kernel name.
    interface_key: str
    bus_path: str | None = None
    permanent_mac: str | None = None
    pci_id: str | None = None
    usb_vid_pid: str | None = None
    serial: str | None = None
    driver: str | None = None
    driver_version: str | None = None
    firmware_version: str | None = None
    wireless_phy: str | None = None
    physical_label: str | None = None
    #: Recorded because an operator sees it; never part of identity.
    kernel_name_observed: str | None = None
    #: Why this observation cannot carry a confirmed role. Empty when it can.
    incomplete_reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_commissionable(self) -> bool:
        """True when a role *may* be confirmed against this identity.

        It says the identity is sufficient to be confirmed against. It does not
        say a role was confirmed, and it grants nothing.
        """

        return not self.incomplete_reasons


def _read_text(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    return value or None


def _read_link_name(path: Path) -> str | None:
    """Return the basename a symlink points at, without following into it."""

    try:
        return Path(path.readlink()).name
    except OSError:
        return None


def _bus_path(device_dir: Path) -> str | None:
    """The device's position on its bus, which a physical port keeps.

    `device` is a symlink into the bus tree; its target path *is* the bus
    position. It is resolved relative to the interface directory so a captured
    tree behaves like a live one.
    """

    try:
        target = device_dir.readlink()
    except OSError:
        return None
    parts = [p for p in Path(target).parts if p not in ("..", "/")]
    return "/".join(parts) or None


def normalize_permanent_mac(raw: str | None) -> str | None:
    """Accept a permanent MAC only in the one form identity may use.

    Lowercase, colon-separated, and not the all-zero address a driver reports
    when it has **no** permanent address to give. That value is an absence, not
    an address, and treating it as one would give every such interface the same
    identity.
    """

    if not raw:
        return None
    mac = raw.strip().lower()
    if mac == _NULL_MAC or not _MAC.match(mac):
        return None
    return mac


def no_permanent_mac(kernel_name: str) -> str | None:  # noqa: ARG001
    """The default reader: it reads nothing, and says so.

    The permanent MAC comes from the ``ETHTOOL_GPERMADDR`` ioctl — what
    ``ethtool -P`` performs. `/sys/class/net/<name>/address` is the *current*
    address, which a randomized MAC or a bond changes, so substituting it would
    let a cloned address resolve an assignment. There is no sysfs file carrying
    the permanent one.

    Querying a driver is **operational**, and this repository's bootstrap may
    not run a process or reach a device (issue #1, enforced by
    `tests/unit/test_boundary_static.py`). So the default reads nothing and every
    interface comes back incomplete, which resolves to ``COMMISSIONING_REQUIRED``
    — the correct answer for a host whose identity has not actually been read.

    A component that *is* permitted to query drivers injects a real reader and
    passes its result through :func:`normalize_permanent_mac`. Until one exists,
    this is not a gap being papered over: it is the gap, reported.
    """

    return None


def _observe(
    interface_dir: Path,
    *,
    permanent_mac_reader,
) -> InterfaceObservation:
    kernel_name = interface_dir.name
    device_dir = interface_dir / "device"

    bus_path = _bus_path(device_dir)
    permanent_mac = normalize_permanent_mac(permanent_mac_reader(kernel_name))

    vendor = _read_text(device_dir / "vendor")
    device = _read_text(device_dir / "device")
    pci_id = f"{vendor}:{device}" if vendor and device else None

    id_vendor = _read_text(device_dir / "idVendor")
    id_product = _read_text(device_dir / "idProduct")
    usb_vid_pid = f"{id_vendor}:{id_product}" if id_vendor and id_product else None

    observation_fields = {
        "bus_path": bus_path,
        "permanent_mac": permanent_mac,
        "pci_id": pci_id,
        "usb_vid_pid": usb_vid_pid,
        "serial": _read_text(device_dir / "serial"),
        "driver": _read_link_name(device_dir / "driver"),
        "driver_version": _read_text(device_dir / "driver" / "module" / "version"),
        "firmware_version": _read_text(interface_dir / "device" / "firmware_version"),
        "wireless_phy": _read_text(interface_dir / "phy80211" / "name"),
        "physical_label": _read_text(device_dir / "label")
        or _read_text(interface_dir / "phys_port_name"),
        "kernel_name_observed": kernel_name,
    }

    reasons: list[str] = []
    for name in REQUIRED_IDENTITY_FIELDS:
        if not observation_fields[name]:
            reasons.append(f"{name}_unavailable")
    if not any(observation_fields[name] for name in DISCRIMINATOR_FIELDS):
        reasons.append("no_discriminator_beyond_mac")

    return InterfaceObservation(
        interface_key=_interface_key(observation_fields, kernel_name),
        incomplete_reasons=tuple(reasons),
        **observation_fields,
    )


def _interface_key(fields: dict[str, str | None], kernel_name: str) -> str:
    """A key from the composite identity, falling back only when it must.

    An incomplete observation still needs a key so it can be *reported*. The
    fallback is prefixed `unidentified:` so it can never be mistaken for an
    identity, and `is_commissionable` is False for exactly those observations.
    """

    bus_path = fields.get("bus_path")
    permanent_mac = fields.get("permanent_mac")
    if bus_path and permanent_mac:
        return f"{bus_path}|{permanent_mac}"
    return f"unidentified:{kernel_name}"


def collect_interfaces(
    sysfs_net: Path | None = None,
    *,
    permanent_mac_reader=no_permanent_mac,
) -> tuple[InterfaceObservation, ...]:
    """Read every interface under ``sysfs_net``, in a stable order.

    Sorted by kernel name so two runs over one tree produce the same sequence:
    directory iteration order is not stable, and an inventory whose order moved
    between reads would change its own digest for no reason.

    Loopback is excluded — it is not a port an operator can commission.
    """

    root = DEFAULT_SYSFS_NET if sysfs_net is None else Path(sysfs_net)
    if not root.is_dir():
        return ()

    observations = [
        _observe(entry, permanent_mac_reader=permanent_mac_reader)
        for entry in sorted(root.iterdir(), key=lambda p: p.name)
        if entry.is_dir() and entry.name != "lo"
    ]
    return tuple(observations)


def duplicate_identity_keys(
    observations: tuple[InterfaceObservation, ...],
) -> tuple[str, ...]:
    """Identity keys claimed by more than one interface.

    Two interfaces that present the same composite identity make an assignment
    ambiguous, and an ambiguous identity fails closed rather than picking one.
    Fabric's ``resolve_interface_assignment`` enforces the same rule at the
    contract level; this reports it at the inventory level, before a record is
    ever built.
    """

    seen: dict[str, int] = {}
    for observation in observations:
        seen[observation.interface_key] = seen.get(observation.interface_key, 0) + 1
    return tuple(sorted(key for key, count in seen.items() if count > 1))
