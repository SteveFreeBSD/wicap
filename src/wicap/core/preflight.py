"""
Preflight helpers for interface selection and device readiness.
"""
from __future__ import annotations

import glob
import logging
import os
import re
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path

logger = logging.getLogger("wicap.preflight")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def list_wireless_interfaces() -> list[str]:
    interfaces: list[str] = []

    try:
        result = subprocess.run(
            ["iw", "dev"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface "):
                    parts = line.split()
                    if len(parts) >= 2:
                        interfaces.append(parts[1])
    except Exception:
        pass

    if not interfaces:
        try:
            for name in os.listdir("/sys/class/net"):
                if name.startswith(("wlan", "wl")):
                    interfaces.append(name)
        except Exception:
            pass

    return sorted(set(interfaces))


def _read_interface_mac(interface: str) -> str | None:
    try:
        path = Path("/sys/class/net") / interface / "address"
        if path.exists():
            return path.read_text().strip().lower()
    except Exception:
        return None
    return None


def select_wifi_interface(
    interfaces: Iterable[str],
    preferred: str | None,
    mac_target: str | None = None,
    regex: str | None = None,
    exclude_regex: str | None = None,
    mac_map: dict[str, str] | None = None,
) -> str | None:
    interfaces = list(interfaces)
    if not interfaces:
        return None

    if exclude_regex:
        try:
            exclude = re.compile(exclude_regex)
            interfaces = [i for i in interfaces if not exclude.search(i)]
        except re.error:
            logger.warning("Invalid WICAP_INTERFACE_EXCLUDE_REGEX=%s", exclude_regex)

    if preferred and preferred.lower() != "auto":
        if preferred in interfaces:
            return preferred

    if mac_target:
        target = mac_target.lower()
        mac_map = mac_map or {iface: _read_interface_mac(iface) for iface in interfaces}
        for iface in interfaces:
            if mac_map.get(iface) == target:
                return iface

    if regex:
        try:
            pattern = re.compile(regex)
            for iface in interfaces:
                if pattern.search(iface):
                    return iface
        except re.error:
            logger.warning("Invalid WICAP_INTERFACE_REGEX=%s", regex)

    if "wlan1" in interfaces:
        return "wlan1"

    indexed = []
    for iface in interfaces:
        match = re.match(r"^wlan(\d+)$", iface)
        if match:
            indexed.append((int(match.group(1)), iface))
    if indexed:
        return sorted(indexed, reverse=True)[0][1]

    return interfaces[0]


def resolve_wifi_interface(preferred: str | None = None) -> str | None:
    interfaces = list_wireless_interfaces()
    if not interfaces:
        logger.error("No wireless interfaces detected via iw or /sys/class/net.")
        return None

    mac_target = os.getenv("WICAP_INTERFACE_MAC")
    regex = os.getenv("WICAP_INTERFACE_REGEX")
    exclude_regex = os.getenv("WICAP_INTERFACE_EXCLUDE_REGEX")
    mac_map = {iface: _read_interface_mac(iface) for iface in interfaces}

    selected = select_wifi_interface(
        interfaces,
        preferred=preferred,
        mac_target=mac_target,
        regex=regex,
        exclude_regex=exclude_regex,
        mac_map=mac_map,
    )

    if not selected:
        logger.error(
            "Unable to resolve Wi-Fi interface. Set WICAP_INTERFACE or WICAP_INTERFACE_MAC/REGEX."
        )
        return None

    logger.info("Resolved Wi-Fi interface: %s (available=%s)", selected, ", ".join(interfaces))
    return selected


def resolve_ble_interface() -> str | None:
    if not _env_bool("WICAP_BT_ENABLED", False):
        return None

    def _configured_interface_exists(value: str) -> bool:
        if os.path.exists(value):
            return True
        base = os.path.basename(value)
        # extcap-style interface name (e.g. /dev/ttyACM0-None)
        if re.match(r"^tty(ACM|USB)\d+-", base):
            tty_base = base.split("-", 1)[0]
            return os.path.exists(str(Path(value).with_name(tty_base)))
        return False

    interface = os.getenv("WICAP_BT_INTERFACE")
    if interface and interface.lower() != "auto":
        if _configured_interface_exists(interface):
            return interface
        logger.warning(
            "Configured BLE interface %s was not found. Falling back to auto-detection.",
            interface,
        )

    bt_glob = os.getenv("WICAP_BT_INTERFACE_GLOB", "").strip()
    if bt_glob:
        matches = sorted(glob.glob(bt_glob))
        if matches:
            return str(matches[0])

    bt_serial = os.getenv("WICAP_BT_SERIAL", "").strip()
    if bt_serial:
        matches = sorted(Path("/dev/serial/by-id").glob(f"*{bt_serial}*"))
        if matches:
            return str(matches[0])

    for pattern in ("/dev/ttyACM*", "/dev/ttyUSB*"):
        matches = sorted(glob.glob(pattern))
        if matches:
            return matches[0]

    return None


def unblock_rfkill() -> None:
    if not shutil.which("rfkill"):
        return
    try:
        result = subprocess.run(
            ["rfkill", "list", "wifi"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return
        if "Soft blocked: yes" in result.stdout:
            logger.warning("Wi-Fi is soft-blocked; running rfkill unblock wifi.")
            subprocess.run(["rfkill", "unblock", "wifi"], check=False)
    except Exception:
        return
