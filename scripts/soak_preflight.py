#!/usr/bin/env python3
"""
Soak preflight helper.

Resolves Wi-Fi/BLE interfaces, validates device availability, and emits shell
exports for use by run_soak.sh or other launchers.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(REPO_ROOT))

from src.wicap.core import preflight  # noqa: E402


def _env_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _emit_env(name: str, value: str | None) -> None:
    if value is None:
        return
    print(f"export {name}={shlex.quote(str(value))}")


def _resolve_ble_interface() -> str | None:
    interface = os.getenv("WICAP_BT_INTERFACE", "").strip()
    if interface and interface.lower() != "auto":
        return interface

    bt_glob = os.getenv("WICAP_BT_INTERFACE_GLOB", "").strip()
    if bt_glob:
        matches = sorted(glob.glob(bt_glob))
        if matches:
            return matches[0]

    bt_serial = os.getenv("WICAP_BT_SERIAL", "").strip()
    if bt_serial:
        matches = sorted(Path("/dev/serial/by-id").glob(f"*{bt_serial}*"))
        if matches:
            return str(matches[0])

    # Auto-detect Nordic dongles if present.
    for path in Path("/dev/serial/by-id").glob("*"):
        if re.search(r"nrf|nordic", path.name, re.IGNORECASE):
            return str(path)

    acm_matches = sorted(Path("/dev").glob("ttyACM*"))
    if len(acm_matches) == 1:
        return str(acm_matches[0])

    return None


def _validate_interface(interface: str, label: str) -> None:
    result = subprocess.run(
        ["ip", "link", "show", interface],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            f"❌ {label} interface '{interface}' not found. "
            "Set WICAP_INTERFACE or WICAP_INTERFACE_REGEX.",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-env", action="store_true", help="Emit shell exports")
    args = parser.parse_args()

    preferred = os.getenv("WICAP_INTERFACE")
    resolved_wifi = preflight.resolve_wifi_interface(preferred=preferred)
    if not resolved_wifi:
        print(
            "❌ Unable to resolve Wi-Fi interface. "
            "Set WICAP_INTERFACE or WICAP_INTERFACE_REGEX/WICAP_INTERFACE_MAC.",
            file=sys.stderr,
        )
        return 1

    wifi_interfaces = preflight.list_wireless_interfaces()
    if resolved_wifi == "wlan0" and "wlan1" in wifi_interfaces and not preferred:
        print(
            "⚠️ WICAP resolved wlan0, but wlan1 is available. "
            "Set WICAP_INTERFACE=wlan1 to avoid the internal adapter.",
            file=sys.stderr,
        )

    _validate_interface(resolved_wifi, "Wi-Fi")

    bt_enabled = _env_truthy(os.getenv("WICAP_BT_ENABLED"))
    bt_interface = _resolve_ble_interface()

    if bt_enabled and not bt_interface:
        print(
            "❌ Bluetooth capture enabled but no BLE interface resolved. "
            "Set WICAP_BT_INTERFACE or WICAP_BT_INTERFACE_GLOB.",
            file=sys.stderr,
        )
        return 1

    if not bt_enabled and bt_interface:
        bt_enabled = True

    if bt_enabled and bt_interface and not os.path.exists(bt_interface):
        print(
            f"❌ BLE interface '{bt_interface}' not found. "
            "Check WICAP_BT_INTERFACE settings.",
            file=sys.stderr,
        )
        return 1

    if args.print_env:
        _emit_env("WICAP_INTERFACE", resolved_wifi)
        _emit_env("WICAP_BT_ENABLED", "true" if bt_enabled else "false")
        if bt_interface:
            _emit_env("WICAP_BT_INTERFACE", bt_interface)
    else:
        print(f"✅ Wi-Fi interface: {resolved_wifi}")
        if bt_enabled:
            print(f"✅ BLE interface: {bt_interface}")
        else:
            print("ℹ️ BLE capture disabled (no interface detected).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
