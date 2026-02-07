#!/usr/bin/env python3
"""Manual BLE capture sanity check (hardware required)."""

from __future__ import annotations

import glob
import logging
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.append(os.path.abspath("."))

from src.wicap.core.capture.bluetooth_backend import BluetoothCaptureBackend


def _resolve_interface() -> str:
    configured = os.getenv("WICAP_BT_INTERFACE", "auto").strip()
    if configured and configured.lower() != "auto":
        return configured

    glob_pattern = os.getenv("WICAP_BT_INTERFACE_GLOB", "/dev/serial/by-id/*nRF*")
    for candidate in sorted(glob.glob(glob_pattern)):
        if os.path.exists(candidate):
            return candidate
    for fallback_glob in ("/dev/ttyACM*", "/dev/ttyUSB*"):
        matches = sorted(glob.glob(fallback_glob))
        if matches:
            return matches[0]
    return "/dev/ttyACM0"


def verify_bt_capture() -> int:
    logging.basicConfig(level=logging.INFO)
    duration_sec = int(os.getenv("WICAP_BT_VERIFY_SECONDS", "8"))
    interface = _resolve_interface()
    capture_dir = Path("./captures_verify/bt")

    print("Starting Bluetooth capture verification...")
    print(f"Interface: {interface}")
    print(f"Capture directory: {capture_dir}")
    print(f"Duration: {duration_sec}s")

    if capture_dir.exists():
        shutil.rmtree(capture_dir)
    capture_dir.mkdir(parents=True, exist_ok=True)

    backend = BluetoothCaptureBackend(interface, capture_dir)

    def event_callback(event: dict) -> None:
        bt = event.get("bt", {}) or {}
        keys = event.get("keys", {}) or {}
        print(
            f"[EVENT] {event.get('event_type')} "
            f"{bt.get('addr', '-')}"
            f" RSSI={keys.get('rssi_dbm', '-')}"
        )

    try:
        backend.start_capture("verify_bt_capture", callback=event_callback)
    except Exception as exc:
        print(f"[FAIL] Capture failed to start: {exc}")
        return 2

    time.sleep(duration_sec)
    running = backend.is_running()
    backend.stop_capture()

    files = sorted(capture_dir.glob("*.pcapng"))
    if not running:
        print("[FAIL] Capture process exited before verification window finished.")
        return 3
    if not files:
        print("[FAIL] No pcapng files were created.")
        return 4

    print("[OK] Capture process remained healthy and produced files:")
    for pcap in files:
        print(f"  - {pcap} ({pcap.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(verify_bt_capture())
