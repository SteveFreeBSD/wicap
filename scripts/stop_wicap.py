#!/usr/bin/env python3
import glob
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

_SUDO_CHECKED = False
_SUDO_AVAILABLE = False


def _can_run_sudo_noninteractive() -> bool:
    """Return True when sudo can run without prompting for a password."""
    global _SUDO_CHECKED
    global _SUDO_AVAILABLE
    if _SUDO_CHECKED:
        return _SUDO_AVAILABLE

    _SUDO_CHECKED = True
    if os.geteuid() == 0:
        _SUDO_AVAILABLE = True
        return True

    try:
        result = subprocess.run(
            ["sudo", "-n", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        _SUDO_AVAILABLE = result.returncode == 0
    except Exception:
        _SUDO_AVAILABLE = False
    return _SUDO_AVAILABLE


def _current_uid() -> int:
    try:
        return os.getuid()
    except Exception:
        return -1


def _can_send_signal_unprivileged(cmd: list[str]) -> bool:
    """Return True when current user can signal every target PID in a kill command."""
    if not cmd or cmd[0] != "kill":
        return False

    pids: list[int] = []
    for token in cmd[1:]:
        if token.startswith("-"):
            continue
        try:
            pids.append(int(token))
        except ValueError:
            return False

    if not pids:
        return False

    uid = _current_uid()
    if uid < 0:
        return False

    for pid in pids:
        status_path = Path(f"/proc/{pid}/status")
        try:
            with open(status_path) as handle:
                owner_uid = None
                for line in handle:
                    if line.startswith("Uid:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            owner_uid = int(parts[1])
                        break
            if owner_uid is None or owner_uid != uid:
                return False
        except Exception:
            return False
    return True


def load_env_interface():
    # Attempt to load WICAP_INTERFACE from .env if it exists
    try:
        if os.path.exists(".env"):
            with open(".env") as f:
                for line in f:
                    if line.startswith("WICAP_INTERFACE="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                             return val
    except Exception:
        pass
    return os.environ.get("WICAP_INTERFACE", "wlan0")

def load_env_value(key: str) -> str:
    try:
        if os.path.exists(".env"):
            with open(".env") as f:
                for line in f:
                    if line.startswith(f"{key}="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            return val
    except Exception:
        pass
    return os.environ.get(key, "")

def resolve_ble_interface() -> str:
    interface = load_env_value("WICAP_BT_INTERFACE")
    if interface and interface.lower() != "auto":
        return interface

    bt_glob = load_env_value("WICAP_BT_INTERFACE_GLOB")
    if bt_glob:
        matches = sorted(glob.glob(bt_glob))
        if matches:
            return matches[0]

    bt_serial = load_env_value("WICAP_BT_SERIAL")
    if bt_serial:
        matches = sorted(Path("/dev/serial/by-id").glob(f"*{bt_serial}*"))
        if matches:
            return str(matches[0])

    return ""

HOST_PROCESSES = [
    "start_wicap.py",
    "scout.py",
    "event_processor.py",
    "nexus.watcher",
    "hashcat",
    "dumpcap",
    "tshark",
    "nrf_sniffer_ble",
    "nrf_sniffer_ble.py",
]

def run_cmd(cmd, check=True):
    resolved_cmd = list(cmd)

    # Avoid noisy sudo password prompts in non-interactive environments.
    if resolved_cmd and resolved_cmd[0] == "sudo":
        if os.geteuid() == 0:
            resolved_cmd = resolved_cmd[1:]
        elif _can_run_sudo_noninteractive():
            resolved_cmd = ["sudo", "-n", *resolved_cmd[1:]]
        else:
            fallback = resolved_cmd[1:]
            if fallback and _can_send_signal_unprivileged(fallback):
                print(
                    "sudo unavailable non-interactively; attempting unprivileged kill: "
                    + " ".join(fallback)
                )
                resolved_cmd = fallback
            else:
                print(
                    "Skipping privileged command (sudo unavailable non-interactively): "
                    + " ".join(resolved_cmd)
                )
                return False

    print(f"Running: {' '.join(resolved_cmd)}")
    try:
        result = subprocess.run(resolved_cmd, check=False, text=True)
    except Exception as e:
        print(f"Error executing command: {e}")
        if check:
            sys.exit(1)
        return False

    if check and result.returncode != 0:
        print(f"Error executing command (exit={result.returncode}): {' '.join(resolved_cmd)}")
        sys.exit(1)

    return result.returncode == 0

def kill_host_processes():
    print("🛑 Checking for host-based WICAP processes...")
    try:
        # Get all related PIDs
        cmd = ["pgrep", "-f", "|".join(HOST_PROCESSES)]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            pids = result.stdout.strip().split("\n")
            if pids:
                print(f"   Found {len(pids)} processes to kill: {', '.join(pids)}")
                # Try graceful SIGINT first
                run_cmd(["sudo", "kill", "-2"] + pids, check=False)
                time.sleep(2)

                # Check if any remain
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                     pids_remaining = result.stdout.strip().split("\n")
                     print(f"   Force killing {len(pids_remaining)} remaining processes...")
                     run_cmd(["sudo", "kill", "-9"] + pids_remaining, check=False)
        else:
             print("   No host processes found.")

    except Exception as e:
        print(f"⚠️ Error cleaning up host processes: {e}")

def clean_pid_files():
    print("🧹 Cleaning PID files...")
    for pidfile in glob.glob("captures/*.pid"):
        try:
            os.remove(pidfile)
            print(f"   Removed {pidfile}")
        except Exception as e:
            print(f"   Failed to remove {pidfile}: {e}")

def stop_docker():
    print("🛑 Stopping WICAP Docker containers...")
    try:
        # Check if containers are actually running before trying to stop
        res = subprocess.run(["docker", "compose", "ps", "-q"], capture_output=True, text=True)
        if res.stdout.strip():
             run_cmd(["docker", "compose", "down"])
        else:
             print("   No Docker containers running.")
    except FileNotFoundError:
        print("   Docker not found, skipping.")

def reset_wifi(interface="wlan0"):
    print(f"📡 Resetting {interface} to Managed Mode...")
    try:
        # Only reset if interface exists
        if os.path.exists(f"/sys/class/net/{interface}"):
            ran_any = False
            ran_any |= run_cmd(["sudo", "ip", "link", "set", "dev", interface, "down"], check=False)
            ran_any |= run_cmd(["sudo", "iw", "dev", interface, "set", "type", "managed"], check=False)
            ran_any |= run_cmd(["sudo", "ip", "link", "set", "dev", interface, "up"], check=False)
            if ran_any:
                print(f"✅ {interface} reset to managed mode.")
            else:
                print(f"⚠️ Skipped WiFi reset for {interface} (sudo required).")
        else:
            print(f"   Interface {interface} not found, skipping reset.")
    except Exception as e:
        print(f"⚠️ Failed to reset WiFi info: {e}")

def reset_bluetooth(interface: str = ""):
    print("🔵 Releasing Bluetooth capture resources...")
    if not interface:
        print("   No BLE interface configured; skipping device release.")
        return
    if not os.path.exists(interface):
        print(f"   BLE interface {interface} not found; skipping.")
        return

    # Try to release the serial device if anything still holds it.
    if shutil.which("fuser"):
        released = run_cmd(["sudo", "fuser", "-k", interface], check=False)
    else:
        print("   fuser not available; relying on process cleanup.")
        released = False
    if released:
        print(f"✅ BLE device released: {interface}")
    else:
        print(f"⚠️ Skipped BLE device release for {interface} (sudo required).")

if __name__ == "__main__":
    print("="*40)
    print("   WICAP SHUTDOWN SEQUENCE")
    print("="*40)

    # 1. Kill host processes (if running without Docker)
    kill_host_processes()

    # 2. Stop Docker (if running with Docker)
    stop_docker()

    # 3. Clean PID files
    clean_pid_files()

    # Optional: Small delay
    time.sleep(1)

    # 4. Reset WiFi
    reset_wifi(load_env_interface())
    # 5. Release BLE interface (if configured)
    reset_bluetooth(resolve_ble_interface())

    print("\n✅ Shutdown Complete.")
