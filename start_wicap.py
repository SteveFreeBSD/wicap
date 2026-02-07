#!/usr/bin/env python3
"""
start_wicap.py
Professional Launcher for WiFiWizard Suite.

Orchestrates the execution of:
1. Scout (Data Capture) - Requires Root
2. Event Processor (Data Curation & SQL)

Features:
- Unified logging output with service prefixes
- Process health monitoring (auto-shutdown if one fails)
- Graceful signal handling (SIGINT/SIGTERM)
- Environment variable pass-through
"""

import argparse
import atexit
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time

# Module-level interface tracking for reliable cleanup
_active_interface: str | None = None

# Configure robust logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-7s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('wicap_launcher')

# Import defaults
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import DEFAULT_INTERFACE  # noqa: E402
from src.wicap.core.preflight import resolve_ble_interface, resolve_wifi_interface, unblock_rfkill  # noqa: E402


class ServiceRunner:
    def __init__(self, name: str, cmd: list[str], cwd: str = "."):
        self.name = name
        self.cmd = cmd
        self.cwd = cwd
        self.process: subprocess.Popen | None = None
        self.thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        env = os.environ.copy()
        # Force Python to unbuffer stdout/stderr for real-time logging
        env["PYTHONUNBUFFERED"] = "1"

        try:
            self.process = subprocess.Popen(
                self.cmd,
                cwd=self.cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Merge stdout/stderr
                env=env,
                universal_newlines=True,
                bufsize=1
            )

            # Start monitoring thread
            self.thread = threading.Thread(target=self._monitor_output, daemon=True)
            self.thread.start()
            logger.info(f"Started service: {self.name} (PID {self.process.pid})")

        except Exception as e:
            logger.error(f"Failed to start {self.name}: {e}")
            raise

    def base_name(self) -> str:
        return f"[{self.name.upper()}]".ljust(10)

    def _monitor_output(self):
        """Read output stream and log it."""
        if not self.process or not self.process.stdout:
            return

        try:
            for line in iter(self.process.stdout.readline, ''):
                line = line.strip()
                if line:
                    # Log with prefix, mirroring child log level logic if possible
                    # For now, just print clean info
                    print(f"{self.base_name()} {line}")
        except ValueError:
            pass # File closed
        except Exception as e:
            logger.error(f"Error reading from {self.name}: {e}")

    def is_alive(self) -> bool:
        if self.process is None:
            return False
        return self.process.poll() is None

    def stop(self) -> None:
        if self.process and self.is_alive():
            logger.info(f"Stopping {self.name}...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning(f"{self.name} did not stop gracefuly, killing...")
                self.process.kill()

def cleanup_interface(interface: str = None) -> None:
    """Reset WiFi interface to managed mode."""
    global _active_interface
    iface = interface or _active_interface
    if not iface:
        return
    logger.info(f"Resetting interface {iface}...")
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], check=False)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"], check=False)
        subprocess.run(["ip", "link", "set", iface, "up"], check=False)
        logger.info(f"Interface {iface} reset to managed mode.")
        _active_interface = None  # Mark as cleaned
    except Exception as e:
        logger.error(f"Failed to reset interface: {e}")


def _get_interface_type(interface: str) -> str | None:
    """Return interface type from iw output (e.g., monitor/managed)."""
    try:
        res = subprocess.run(
            ["iw", "dev", interface, "info"],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            return None
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("type "):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
        return None
    except Exception:
        return None


def prepare_interface(interface: str, kill_interference: bool = True) -> bool:
    """Prepare interface for monitor-mode channel hopping."""
    if kill_interference:
        if shutil.which("airmon-ng"):
            logger.info("Running airmon-ng check kill to clear interference...")
            try:
                res = subprocess.run(
                    ["airmon-ng", "check", "kill"],
                    capture_output=True,
                    text=True,
                    input="y\n",
                    timeout=15,
                )
                if res.returncode != 0:
                    logger.warning(
                        f"airmon-ng check kill failed: {(res.stderr or res.stdout).strip()}"
                    )
            except subprocess.TimeoutExpired:
                logger.warning("airmon-ng check kill timed out; continuing without confirmation.")
        else:
            logger.warning(
                "airmon-ng not found; cannot auto-kill interfering services."
            )

    logger.info(f"Setting {interface} to monitor mode...")
    subprocess.run(["ip", "link", "set", interface, "down"], check=False)
    res = subprocess.run(
        ["iw", "dev", interface, "set", "type", "monitor"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        logger.warning(
            f"Failed to set monitor mode on {interface}: {(res.stderr or res.stdout).strip()}"
        )
    subprocess.run(["ip", "link", "set", interface, "up"], check=False)

    iface_type = _get_interface_type(interface)
    if iface_type and iface_type != "monitor":
        logger.error(
            f"{interface} is in {iface_type} mode; channel switching may fail."
        )
        return False
    if iface_type is None:
        logger.warning(f"Could not confirm {interface} mode via iw.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="WiFiWizard Suite Launcher")
    parser.add_argument("-i", "--interface", default=os.getenv("WICAP_INTERFACE", DEFAULT_INTERFACE), help="Wireless interface")
    parser.add_argument("--push-to-sql", action="store_true", help="Enable SQL sync")
    parser.add_argument("--no-preflight", action="store_true",
                        help="Skip interface preflight (monitor mode + interference kill)")
    parser.add_argument("--no-airmon-kill", action="store_true",
                        help="Skip airmon-ng check kill during preflight")
    parser.add_argument("--baseline-captures", action="store_true",
                        help="Mark existing dwell_*.pcapng as processed before watcher starts")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--services", default="all", help="Comma-separated services to run: scout,processor,watcher (default: all)")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.getLogger().setLevel(log_level)
    logger.setLevel(log_level)

    # Parse selected services
    selected_services = {"scout", "processor", "watcher"}
    if args.services != "all":
        selected_services = set(args.services.split(","))

    # Check root for scout
    if "scout" in selected_services and os.geteuid() != 0:
        logger.error("Scout requires root privileges. Please run with sudo.")
        sys.exit(1)

    # Interface preflight (only if scout is running)
    if "scout" in selected_services:
        resolved_iface = resolve_wifi_interface(args.interface)
        if not resolved_iface:
            sys.exit(1)
        if resolved_iface != args.interface:
            logger.info("Using resolved interface %s (requested %s)", resolved_iface, args.interface)
            args.interface = resolved_iface
            os.environ["WICAP_INTERFACE"] = resolved_iface

        # BLE preflight (optional)
        if os.getenv("WICAP_BT_ENABLED", "false").lower() in ("1", "true", "yes"):
            bt_iface = resolve_ble_interface()
            if bt_iface:
                os.environ["WICAP_BT_INTERFACE"] = bt_iface
                logger.info("Resolved Bluetooth interface: %s", bt_iface)
            else:
                logger.warning("Bluetooth enabled but no device found. Disabling for this run.")
                os.environ["WICAP_BT_ENABLED"] = "false"

        if not args.no_preflight:
            unblock_rfkill()
            ok = prepare_interface(args.interface, kill_interference=not args.no_airmon_kill)
            if not ok:
                logger.error("Preflight failed. Aborting startup.")
                sys.exit(1)

    # Track interface for cleanup (even on external kill)
    global _active_interface
    _active_interface = args.interface
    atexit.register(cleanup_interface)

    # Define services
    services = []

    # 1. Scout
    if "scout" in selected_services:
        scout_cmd = [sys.executable, "scout.py", "start", "-i", args.interface]
        if args.verbose:
            scout_cmd.append("-v")
        services.append(ServiceRunner("scout", scout_cmd))

    # 2. Processor
    if "processor" in selected_services:
        proc_cmd = [sys.executable, "event_processor.py", "watch"]
        if args.push_to_sql:
            proc_cmd.append("--push-to-sql")
        if args.verbose:
            proc_cmd.append("-v")
        services.append(ServiceRunner("processor", proc_cmd))

    # 3. Nexus Watcher (Attack Engine)
    if "watcher" in selected_services:
        # Runs as module 'nexus.watcher' - note: doesn't support -v flag
        watch_cmd = [sys.executable, "-m", "nexus.watcher", "start"]
        if args.baseline_captures:
            watch_cmd.append("--baseline")
        services.append(ServiceRunner("watcher", watch_cmd))

    stop_event = threading.Event()

    def signal_handler(sig, frame) -> None:
        logger.info("\nShutdown signal received.")
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("Initializing WiFiWizard Suite...")

    try:
        # Start all
        for svc in services:
            svc.start()
            # Brief pause to let services initialize files
            time.sleep(0.5)

        logger.info("Suite running. Press Ctrl+C to stop.")

        # Watchdog loop
        while not stop_event.is_set():
            all_alive = True
            for svc in services:
                if not svc.is_alive():
                    logger.error(f"Service {svc.name} died unexpectedly! Shutting down suite.")
                    all_alive = False
                    stop_event.set()
                    break

            if not all_alive:
                break

            time.sleep(1)

    except Exception as e:
        logger.error(f"Runtime error: {e}")
    finally:
        logger.info("Shutting down services...")
        # Stop in reverse order (Processor first, then Scout)
        # Actually better to stop Scout first (stop incoming) then Processor
        # usage logic implies: scout produces -> queue -> processor.
        # stopping scout stops new data.
        for svc in services: # Scout is first in list
            svc.stop()

        # Cleanup interface
        cleanup_interface()  # Uses module-level _active_interface

        logger.info("Shutdown complete.")

if __name__ == "__main__":
    main()
