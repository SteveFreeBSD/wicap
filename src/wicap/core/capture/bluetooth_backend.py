"""
Bluetooth Capture Backend for WICAP.

Uses tshark/dumpcap to capture from nRF52840 dongles (via Nordic sniffer extcap).
Requires WIRESHARK_EXTCAP_DIR to be set to the location of the Nordic sniffer scripts.
"""

import grp
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path

try:
    from logger import get_logger
except ImportError:
    # Fallback if we are in a package context where logger is not at root
    import logging
    def get_logger(name): return logging.getLogger(name)

logger = get_logger(__name__)

class BluetoothCaptureBackend:
    _FIELD_CACHE: set[str] | None = None
    _RUNTIME_MODULES = {
        "serial": "pyserial",
        "psutil": "psutil",
    }

    def __init__(self, interface: str, captures_dir: Path, extcap_path: str = "tools/bluetooth/extcap"):
        self.interface = interface
        self.captures_dir = captures_dir
        self.extcap_path = os.path.abspath(extcap_path)
        self.process: subprocess.Popen | None = None
        self.current_file: Path | None = None
        self.parser = None
        self.callback = None
        self._reader_thread = None
        self._field_names: list[str] = []
        self._restart_backoff_sec = 5.0
        self._next_restart_ts = 0.0
        self._suspend_until_ts = 0.0
        self._last_suspend_reason: str | None = None

    def start_capture(self, output_filename: str = "bt_capture", callback=None):
        """
        Start a continuous Bluetooth capture.

        Args:
            output_filename: Base name for pcap file.
            callback: Function(event_dict) -> None. Called for each parsed event.
        """
        if self.process:
            logger.warning("BT capture already running.")
            return

        import threading

        from src.wicap.core.processing.ble_parser import BLEParser

        self.callback = callback
        if callback:
            self.parser = BLEParser()
            self._field_names = self._resolve_field_list()

        missing_modules = self._missing_runtime_modules()
        if missing_modules:
            missing_text = ", ".join(missing_modules)
            raise RuntimeError(
                f"Missing Bluetooth runtime dependencies: {missing_text}. "
                "Install requirements and rebuild the runtime image."
            )

        # Ensure extcap is discoverable by tshark (install symlink if needed)
        self._ensure_extcap_installed()

        # Resolve extcap interface name if a device path (or auto) was provided
        resolved = self._resolve_extcap_interface()
        if not resolved:
            raise RuntimeError(
                "No Nordic BLE extcap interface resolved. Verify dongle access and run tshark -D."
            )
        if resolved and resolved != self.interface:
            logger.info("Resolved BT interface %s -> %s", self.interface, resolved)
            self.interface = resolved

        timestamp = int(time.time())
        filename = f"{output_filename}_{timestamp}.pcapng"
        self.current_file = self.captures_dir / filename

        # Ensure capture dir exists and is writable for dumpcap
        self._ensure_capture_permissions()

        env = os.environ.copy()
        if self.extcap_path and os.path.isdir(self.extcap_path):
            env.setdefault("WIRESHARK_EXTCAP_DIR", self.extcap_path)
        else:
            logger.warning("BT extcap path not found: %s", self.extcap_path)

        cmd = self._build_cmd()

        logger.info(f"Starting BT capture on {self.interface} -> {self.current_file}")

        try:
            stdout_target = subprocess.PIPE if callback else subprocess.DEVNULL
            stderr_target = subprocess.PIPE
            self.process = subprocess.Popen(
                cmd,
                env=env,
                stdout=stdout_target,
                stderr=stderr_target,
                preexec_fn=os.setsid,
                text=True
            )

            if callback:
                self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
                self._reader_thread.start()

            self._restart_backoff_sec = 5.0
            self._next_restart_ts = 0.0
            self._suspend_until_ts = 0.0
            self._last_suspend_reason = None

        except Exception as e:
            logger.error(f"Failed to start BT capture: {e}")
            raise

    def check_health(self) -> bool:
        """Check if process is running, restart if needed."""
        if self._suspend_until_ts and time.time() < self._suspend_until_ts:
            return False

        if not self.process:
            return False

        returncode = self.process.poll()
        if returncode is not None:
            # Capture any remaining output for diagnostics.
            stderr_out = ""
            stdout_out = ""
            try:
                if self.process.stderr:
                    stderr_out = self.process.stderr.read()
            except Exception:
                stderr_out = ""
            try:
                if self.process.stdout:
                    stdout_out = self.process.stdout.read()
            except Exception:
                stdout_out = ""

            diagnostics = self._clip_diagnostics(
                "\n".join(part for part in (stderr_out, stdout_out) if part)
            )
            if diagnostics:
                logger.warning("BT capture process died (code %s). output: %s", returncode, diagnostics)
            else:
                logger.warning("BT capture process died (code %s).", returncode)

            self.process = None
            fatal_reason = self._classify_fatal_startup_error(diagnostics)
            if fatal_reason:
                self._suspend_until_ts = time.time() + 180.0
                if fatal_reason != self._last_suspend_reason:
                    logger.error("Suspending BT capture restarts for 180s: %s", fatal_reason)
                    self._last_suspend_reason = fatal_reason
                return False

            now = time.time()
            if self._next_restart_ts and now < self._next_restart_ts:
                return False
            try:
                self.start_capture(callback=self.callback)
                return True
            except Exception as e:
                self._next_restart_ts = now + self._restart_backoff_sec
                self._restart_backoff_sec = min(self._restart_backoff_sec * 2.0, 60.0)
                logger.error(f"Failed to restart BT capture: {e}")
                return False
        return True

    @staticmethod
    def _module_available(module_name: str) -> bool:
        try:
            __import__(module_name)
            return True
        except Exception:
            return False

    @classmethod
    def _missing_runtime_modules(cls) -> list[str]:
        missing: list[str] = []
        for module_name, package_name in cls._RUNTIME_MODULES.items():
            if not cls._module_available(module_name):
                missing.append(package_name)
        return missing

    @staticmethod
    def _clip_diagnostics(text: str, max_chars: int = 1600) -> str:
        clean = (text or "").strip()
        if len(clean) <= max_chars:
            return clean
        return clean[:max_chars] + " ...<truncated>"

    @staticmethod
    def _classify_fatal_startup_error(stderr_text: str) -> str | None:
        text = (stderr_text or "").lower()
        if "pyserial not found" in text or "no module named 'serial'" in text:
            return "pyserial dependency is missing in the container runtime"
        if "no module named 'psutil'" in text:
            return "psutil dependency is missing in the container runtime"
        if "there is no device named" in text or "no such device exists" in text:
            return "configured BLE interface is not available to tshark/extcap"
        if "permission denied" in text and "/dev/tty" in text:
            return "BLE serial device permission denied"
        return None

    def _build_cmd(self) -> Iterable[str]:
        """Build tshark capture command."""
        cmd = [
            "tshark",
            "-l",
            "-n",
            "-i", self.interface,
            "-w", str(self.current_file),
        ]

        if self.callback:
            cmd.extend([
                "-T", "fields",
                "-E", "separator=|",
                "-E", "quote=d",
                "-E", "occurrence=f",
            ])
            for field_name in self._field_names:
                cmd.extend(["-e", field_name])

        return cmd

    def _ensure_capture_permissions(self) -> None:
        """Ensure capture directory is writable by dumpcap."""
        try:
            self.captures_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Failed to create BT capture dir %s: %s", self.captures_dir, exc)
            return

        # Try to grant wireshark group access; fallback to world-writable
        try:
            try:
                gid = grp.getgrnam("wireshark").gr_gid
                os.chown(self.captures_dir, -1, gid)
                os.chmod(self.captures_dir, 0o775)
            except KeyError:
                os.chmod(self.captures_dir, 0o777)
        except Exception as exc:
            logger.debug("BT capture dir permission adjust failed: %s", exc)

    def _resolve_extcap_interface(self) -> str:
        """
        Resolve a user-provided device path (or 'auto') into the extcap interface name.
        The Nordic extcap exposes interfaces like /dev/ttyACM0-None.
        """
        interface = (self.interface or "").strip()
        if not interface or interface.lower() == "auto":
            target_path = None
        else:
            if interface.startswith("/dev/"):
                # Treat extcap interfaces as /dev/ttyACM0-None or /dev/ttyUSB0-<suffix>
                base = os.path.basename(interface)
                if re.match(r"^tty(ACM|USB)\d+-", base):
                    return interface
                # Otherwise resolve symlink/device path (e.g., /dev/serial/by-id/...)
                target_path = os.path.realpath(interface)
            else:
                # Non-device name: pass through (might already be extcap name)
                return interface

        values = self._list_extcap_interfaces()

        if not values:
            if not interface or interface.lower() == "auto":
                return ""
            if target_path:
                return ""
            return interface

        if target_path:
            # Match by prefix (e.g., /dev/ttyACM0-None)
            for value in values:
                if value.startswith(target_path):
                    return value
                # Also match realpath of the value base (strip suffix after '-')
                base = value.split("-", 1)[0]
                if os.path.realpath(base) == target_path:
                    return value

        # Fallback to first extcap interface
        return values[0]

    def _list_extcap_interfaces(self) -> list[str]:
        """List extcap interfaces for Nordic BLE (preferred: tshark -D)."""
        values: list[str] = []

        # Prefer tshark -D to match actual interface names it understands
        try:
            result = subprocess.run(
                ["tshark", "-D"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.stdout:
                for line in result.stdout.splitlines():
                    if "nRF Sniffer for Bluetooth LE" not in line:
                        continue
                    match = re.search(r"^\s*\d+\.\s+([^\s]+)\s+\(nRF Sniffer for Bluetooth LE\)", line)
                    if match:
                        values.append(match.group(1))
        except Exception:
            pass

        if values:
            return values

        # Fallback: run extcap script directly
        extcap_script = Path(self.extcap_path) / "nrf_sniffer_ble.py"
        if not extcap_script.exists():
            return values

        try:
            result = subprocess.run(
                [sys.executable, str(extcap_script), "--extcap-interfaces"],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception:
            return values

        if result.stdout:
            for line in result.stdout.splitlines():
                match = re.search(r"interface \{value=([^}]+)\}", line)
                if match:
                    values.append(match.group(1))

        return values

    def _ensure_extcap_installed(self) -> None:
        """Ensure tshark can see the Nordic extcap script."""
        source = Path(self.extcap_path) / "nrf_sniffer_ble.py"
        if not source.exists():
            return

        # Candidate extcap dirs (tshark won't honor WIRESHARK_EXTCAP_DIR reliably)
        candidates = [
            os.getenv("WIRESHARK_EXTCAP_DIR"),
            "/usr/lib/x86_64-linux-gnu/wireshark/extcap",
            "/usr/lib/wireshark/extcap",
            "/usr/local/lib/wireshark/extcap",
            os.path.expanduser("~/.local/lib/wireshark/extcap"),
        ]

        for candidate in candidates:
            if not candidate:
                continue
            try:
                dest_dir = Path(candidate)
                if not dest_dir.exists():
                    continue
                dest = dest_dir / "nrf_sniffer_ble"
                if dest.exists():
                    return
                try:
                    dest.symlink_to(source)
                    logger.info("Installed BLE extcap at %s", dest)
                    return
                except Exception as exc:
                    logger.debug("Failed to install extcap in %s: %s", dest_dir, exc)
            except Exception:
                continue

    def _read_loop(self):
        """Read stdout line by line and parse."""
        if not self.process or not self.process.stdout:
            return

        try:
            for line in iter(self.process.stdout.readline, ''):
                if not line:
                    break
                if "|" not in line:
                    continue
                event = self.parser.parse_line(line, self._field_names)
                if event and self.callback:
                    try:
                        self.callback(event)
                    except Exception as e:
                        logger.error(f"BT Callback error: {e}")
        except Exception as e:
            logger.error(f"BT Reader loop error: {e}")

    def _resolve_field_list(self) -> list[str]:
        """Return the ordered tshark field list that exists in this environment."""
        available = self._get_available_fields()

        def use_field(name: str) -> bool:
            return not available or name in available

        rssi_field = "nordic_ble.rssi" if use_field("nordic_ble.rssi") else (
            "btle.rssi" if use_field("btle.rssi") else None
        )
        channel_field = "nordic_ble.channel" if use_field("nordic_ble.channel") else (
            "btle.channel" if use_field("btle.channel") else None
        )

        fields = [
            "frame.time_epoch",
            "btle.advertising_address",
            "btle.advertising_header.randomized_tx",
        ]
        if rssi_field:
            fields.append(rssi_field)
        if channel_field:
            fields.append(channel_field)
        fields.extend([
            "btle.advertising_header.pdu_type",
            "btle.access_address",
            "btle.initiator_address",
            "btle.initiator_address_resolved",
            "btcommon.eir_ad.entry.company_id",
            "btcommon.eir_ad.entry.device_name",
            "btcommon.eir_ad.entry.manufacturer_data",
            "btcommon.eir_ad.entry.uuid_16",
            "btcommon.eir_ad.entry.uuid_32",
            "btcommon.eir_ad.entry.uuid_128",
            "btcommon.eir_ad.entry.service_uuid",
            "btcommon.eir_ad.entry.service_uuid_16",
            "btcommon.eir_ad.entry.service_uuid_32",
            "btcommon.eir_ad.entry.service_uuid_128",
        ])

        if available:
            fields = [f for f in fields if f in available]

        return fields

    @classmethod
    def _get_available_fields(cls) -> set[str]:
        if cls._FIELD_CACHE is not None:
            return cls._FIELD_CACHE
        try:
            result = subprocess.run(
                ["tshark", "-G", "fields"],
                capture_output=True,
                text=True,
                check=False,
            )
            fields: set[str] = set()
            if result.stdout:
                for line in result.stdout.splitlines():
                    if not line or line.startswith("#"):
                        continue
                    # Format: F\t<desc>\t<field_name>\t<type>\t<protocol>...
                    if line.startswith("F\t"):
                        parts = line.split("\t")
                        if len(parts) > 2 and parts[2]:
                            fields.add(parts[2])
            cls._FIELD_CACHE = fields
            return fields
        except Exception:
            cls._FIELD_CACHE = set()
            return cls._FIELD_CACHE

    def stop_capture(self):
        """Stop the capture process."""
        if not self.process:
            return

        logger.info("Stopping BT capture...")
        try:
            # Send SIGTERM to the process group (tshark + dumpcap)
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("BT capture hung, killing force...")
            os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
        except Exception as e:
            logger.error(f"Error stopping BT capture: {e}")
        finally:
            self.process = None

    def is_running(self) -> bool:
        """Check if capture is running."""
        if self.process:
            return self.process.poll() is None
        return False
