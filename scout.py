"""
WiFiWizard Phase 3 - Scout Main Module

Single-process scout with integrated dwell capture mode.
Uses scapy for live capture with BPF filters.

Supports:
- start: Begin scout-dwell loop (with pidfile)
- stop: Gracefully stop via SIGTERM
"""

import json
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from config import DEFAULT_INTERFACE, ScoutConfig, get_scout_config
from event_queue import EventQueueWriter, RemoteEventQueueWriter
from logger import EventLogger
from parser import FrameParser, ParsedFrame
from scorer import RuleScorer, ScoreResult

# Phase 2: Import refactored components
# Try absolute import first, fall back to relative if src/ not in path
try:
    from src.wicap.core.capture.backends.factory import get_capture_backend
    from src.wicap.core.capture.bluetooth_backend import BluetoothCaptureBackend
    from src.wicap.core.capture.channel_hopper import ChannelHopper, ChannelInfo
    from src.wicap.core.capture.interface import CaptureInterface
except ImportError:
    # Fallback: ensure repo root is on sys.path so `src` namespace is importable.
    repo_root = Path(__file__).resolve().parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from src.wicap.core.capture.backends.factory import get_capture_backend
    from src.wicap.core.capture.bluetooth_backend import BluetoothCaptureBackend
    from src.wicap.core.capture.channel_hopper import ChannelHopper, ChannelInfo
    from src.wicap.core.capture.interface import CaptureInterface

try:
    from nexus.intel import DeviceFingerprinter
    from nexus.intel.identity_lattice import IdentityLattice
    from nexus.intel.network_baseline import load_network_baseline
    from nexus.intel.wids import WIDSEngine
except ImportError:
    DeviceFingerprinter = None
    IdentityLattice = None
    WIDSEngine = None
    load_network_baseline = None


# Configure logging
logger = logging.getLogger('wicap.scout')

# Phase 2: Capture backends moved to src.wicap.core.capture.backends
# Imported above from new modules


class PidFile:
    """PID file manager with safety validation."""

    def __init__(self, path: Path):
        self.path = path

    def is_running(self) -> bool:
        """Check if the specific process described in pidfile is running."""
        if not self.path.exists():
            return False

        try:
            data = json.loads(self.path.read_text())
            pid = data['pid']

            # 1. Check existence
            os.kill(pid, 0)

            # 2. Check identity (cmdline contains 'scout.py' or similar)
            # This prevents killing a random reuse PID
            try:
                proc_cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b'\0', b' ').decode()
                # Basic check: if our script name in their cmdline
                if 'scout.py' not in proc_cmdline and 'wicap' not in proc_cmdline:
                     return False

                # 3. Check start time (prevent PID reuse race)
                # stored_start = data.get('start_time')
                # proc_start = os.stat(f"/proc/{pid}").st_ctime
                # if abs(stored_start - proc_start) > 2.0: return False

            except (FileNotFoundError, PermissionError):
                return False

            return True
        except (ValueError, json.JSONDecodeError, KeyError, ProcessLookupError, PermissionError):
            return False

    def get_pid(self) -> int | None:
        """Get the stored PID if valid."""
        if not self.is_running():
            return None
        try:
            return json.loads(self.path.read_text())['pid']
        except (ValueError, json.JSONDecodeError, KeyError, ProcessLookupError, PermissionError, OSError):
            return None

    def write(self) -> None:
        """Write current process info to file."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        info = {
            'pid': os.getpid(),
            'cmdline': sys.argv,
            'start_time': time.time()
        }
        self.path.write_text(json.dumps(info))

    def remove(self) -> None:
        """Remove the PID file."""
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class Scout:
    """
    Main scout-dwell process.

    Operates in two modes:
    1. SCOUT: Hops channels quickly, captures management frames only
    2. DWELL: Stays on one channel, captures all frames, writes PCAP

    Switches to dwell when channel score exceeds threshold.
    """

    # Mode constants
    MODE_SCOUT = 'scout'
    MODE_DWELL = 'dwell'

    # BPF filters (note: 'wlan' filters may not work on all systems)
    # If capture fails, try without filter
    FILTER_SCOUT = ''  # No filter - capture all, parse management frames
    FILTER_DWELL = ''  # No filter - capture all frames in monitor mode

    def __init__(self, config: ScoutConfig | None = None):
        self.config = config or get_scout_config()
        self.sensor_id = self.config.sensor_id

        self.parser = FrameParser()
        self.scorer = RuleScorer(self.config)
        self.event_logger = EventLogger(self.config, emit_startup=False)
        if self.config.sensor_hub_host:
            self.event_queue = RemoteEventQueueWriter(
                self.config,
                hub_host=self.config.sensor_hub_host,
                hub_port=self.config.sensor_hub_port,
                auth_token=self.config.sensor_auth_token,
                protocol=self.config.sensor_protocol,
                tls_verify=self.config.sensor_tls_verify,
                sensor_name=self.config.sensor_name,
                location=self.config.sensor_location,
                ws_path=self.config.sensor_ws_path,
            )
            logger.info("Remote sensor hub enabled for event streaming.")
        else:
            self.event_queue = EventQueueWriter(self.config)  # Phase 1.5: durable queue
        self.pidfile = PidFile(self.config.pidfile)
        self._capture_backend: CaptureInterface | None = None
        self._bt_backend: BluetoothCaptureBackend | None = None

        self.fingerprinter = DeviceFingerprinter() if DeviceFingerprinter else None
        self.identity_lattice = IdentityLattice() if IdentityLattice else None
        baseline_snapshot = None
        if WIDSEngine and load_network_baseline is not None:
            baseline_enabled = os.getenv("WICAP_NETWORK_BASELINE_ENABLED")
            if baseline_enabled is None:
                baseline_snapshot = load_network_baseline()
            elif baseline_enabled.lower() in ("1", "true", "yes", "on"):
                baseline_snapshot = load_network_baseline()
        self.wids_engine = (
            WIDSEngine(baseline_snapshot=baseline_snapshot) if WIDSEngine else None
        )

        self._mode = self.MODE_SCOUT

        # Phase 2: Use ChannelHopper for channel management
        self.channel_hopper = ChannelHopper(
            channels=self.config.channels or [],
            priority_channels=self.config.priority_channels,
            interface=self.config.interface
        )
        # Exposure for testing and convenience
        self.hopper = self.channel_hopper

        # Legacy support for _current_channel and _current_channel_obj
        self._current_channel = 1
        self._current_channel_obj = None

        self._running = False
        self._current_time = time.time()
        self._is_replay = False
        self._replay_packets_seen = False

        # Dwell state
        self._dwell_start: float | None = None
        self._dwell_frame_count = 0
        self._dwell_pcap_proc: subprocess.Popen | None = None
        self._dwell_pcap_path: Path | None = None

        # Telemetry during dwell
        self._dwell_telemetry: dict = {}
        self._encrypted_streams: dict[str, dict] = {}  # {bssid: {count, total_size, first_seen}}

        # Statistics
        self._stats = {
            'start_time': 0,
            'total_frames': 0,
            'scout_frames': 0,
            'dwell_frames': 0,
            'dwell_count': 0,
            'channel_hops': 0,
        }

        # Neuro-Adaptive Governor State (Phase 1)
        # {freq_mhz: {'hits': int, 'visits': int, 'last_visit': float, 'avg_yield': float}}
        self.channel_reputation: dict[int, dict] = {}

    def start(self) -> None:
        """Start the scout-dwell loop."""
        # Check if already running
        if self.pidfile.is_running():
            existing_pid = self.pidfile.get_pid()
            logger.error(f"Scout already running (PID {existing_pid}). Use 'stop' first.")
            sys.exit(1)

        # Write PID file
        self.pidfile.write()

        logger.info(f"Starting scout on interface {self.config.interface}")
        logger.info(f"Channels: {self.config.channels}")
        logger.info(f"Dwell threshold: {self.config.dwell_threshold}, duration: {self.config.dwell_duration_sec}s")
        logger.info(f"Captures dir: {self.config.captures_dir}")
        logger.info(f"PID file: {self.config.pidfile}")

        self._running = True
        self._current_time = time.time()
        self._stats['start_time'] = self._current_time
        self.event_logger.log_startup(timestamp=self._current_time)

        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        try:
            self._run_loop()
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        finally:
            self._shutdown()

    def _shutdown(self):
        """Clean shutdown of all backends."""
        if self._capture_backend:
            try:
                self._capture_backend.stop()
            except Exception as e:
                logger.error(f"Error stopping Wi-Fi backend: {e}")

        if self._bt_backend:
            try:
                self._bt_backend.stop_capture()
            except Exception as e:
                logger.error(f"Error stopping BT backend: {e}")

        self.pidfile.remove()
        self._running = False

    def stop(self) -> bool:
        """
        Stop a running scout process.

        Returns True if stopped successfully, False otherwise.
        """
        if not self.pidfile.is_running():
            logger.info("Scout is not running")
            self.pidfile.remove()  # Clean up stale pidfile
            return True

        pid = self.pidfile.get_pid()
        logger.info(f"Sending SIGTERM to scout process (PID {pid})")

        try:
            os.kill(pid, signal.SIGTERM)

            # Wait for process to exit
            for _ in range(10):  # Wait up to 5 seconds
                time.sleep(0.5)
                try:
                    os.kill(pid, 0)  # Check if still running
                except ProcessLookupError:
                    logger.info("Scout stopped successfully")
                    self.pidfile.remove()
                    return True

            # Still running, try SIGKILL
            logger.warning("Scout did not stop gracefully, sending SIGKILL")
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)
            self.pidfile.remove()
            return True

        except ProcessLookupError:
            logger.info("Scout process already terminated")
            self.pidfile.remove()
            return True
        except PermissionError:
            logger.error(f"Permission denied to stop process {pid}")
            return False

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}")
        self._running = False

    def _run_loop(self) -> None:
        """Main scout-dwell loop."""
        self._capture_backend = get_capture_backend()
        backend_name = self._capture_backend.__class__.__name__
        logger.info(f"Capture backend: {backend_name}")
        try:
            self._capture_backend.start(self.config.interface)
        except Exception as exc:
            logger.error(f"Capture backend init failed: {exc}")
            return

        # Initialize Bluetooth Backend if enabled
        if self.config.bt_enabled:
            try:
                self._bt_backend = BluetoothCaptureBackend(
                    interface=self.config.bt_interface,
                    captures_dir=self.config.bt_capture_dir,
                    extcap_path=self.config.bt_extcap_dir
                )
                self._bt_backend.start_capture(callback=self._process_bt_event)
            except Exception as e:
                logger.error(f"Failed to start Bluetooth backend: {e}")
                # Don't crash main loop if BT fails, just log it


        while self._running:
            self._current_time = time.time()

            if self._mode == self.MODE_SCOUT:
                self._run_scout_cycle()
            else:
                self._run_dwell_cycle()

            # Periodically check BT health (every ~5s)
            if self._bt_backend and int(self._current_time) % 5 == 0:
                self._bt_backend.check_health()

    def _calculate_dynamic_dwell(self, channel: int, freq: int = None) -> float:
        """
        Phase 2: Elastic Dwell
        Calculate dwell time based on channel reputation (ROI).
        Uses freq if available for uniqueness, otherwise channel.
        """
        key = freq if freq else channel
        rep = self.channel_reputation.get(key, {})
        avg_yield = rep.get('avg_yield', 0.0)

        # Base config (default 150ms usually)
        base_dwell = self.config.scout_dwell_ms / 1000.0

        # 1. Silence is Expensive: Fast skip for dead channels
        if avg_yield < 0.1 and rep.get('visits', 0) > 5:
            return max(0.050, base_dwell * 0.3) # Min 50ms or 30% of base

        # 2. Action is Valuable: Dilate time for active channels
        # If yield is high (e.g. > 10 pps), extend up to 1.0s or 5x base
        multiplier = 1.0 + (avg_yield / 20.0) # 20pps = 2x dwell
        return min(1.0, base_dwell * multiplier)

    def _run_scout_cycle(self) -> None:
        """Run one scout cycle on current channel."""
        # Phase 2: Use ChannelHopper
        chan_info = self.channel_hopper.get_next_channel()
        self.channel_hopper.set_channel(chan_info)

        # Update legacy state for compatibility
        self._current_channel = chan_info.channel
        self._current_channel_obj = {
            'channel': chan_info.channel,
            'freq': chan_info.freq,
            'band': chan_info.band
        }

        channel = chan_info.channel
        freq = chan_info.freq
        key = freq if freq else channel

        # Update stats from channel hopper
        hopper_stats = self.channel_hopper.stats
        self._stats['channel_hops'] = hopper_stats.get('channel_hops', 0)

        # Capture for scout_dwell_ms
        # Neuro-Adaptive Governor (Phase 2): Elastic Time
        duration = self._calculate_dynamic_dwell(channel, freq=freq)
        if hasattr(self, 'channel_reputation') and key in self.channel_reputation:
             # Reduce noise: only log if we deviated from base or have history
             logger.debug(f"🧠 Governor: Ch{channel} ({freq}MHz) -> {duration*1000:.0f}ms (Avg Yield: {self.channel_reputation[key].get('avg_yield',0):.2f})")

        try:
            if not self._capture_backend:
                raise RuntimeError("Capture backend unavailable")

            # Track start time and frame count for yield calculation
            start_frames = self._stats['scout_frames']
            start_time = time.time()

            self._capture_backend.capture(duration, self._process_scout_bytes, bpf_filter=self.FILTER_SCOUT)

            # Phase 1: Update Channel Reputation
            frames_captured = self._stats['scout_frames'] - start_frames
            actual_duration = time.time() - start_time
            yield_rate = frames_captured / max(0.001, actual_duration)

            if key not in self.channel_reputation:
                self.channel_reputation[key] = {'hits': 0, 'visits': 0, 'last_visit': 0, 'avg_yield': 0.0}

            rep = self.channel_reputation[key]
            rep['visits'] += 1
            rep['last_visit'] = time.time()
            rep['hits'] += frames_captured
            # Exponential moving average for yield (alpha=0.3)
            rep['avg_yield'] = (0.7 * rep['avg_yield']) + (0.3 * yield_rate)

            logger.debug(f"Channel {channel} yield: {yield_rate:.2f} pps (Avg: {rep['avg_yield']:.2f})")

            # Always emit a heartbeat pulse for the UI waterfall
            # This ensures the graph advances even if no packets are seen
            self.event_queue.write_event(
                event_type='telemetry_pulse',
                channel=self._current_channel,
                score=0,
                dwell_triggered=False,
                bssid=None,
                ssid=None,
                sa=None,
                da=None,
                rssi_dbm=None,
                timestamp=time.time(),
                fingerprint=None,
                device_identity_id=None,
                band=self._current_channel_obj.get('band'),
                freq=self._current_channel_obj.get('freq'),
            )

        except Exception as e:
            logger.error(f"Scout capture error: {e}")
            time.sleep(0.5)
            return

        # Check if we should switch to dwell
        if self.scorer.should_dwell(channel):
            score = self.scorer.get_channel_score(channel)
            summary = self.scorer.get_score_summary(channel)

            logger.info(f"🎯 Channel {channel} score {score} >= threshold, entering DWELL mode")
            logger.info(f"   Triggers: {summary.get('triggers', [])}")

            self.event_logger.log_mode_switch(
                self.MODE_DWELL, channel,
                reason=', '.join(summary.get('triggers', [])[-3:]),
                score=score,
                timestamp=self._current_time
            )

            self._enter_dwell_mode(channel)

    def _run_dwell_cycle(self) -> None:
        """Run dwell mode capture on current channel."""
        elapsed = self._current_time - self._dwell_start

        if elapsed >= self.config.dwell_duration_sec or not self._running:
            self._exit_dwell_mode()
            return

        # Capture in smaller chunks
        remaining = self.config.dwell_duration_sec - elapsed
        duration = min(2.0, remaining)


        try:
            if not self._capture_backend:
                raise RuntimeError("Capture backend unavailable")
            self._capture_backend.capture(duration, self._process_dwell_bytes, bpf_filter=self.FILTER_DWELL)
        except Exception as e:
            logger.error(f"Dwell capture error: {e}")

    def replay_file(
        self,
        pcap_path: Path,
        force_channel: int | None = None,
        run_id: str | None = None,
    ) -> None:
        """Replay a PCAP file through the scout pipeline."""
        if not pcap_path.exists():
            logger.error(f"PCAP file not found: {pcap_path}")
            return

        import hashlib
        if not run_id:
            hasher = hashlib.sha256()
            try:
                with open(pcap_path, "rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        hasher.update(chunk)
                run_hash = hasher.hexdigest()[:8]
            except Exception as exc:
                logger.warning(f"Replay hash failed, falling back to path hash: {exc}")
                run_hash = hashlib.sha256(str(pcap_path.resolve()).encode()).hexdigest()[:8]
            run_id = f"replay-{run_hash}"

        # Channel inference
        if force_channel:
            self._current_channel = force_channel
            logger.info(f"Replay forcing channel {force_channel}")
        else:
            import re
            match = re.search(r'_ch(\d+)', pcap_path.name)
            if match:
                self._current_channel = int(match.group(1))
                logger.info(f"Replay inferred channel {self._current_channel} from filename")

        logger.info(f"Replaying PCAP: {pcap_path} (run_id={run_id})")
        self._running = True
        self._is_replay = True
        self._replay_packets_seen = False
        self._stats['start_time'] = 0.0  # Set on first packet for determinism

        # Reset scorer state
        self.scorer = RuleScorer(self.config)
        # Reset queue with stable ID
        self.event_queue.close()
        self.event_queue = EventQueueWriter(self.config, run_id=run_id)
        startup_logged = False

        try:
            from scapy.all import PcapReader

            with PcapReader(str(pcap_path)) as pcap_reader:
                for pkt in pcap_reader:
                    if not self._running:
                        break

                    # Update current time to packet time
                    try:
                        self._current_time = float(pkt.time)
                    except (TypeError, ValueError, AttributeError):
                        continue

                    if not startup_logged:
                        self.event_logger.log_startup(timestamp=self._current_time)
                        self._stats['start_time'] = self._current_time
                        self._replay_packets_seen = True
                        startup_logged = True

                    if self._mode == self.MODE_SCOUT:
                        self._process_scout_packet(pkt, timestamp=self._current_time)
                    else:
                        self._process_dwell_packet(pkt, timestamp=self._current_time)

                        elapsed = self._current_time - self._dwell_start
                        if elapsed >= self.config.dwell_duration_sec:
                            self._exit_dwell_mode()

            # Ensure we close out any active dwell at EOF
            if self._mode == self.MODE_DWELL:
                self._exit_dwell_mode()

        except Exception as e:
            logger.error(f"Replay error: {e}")
        finally:
            self._shutdown()

    def _process_scout_bytes(self, raw_bytes: bytes, timestamp: float | None = None) -> None:
        """Process a raw frame during scout mode."""
        ts = timestamp if timestamp is not None else self._current_time
        frame = self.parser.parse(raw_bytes, ts, self._current_channel)

        if not frame:
            return

        # Update channel from frame (crucial for replay where channel hopping isn't active)
        if self._is_replay and frame.channel:
            self._current_channel = frame.channel

        self._stats['total_frames'] += 1
        self._stats['scout_frames'] += 1

        # Score the frame - returns structured result
        # Note: Scorer uses frame.timestamp (set from ts above)
        result: ScoreResult = self.scorer.score_frame(frame)

        # Check if this score triggers dwell
        dwell_triggered = self.scorer.should_dwell(self._current_channel, current_time=ts)


        # -------------------------------------------------------------------------
        # Identity Intelligence: Capability Fingerprinting
        # -------------------------------------------------------------------------
        fingerprint_data = None
        if self.fingerprinter and frame.is_assoc_request:
            try:
                # We need to re-inflate Scapy packet to use the fingerprinter
                # This is expensive, so we ONLY do it for Association Requests (rare)
                from scapy.all import RadioTap
                from scapy.layers.dot11 import Dot11

                # raw_bytes usually includes RadioTap header
                pkt = RadioTap(raw_bytes)
                if not pkt.haslayer(Dot11):
                    # Fallback if no radiotap
                    pkt = Dot11(raw_bytes)

                sig = self.fingerprinter.process_packet(pkt)
                if sig:
                    fingerprint_data = {
                        'hash': sig.hash,
                        'raw': sig.raw_string,
                        'is_wifi6': sig.he_caps is not None
                    }
                    logger.info(f"Adding fingerprint for {frame.src_mac}: {sig.hash}")
            except Exception as e:
                logger.error(f"Fingerprint failed: {e}")

        # -------------------------------------------------------------------------
        # Identity Lattice: Track device across MAC changes
        # -------------------------------------------------------------------------
        device_identity_id = None
        if self.identity_lattice and frame.src_mac:
            fingerprint_hash = fingerprint_data.get('hash') if fingerprint_data else None
            identity = self.identity_lattice.observe(
                mac=frame.src_mac,
                fingerprint_hash=fingerprint_hash,
                rssi=frame.rssi,
                timestamp=ts,
                ssid=frame.ssid,
                channel=self._current_channel,
                band=self._current_channel_obj.get('band') if self._current_channel_obj else None,
                freq=self._current_channel_obj.get('freq') if self._current_channel_obj else None,
                is_wifi6=fingerprint_data.get('is_wifi6', False) if fingerprint_data else False,
            )
            device_identity_id = identity.id

        if result.points > 0 or fingerprint_data:
            event_type = self._determine_event_type(result, frame)
            # If we have a fingerprint but low score, force event type 'association'
            if fingerprint_data and result.points == 0:
                event_type = 'association'

            self.event_queue.write_event(
                event_type=event_type,
                channel=self._current_channel,
                band=self._current_channel_obj.get('band') if self._current_channel_obj else None,
                freq=self._current_channel_obj.get('freq') if self._current_channel_obj else None,
                score=result.points,
                dwell_triggered=dwell_triggered,
                bssid=frame.bssid,
                ssid=frame.ssid,
                sa=frame.src_mac,
                da=frame.dst_mac,
                rssi_dbm=frame.rssi,
                seq_num=frame.seq_num,
                beacon_interval=frame.beacon_interval,
                assoc_request=frame.is_assoc_request,
                frame_type=frame.frame_type,
                frame_subtype=frame.frame_subtype,
                timestamp=ts,
                fingerprint=fingerprint_data,
                device_identity_id=device_identity_id,
            )

        # -------------------------------------------------------------------------
        # WIDS Engine: Check for intrusion/attack patterns
        # -------------------------------------------------------------------------
        if self.wids_engine:
            wids_alert = self.wids_engine.process_frame(frame)
            if wids_alert:
                # Write alert as a special event
                self.event_queue.write_event(
                    event_type=f"wids_{wids_alert.alert_type}",
                    channel=wids_alert.channel or self._current_channel,
                    band=self._current_channel_obj.get('band') if self._current_channel_obj else None,
                    score=wids_alert.severity * 10,  # Convert severity to score
                    dwell_triggered=True,  # WIDS alerts should trigger dwell
                    bssid=wids_alert.bssid,
                    ssid=wids_alert.ssid,
                    sa=wids_alert.source_mac,
                    da=wids_alert.target_mac,
                    rssi_dbm=None,
                    timestamp=wids_alert.timestamp,
                    alert={
                        "title": wids_alert.title,
                        "description": wids_alert.description,
                        "event_count": wids_alert.event_count,
                        "severity": wids_alert.severity,
                    },
                )

        # Log events based on score result (no double-counting)
        if result.is_new_ssid:
            self.event_logger.log_new_ssid(frame, is_hidden=result.is_hidden_ssid, timestamp=ts)
        elif result.is_hidden_ssid:
            self.event_logger.log_new_ssid(frame, is_hidden=True, timestamp=ts)

        if result.is_open_network:
            self.event_logger.log_open_network(frame, timestamp=ts)

        if result.is_probe_directed:
            self.event_logger.log_probe_request(frame, timestamp=ts)

        if frame.is_deauth or frame.is_disassoc:
            self.event_logger.log_deauth(frame, is_spike=result.is_deauth_spike, timestamp=ts)

    def _process_scout_packet(self, pkt, timestamp: float = None) -> None:
        """Process a packet during scout mode."""
        ts = timestamp if timestamp is not None else getattr(pkt, "time", None)
        try:
            ts = float(ts) if ts is not None else None
        except (TypeError, ValueError):
            ts = None
        self._process_scout_bytes(bytes(pkt), ts)

    def _determine_event_type(self, result: ScoreResult, frame: ParsedFrame) -> str:
        """Determine the primary event type for the queue."""
        # Priority order for event type determination
        if result.is_deauth_spike:
            return 'deauth_spike'
        if frame.is_deauth or frame.is_disassoc:
            return 'deauth'
        if result.is_open_network:
            return 'open_network'
        if result.is_hidden_ssid:
            return 'hidden_ssid'
        if result.is_new_ssid:
            return 'new_ssid'
        if result.is_new_bssid:
            return 'new_bssid'
        if result.is_probe_directed:
            return 'probe_directed'
        if result.is_strong_rssi:
            return 'strong_rssi'
        return 'scored_event'

    def _process_dwell_bytes(self, raw_bytes: bytes, timestamp: float | None = None) -> None:
        """Process a raw frame during dwell mode."""
        ts = timestamp if timestamp is not None else self._current_time
        frame = self.parser.parse(raw_bytes, ts, self._current_channel)

        if not frame:
            return

        self._stats['total_frames'] += 1
        self._stats['dwell_frames'] += 1
        self._dwell_frame_count += 1

        # Track encrypted streams
        if frame.is_encrypted and frame.bssid:
            if frame.bssid not in self._encrypted_streams:
                self._encrypted_streams[frame.bssid] = {
                    'count': 0,
                    'total_size': 0,
                    'first_seen': ts,
                }
            stream = self._encrypted_streams[frame.bssid]
            stream['count'] += 1
            stream['total_size'] += frame.frame_length

        # Update telemetry
        ftype = frame.frame_type
        self._dwell_telemetry[f'type_{ftype}'] = self._dwell_telemetry.get(f'type_{ftype}', 0) + 1

    def _process_dwell_packet(self, pkt, timestamp: float = None) -> None:
        """Process a packet during dwell mode."""
        ts = timestamp if timestamp is not None else getattr(pkt, "time", None)
        try:
            ts = float(ts) if ts is not None else None
        except (TypeError, ValueError):
            ts = None
        self._process_dwell_bytes(bytes(pkt), ts)

    def _enter_dwell_mode(self, channel: int) -> None:
        """Switch to dwell mode on specified channel."""
        self._mode = self.MODE_DWELL
        self._current_channel = channel
        self._dwell_start = self._current_time
        self._dwell_frame_count = 0
        self._dwell_telemetry.clear()
        self._encrypted_streams.clear()
        self._stats['dwell_count'] += 1

        # Start PCAP capture subprocess (one file per dwell, no rotation)
        if not self._is_replay:
            self._start_pcap_capture(channel)

        logger.info(f"📡 DWELL mode on channel {channel} for {self.config.dwell_duration_sec}s")

    def _exit_dwell_mode(self) -> None:
        """Exit dwell mode and resume scouting."""
        duration = self._current_time - self._dwell_start

        # Stop PCAP capture
        if not self._is_replay:
            self._stop_pcap_capture()

        # Log encrypted stream summaries
        for bssid, stream in self._encrypted_streams.items():
            if stream['count'] >= 10:
                elapsed = self._current_time - stream['first_seen']
                pkt_rate = stream['count'] / max(0.1, elapsed)
                avg_size = stream['total_size'] // stream['count']

                # Guess stream type by packet size
                stream_type = 'unknown'
                if avg_size > 1000:
                    stream_type = 'video'
                elif avg_size > 200:
                    stream_type = 'voip'
                elif avg_size < 100:
                    stream_type = 'control'

                self.event_logger.log_encrypted_stream(
                    bssid, self._current_channel,
                    avg_size, pkt_rate, stream_type,
                    timestamp=self._current_time
                )

        # Log dwell summary
        self.event_logger.log_dwell_summary(
            channel=self._current_channel,
            duration_sec=duration,
            frame_count=self._dwell_frame_count,
            encrypted_streams=len(self._encrypted_streams),
            telemetry=self._dwell_telemetry,
            pcap_file=str(self._dwell_pcap_path) if self._dwell_pcap_path else None,
            timestamp=self._current_time
        )

        # Reset channel score
        self.scorer.reset_channel(self._current_channel)

        # Resume scouting
        self._mode = self.MODE_SCOUT
        self.event_logger.log_mode_switch(
            self.MODE_SCOUT, self._current_channel,
            reason='dwell_complete',
            timestamp=self._current_time
        )

        logger.info(f"✅ DWELL complete: {self._dwell_frame_count} frames, {len(self._encrypted_streams)} encrypted streams")
        if self._dwell_pcap_path:
            logger.info(f"   PCAP: {self._dwell_pcap_path}")

    def _start_pcap_capture(self, channel: int) -> None:
        """Start PCAP capture subprocess during dwell (one file per dwell)."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._dwell_pcap_path = self.config.captures_dir / f"dwell_{timestamp}_ch{channel}.pcapng"

        try:
            # Use tcpdump for PCAP capture - simple mode, no rotation
            # No BPF filter - capture all frames in monitor mode
            cmd = [
                'tcpdump',
                '-i', self.config.interface,
                '-w', str(self._dwell_pcap_path),
                '-c', str(self.config.pcap_max_packets),  # Max packets
                # No filter - 'wlan' not supported on all systems
            ]

            self._dwell_pcap_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )

            # Verify startup
            time.sleep(0.1)
            if self._dwell_pcap_proc.poll() is not None:
                err = self._dwell_pcap_proc.stderr.read().decode()
                logger.error(f"tcpdump failed to start: {err}")
                self._dwell_pcap_proc = None
                self._dwell_pcap_path = None
                return

            logger.info(f"📝 PCAP capture started: {self._dwell_pcap_path}")

        except Exception as e:
            logger.error(f"Failed to start PCAP capture: {e}")
            self._dwell_pcap_proc = None
            self._dwell_pcap_path = None

    def _stop_pcap_capture(self) -> None:
        """Stop PCAP capture subprocess."""
        if self._dwell_pcap_proc:
            try:
                self._dwell_pcap_proc.terminate()
                self._dwell_pcap_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    self._dwell_pcap_proc.kill()
                    self._dwell_pcap_proc.wait(timeout=1)
                except Exception:
                    pass
            except Exception:
                pass
            self._dwell_pcap_proc = None

    def _get_next_channel(self) -> dict:
        """Get next channel from hopping sequence.

        DEPRECATED: Use channel_hopper.get_next_channel() instead.
        Kept for backward compatibility.
        """
        chan_info = self.channel_hopper.get_next_channel()
        return {
            'channel': chan_info.channel,
            'freq': chan_info.freq,
            'band': chan_info.band
        }

    def _set_channel(self, chan_data: dict) -> None:
        """Set the wireless interface to specified channel.

        DEPRECATED: Use channel_hopper.set_channel() instead.
        Kept for backward compatibility.
        """
        chan_info = ChannelInfo(
            channel=chan_data['channel'],
            freq=chan_data.get('freq', 0),
            band=chan_data.get('band', '2.4ghz')
        )
        self.channel_hopper.set_channel(chan_info)
        self._current_channel = chan_info.channel
        self._current_channel_obj = chan_data

    def _shutdown(self) -> None:
        """Clean shutdown."""
        logger.info("Shutting down scout...")

        # Stop any running PCAP capture
        self._stop_pcap_capture()
        if self._capture_backend:
            try:
                self._capture_backend.stop()
            except Exception as exc:
                logger.debug(f"Capture backend stop error: {exc}")

        # Log final stats
        log_shutdown = True
        shutdown_ts = None
        if self._is_replay:
            if self._replay_packets_seen and self._stats['start_time']:
                elapsed = max(0.0, self._current_time - self._stats['start_time'])
                shutdown_ts = self._current_time
            else:
                elapsed = 0.0
                log_shutdown = False
        else:
            elapsed = time.time() - self._stats['start_time']
        final_stats = {
            'runtime_sec': round(elapsed, 1),
            'total_frames': self._stats['total_frames'],
            'scout_frames': self._stats['scout_frames'],
            'dwell_frames': self._stats['dwell_frames'],
            'dwell_count': self._stats['dwell_count'],
            'channel_hops': self.channel_hopper.stats.get('channel_hops', 0),
            'unique_ssids': self.scorer.seen_ssid_count,
            'unique_bssids': self.scorer.seen_bssid_count,
        }

        if log_shutdown:
            self.event_logger.log_shutdown(final_stats, timestamp=shutdown_ts)
        self.event_logger.close()

        # Phase 1.5: Close event queue
        self.event_queue.close()

        # Remove PID file
        self.pidfile.remove()

        logger.info(f"Scout shutdown complete. Stats: {final_stats}")

    def _process_bt_event(self, event: dict) -> None:
        """Callback for Bluetooth events."""
        if not event:
            return

        bt_event = dict(event)
        if "sensor_id" not in bt_event and self.sensor_id:
            bt_event["sensor_id"] = self.sensor_id
        if "run_id" not in bt_event:
            bt_event["run_id"] = getattr(self.event_queue, "run_id", None)
        if "ts_epoch" not in bt_event:
            ts = bt_event.pop("timestamp", None)
            bt_event["ts_epoch"] = ts if ts is not None else time.time()

        try:
            self.event_queue.write_event_dict(bt_event)
        except Exception as e:
            logger.error(f"Error processing BT event: {e}")

    @property
    def stats(self) -> dict:
        """Get current statistics."""
        return {
            **self._stats,
            'mode': self._mode,
            'current_channel': self._current_channel,
            'scorer': self.scorer.stats,
        }


def start_scout(config: ScoutConfig | None = None) -> None:
    """Start the scout process."""
    scout = Scout(config)
    scout.start()


def stop_scout(config: ScoutConfig | None = None) -> bool:
    """Stop a running scout process."""
    config = config or get_scout_config()
    scout = Scout(config)
    return scout.stop()


def start_replay(
    config: ScoutConfig,
    pcap_path: Path,
    force_channel: int | None = None,
    run_id: str | None = None,
) -> None:
    """Start the scout in replay mode."""
    scout = Scout(config)
    scout.replay_file(pcap_path, force_channel=force_channel, run_id=run_id)


def main() -> None:
    """CLI entry point."""
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description='WiFiWizard Scout-Dwell Module')
    parser.add_argument('command', choices=['start', 'stop', 'status', 'replay'], help='Command to run')
    parser.add_argument('-i', '--interface', default=DEFAULT_INTERFACE, help='Wireless interface')
    parser.add_argument('-t', '--threshold', type=int, default=3, help='Dwell threshold')
    parser.add_argument('-d', '--dwell', type=int, default=30, help='Dwell duration (seconds)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--pcap', help='PCAP file for replay')
    parser.add_argument('--channel', type=int, help='Force channel for replay')
    parser.add_argument('--run-id', help='Override replay run_id (default: hash of file)')

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    config = get_scout_config()
    config.interface = args.interface
    config.dwell_threshold = args.threshold
    config.dwell_duration_sec = args.dwell

    if args.command == 'start':
        start_scout(config)

    elif args.command == 'stop':
        success = stop_scout(config)
        sys.exit(0 if success else 1)

    elif args.command == 'status':
        pidfile = PidFile(config.pidfile)
        if pidfile.is_running():
            pid = pidfile.get_pid()
            print(f"Scout is running (PID {pid})")
            print(f"  Events log: {config.events_log}")
            print(f"  Captures dir: {config.captures_dir}")
        else:
            print("Scout is not running")
            if config.pidfile.exists():
                print(f"  (stale pidfile: {config.pidfile})")

    elif args.command == 'replay':
        if not args.pcap:
            parser.error("Replay command requires --pcap argument")

        pcap_path = Path(args.pcap).resolve()
        start_replay(config, pcap_path, force_channel=args.channel, run_id=args.run_id)


if __name__ == '__main__':
    main()
