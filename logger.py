"""
WiFiWizard Phase 1 - Event Logger

Structured event logging to file for scout-dwell events.
"""

import json
import logging
import time
from datetime import datetime
from threading import Lock
from typing import Any

from config import ScoutConfig
from log_config import build_rotating_handler
from parser import ParsedFrame

logger = logging.getLogger(__name__)


class EventLogger:
    """
    Event logger for scout-dwell mode.

    Logs events to a structured file in JSON-lines format.
    Events include: new SSIDs, deauths, mode switches, telemetry.
    """

    def __init__(self, config: ScoutConfig, emit_startup: bool = True, startup_ts: float | None = None):
        self.config = config
        self._lock = Lock()
        self._event_count = 0

        # Ensure log file parent exists
        config.events_log.parent.mkdir(parents=True, exist_ok=True)

        # Dedicated logger for JSONL events with rotation
        self._logger = logging.getLogger("wicap.events")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        for handler in list(self._logger.handlers):
            self._logger.removeHandler(handler)
        self._handler = build_rotating_handler(config.events_log)
        self._logger.addHandler(self._handler)

        if emit_startup:
            self.log_startup(timestamp=startup_ts)

    def _log_event(self, event_type: str, data: dict[str, Any], timestamp: float | None = None) -> None:
        """Write an event to the log file."""
        ts = timestamp if timestamp is not None else time.time()
        dt = datetime.utcfromtimestamp(ts)

        event = {
            'ts': dt.isoformat() + 'Z',
            'epoch': ts,
            'type': event_type,
            **data
        }

        with self._lock:
            try:
                self._logger.info(json.dumps(event))
                self._event_count += 1
            except Exception as e:
                logger.error(f"Failed to write event: {e}")

    def log_startup(self, timestamp: float | None = None) -> None:
        """Log startup with optional timestamp override."""
        self._log_event('startup', {'version': '0.1.0'}, timestamp=timestamp)

    def log_new_ssid(self, frame: ParsedFrame, is_hidden: bool = False, timestamp: float | None = None) -> None:
        """Log a new SSID discovery."""
        self._log_event('new_ssid', {
            'ssid': frame.ssid or '<hidden>',
            'bssid': frame.bssid,
            'channel': frame.channel,
            'rssi': frame.rssi,
            'hidden': is_hidden,
            'security': {
                'open': frame.security.is_open,
                'wpa': frame.security.has_wpa,
                'wpa2': frame.security.has_wpa2,
                'wpa3': frame.security.has_wpa3,
                'cipher': frame.security.cipher,
                'akm': frame.security.akm,
            }
        }, timestamp=timestamp)

    def log_new_bssid(self, frame: ParsedFrame, timestamp: float | None = None) -> None:
        """Log a new BSSID discovery."""
        self._log_event('new_bssid', {
            'bssid': frame.bssid,
            'channel': frame.channel,
            'rssi': frame.rssi,
            'ssid': frame.ssid,
        }, timestamp=timestamp)

    def log_probe_request(self, frame: ParsedFrame, timestamp: float | None = None) -> None:
        """Log a directed probe request."""
        self._log_event('probe_request', {
            'src': frame.src_mac,
            'ssid': frame.ssid,
            'channel': frame.channel,
            'rssi': frame.rssi,
            'broadcast': frame.probe_is_broadcast,
            'ie_count': len(frame.ie_tags),
        }, timestamp=timestamp)

    def log_deauth(self, frame: ParsedFrame, is_spike: bool = False, timestamp: float | None = None) -> None:
        """Log a deauth/disassoc frame."""
        self._log_event('deauth', {
            'bssid': frame.bssid,
            'src': frame.src_mac,
            'dst': frame.dst_mac,
            'channel': frame.channel,
            'reason': frame.reason_code,
            'spike': is_spike,
        }, timestamp=timestamp)

    def log_open_network(self, frame: ParsedFrame, timestamp: float | None = None) -> None:
        """Log an open (unencrypted) network."""
        self._log_event('open_network', {
            'ssid': frame.ssid,
            'bssid': frame.bssid,
            'channel': frame.channel,
            'rssi': frame.rssi,
        }, timestamp=timestamp)

    def log_mode_switch(self, mode: str, channel: int, reason: str, score: int = 0, timestamp: float | None = None) -> None:
        """Log a mode switch (scout -> dwell or vice versa)."""
        self._log_event('mode_switch', {
            'mode': mode,
            'channel': channel,
            'reason': reason,
            'score': score,
        }, timestamp=timestamp)

    def log_dwell_summary(
        self,
        channel: int,
        duration_sec: float,
        frame_count: int,
        encrypted_streams: int = 0,
        telemetry: dict | None = None,
        pcap_file: str | None = None,
        timestamp: float | None = None
    ) -> None:
        """Log summary after dwell mode completes."""
        data = {
            'channel': channel,
            'duration_sec': round(duration_sec, 1),
            'frame_count': frame_count,
            'encrypted_streams': encrypted_streams,
            'telemetry': telemetry or {},
        }
        if pcap_file:
            data['pcap_file'] = pcap_file
        self._log_event('dwell_summary', data, timestamp=timestamp)

    def log_encrypted_stream(
        self,
        bssid: str,
        channel: int,
        avg_packet_size: int,
        packets_per_sec: float,
        stream_type: str = 'unknown',
        timestamp: float | None = None
    ) -> None:
        """Log detection of encrypted stream during dwell."""
        self._log_event('encrypted_stream', {
            'bssid': bssid,
            'channel': channel,
            'avg_pkt_size': avg_packet_size,
            'pkt_rate': round(packets_per_sec, 1),
            'type_guess': stream_type,
        }, timestamp=timestamp)

    def log_telemetry(self, channel: int, stats: dict[str, Any]) -> None:
        """Log periodic telemetry stats."""
        self._log_event('telemetry', {
            'channel': channel,
            **stats
        })

    def log_error(self, error: str, context: dict | None = None) -> None:
        """Log an error event."""
        self._log_event('error', {
            'error': error,
            'context': context or {},
        })

    def log_shutdown(self, stats: dict[str, Any], timestamp: float | None = None) -> None:
        """Log shutdown with final stats."""
        self._log_event('shutdown', stats, timestamp=timestamp)

    def close(self) -> None:
        """Close the log file."""
        with self._lock:
            try:
                self._handler.close()
            except Exception:
                pass

    @property
    def event_count(self) -> int:
        """Total events logged."""
        return self._event_count
