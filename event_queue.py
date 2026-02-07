"""
WiFiWizard Phase 1.5 - Event Queue Writer

Append-only event queue for downstream processing.
Machine-consumed JSONL format with stable schema.
"""

import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from config import REDIS_QUEUE_KEY, ScoutConfig

logger = logging.getLogger(__name__)


def build_event_dict(
    run_id: str,
    event_type: str,
    channel: int,
    score: int,
    dwell_triggered: bool,
    bssid: str | None = None,
    ssid: str | None = None,
    sa: str | None = None,
    da: str | None = None,
    rssi_dbm: int | None = None,
    seq_num: int | None = None,
    beacon_interval: int | None = None,
    assoc_request: bool | None = None,
    frame_type: int | None = None,
    frame_subtype: int | None = None,
    fingerprint: dict[str, str] | None = None,
    device_identity_id: str | None = None,
    timestamp: float | None = None,
    band: str | None = None,
    freq: int | None = None,
    alert: dict[str, Any] | None = None,
    sensor_id: str | None = None,
) -> dict:
    """Build an event dict with a deterministic event_id."""
    ts_epoch = timestamp if timestamp is not None else time.time()
    event_content = {
        "run_id": run_id,
        "ts_epoch": ts_epoch,
        "event_type": event_type,
        "channel": channel,
        "band": band,
        "freq": freq,
        "score": score,
        "dwell_triggered": dwell_triggered,
        "keys": {
            "bssid": bssid,
            "ssid": ssid,
            "sa": sa,
            "da": da,
            "rssi_dbm": rssi_dbm,
        },
        "fingerprint": fingerprint,
        "device_identity_id": device_identity_id,
    }
    if sensor_id:
        event_content["sensor_id"] = sensor_id

    frame_meta = {
        "type": frame_type,
        "subtype": frame_subtype,
        "seq_num": seq_num,
        "beacon_interval": beacon_interval,
    }
    if assoc_request is True:
        frame_meta["assoc_request"] = True

    frame_meta_present = any(value is not None for value in frame_meta.values()) or assoc_request is True
    if frame_meta_present:
        event_content["frame"] = frame_meta
    if alert:
        event_content["alert"] = alert

    content_for_hash = json.dumps(event_content, sort_keys=True, separators=(',', ':'))
    event_id = hashlib.sha256(content_for_hash.encode()).hexdigest()
    return {"event_id": event_id, **event_content}


def ensure_event_id(event: dict) -> dict:
    """Ensure event dict includes event_id."""
    if event.get("event_id"):
        return event
    event_content = {key: value for key, value in event.items() if key != "event_id"}
    content_for_hash = json.dumps(event_content, sort_keys=True, separators=(',', ':'))
    event_id = hashlib.sha256(content_for_hash.encode()).hexdigest()
    return {"event_id": event_id, **event_content}


class EventQueueWriter:
    """
    Writes events to the durable event queue (event_queue.jsonl).

    This is separate from the human-readable events.log.
    Schema is stable and machine-consumed.
    Writes are fsync'd for crash-safety.
    Each event includes a deterministic event_id for SQL idempotency.
    """

    def __init__(self, config: ScoutConfig, run_id: str | None = None):
        """
        Initialize the event queue writer.

        Args:
            config: Scout configuration.
            run_id: Unique ID for this scout run. Generated if not provided.
        """
        self.config = config
        self.run_id = run_id or str(uuid.uuid4())
        self._lock = Lock()
        self._event_count = 0
        self._backpressure_bytes = 0
        self._backpressure_check_every = 25
        self._backpressure_last_log = 0.0
        self._backpressure_drop_count = 0

        # Redis Backend (optional)
        self.redis = None
        self.redis_queue_key = REDIS_QUEUE_KEY
        if getattr(config, "redis_url", None):
            try:
                import redis
                self.redis = redis.from_url(config.redis_url)
                logger.info(f"Connected to Redis Queue at {config.redis_url}")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}. Falling back to file.")

        # Ensure captures dir exists
        config.captures_dir.mkdir(parents=True, exist_ok=True)

        # Open queue file for appending (fallback or primary)
        self._queue_path = config.captures_dir / "event_queue.jsonl"
        self._queue_file = open(self._queue_path, 'a')

        logger.info(f"Event queue initialized: {self._queue_path} (run_id={self.run_id[:8]}...)")

    def _current_backlog_bytes(self) -> int:
        """Return total bytes across active and rotated queues."""
        if self.redis:
            # For Redis, approximate backlog based on queue length * avg event size (say 500 bytes)
            try:
                length = self.redis.llen(self.redis_queue_key)
                return length * 500
            except Exception:
                return 0

        total = 0
        for path in self._queue_path.parent.glob("event_queue*.jsonl"):
            try:
                total += path.stat().st_size
            except FileNotFoundError:
                continue
        return total

    def _backpressure_exceeded(self) -> bool:
        """Check if backlog exceeds configured threshold."""
        max_bytes = getattr(self.config, "queue_backpressure_max_bytes", 0)
        if max_bytes <= 0:
            return False
        if self._event_count % self._backpressure_check_every == 0:
            self._backpressure_bytes = self._current_backlog_bytes()
        return self._backpressure_bytes >= max_bytes

    def _handle_backpressure(self, event_type: str) -> bool:
        """Apply backpressure policy. Returns True if event should be dropped."""
        action = getattr(self.config, "queue_backpressure_action", "drop_pulse").lower()
        drop = False
        if action == "drop":
            drop = True
        elif action == "drop_pulse" and event_type == "telemetry_pulse":
            drop = True
        elif action not in ("drop", "drop_pulse"):
            if event_type == "telemetry_pulse":
                drop = True

        if drop:
            self._backpressure_drop_count += 1
            now = time.time()
            if now - self._backpressure_last_log > 30:
                logger.warning(
                    "Backpressure active: dropped %d events (backlog=%d bytes, action=%s)",
                    self._backpressure_drop_count,
                    self._backpressure_bytes,
                    action,
                )
                self._backpressure_last_log = now
        return drop

    def _prune_rotated_files(self) -> None:
        """Prune rotated queue files to configured retention."""
        max_files = getattr(self.config, "queue_max_files", 0)
        if max_files <= 0:
            return

        rotated = sorted(
            self._queue_path.parent.glob("event_queue_*.jsonl"),
            key=lambda p: p.stat().st_mtime,
        )
        if len(rotated) <= max_files:
            return

        to_remove = rotated[:len(rotated) - max_files]
        for path in to_remove:
            try:
                path.unlink()
                logger.warning(f"Pruned rotated queue file: {path.name}")
            except Exception as e:
                logger.warning(f"Failed to prune {path.name}: {e}")

    def _rotate_if_needed(self) -> None:
        """Rotate queue file if it exceeds configured max size."""
        if self.redis:
            return  # No rotation needed for Redis

        max_bytes = getattr(self.config, "queue_max_bytes", 0)
        if max_bytes <= 0:
            return

        try:
            size = self._queue_path.stat().st_size
        except FileNotFoundError:
            size = 0
        except Exception as e:
            logger.warning(f"Queue size check failed: {e}")
            return

        if size < max_bytes:
            return

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        rotated_path = self._queue_path.with_name(f"event_queue_{timestamp}.jsonl")
        try:
            self._queue_file.flush()
            os.fsync(self._queue_file.fileno())
            self._queue_file.close()
            self._queue_path.rename(rotated_path)
            self._queue_file = open(self._queue_path, 'a')
            logger.info(f"Rotated event queue: {rotated_path.name}")
            self._prune_rotated_files()
        except Exception as e:
            logger.error(f"Queue rotation failed: {e}")
            try:
                self._queue_file = open(self._queue_path, 'a')
            except Exception:
                pass

    def write_event(
        self,
        event_type: str,
        channel: int,
        score: int,
        dwell_triggered: bool,
        bssid: str | None = None,
        ssid: str | None = None,
        sa: str | None = None,  # Source address
        da: str | None = None,  # Destination address
        rssi_dbm: int | None = None,
        seq_num: int | None = None,
        beacon_interval: int | None = None,
        assoc_request: bool | None = None,
        frame_type: int | None = None,
        frame_subtype: int | None = None,
        fingerprint: dict[str, str] | None = None,  # Added for WS2
        device_identity_id: str | None = None,  # Added for WS2 Phase 2
        timestamp: float | None = None,
        band: str | None = None,
        freq: int | None = None,
        alert: dict[str, Any] | None = None,
        sensor_id: str | None = None,
    ) -> None:
        """
        Write an event to the queue with stable schema.

        Writes are flushed and fsync'd for durability.
        Includes deterministic event_id for SQL idempotency.
        """
        resolved_sensor_id = sensor_id or getattr(self.config, "sensor_id", None)
        event = build_event_dict(
            run_id=self.run_id,
            event_type=event_type,
            channel=channel,
            score=score,
            dwell_triggered=dwell_triggered,
            bssid=bssid,
            ssid=ssid,
            sa=sa,
            da=da,
            rssi_dbm=rssi_dbm,
            seq_num=seq_num,
            beacon_interval=beacon_interval,
            assoc_request=assoc_request,
            frame_type=frame_type,
            frame_subtype=frame_subtype,
            fingerprint=fingerprint,
            device_identity_id=device_identity_id,
            timestamp=timestamp,
            band=band,
            freq=freq,
            alert=alert,
            sensor_id=resolved_sensor_id,
        )
        self.write_event_dict(event)

    def write_event_dict(self, event: dict) -> None:
        """Write a pre-built event dict to the queue."""
        event_type = event.get("event_type", "")
        if self._backpressure_exceeded():
            if self._handle_backpressure(event_type):
                return
        if "sensor_id" not in event:
            resolved_sensor_id = getattr(self.config, "sensor_id", None)
            if resolved_sensor_id:
                event = dict(event)
                event["sensor_id"] = resolved_sensor_id
        event = ensure_event_id(event)
        event_json = json.dumps(event, separators=(',', ':'))
        self._write_event_json(event_json)

    def _write_event_json(self, event_json: str) -> None:
        """Write a JSONL event to Redis or file."""
        if self.redis:
            try:
                self.redis.lpush(self.redis_queue_key, event_json)
                self._event_count += 1
                return
            except Exception as e:
                logger.error(f"Redis write failed: {e}. Falling back to file.")

        with self._lock:
            try:
                self._rotate_if_needed()
                self._queue_file.write(event_json + '\n')
                self._queue_file.flush()
                os.fsync(self._queue_file.fileno())
                self._event_count += 1
            except Exception as e:
                logger.error(f"Failed to write event to queue: {e}")

    def close(self) -> None:
        """Close the queue file."""
        with self._lock:
            try:
                self._queue_file.flush()
                self._queue_file.close()
            except Exception:
                pass
        logger.info(f"Event queue closed: {self._event_count} events written")

    @property
    def event_count(self) -> int:
        """Number of events written."""
        return self._event_count

    @property
    def queue_path(self) -> Path:
        """Path to the queue file."""
        return self._queue_path


class RemoteEventQueueWriter:
    """
    Send events to a remote sensor hub instead of local queue storage.

    Intended for distributed sensors forwarding curated events upstream.
    """

    def __init__(
        self,
        config: ScoutConfig,
        run_id: str | None = None,
        hub_host: str | None = None,
        hub_port: int | None = None,
        auth_token: str | None = None,
        protocol: str | None = None,
        use_tls: bool = False,
        tls_verify: bool = True,
        sensor_name: str | None = None,
        interface: str | None = None,
        location: str | None = None,
        ws_path: str = "/ws/sensors",
    ):
        self.config = config
        self.run_id = run_id or str(uuid.uuid4())
        self._event_count = 0
        self._last_warning = 0.0

        self.hub_host = hub_host or os.getenv("WICAP_SENSOR_HUB_HOST") or os.getenv("WICAP_SENSOR_HOST")
        self.hub_port = hub_port or int(os.getenv("WICAP_SENSOR_HUB_PORT", os.getenv("WICAP_SENSOR_PORT", "9999")))
        self.auth_token = auth_token or os.getenv("WICAP_SENSOR_AUTH_TOKEN")
        self.protocol = (protocol or os.getenv("WICAP_SENSOR_PROTOCOL", "ws")).lower()
        self.use_tls = use_tls or self.protocol == "wss"
        self.tls_verify = tls_verify
        self.sensor_name = sensor_name or os.getenv("WICAP_SENSOR_NAME", "sensor")
        self.interface = interface or config.interface
        self.location = location or os.getenv("WICAP_SENSOR_LOCATION")
        self.ws_path = ws_path
        self.sensor_id = getattr(config, "sensor_id", None)

        if not self.hub_host:
            raise ValueError("Remote sensor hub host is required")

        self._client = self._build_client()
        self._connected = self._client.connect()
        if not self._connected:
            logger.warning("Remote sensor hub unavailable; events will be dropped.")

    def _build_client(self):
        if self.protocol in ("ws", "wss"):
            from nexus.intel.remote_sensor import SensorWebSocketClient
            return SensorWebSocketClient(
                server_host=self.hub_host,
                server_port=self.hub_port,
                sensor_name=self.sensor_name,
                interface=self.interface,
                location=self.location,
                auth_token=self.auth_token,
                use_tls=self.use_tls,
                tls_verify=self.tls_verify,
                path=self.ws_path,
                sensor_id=self.sensor_id,
            )

        from nexus.intel.remote_sensor import SensorClient
        return SensorClient(
            server_host=self.hub_host,
            server_port=self.hub_port,
            sensor_name=self.sensor_name,
            interface=self.interface,
            location=self.location,
            auth_token=self.auth_token,
            sensor_id=self.sensor_id,
        )

    def write_event(
        self,
        event_type: str,
        channel: int,
        score: int,
        dwell_triggered: bool,
        bssid: str | None = None,
        ssid: str | None = None,
        sa: str | None = None,
        da: str | None = None,
        rssi_dbm: int | None = None,
        seq_num: int | None = None,
        beacon_interval: int | None = None,
        assoc_request: bool | None = None,
        frame_type: int | None = None,
        frame_subtype: int | None = None,
        fingerprint: dict[str, str] | None = None,
        device_identity_id: str | None = None,
        timestamp: float | None = None,
        band: str | None = None,
        freq: int | None = None,
        alert: dict[str, Any] | None = None,
        sensor_id: str | None = None,
    ) -> None:
        if not self._connected:
            self._warn_drop(event_type)
            return

        resolved_sensor_id = sensor_id or self.sensor_id
        event = build_event_dict(
            run_id=self.run_id,
            event_type=event_type,
            channel=channel,
            score=score,
            dwell_triggered=dwell_triggered,
            bssid=bssid,
            ssid=ssid,
            sa=sa,
            da=da,
            rssi_dbm=rssi_dbm,
            seq_num=seq_num,
            beacon_interval=beacon_interval,
            assoc_request=assoc_request,
            frame_type=frame_type,
            frame_subtype=frame_subtype,
            fingerprint=fingerprint,
            device_identity_id=device_identity_id,
            timestamp=timestamp,
            band=band,
            freq=freq,
            alert=alert,
            sensor_id=resolved_sensor_id,
        )

        if not self._client.send_event(event):
            self._connected = False
            self._warn_drop(event_type)
            return

        self._event_count += 1

    def write_event_dict(self, event: dict) -> None:
        """Write a pre-built event dict to the remote queue."""
        event_type = event.get("event_type", "")
        if not self._connected:
            self._warn_drop(event_type)
            return

        if "sensor_id" not in event and self.sensor_id:
            event = dict(event)
            event["sensor_id"] = self.sensor_id
        event = ensure_event_id(event)
        if not self._client.send_event(event):
            self._connected = False
            self._warn_drop(event_type)
            return

        self._event_count += 1

    def _warn_drop(self, event_type: str) -> None:
        if event_type == "telemetry_pulse":
            return
        now = time.time()
        if now - self._last_warning > 30:
            logger.warning("Remote sensor hub disconnected; dropping events.")
            self._last_warning = now

    def close(self) -> None:
        try:
            self._client.disconnect()
        except Exception:
            pass

    @property
    def event_count(self) -> int:
        return self._event_count
