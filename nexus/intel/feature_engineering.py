"""
Streaming feature engineering for anomaly detection pipelines.

This module builds rolling feature windows from live event streams and
stores them in a lightweight feature store (Redis or JSONL files).
"""

from __future__ import annotations

import logging
import math
import os
import time
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from nexus.utils import json_compat

logger = logging.getLogger("nexus.intel.feature_engineering")


DEAUTH_EVENT_TYPES = {"deauth", "deauth_spike", "disassoc"}
DEFAULT_WINDOW_SEC = 300
DEFAULT_MIN_EVENTS = 20
DEFAULT_RETENTION_SEC = 7 * 24 * 3600
MAX_EVIDENCE_EVENTS = 25

FEATURE_NAMES = [
    "event_count",
    "unique_clients",
    "unique_ssids",
    "deauth_rate",
    "assoc_rate",
    "channel_count",
    "channel_top_ratio",
    "seq_jitter_avg",
    "seq_jitter_max",
    "beacon_interval_avg",
    "beacon_interval_jitter",
    "hour_sin",
    "hour_cos",
]


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _seq_delta(prev_seq: int, next_seq: int) -> int:
    if prev_seq is None or next_seq is None:
        return 0
    diff = (next_seq - prev_seq) % 4096
    if diff > 2048:
        diff = 4096 - diff
    return diff


def _is_valid_mac(value: str | None) -> bool:
    if not value:
        return False
    lowered = value.lower()
    if lowered in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    return True


def _hour_sin_cos(ts: float) -> tuple[float, float]:
    if ts <= 0:
        return 0.0, 0.0
    tm = time.gmtime(ts)
    hour = tm.tm_hour + (tm.tm_min / 60.0)
    angle = 2.0 * math.pi * (hour / 24.0)
    return math.sin(angle), math.cos(angle)


def _mean(values: Sequence[int]) -> float:
    if not values:
        return 0.0
    return float(sum(values)) / float(len(values))


def _stddev(values: Sequence[int]) -> float:
    if len(values) < 2:
        return 0.0
    avg = _mean(values)
    variance = sum((val - avg) ** 2 for val in values) / float(len(values))
    return math.sqrt(variance)


@dataclass
class FeatureWindow:
    scope: str
    window_start: float
    window_end: float
    event_count: int
    features: dict[str, float]
    bssid: str | None = None
    ssid: str | None = None
    evidence_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "event_count": self.event_count,
            "features": {k: float(self.features.get(k, 0.0)) for k in FEATURE_NAMES},
            "evidence_event_ids": list(self.evidence_event_ids),
        }


class FeatureStore:
    def write_window(self, window: FeatureWindow) -> None:
        raise NotImplementedError

    def export_windows(
        self,
        since_ts: float,
        until_ts: float,
        *,
        scope: str | None = None,
        bssid: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError


class MemoryFeatureStore(FeatureStore):
    def __init__(self) -> None:
        self._windows: list[dict[str, Any]] = []

    def write_window(self, window: FeatureWindow) -> None:
        self._windows.append(window.to_dict())

    def export_windows(
        self,
        since_ts: float,
        until_ts: float,
        *,
        scope: str | None = None,
        bssid: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        results = []
        for window in self._windows:
            if window["window_end"] < since_ts or window["window_start"] > until_ts:
                continue
            if scope and window.get("scope") != scope:
                continue
            if bssid and window.get("bssid") != bssid.lower():
                continue
            results.append(window)
            if len(results) >= limit:
                break
        return results


class FileFeatureStore(FeatureStore):
    def __init__(
        self,
        base_dir: Path,
        retention_sec: int = DEFAULT_RETENTION_SEC,
        prefix: str = "feature_windows",
    ) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.retention_sec = retention_sec
        self.prefix = prefix
        self._last_cleanup = 0.0

    def _file_for_ts(self, ts: float) -> Path:
        date_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d")
        filename = f"{self.prefix}_{date_str}.jsonl"
        return self.base_dir / filename

    def _cleanup_old_files(self, now_ts: float) -> None:
        if self.retention_sec <= 0:
            return
        if now_ts - self._last_cleanup < 3600:
            return
        cutoff = datetime.fromtimestamp(now_ts - self.retention_sec, tz=timezone.utc).strftime("%Y%m%d")
        for path in self.base_dir.glob(f"{self.prefix}_*.jsonl"):
            name = path.stem.replace(self.prefix + "_", "")
            if name.isdigit() and name < cutoff:
                try:
                    path.unlink()
                except Exception:
                    continue
        self._last_cleanup = now_ts

    def write_window(self, window: FeatureWindow) -> None:
        path = self._file_for_ts(window.window_end)
        line = json_compat.dumps(window.to_dict(), separators=(",", ":"))
        with open(path, "a") as handle:
            handle.write(line + "\n")
        self._cleanup_old_files(time.time())

    def export_windows(
        self,
        since_ts: float,
        until_ts: float,
        *,
        scope: str | None = None,
        bssid: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        if since_ts > until_ts:
            return results
        start_date = datetime.fromtimestamp(since_ts, tz=timezone.utc).date()
        end_date = datetime.fromtimestamp(until_ts, tz=timezone.utc).date()
        current = start_date
        while current <= end_date:
            filename = f"{self.prefix}_{current.strftime('%Y%m%d')}.jsonl"
            path = self.base_dir / filename
            if path.exists():
                try:
                    with open(path) as handle:
                        for line in handle:
                            if not line.strip():
                                continue
                            try:
                                window = json_compat.loads(line)
                            except Exception:
                                continue
                            if window.get("window_end", 0) < since_ts or window.get("window_start", 0) > until_ts:
                                continue
                            if scope and window.get("scope") != scope:
                                continue
                            if bssid and window.get("bssid") != bssid.lower():
                                continue
                            results.append(window)
                            if len(results) >= limit:
                                return results
                except Exception:
                    pass
            current += timedelta(days=1)
        return results


class RedisFeatureStore(FeatureStore):
    def __init__(
        self,
        redis_url: str,
        retention_sec: int = DEFAULT_RETENTION_SEC,
        key_prefix: str = "wicap:features",
    ) -> None:
        try:
            import redis  # type: ignore
        except ImportError as exc:
            raise RuntimeError("redis module is required for RedisFeatureStore") from exc
        self.redis = redis.from_url(redis_url)
        self.retention_sec = retention_sec
        self.key = f"{key_prefix}:windows"

    def write_window(self, window: FeatureWindow) -> None:
        payload = json_compat.dumps(window.to_dict(), separators=(",", ":"))
        self.redis.zadd(self.key, {payload: window.window_end})
        if self.retention_sec > 0:
            cutoff = window.window_end - self.retention_sec
            self.redis.zremrangebyscore(self.key, 0, cutoff)

    def export_windows(
        self,
        since_ts: float,
        until_ts: float,
        *,
        scope: str | None = None,
        bssid: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        raw = self.redis.zrangebyscore(self.key, since_ts, until_ts)
        for item in raw:
            try:
                if isinstance(item, bytes):
                    item = item.decode("utf-8")
                window = json_compat.loads(item)
            except Exception:
                continue
            if scope and window.get("scope") != scope:
                continue
            if bssid and window.get("bssid") != bssid.lower():
                continue
            results.append(window)
            if len(results) >= limit:
                break
        return results


class FeatureAccumulator:
    def __init__(self, scope: str, window_start: float, window_sec: int, bssid: str | None) -> None:
        self.scope = scope
        self.window_start = window_start
        self.window_end = window_start + window_sec
        self.bssid = bssid
        self.event_count = 0
        self.client_set: set[str] = set()
        self.ssid_set: set[str] = set()
        self.deauth_count = 0
        self.assoc_count = 0
        self.channel_counts: Counter[int] = Counter()
        self.seq_prev: int | None = None
        self.seq_deltas: list[int] = []
        self.beacon_intervals: list[int] = []
        self.event_ids: list[str] = []

    def add_event(self, event: dict[str, Any]) -> None:
        self.event_count += 1
        keys = event.get("keys", {})
        sa = keys.get("sa") or keys.get("source") or keys.get("src_mac")
        if _is_valid_mac(sa):
            self.client_set.add(sa.lower())
        ssid = keys.get("ssid")
        if ssid:
            self.ssid_set.add(ssid)
        event_type = event.get("event_type")
        if event_type in DEAUTH_EVENT_TYPES:
            self.deauth_count += 1
        assoc_request = False
        frame = event.get("frame", {}) if isinstance(event.get("frame"), dict) else {}
        if frame.get("assoc_request") is True:
            assoc_request = True
        if event_type == "association" or assoc_request:
            self.assoc_count += 1
        channel = _safe_int(event.get("channel"))
        if channel is not None:
            self.channel_counts[channel] += 1
        seq_num = _safe_int(frame.get("seq_num"))
        if seq_num is not None:
            if self.seq_prev is not None:
                self.seq_deltas.append(_seq_delta(self.seq_prev, seq_num))
            self.seq_prev = seq_num
        beacon_interval = _safe_int(frame.get("beacon_interval"))
        if beacon_interval is not None:
            self.beacon_intervals.append(beacon_interval)
        event_id = event.get("event_id")
        if event_id and len(self.event_ids) < MAX_EVIDENCE_EVENTS:
            self.event_ids.append(event_id)

    def finalize(self) -> FeatureWindow:
        window_duration = max(1.0, self.window_end - self.window_start)
        seq_avg = _mean(self.seq_deltas)
        seq_max = max(self.seq_deltas) if self.seq_deltas else 0.0
        beacon_avg = _mean(self.beacon_intervals)
        beacon_jitter = _stddev(self.beacon_intervals)
        hour_sin, hour_cos = _hour_sin_cos(self.window_start)
        channel_count = len(self.channel_counts)
        channel_top_ratio = 0.0
        if self.event_count > 0 and self.channel_counts:
            channel_top_ratio = max(self.channel_counts.values()) / float(self.event_count)
        ssid = next(iter(self.ssid_set)) if len(self.ssid_set) == 1 else None
        features = {
            "event_count": float(self.event_count),
            "unique_clients": float(len(self.client_set)),
            "unique_ssids": float(len(self.ssid_set)),
            "deauth_rate": float(self.deauth_count) / window_duration,
            "assoc_rate": float(self.assoc_count) / window_duration,
            "channel_count": float(channel_count),
            "channel_top_ratio": float(channel_top_ratio),
            "seq_jitter_avg": float(seq_avg),
            "seq_jitter_max": float(seq_max),
            "beacon_interval_avg": float(beacon_avg),
            "beacon_interval_jitter": float(beacon_jitter),
            "hour_sin": float(hour_sin),
            "hour_cos": float(hour_cos),
        }
        return FeatureWindow(
            scope=self.scope,
            window_start=self.window_start,
            window_end=self.window_end,
            event_count=self.event_count,
            features=features,
            bssid=self.bssid,
            ssid=ssid,
            evidence_event_ids=list(self.event_ids),
        )


class StreamingFeatureEngineer:
    def __init__(
        self,
        store: FeatureStore,
        *,
        window_sec: int = DEFAULT_WINDOW_SEC,
        min_events: int = DEFAULT_MIN_EVENTS,
        include_global: bool = True,
        include_bssid: bool = True,
    ) -> None:
        self.store = store
        self.window_sec = window_sec
        self.min_events = min_events
        self.include_global = include_global
        self.include_bssid = include_bssid
        self._accumulators: dict[tuple[str, str | None], FeatureAccumulator] = {}

    def ingest_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("event_type")
        if event_type == "telemetry_pulse":
            return
        ts = _safe_float(event.get("ts_epoch"))
        if ts is None:
            return
        window_start = ts - (ts % self.window_sec)
        for scope, bssid in self._scopes_for_event(event):
            key = (scope, bssid)
            acc = self._accumulators.get(key)
            if acc is None or acc.window_start != window_start:
                if acc is not None:
                    self._finalize_window(acc)
                acc = FeatureAccumulator(scope, window_start, self.window_sec, bssid)
                self._accumulators[key] = acc
            acc.add_event(event)

    def flush_expired(self, now_ts: float | None = None) -> None:
        ts = now_ts if now_ts is not None else time.time()
        expired_keys = [
            key for key, acc in self._accumulators.items() if acc.window_end <= ts
        ]
        for key in expired_keys:
            acc = self._accumulators.pop(key, None)
            if acc:
                self._finalize_window(acc)

    def flush_all(self) -> None:
        for acc in list(self._accumulators.values()):
            self._finalize_window(acc)
        self._accumulators.clear()

    def _finalize_window(self, acc: FeatureAccumulator) -> None:
        if self.min_events > 0 and acc.event_count < self.min_events:
            return
        window = acc.finalize()
        self.store.write_window(window)

    def _scopes_for_event(self, event: dict[str, Any]) -> Iterable[tuple[str, str | None]]:
        if self.include_global:
            yield "global", None
        if not self.include_bssid:
            return
        keys = event.get("keys", {})
        bssid = keys.get("bssid")
        if _is_valid_mac(bssid):
            yield "bssid", bssid.lower()


def _default_store_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    default_path = repo_root / "captures" / "feature_windows"
    return Path(os.getenv("WICAP_FEATURE_STORE_PATH", str(default_path)))


def build_feature_store(redis_url: str | None = None) -> FeatureStore | None:
    store_kind = os.getenv("WICAP_FEATURE_STORE", "").strip().lower()
    if not store_kind:
        store_kind = "redis" if redis_url else "file"
    retention_sec = _safe_int(os.getenv("WICAP_FEATURE_RETENTION_SEC")) or DEFAULT_RETENTION_SEC
    if store_kind == "redis":
        if not redis_url:
            logger.warning("Feature store set to redis but WICAP_REDIS_URL is missing; falling back to file store.")
            store_kind = "file"
        else:
            return RedisFeatureStore(redis_url, retention_sec=retention_sec)
    if store_kind == "file":
        return FileFeatureStore(_default_store_dir(), retention_sec=retention_sec)
    if store_kind == "memory":
        return MemoryFeatureStore()
    if store_kind in ("off", "disabled", "none"):
        return None
    logger.warning("Unknown WICAP_FEATURE_STORE=%s; disabling feature store.", store_kind)
    return None


def build_feature_engineer(redis_url: str | None = None) -> StreamingFeatureEngineer | None:
    if not _env_bool("WICAP_FEATURE_STREAM_ENABLED", False):
        return None
    store = build_feature_store(redis_url)
    if store is None:
        return None
    window_sec = _safe_int(os.getenv("WICAP_FEATURE_WINDOW_SEC")) or DEFAULT_WINDOW_SEC
    min_events = _safe_int(os.getenv("WICAP_FEATURE_MIN_EVENTS")) or DEFAULT_MIN_EVENTS
    include_global = _env_bool("WICAP_FEATURE_GLOBAL_ENABLED", True)
    include_bssid = _env_bool("WICAP_FEATURE_BSSID_ENABLED", True)
    return StreamingFeatureEngineer(
        store=store,
        window_sec=window_sec,
        min_events=min_events,
        include_global=include_global,
        include_bssid=include_bssid,
    )
