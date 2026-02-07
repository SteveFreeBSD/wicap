"""
Streaming baseline builder for anomaly detection.

Builds a rolling 24-hour baseline from feature windows and persists a snapshot
for downstream scoring and monitoring.
"""

from __future__ import annotations

import argparse
import logging
import math
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nexus.intel.feature_engineering import FEATURE_NAMES, FeatureStore, build_feature_store
from nexus.utils import json_compat

logger = logging.getLogger("nexus.intel.stream_baseline")

DEFAULT_HORIZON_SEC = 24 * 3600
DEFAULT_REFRESH_SEC = 300
DEFAULT_MIN_WINDOWS = 20


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def _safe_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_offset(value: str, now_ts: float) -> float:
    value = value.strip().lower()
    if value.endswith("d"):
        return now_ts - (float(value[:-1]) * 86400.0)
    if value.endswith("h"):
        return now_ts - (float(value[:-1]) * 3600.0)
    if value.endswith("m"):
        return now_ts - (float(value[:-1]) * 60.0)
    return float(value)


def _default_baseline_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    default_path = repo_root / "captures" / "feature_baselines"
    return Path(os.getenv("WICAP_BASELINE_STORE_PATH", str(default_path)))


def _sanitize_token(value: str | None) -> str:
    if not value:
        return "global"
    return "".join(ch for ch in value.lower() if ch.isalnum() or ch in ("_", "-"))


@dataclass
class BaselineSnapshot:
    scope: str
    bssid: str | None
    horizon_sec: int
    window_sec: int
    min_windows: int
    sample_count: int
    updated_at: float
    ready: bool
    feature_means: dict[str, float]
    feature_stds: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "bssid": self.bssid,
            "horizon_sec": self.horizon_sec,
            "window_sec": self.window_sec,
            "min_windows": self.min_windows,
            "sample_count": self.sample_count,
            "updated_at": self.updated_at,
            "ready": self.ready,
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineSnapshot:
        return cls(
            scope=data.get("scope", "global"),
            bssid=data.get("bssid"),
            horizon_sec=int(data.get("horizon_sec", DEFAULT_HORIZON_SEC)),
            window_sec=int(data.get("window_sec", 300)),
            min_windows=int(data.get("min_windows", DEFAULT_MIN_WINDOWS)),
            sample_count=int(data.get("sample_count", 0)),
            updated_at=float(data.get("updated_at", 0.0)),
            ready=bool(data.get("ready", False)),
            feature_means=dict(data.get("feature_means", {})),
            feature_stds=dict(data.get("feature_stds", {})),
        )


class BaselineStore:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, scope: str, bssid: str | None) -> Path:
        scope_token = _sanitize_token(scope)
        bssid_token = _sanitize_token(bssid)
        filename = f"baseline_{scope_token}_{bssid_token}.json"
        return self.base_dir / filename

    def save(self, snapshot: BaselineSnapshot) -> Path:
        path = self._path_for(snapshot.scope, snapshot.bssid)
        with open(path, "w") as handle:
            handle.write(json_compat.dumps(snapshot.to_dict(), separators=(",", ":")))
        return path

    def load(self, scope: str, bssid: str | None) -> BaselineSnapshot | None:
        path = self._path_for(scope, bssid)
        if not path.exists():
            return None
        try:
            with open(path) as handle:
                return BaselineSnapshot.from_dict(json_compat.loads(handle.read()))
        except Exception:
            return None


class BaselineUpdater:
    def __init__(
        self,
        store: FeatureStore,
        baseline_store: BaselineStore,
        *,
        scope: str = "global",
        bssid: str | None = None,
        horizon_sec: int = DEFAULT_HORIZON_SEC,
        min_windows: int = DEFAULT_MIN_WINDOWS,
        refresh_sec: int = DEFAULT_REFRESH_SEC,
        window_sec: int = 300,
    ) -> None:
        self.store = store
        self.baseline_store = baseline_store
        self.scope = scope
        self.bssid = bssid
        self.horizon_sec = horizon_sec
        self.min_windows = min_windows
        self.refresh_sec = refresh_sec
        self.window_sec = window_sec
        self._last_refresh = 0.0
        self._warned = False

    def maybe_refresh(self, now_ts: float | None = None) -> BaselineSnapshot | None:
        ts = now_ts if now_ts is not None else time.time()
        if ts - self._last_refresh < self.refresh_sec:
            return None
        snapshot = self.refresh(ts)
        self._last_refresh = ts
        return snapshot

    def refresh(self, now_ts: float | None = None) -> BaselineSnapshot | None:
        ts = now_ts if now_ts is not None else time.time()
        since_ts = ts - self.horizon_sec
        limit = max(1000, int(self.horizon_sec / max(self.window_sec, 1)) * 4)
        windows = self.store.export_windows(
            since_ts,
            ts,
            scope=self.scope,
            bssid=self.bssid,
            limit=limit,
        )
        if not windows:
            if not self._warned:
                logger.info("Baseline refresh skipped: no feature windows available.")
                self._warned = True
            return None

        means, stds = _compute_stats(windows)
        sample_count = len(windows)
        ready = sample_count >= self.min_windows
        snapshot = BaselineSnapshot(
            scope=self.scope,
            bssid=self.bssid,
            horizon_sec=self.horizon_sec,
            window_sec=self.window_sec,
            min_windows=self.min_windows,
            sample_count=sample_count,
            updated_at=ts,
            ready=ready,
            feature_means=means,
            feature_stds=stds,
        )
        self.baseline_store.save(snapshot)
        return snapshot


def _compute_stats(windows: Iterable[dict[str, Any]]) -> tuple[dict[str, float], dict[str, float]]:
    sums = dict.fromkeys(FEATURE_NAMES, 0.0)
    sumsq = dict.fromkeys(FEATURE_NAMES, 0.0)
    count = 0
    for window in windows:
        features = window.get("features") or {}
        count += 1
        for name in FEATURE_NAMES:
            value = float(features.get(name, 0.0))
            sums[name] += value
            sumsq[name] += value * value
    if count <= 0:
        return dict.fromkeys(FEATURE_NAMES, 0.0), dict.fromkeys(FEATURE_NAMES, 1.0)
    means = {}
    stds = {}
    for name in FEATURE_NAMES:
        mean = sums[name] / float(count)
        variance = (sumsq[name] / float(count)) - (mean * mean)
        if variance < 0.0:
            variance = 0.0
        std = math.sqrt(variance)
        means[name] = mean
        stds[name] = max(std, 1e-6)
    return means, stds


def build_baseline_updater(
    store: FeatureStore | None = None,
    redis_url: str | None = None,
) -> BaselineUpdater | None:
    if not _env_bool("WICAP_BASELINE_STREAM_ENABLED", False):
        return None
    if store is None:
        store = build_feature_store(redis_url)
    if store is None:
        return None
    horizon_sec = _safe_int(os.getenv("WICAP_BASELINE_HORIZON_SEC")) or DEFAULT_HORIZON_SEC
    min_windows = _safe_int(os.getenv("WICAP_BASELINE_MIN_WINDOWS")) or DEFAULT_MIN_WINDOWS
    refresh_sec = _safe_int(os.getenv("WICAP_BASELINE_REFRESH_SEC")) or DEFAULT_REFRESH_SEC
    window_sec = _safe_int(os.getenv("WICAP_FEATURE_WINDOW_SEC")) or 300
    scope = os.getenv("WICAP_BASELINE_SCOPE", "global").strip().lower() or "global"
    bssid = os.getenv("WICAP_BASELINE_BSSID", "").strip().lower() or None
    baseline_store = BaselineStore(_default_baseline_dir())
    return BaselineUpdater(
        store=store,
        baseline_store=baseline_store,
        scope=scope,
        bssid=bssid,
        horizon_sec=horizon_sec,
        min_windows=min_windows,
        refresh_sec=refresh_sec,
        window_sec=window_sec,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Streaming baseline builder")
    parser.add_argument("command", choices=["refresh"])
    parser.add_argument("--since", default="24h", help="Time window for baseline (e.g., 24h, 7d)")
    parser.add_argument("--min-windows", type=int, default=DEFAULT_MIN_WINDOWS)
    parser.add_argument("--scope", default="global")
    parser.add_argument("--bssid", default="")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    store = build_feature_store(os.getenv("WICAP_REDIS_URL"))
    if store is None:
        raise SystemExit("Feature store is not configured")

    now_ts = time.time()
    since_ts = _parse_offset(args.since, now_ts)
    horizon_sec = max(1, int(now_ts - since_ts))

    updater = BaselineUpdater(
        store=store,
        baseline_store=BaselineStore(_default_baseline_dir()),
        scope=args.scope.strip().lower() or "global",
        bssid=args.bssid.strip().lower() or None,
        horizon_sec=horizon_sec,
        min_windows=args.min_windows,
        refresh_sec=0,
        window_sec=_safe_int(os.getenv("WICAP_FEATURE_WINDOW_SEC")) or 300,
    )
    snapshot = updater.refresh(now_ts)
    if snapshot is None:
        raise SystemExit("No windows available for baseline refresh.")
    status = "ready" if snapshot.ready else "cold-start"
    logger.info("Baseline refreshed (%s). windows=%d", status, snapshot.sample_count)


if __name__ == "__main__":
    main()
