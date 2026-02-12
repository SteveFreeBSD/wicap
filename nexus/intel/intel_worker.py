"""Standalone sidecar worker for anomaly v2/v3 and prediction artifact emission."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from nexus.intel.feature_engineering import build_feature_store
from nexus.intel.stream_baseline import build_baseline_updater
from nexus.intel.stream_scoring import build_stream_scorer
from src.wicap.telemetry.anomaly_events import (
    append_anomaly_events,
    append_anomaly_events_v2,
    append_anomaly_events_v3,
)
from src.wicap.telemetry.prediction_events import append_prediction_events, build_prediction_events

logger = logging.getLogger("nexus.intel.intel_worker")


def _safe_float(value: str | None, default: float) -> float:
    try:
        if value is None:
            raise ValueError
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _captures_dir() -> Path:
    default_path = _repo_root() / "captures"
    value = os.getenv("WICAP_CAPTURES_DIR", str(default_path)).strip() or str(default_path)
    return Path(value).expanduser()


def _parse_horizons(raw: str | None) -> list[int]:
    text = str(raw or "").strip()
    if not text:
        return [300, 1800]
    values: list[int] = []
    for token in text.split(","):
        try:
            parsed = int(token.strip())
        except ValueError:
            continue
        if parsed > 0:
            values.append(parsed)
    if not values:
        return [300, 1800]
    return sorted(set(values))


def _prediction_horizons() -> list[int]:
    return _parse_horizons(os.getenv("WICAP_PREDICTION_HORIZONS_SEC"))


def run_intel_worker_loop(
    *,
    once: bool = False,
    interval_seconds: float = 10.0,
) -> int:
    redis_url = os.getenv("WICAP_REDIS_URL")
    sensor_id = os.getenv("WICAP_SENSOR_ID", "wicap-local").strip() or "wicap-local"
    captures_dir = _captures_dir()
    anomaly_path_v1 = Path(os.getenv("WICAP_ANOMALY_EVENTS_PATH", str(captures_dir / "wicap_anomaly_events.jsonl")))
    anomaly_path_v2 = Path(os.getenv("WICAP_ANOMALY_EVENTS_V2_PATH", str(captures_dir / "wicap_anomaly_events_v2.jsonl")))
    anomaly_path_v3 = Path(os.getenv("WICAP_ANOMALY_EVENTS_V3_PATH", str(captures_dir / "wicap_anomaly_events_v3.jsonl")))
    prediction_path = Path(os.getenv("WICAP_PREDICTION_EVENTS_PATH", str(captures_dir / "wicap_predictions.jsonl")))
    horizons = _prediction_horizons()
    sleep_seconds = max(0.5, float(interval_seconds))

    store = build_feature_store(redis_url)
    if store is None:
        logger.error("Intel worker disabled: feature store unavailable.")
        return 2

    baseline_updater = build_baseline_updater(store, redis_url)
    scorer = build_stream_scorer(
        store=store,
        redis_url=redis_url,
        connection_string=None,
    )
    if scorer is None:
        logger.error("Intel worker disabled: stream scorer unavailable.")
        return 2

    logger.info(
        "Intel worker started (sensor=%s, horizons=%s, interval=%.1fs)",
        sensor_id,
        ",".join(str(item) for item in horizons),
        sleep_seconds,
    )

    while True:
        now_ts = time.time()
        try:
            if baseline_updater is not None:
                baseline_updater.maybe_refresh(now_ts)
        except Exception as exc:
            logger.warning("Baseline refresh failed (continuing): %s", exc)

        try:
            scores = scorer.score_recent_windows(now_ts)
        except Exception as exc:
            logger.warning("Scoring failed (continuing): %s", exc)
            scores = []

        if scores:
            try:
                append_anomaly_events(
                    output_path=anomaly_path_v1,
                    scores=scores,
                    sensor_id=sensor_id,
                    anomalies_only=True,
                )
                append_anomaly_events_v2(
                    output_path=anomaly_path_v2,
                    scores=scores,
                    sensor_id=sensor_id,
                    anomalies_only=True,
                )
                append_anomaly_events_v3(
                    output_path=anomaly_path_v3,
                    scores=scores,
                    sensor_id=sensor_id,
                    anomalies_only=True,
                )
                prediction_events = build_prediction_events(
                    scores=scores,
                    horizons_sec=horizons,
                    sensor_id=sensor_id,
                )
                append_prediction_events(output_path=prediction_path, events=prediction_events)
                scorer.persist_anomalies(scores)
            except Exception as exc:
                logger.warning("Artifact export failed (continuing): %s", exc)

        if once:
            break
        time.sleep(sleep_seconds)

    logger.info("Intel worker stopped.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    _ = argv
    interval = _safe_float(os.getenv("WICAP_INTEL_WORKER_INTERVAL_SECONDS"), 10.0)
    once = str(os.getenv("WICAP_INTEL_WORKER_ONCE", "")).strip().lower() in {"1", "true", "yes", "on"}
    return run_intel_worker_loop(once=once, interval_seconds=interval)
