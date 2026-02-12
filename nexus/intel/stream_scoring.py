"""
Streaming anomaly scoring against baseline snapshots.

Scores feature windows produced by the live stream, applies baseline maturity
to confidence, and persists anomalies to attack_timeline.
"""

from __future__ import annotations

import logging
import math
import os
import time
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from nexus.intel.feature_engineering import FEATURE_NAMES, FeatureStore, build_feature_store
from nexus.intel.feedback_calibration import CalibrationSnapshot, CalibrationStore
from nexus.intel.stream_baseline import BaselineSnapshot, BaselineStore
from nexus.utils import json_compat

try:
    import pyodbc
except ImportError:
    pyodbc = None


logger = logging.getLogger("nexus.intel.stream_scoring")

DEFAULT_SCORE_THRESHOLD = 70.0
DEFAULT_SCORE_SCALE = 3.0
DEFAULT_MIN_CONFIDENCE = 40


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


def _safe_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _default_baseline_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    default_path = repo_root / "captures" / "feature_baselines"
    return Path(os.getenv("WICAP_BASELINE_STORE_PATH", str(default_path)))


@dataclass
class AnomalyScore:
    window: dict[str, Any]
    score: float
    primary_score: float
    confidence: int
    severity: int
    explanation: str
    is_anomaly: bool
    baseline_ready: bool
    baseline_maturity: float
    baseline_sample_count: int
    shadow_scores: dict[str, float]
    model_votes: dict[str, bool]
    vote_agreement: float
    score_components: dict[str, float]
    drift_state: dict[str, Any]


def _baseline_maturity(snapshot: BaselineSnapshot, now_ts: float) -> float:
    if snapshot.min_windows <= 0:
        return 1.0
    maturity = min(1.0, snapshot.sample_count / float(snapshot.min_windows))
    age_sec = max(0.0, now_ts - snapshot.updated_at)
    if snapshot.horizon_sec > 0 and age_sec > snapshot.horizon_sec:
        maturity *= 0.5
    return max(0.0, min(1.0, maturity))


def _severity_from_confidence(confidence: int) -> int:
    if confidence >= 90:
        return 5
    if confidence >= 75:
        return 4
    if confidence >= 60:
        return 3
    if confidence >= 40:
        return 2
    return 1


def _explain(features: dict[str, Any], z_scores: dict[str, float]) -> str:
    ranked = []
    for name in FEATURE_NAMES:
        z = z_scores.get(name, 0.0)
        value = float(features.get(name, 0.0))
        ranked.append((abs(z), name, value, z))
    ranked.sort(reverse=True)
    parts = []
    for _, name, value, z in ranked[:3]:
        parts.append(f"{name}={value:.2f} ({z:+.1f}σ)")
    return " | ".join(parts) if parts else "baseline drift detected"


def score_window(
    window: dict[str, Any],
    snapshot: BaselineSnapshot,
    *,
    score_scale: float = DEFAULT_SCORE_SCALE,
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
    min_confidence: int = DEFAULT_MIN_CONFIDENCE,
    now_ts: float | None = None,
) -> AnomalyScore:
    ts = now_ts if now_ts is not None else time.time()
    features = window.get("features") or {}
    z_scores: dict[str, float] = {}
    for name in FEATURE_NAMES:
        mean = float(snapshot.feature_means.get(name, 0.0))
        std = float(snapshot.feature_stds.get(name, 1.0))
        if std <= 0.0:
            std = 1.0
        value = float(features.get(name, 0.0))
        z_scores[name] = (value - mean) / std
    if z_scores:
        z_rms = math.sqrt(sum(z * z for z in z_scores.values()) / float(len(z_scores)))
    else:
        z_rms = 0.0
    if score_scale <= 0.0:
        score_scale = DEFAULT_SCORE_SCALE
    score = min(100.0, max(0.0, (z_rms / score_scale) * 100.0))
    maturity = _baseline_maturity(snapshot, ts)
    confidence = int(round(score * maturity))
    confidence = max(0, min(100, confidence))
    severity = _severity_from_confidence(confidence)
    explanation = _explain(features, z_scores)
    is_anomaly = snapshot.ready and score >= score_threshold and confidence >= min_confidence
    score_components = {
        "z_rms": round(float(z_rms), 6),
        "score_scale": round(float(score_scale), 6),
        "baseline_maturity": round(float(maturity), 6),
    }
    return AnomalyScore(
        window=window,
        score=score,
        primary_score=score,
        confidence=confidence,
        severity=severity,
        explanation=explanation,
        is_anomaly=is_anomaly,
        baseline_ready=snapshot.ready,
        baseline_maturity=maturity,
        baseline_sample_count=snapshot.sample_count,
        shadow_scores={"primary": round(float(score), 6)},
        model_votes={"primary": bool(is_anomaly)},
        vote_agreement=1.0,
        score_components=score_components,
        drift_state={
            "status": "stable",
            "delta": 0.0,
            "long_mean": round(float(score), 6),
            "short_mean": round(float(score), 6),
            "sample_count": 1,
        },
    )


class StreamAnomalyScorer:
    def __init__(
        self,
        store: FeatureStore,
        baseline_store: BaselineStore,
        *,
        connection_string: str,
        scope: str = "global",
        bssid: str | None = None,
        window_sec: int = 300,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        score_scale: float = DEFAULT_SCORE_SCALE,
        min_confidence: int = DEFAULT_MIN_CONFIDENCE,
        attack_type: str = "anomaly_stream",
        calibration_store: CalibrationStore | None = None,
        calibration_refresh_sec: int = 300,
        persist_to_sql: bool = True,
    ) -> None:
        self.store = store
        self.baseline_store = baseline_store
        self.connection_string = connection_string
        self.scope = scope
        self.bssid = bssid
        self.window_sec = window_sec
        self.score_threshold = score_threshold
        self.score_scale = score_scale
        self.min_confidence = min_confidence
        self.attack_type = attack_type
        self.calibration_store = calibration_store
        self.calibration_refresh_sec = calibration_refresh_sec
        self._last_scored_end = 0.0
        self._warned = False
        self._calibration_warned = False
        self._calibration_snapshot: CalibrationSnapshot | None = None
        self._calibration_refreshed = 0.0
        self.persist_to_sql = bool(persist_to_sql)
        self._recent_scores: deque[float] = deque(maxlen=256)
        self._ewma_score: float | None = None

    def _shadow_and_drift(self, primary_score: float, *, score_threshold: float) -> tuple[dict[str, float], dict[str, bool], float, dict[str, Any]]:
        self._recent_scores.append(float(primary_score))
        values = list(self._recent_scores)
        long_window = values[-60:] if len(values) >= 60 else values
        short_window = values[-10:] if len(values) >= 10 else values

        long_mean = (sum(long_window) / float(len(long_window))) if long_window else float(primary_score)
        short_mean = (sum(short_window) / float(len(short_window))) if short_window else float(primary_score)
        delta = short_mean - long_mean

        self._ewma_score = float(primary_score) if self._ewma_score is None else ((0.25 * float(primary_score)) + (0.75 * float(self._ewma_score)))
        ewma_drift = abs(float(primary_score) - float(self._ewma_score))
        robust_delta = abs(delta)

        mad = 0.0
        if long_window:
            median = sorted(long_window)[len(long_window) // 2]
            deviations = [abs(item - median) for item in long_window]
            mad = sorted(deviations)[len(deviations) // 2] if deviations else 0.0
        mad_norm = 0.0 if mad <= 1e-6 else abs(float(primary_score) - long_mean) / mad

        shadow_scores = {
            "primary": round(float(primary_score), 6),
            "mad_robust": round(min(100.0, mad_norm * 10.0), 6),
            "ewma_drift": round(min(100.0, ewma_drift), 6),
            "delta_abs": round(min(100.0, robust_delta), 6),
        }
        model_votes = {
            "primary": float(primary_score) >= float(score_threshold),
            "mad_robust": float(shadow_scores["mad_robust"]) >= float(score_threshold * 0.75),
            "ewma_drift": float(shadow_scores["ewma_drift"]) >= float(max(10.0, score_threshold * 0.2)),
            "delta_abs": float(shadow_scores["delta_abs"]) >= float(max(8.0, score_threshold * 0.15)),
        }
        positives = sum(1 for value in model_votes.values() if bool(value))
        vote_agreement = max(positives, len(model_votes) - positives) / float(len(model_votes)) if model_votes else 1.0
        drift_state = {
            "status": "drift" if abs(delta) >= 12.5 and len(values) >= 20 else "stable",
            "delta": round(float(delta), 6),
            "long_mean": round(float(long_mean), 6),
            "short_mean": round(float(short_mean), 6),
            "sample_count": int(len(values)),
        }
        return shadow_scores, model_votes, float(vote_agreement), drift_state

    def _maybe_refresh_calibration(self, now_ts: float) -> CalibrationSnapshot | None:
        if self.calibration_store is None:
            return None
        if now_ts - self._calibration_refreshed < self.calibration_refresh_sec:
            return self._calibration_snapshot
        snapshot = self.calibration_store.load(self.attack_type, self.scope, self.bssid)
        self._calibration_snapshot = snapshot
        self._calibration_refreshed = now_ts
        if snapshot is None and not self._calibration_warned:
            logger.info("Stream calibration snapshot not found; using default thresholds.")
            self._calibration_warned = True
        return snapshot

    def score_recent_windows(self, now_ts: float | None = None) -> list[AnomalyScore]:
        ts = now_ts if now_ts is not None else time.time()
        snapshot = self.baseline_store.load(self.scope, self.bssid)
        if snapshot is None:
            if not self._warned:
                logger.info("Stream scoring skipped: baseline snapshot not found.")
                self._warned = True
            return []
        since_ts = self._last_scored_end
        if since_ts <= 0.0:
            since_ts = max(0.0, ts - (self.window_sec * 2))
        limit = max(200, int(snapshot.horizon_sec / max(snapshot.window_sec, 1)) * 4)
        windows = self.store.export_windows(
            since_ts,
            ts,
            scope=self.scope,
            bssid=self.bssid,
            limit=limit,
        )
        if not windows:
            return []
        windows = sorted(windows, key=lambda w: float(w.get("window_end", 0.0)))
        results: list[AnomalyScore] = []
        calibration = self._maybe_refresh_calibration(ts)
        score_threshold = self.score_threshold
        min_confidence = self.min_confidence
        if calibration is not None:
            score_threshold = calibration.recommended_threshold
        for window in windows:
            window_end = float(window.get("window_end", 0.0))
            if window_end <= self._last_scored_end:
                continue
            result = score_window(
                window,
                snapshot,
                score_scale=self.score_scale,
                score_threshold=score_threshold,
                min_confidence=min_confidence,
                now_ts=ts,
            )
            shadow_scores, model_votes, vote_agreement, drift_state = self._shadow_and_drift(
                result.score,
                score_threshold=float(score_threshold),
            )
            result.shadow_scores = shadow_scores
            result.model_votes = model_votes
            result.vote_agreement = round(float(vote_agreement), 6)
            result.drift_state = drift_state
            result.score_components = {
                **dict(result.score_components),
                "shadow_mad_robust": float(shadow_scores.get("mad_robust", 0.0)),
                "shadow_ewma_drift": float(shadow_scores.get("ewma_drift", 0.0)),
                "shadow_delta_abs": float(shadow_scores.get("delta_abs", 0.0)),
                "vote_agreement": round(float(vote_agreement), 6),
            }
            primary_votes = sum(1 for value in model_votes.values() if bool(value))
            vote_ratio = float(primary_votes) / float(len(model_votes)) if model_votes else 0.0
            if result.baseline_ready and vote_ratio >= 0.5 and result.confidence >= self.min_confidence:
                result.is_anomaly = True
            if str(drift_state.get("status")) == "drift":
                result.confidence = int(max(0, round(result.confidence * 0.85)))
            results.append(result)
            if window_end > self._last_scored_end:
                self._last_scored_end = window_end
        return results

    def persist_anomalies(self, scores: Sequence[AnomalyScore]) -> int:
        if not scores:
            return 0
        if not self.persist_to_sql:
            return 0
        if pyodbc is None:
            raise RuntimeError("pyodbc is required for stream anomaly persistence")
        rows = []
        for score in scores:
            if not score.is_anomaly:
                continue
            window = score.window
            start_ts = float(window.get("window_start", 0.0))
            end_ts = float(window.get("window_end", 0.0))
            start_dt = datetime.fromtimestamp(start_ts)
            end_dt = datetime.fromtimestamp(end_ts)
            duration = int(max(0.0, end_ts - start_ts))
            evidence = json_compat.dumps(window.get("evidence_event_ids") or [])
            ioc_summary = json_compat.dumps(
                {
                    "features": window.get("features") or {},
                    "score": round(score.score, 6),
                    "primary_score": round(score.primary_score, 6),
                    "confidence": score.confidence,
                    "baseline_maturity": round(score.baseline_maturity, 3),
                    "baseline_sample_count": score.baseline_sample_count,
                    "shadow_scores": score.shadow_scores,
                    "model_votes": score.model_votes,
                    "vote_agreement": round(score.vote_agreement, 4),
                    "drift_state": score.drift_state,
                    "score_components": score.score_components,
                }
            )
            rows.append(
                (
                    self.attack_type,
                    score.severity,
                    score.confidence,
                    window.get("bssid"),
                    window.get("ssid"),
                    None,
                    None,
                    None,
                    start_dt,
                    end_dt,
                    duration,
                    int(window.get("event_count", 0) or 0),
                    evidence,
                    None,
                    score.explanation,
                    ioc_summary,
                    None,
                )
            )
        if not rows:
            return 0
        with pyodbc.connect(self.connection_string, timeout=30) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                IF OBJECT_ID('attack_timeline', 'U') IS NULL
                    CREATE TABLE attack_timeline (
                        id BIGINT IDENTITY PRIMARY KEY,
                        attack_type VARCHAR(32) NOT NULL,
                        severity INT NOT NULL,
                        confidence INT NOT NULL,
                        target_bssid CHAR(17),
                        target_ssid NVARCHAR(64),
                        target_client CHAR(17),
                        attacker_mac CHAR(17),
                        attacker_vendor NVARCHAR(100),
                        start_time DATETIME2 NOT NULL,
                        end_time DATETIME2,
                        duration_sec INT,
                        event_count INT,
                        evidence_events NVARCHAR(MAX),
                        evidence_pcaps NVARCHAR(MAX),
                        description NVARCHAR(MAX),
                        ioc_summary NVARCHAR(MAX),
                        mitre_technique VARCHAR(32),
                        inserted_at DATETIME2 DEFAULT SYSDATETIME()
                    );
                """
            )
            conn.commit()
            cursor.execute(
                """
                IF OBJECT_ID('tempdb..#StreamAnomalyStaging') IS NULL
                    CREATE TABLE #StreamAnomalyStaging (
                        attack_type VARCHAR(32),
                        severity INT,
                        confidence INT,
                        target_bssid CHAR(17),
                        target_ssid NVARCHAR(64),
                        target_client CHAR(17),
                        attacker_mac CHAR(17),
                        attacker_vendor NVARCHAR(100),
                        start_time DATETIME2,
                        end_time DATETIME2,
                        duration_sec INT,
                        event_count INT,
                        evidence_events NVARCHAR(MAX),
                        evidence_pcaps NVARCHAR(MAX),
                        description NVARCHAR(MAX),
                        ioc_summary NVARCHAR(MAX),
                        mitre_technique VARCHAR(32)
                    )
                ELSE
                    TRUNCATE TABLE #StreamAnomalyStaging
                """
            )
            cursor.fast_executemany = True
            cursor.executemany(
                """
                INSERT INTO #StreamAnomalyStaging VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                rows,
            )
            cursor.execute(
                """
                MERGE attack_timeline AS target
                USING #StreamAnomalyStaging AS source
                ON target.attack_type = source.attack_type
                    AND ISNULL(target.target_bssid, '') = ISNULL(source.target_bssid, '')
                    AND target.start_time = source.start_time
                    AND target.end_time = source.end_time
                WHEN MATCHED THEN
                    UPDATE SET
                        severity = source.severity,
                        confidence = source.confidence,
                        event_count = source.event_count,
                        evidence_events = source.evidence_events,
                        description = source.description,
                        ioc_summary = source.ioc_summary
                WHEN NOT MATCHED THEN
                    INSERT (
                        attack_type, severity, confidence, target_bssid, target_ssid,
                        target_client, attacker_mac, attacker_vendor, start_time, end_time,
                        duration_sec, event_count, evidence_events, evidence_pcaps,
                        description, ioc_summary, mitre_technique
                    )
                    VALUES (
                        source.attack_type, source.severity, source.confidence, source.target_bssid,
                        source.target_ssid, source.target_client, source.attacker_mac,
                        source.attacker_vendor, source.start_time, source.end_time,
                        source.duration_sec, source.event_count, source.evidence_events,
                        source.evidence_pcaps, source.description, source.ioc_summary,
                        source.mitre_technique
                    );
                """
            )
            conn.commit()
        return len(rows)


def build_stream_scorer(
    store: FeatureStore | None = None,
    redis_url: str | None = None,
    *,
    connection_string: str | None = None,
) -> StreamAnomalyScorer | None:
    if not _env_bool("WICAP_ANOMALY_STREAM_ENABLED", False):
        return None
    if store is None:
        store = build_feature_store(redis_url)
    if store is None:
        return None
    persist_to_sql = _env_bool("WICAP_ANOMALY_SQL_PERSIST_ENABLED", True)
    if persist_to_sql and not connection_string:
        logger.warning("Stream anomaly scorer disabled: SQL connection string missing.")
        return None
    score_threshold = _safe_float(os.getenv("WICAP_ANOMALY_SCORE_THRESHOLD")) or DEFAULT_SCORE_THRESHOLD
    score_scale = _safe_float(os.getenv("WICAP_ANOMALY_SCORE_SCALE")) or DEFAULT_SCORE_SCALE
    min_confidence = _safe_int(os.getenv("WICAP_ANOMALY_MIN_CONFIDENCE")) or DEFAULT_MIN_CONFIDENCE
    window_sec = _safe_int(os.getenv("WICAP_FEATURE_WINDOW_SEC")) or 300
    scope = (os.getenv("WICAP_ANOMALY_SCOPE") or os.getenv("WICAP_BASELINE_SCOPE") or "global").strip().lower()
    bssid = (os.getenv("WICAP_ANOMALY_BSSID") or os.getenv("WICAP_BASELINE_BSSID") or "").strip().lower() or None
    attack_type = os.getenv("WICAP_ANOMALY_ATTACK_TYPE", "anomaly_stream").strip() or "anomaly_stream"
    baseline_store = BaselineStore(_default_baseline_dir())
    calibration_store = None
    calibration_refresh_sec = _safe_int(os.getenv("WICAP_ANOMALY_CALIBRATION_REFRESH_SEC")) or 300
    if _env_bool("WICAP_ANOMALY_CALIBRATION_ENABLED", False):
        calibration_store = CalibrationStore()
    return StreamAnomalyScorer(
        store=store,
        baseline_store=baseline_store,
        connection_string=connection_string,
        scope=scope,
        bssid=bssid,
        window_sec=window_sec,
        score_threshold=score_threshold,
        score_scale=score_scale,
        min_confidence=min_confidence,
        attack_type=attack_type,
        calibration_store=calibration_store,
        calibration_refresh_sec=calibration_refresh_sec,
        persist_to_sql=persist_to_sql,
    )
