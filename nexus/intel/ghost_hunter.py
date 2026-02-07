"""
Ghost Hunter - Baseline anomaly detection for WiFi environments.

Offline-first pipeline:
- Extracts time-windowed features from curated_events
- Trains an IsolationForest baseline
- Scores new windows and persists anomalies to attack_timeline
"""

import argparse
import logging
import os
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np

try:
    import pyodbc
except ImportError:
    pyodbc = None

from nexus.config import NexusConfig, get_nexus_config
from nexus.utils import json_compat

logger = logging.getLogger("nexus.intel.ghost_hunter")

_sklearn_available = None


def _check_sklearn() -> bool:
    global _sklearn_available
    if _sklearn_available is None:
        try:
            import sklearn  # noqa: F401
            _sklearn_available = True
        except ImportError:
            _sklearn_available = False
    return _sklearn_available


FEATURE_NAMES = [
    "event_count",
    "unique_clients",
    "unique_ssids",
    "deauth_rate",
    "assoc_rate",
    "channel_count",
    "seq_jitter_avg",
    "seq_jitter_max",
    "beacon_interval_avg",
    "beacon_interval_jitter",
]

DEAUTH_EVENT_TYPES = {"deauth", "deauth_spike", "disassoc"}

DEFAULT_WINDOW_SEC = 300
DEFAULT_MIN_EVENTS = 20
MAX_EVIDENCE_EVENTS = 25


@dataclass
class FeatureWindow:
    bssid: str
    window_start: float
    window_end: float
    ssid: str | None
    event_count: int
    features: dict[str, float]
    evidence_event_ids: list[str] = field(default_factory=list)

    def vector(self, feature_names: Sequence[str]) -> list[float]:
        return [float(self.features.get(name, 0.0)) for name in feature_names]


@dataclass
class ModelBundle:
    model: Any
    feature_names: list[str]
    feature_means: list[float]
    feature_stds: list[float]
    score_p95: float
    score_p99: float
    window_sec: int
    trained_at: float


@dataclass
class AnomalyResult:
    feature_window: FeatureWindow
    score: float
    confidence: int
    severity: int
    explanation: str
    is_anomaly: bool


def _parse_since(value: str) -> datetime:
    value = value.strip().lower()
    if value.endswith("d"):
        days = int(value[:-1])
        return datetime.now() - timedelta(days=days)
    if value.endswith("h"):
        hours = int(value[:-1])
        return datetime.now() - timedelta(hours=hours)
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Invalid --since value: {value}") from exc


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


class GhostHunter:
    def __init__(
        self,
        config: NexusConfig | None = None,
        window_sec: int = DEFAULT_WINDOW_SEC,
        min_events: int = DEFAULT_MIN_EVENTS,
        model_path: Path | None = None,
    ) -> None:
        self.config = config or get_nexus_config()
        self.window_sec = window_sec
        self.min_events = min_events
        self.model_bundle: ModelBundle | None = None
        self.model_path = model_path or self._default_model_path()

    def _default_model_path(self) -> Path:
        repo_root = Path(__file__).resolve().parents[2]
        return Path(os.getenv("WICAP_GHOST_MODEL_PATH", repo_root / "models" / "ghost_hunter" / "model.joblib"))

    def _connect(self) -> "pyodbc.Connection":
        if pyodbc is None:
            raise RuntimeError("pyodbc is required for GhostHunter database access")
        return pyodbc.connect(self.config.get_sql_connection_string(), timeout=30)

    def _fetch_events(
        self,
        conn: "pyodbc.Connection",
        start_ts: float,
        end_ts: float,
    ) -> list[dict[str, Any]]:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                event_id,
                ts_epoch,
                event_type,
                channel,
                payload_effective_bssid AS bssid,
                payload_effective_ssid AS ssid,
                payload_keys_sa AS sa,
                payload_keys_da AS da,
                JSON_VALUE(payload, '$.frame.seq_num') AS seq_num,
                JSON_VALUE(payload, '$.frame.beacon_interval') AS beacon_interval,
                JSON_VALUE(payload, '$.frame.assoc_request') AS assoc_request
            FROM curated_events
            WHERE ts_epoch >= ? AND ts_epoch < ?
            ORDER BY ts_epoch ASC
            """,
            (start_ts, end_ts),
        )
        events: list[dict[str, Any]] = []
        for row in cursor.fetchall():
            assoc_raw = row[10]
            assoc_request = str(assoc_raw).lower() in ("true", "1", "yes") if assoc_raw is not None else False
            seq_raw = row[8]
            beacon_raw = row[9]
            try:
                seq_num = int(seq_raw) if seq_raw is not None else None
            except (TypeError, ValueError):
                seq_num = None
            try:
                beacon_interval = int(beacon_raw) if beacon_raw is not None else None
            except (TypeError, ValueError):
                beacon_interval = None
            try:
                ts_epoch = float(row[1])
            except (TypeError, ValueError):
                ts_epoch = 0.0
            events.append(
                {
                    "event_id": row[0],
                    "ts_epoch": ts_epoch,
                    "event_type": row[2],
                    "channel": int(row[3]) if row[3] is not None else None,
                    "bssid": row[4],
                    "ssid": row[5],
                    "sa": row[6],
                    "da": row[7],
                    "seq_num": seq_num,
                    "beacon_interval": beacon_interval,
                    "assoc_request": assoc_request,
                }
            )
        return events

    def _iter_windows(self, start_ts: float, end_ts: float) -> Iterable[tuple[float, float]]:
        cursor = start_ts
        while cursor < end_ts:
            window_end = min(end_ts, cursor + self.window_sec)
            yield cursor, window_end
            cursor = window_end

    def _extract_feature_windows(
        self,
        events: Sequence[dict[str, Any]],
        window_start: float,
        window_end: float,
    ) -> list[FeatureWindow]:
        buckets: dict[str, dict[str, Any]] = {}
        events_sorted = sorted(events, key=lambda e: e.get("ts_epoch", 0.0))
        for event in events_sorted:
            bssid = event.get("bssid")
            if not _is_valid_mac(bssid):
                continue
            bucket = buckets.setdefault(
                bssid,
                {
                    "event_count": 0,
                    "client_set": set(),
                    "ssid_set": set(),
                    "deauth_count": 0,
                    "assoc_count": 0,
                    "channel_set": set(),
                    "seq_prev": None,
                    "seq_deltas": [],
                    "beacon_intervals": [],
                    "event_ids": [],
                },
            )

            bucket["event_count"] += 1
            if _is_valid_mac(event.get("sa")):
                bucket["client_set"].add(event.get("sa").lower())
            if event.get("ssid"):
                bucket["ssid_set"].add(event.get("ssid"))
            if event.get("event_type") in DEAUTH_EVENT_TYPES:
                bucket["deauth_count"] += 1
            if event.get("assoc_request"):
                bucket["assoc_count"] += 1
            if event.get("channel") is not None:
                bucket["channel_set"].add(int(event.get("channel")))

            seq_num = event.get("seq_num")
            if seq_num is not None:
                prev = bucket["seq_prev"]
                if prev is not None:
                    bucket["seq_deltas"].append(_seq_delta(prev, seq_num))
                bucket["seq_prev"] = seq_num

            if event.get("beacon_interval") is not None:
                bucket["beacon_intervals"].append(int(event.get("beacon_interval")))

            if event.get("event_id") and len(bucket["event_ids"]) < MAX_EVIDENCE_EVENTS:
                bucket["event_ids"].append(event.get("event_id"))

        window_duration = max(1.0, window_end - window_start)
        features: list[FeatureWindow] = []
        for bssid, bucket in buckets.items():
            event_count = bucket["event_count"]
            if event_count < self.min_events:
                continue
            seq_deltas = bucket["seq_deltas"]
            beacon_intervals = bucket["beacon_intervals"]
            seq_avg = float(np.mean(seq_deltas)) if seq_deltas else 0.0
            seq_max = float(max(seq_deltas)) if seq_deltas else 0.0
            beacon_avg = float(np.mean(beacon_intervals)) if beacon_intervals else 0.0
            beacon_jitter = float(np.std(beacon_intervals)) if len(beacon_intervals) > 1 else 0.0
            ssid_set = bucket["ssid_set"]
            ssid = next(iter(ssid_set)) if len(ssid_set) == 1 else None

            feature_values = {
                "event_count": float(event_count),
                "unique_clients": float(len(bucket["client_set"])),
                "unique_ssids": float(len(ssid_set)),
                "deauth_rate": float(bucket["deauth_count"]) / window_duration,
                "assoc_rate": float(bucket["assoc_count"]) / window_duration,
                "channel_count": float(len(bucket["channel_set"])),
                "seq_jitter_avg": seq_avg,
                "seq_jitter_max": seq_max,
                "beacon_interval_avg": beacon_avg,
                "beacon_interval_jitter": beacon_jitter,
            }

            features.append(
                FeatureWindow(
                    bssid=bssid,
                    window_start=window_start,
                    window_end=window_end,
                    ssid=ssid,
                    event_count=event_count,
                    features=feature_values,
                    evidence_event_ids=bucket["event_ids"],
                )
            )
        return features

    def build_feature_windows(self, start_ts: float, end_ts: float) -> list[FeatureWindow]:
        windows: list[FeatureWindow] = []
        with self._connect() as conn:
            for window_start, window_end in self._iter_windows(start_ts, end_ts):
                events = self._fetch_events(conn, window_start, window_end)
                windows.extend(self._extract_feature_windows(events, window_start, window_end))
        return windows

    def train_from_feature_windows(self, feature_windows: Sequence[FeatureWindow]) -> ModelBundle:
        if not _check_sklearn():
            raise RuntimeError("scikit-learn is required for GhostHunter training")
        if len(feature_windows) < 5:
            raise ValueError("Need at least 5 feature windows to train")

        from sklearn.ensemble import IsolationForest

        X_raw = np.array([fw.vector(FEATURE_NAMES) for fw in feature_windows], dtype=float)
        means = X_raw.mean(axis=0)
        stds = X_raw.std(axis=0)
        stds = np.where(stds == 0.0, 1.0, stds)
        X = (X_raw - means) / stds

        model = IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination="auto",
            random_state=42,
        )
        model.fit(X)

        raw_scores = -model.score_samples(X)
        score_p95 = float(np.percentile(raw_scores, 95))
        score_p99 = float(np.percentile(raw_scores, 99))

        bundle = ModelBundle(
            model=model,
            feature_names=list(FEATURE_NAMES),
            feature_means=means.tolist(),
            feature_stds=stds.tolist(),
            score_p95=score_p95,
            score_p99=score_p99,
            window_sec=self.window_sec,
            trained_at=time.time(),
        )
        self.model_bundle = bundle
        return bundle

    def train(self, start_ts: float, end_ts: float) -> ModelBundle:
        feature_windows = self.build_feature_windows(start_ts, end_ts)
        return self.train_from_feature_windows(feature_windows)

    def _score_confidence(self, score: float, p95: float, p99: float) -> int:
        if p95 <= 0.0:
            return 0
        if score <= p95:
            confidence = int(max(0.0, min(30.0, (score / p95) * 30.0)))
            return confidence
        if p99 <= p95:
            return 60
        scale = min(1.0, (score - p95) / (p99 - p95))
        return int(60 + scale * 40)

    def _severity_from_confidence(self, confidence: int) -> int:
        if confidence >= 90:
            return 5
        if confidence >= 75:
            return 4
        if confidence >= 60:
            return 3
        if confidence >= 40:
            return 2
        return 1

    def _explain(self, feature_window: FeatureWindow, bundle: ModelBundle) -> str:
        explanations = []
        for idx, name in enumerate(bundle.feature_names):
            mean = bundle.feature_means[idx]
            std = bundle.feature_stds[idx]
            if std == 0.0:
                continue
            value = feature_window.features.get(name, 0.0)
            z = (value - mean) / std
            explanations.append((abs(z), name, value, z))
        explanations.sort(reverse=True)
        top = explanations[:3]
        parts = []
        for _, name, value, z in top:
            parts.append(f"{name}={value:.2f} ({z:+.1f}σ)")
        return " | ".join(parts) if parts else "baseline drift detected"

    def score_feature_windows(
        self,
        feature_windows: Sequence[FeatureWindow],
        bundle: ModelBundle | None = None,
    ) -> list[AnomalyResult]:
        if bundle is None:
            bundle = self.model_bundle
        if bundle is None:
            raise RuntimeError("Model bundle not loaded")

        X_raw = np.array([fw.vector(bundle.feature_names) for fw in feature_windows], dtype=float)
        means = np.array(bundle.feature_means, dtype=float)
        stds = np.array(bundle.feature_stds, dtype=float)
        stds = np.where(stds == 0.0, 1.0, stds)
        X = (X_raw - means) / stds

        raw_scores = -bundle.model.score_samples(X)
        results: list[AnomalyResult] = []
        for idx, feature_window in enumerate(feature_windows):
            score = float(raw_scores[idx])
            confidence = self._score_confidence(score, bundle.score_p95, bundle.score_p99)
            severity = self._severity_from_confidence(confidence)
            is_anomaly = score >= bundle.score_p99
            explanation = self._explain(feature_window, bundle)
            results.append(
                AnomalyResult(
                    feature_window=feature_window,
                    score=score,
                    confidence=confidence,
                    severity=severity,
                    explanation=explanation,
                    is_anomaly=is_anomaly,
                )
            )
        return results

    def persist_anomalies(self, anomalies: Sequence[AnomalyResult]) -> int:
        if not anomalies:
            return 0
        with self._connect() as conn:
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

            rows = []
            for anomaly in anomalies:
                fw = anomaly.feature_window
                if not _is_valid_mac(fw.bssid):
                    continue
                start_dt = datetime.fromtimestamp(fw.window_start)
                end_dt = datetime.fromtimestamp(fw.window_end)
                duration = int(max(0.0, fw.window_end - fw.window_start))
                evidence = json_compat.dumps(fw.evidence_event_ids)
                ioc_summary = json_compat.dumps(
                    {
                        "features": fw.features,
                        "score": round(anomaly.score, 6),
                        "confidence": anomaly.confidence,
                    }
                )
                rows.append(
                    (
                        "anomaly_drift",
                        anomaly.severity,
                        anomaly.confidence,
                        fw.bssid,
                        fw.ssid,
                        None,
                        None,
                        None,
                        start_dt,
                        end_dt,
                        duration,
                        fw.event_count,
                        evidence,
                        None,
                        anomaly.explanation,
                        ioc_summary,
                        None,
                    )
                )

            if not rows:
                return 0

            cursor.execute(
                """
                IF OBJECT_ID('tempdb..#AttackStaging') IS NULL
                    CREATE TABLE #AttackStaging (
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
                    TRUNCATE TABLE #AttackStaging
                """
            )

            cursor.fast_executemany = True
            cursor.executemany(
                """
                INSERT INTO #AttackStaging VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                rows,
            )
            cursor.execute(
                """
                MERGE attack_timeline AS target
                USING #AttackStaging AS source
                ON target.attack_type = source.attack_type
                    AND target.target_bssid = source.target_bssid
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

    def save_model(self, path: Path | None = None) -> Path:
        if self.model_bundle is None:
            raise RuntimeError("Model bundle not trained")
        if not _check_sklearn():
            raise RuntimeError("scikit-learn required for model persistence")
        import joblib

        path = path or self.model_path
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model_bundle.model,
                "feature_names": self.model_bundle.feature_names,
                "feature_means": self.model_bundle.feature_means,
                "feature_stds": self.model_bundle.feature_stds,
                "score_p95": self.model_bundle.score_p95,
                "score_p99": self.model_bundle.score_p99,
                "window_sec": self.model_bundle.window_sec,
                "trained_at": self.model_bundle.trained_at,
            },
            path,
        )
        return path

    def load_model(self, path: Path | None = None) -> ModelBundle:
        if not _check_sklearn():
            raise RuntimeError("scikit-learn required for model loading")
        import joblib

        path = path or self.model_path
        data = joblib.load(path)
        self.model_bundle = ModelBundle(
            model=data["model"],
            feature_names=list(data["feature_names"]),
            feature_means=list(data["feature_means"]),
            feature_stds=list(data["feature_stds"]),
            score_p95=float(data["score_p95"]),
            score_p99=float(data["score_p99"]),
            window_sec=int(data["window_sec"]),
            trained_at=float(data["trained_at"]),
        )
        return self.model_bundle

    def score(self, start_ts: float, end_ts: float, persist: bool = True) -> list[AnomalyResult]:
        feature_windows = self.build_feature_windows(start_ts, end_ts)
        results = self.score_feature_windows(feature_windows)
        anomalies = [r for r in results if r.is_anomaly]
        if persist:
            self.persist_anomalies(anomalies)
        return results


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(name)s: %(message)s",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Ghost Hunter - baseline anomaly detection")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser("train", help="Train baseline model")
    train_parser.add_argument("--since", default="30d", help="Training window (e.g., 30d, 12h, YYYY-MM-DD)")
    train_parser.add_argument("--window-min", type=int, default=5, help="Window size in minutes")
    train_parser.add_argument("--min-events", type=int, default=DEFAULT_MIN_EVENTS, help="Minimum events per window")
    train_parser.add_argument("--model-path", default=None, help="Path to save model")

    score_parser = subparsers.add_parser("score", help="Score new windows")
    score_parser.add_argument("--since", default="1d", help="Scoring window (e.g., 1d, 6h, YYYY-MM-DD)")
    score_parser.add_argument("--window-min", type=int, default=5, help="Window size in minutes")
    score_parser.add_argument("--min-events", type=int, default=DEFAULT_MIN_EVENTS, help="Minimum events per window")
    score_parser.add_argument("--model-path", default=None, help="Path to load model")
    score_parser.add_argument("--dry-run", action="store_true", help="Do not persist anomalies")

    args = parser.parse_args()
    _configure_logging(args.verbose)

    window_sec = int(args.window_min) * 60
    model_path = Path(args.model_path) if args.model_path else None
    hunter = GhostHunter(window_sec=window_sec, min_events=int(args.min_events), model_path=model_path)

    since_dt = _parse_since(args.since)
    start_ts = since_dt.timestamp()
    end_ts = time.time()

    if args.command == "train":
        bundle = hunter.train(start_ts, end_ts)
        path = hunter.save_model(model_path)
        logger.info(
            "Trained model with %d features, score_p99=%.4f (saved to %s)",
            len(bundle.feature_names),
            bundle.score_p99,
            path,
        )
        return

    if args.command == "score":
        hunter.load_model(model_path)
        results = hunter.score(start_ts, end_ts, persist=not args.dry_run)
        anomalies = [r for r in results if r.is_anomaly]
        logger.info("Scored %d windows, %d anomalies", len(results), len(anomalies))
        for anomaly in anomalies[:10]:
            fw = anomaly.feature_window
            logger.info(
                "Anomaly %s (%.2f, %d%%): %s",
                fw.bssid,
                anomaly.score,
                anomaly.confidence,
                anomaly.explanation,
            )
        return


if __name__ == "__main__":
    main()
