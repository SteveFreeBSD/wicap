"""
Feedback calibration for streaming anomaly detection.

Computes operator feedback metrics and recommends score threshold adjustments.
Persists calibration snapshots for the live stream scorer.
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nexus.utils import json_compat

try:
    import pyodbc
except ImportError:
    pyodbc = None


logger = logging.getLogger("nexus.intel.feedback_calibration")

DEFAULT_MIN_FEEDBACK = 10
DEFAULT_THRESHOLD_DELTA = 5.0


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


def _parse_offset(value: str, now_ts: float) -> float:
    value = value.strip().lower()
    if value.endswith("d"):
        return now_ts - (float(value[:-1]) * 86400.0)
    if value.endswith("h"):
        return now_ts - (float(value[:-1]) * 3600.0)
    if value.endswith("m"):
        return now_ts - (float(value[:-1]) * 60.0)
    return float(value)


def _default_calibration_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    default_path = repo_root / "captures" / "anomaly_calibration"
    return Path(os.getenv("WICAP_ANOMALY_CALIBRATION_PATH", str(default_path)))


def _sanitize_token(value: str | None) -> str:
    if not value:
        return "global"
    return "".join(ch for ch in value.lower() if ch.isalnum() or ch in ("_", "-"))


@dataclass
class FeedbackMetrics:
    total_anomalies: int
    feedback_total: int
    confirmed: int
    benign: int
    noisy: int
    precision: float
    recall_proxy: float
    coverage: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_anomalies": self.total_anomalies,
            "feedback_total": self.feedback_total,
            "confirmed": self.confirmed,
            "benign": self.benign,
            "noisy": self.noisy,
            "precision": self.precision,
            "recall_proxy": self.recall_proxy,
            "coverage": self.coverage,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FeedbackMetrics:
        return cls(
            total_anomalies=int(data.get("total_anomalies", 0)),
            feedback_total=int(data.get("feedback_total", 0)),
            confirmed=int(data.get("confirmed", 0)),
            benign=int(data.get("benign", 0)),
            noisy=int(data.get("noisy", 0)),
            precision=float(data.get("precision", 0.0)),
            recall_proxy=float(data.get("recall_proxy", 0.0)),
            coverage=float(data.get("coverage", 0.0)),
        )


@dataclass
class CalibrationSnapshot:
    attack_type: str
    scope: str
    bssid: str | None
    since_hours: int
    computed_at: float
    min_feedback: int
    current_threshold: float
    recommended_threshold: float
    threshold_delta: float
    reason: str
    metrics: FeedbackMetrics

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_type": self.attack_type,
            "scope": self.scope,
            "bssid": self.bssid,
            "since_hours": self.since_hours,
            "computed_at": self.computed_at,
            "min_feedback": self.min_feedback,
            "current_threshold": self.current_threshold,
            "recommended_threshold": self.recommended_threshold,
            "threshold_delta": self.threshold_delta,
            "reason": self.reason,
            "metrics": self.metrics.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CalibrationSnapshot:
        return cls(
            attack_type=data.get("attack_type", "anomaly_stream"),
            scope=data.get("scope", "global"),
            bssid=data.get("bssid"),
            since_hours=int(data.get("since_hours", 24)),
            computed_at=float(data.get("computed_at", 0.0)),
            min_feedback=int(data.get("min_feedback", DEFAULT_MIN_FEEDBACK)),
            current_threshold=float(data.get("current_threshold", 70.0)),
            recommended_threshold=float(data.get("recommended_threshold", 70.0)),
            threshold_delta=float(data.get("threshold_delta", 0.0)),
            reason=str(data.get("reason", "none")),
            metrics=FeedbackMetrics.from_dict(data.get("metrics", {})),
        )


class CalibrationStore:
    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = Path(base_dir or _default_calibration_dir())
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, attack_type: str, scope: str, bssid: str | None) -> Path:
        attack_token = _sanitize_token(attack_type)
        scope_token = _sanitize_token(scope)
        bssid_token = _sanitize_token(bssid)
        return self.base_dir / f"calibration_{attack_token}_{scope_token}_{bssid_token}.json"

    def save(self, snapshot: CalibrationSnapshot) -> Path:
        path = self._path_for(snapshot.attack_type, snapshot.scope, snapshot.bssid)
        with open(path, "w") as handle:
            handle.write(json_compat.dumps(snapshot.to_dict(), separators=(",", ":")))
        return path

    def load(self, attack_type: str, scope: str, bssid: str | None) -> CalibrationSnapshot | None:
        path = self._path_for(attack_type, scope, bssid)
        if not path.exists():
            return None
        try:
            with open(path) as handle:
                return CalibrationSnapshot.from_dict(json_compat.loads(handle.read()))
        except Exception:
            return None


def compute_metrics(total_anomalies: int, feedback_counts: dict[str, int]) -> FeedbackMetrics:
    confirmed = int(feedback_counts.get("confirmed", 0))
    benign = int(feedback_counts.get("benign", 0))
    noisy = int(feedback_counts.get("noisy", 0))
    feedback_total = confirmed + benign + noisy
    precision = (confirmed / feedback_total) if feedback_total > 0 else 0.0
    recall_proxy = (confirmed / total_anomalies) if total_anomalies > 0 else 0.0
    coverage = (feedback_total / total_anomalies) if total_anomalies > 0 else 0.0
    return FeedbackMetrics(
        total_anomalies=total_anomalies,
        feedback_total=feedback_total,
        confirmed=confirmed,
        benign=benign,
        noisy=noisy,
        precision=precision,
        recall_proxy=recall_proxy,
        coverage=coverage,
    )


def recommend_threshold(
    current_threshold: float,
    metrics: FeedbackMetrics,
    *,
    min_feedback: int = DEFAULT_MIN_FEEDBACK,
    delta_step: float = DEFAULT_THRESHOLD_DELTA,
) -> tuple[float, float, str]:
    if metrics.feedback_total < min_feedback:
        return current_threshold, 0.0, "insufficient_feedback"

    benign_total = metrics.benign + metrics.noisy
    benign_rate = benign_total / metrics.feedback_total if metrics.feedback_total else 0.0
    confirmed_rate = metrics.confirmed / metrics.feedback_total if metrics.feedback_total else 0.0

    delta = 0.0
    reason = "stable"
    if benign_rate >= 0.7:
        delta = delta_step * 2
        reason = "reduce_false_positives_high"
    elif benign_rate >= 0.5:
        delta = delta_step
        reason = "reduce_false_positives"
    elif confirmed_rate >= 0.8 and benign_rate <= 0.1:
        delta = -delta_step
        reason = "increase_sensitivity"

    recommended = max(0.0, min(100.0, current_threshold + delta))
    return recommended, delta, reason


class FeedbackCalibrator:
    def __init__(
        self,
        *,
        connection_string: str,
        attack_type: str = "anomaly_stream",
        scope: str = "global",
        bssid: str | None = None,
        min_feedback: int = DEFAULT_MIN_FEEDBACK,
        current_threshold: float = 70.0,
    ) -> None:
        self.connection_string = connection_string
        self.attack_type = attack_type
        self.scope = scope
        self.bssid = bssid
        self.min_feedback = min_feedback
        self.current_threshold = current_threshold

    def _attack_filter_sql(self) -> tuple[str, list]:
        params = []
        attack_filter = "a.attack_type = ?"
        attack_type = self.attack_type or "anomaly_stream"
        if "%" in attack_type:
            attack_filter = "a.attack_type LIKE ?"
        params.append(attack_type)
        if self.bssid:
            attack_filter += " AND a.target_bssid = ?"
            params.append(self.bssid)
        return attack_filter, params

    def refresh(self, since_hours: int) -> CalibrationSnapshot:
        if pyodbc is None:
            raise RuntimeError("pyodbc is required for feedback calibration")
        attack_filter, params = self._attack_filter_sql()
        with pyodbc.connect(self.connection_string, timeout=30) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'attack_timeline'")
            if not cursor.fetchone():
                raise RuntimeError("attack_timeline table is missing")

            cursor.execute(
                f"""
                SELECT COUNT(*)
                FROM attack_timeline a
                WHERE {attack_filter}
                AND a.start_time >= DATEADD(hour, -?, SYSDATETIME())
                """,
                params + [since_hours],
            )
            total_anomalies = int(cursor.fetchone()[0] or 0)

            feedback_counts = {"confirmed": 0, "benign": 0, "noisy": 0}
            cursor.execute("SELECT 1 FROM sys.tables WHERE name = 'attack_feedback'")
            if cursor.fetchone():
                cursor.execute(
                    f"""
                    SELECT f.label, COUNT(*)
                    FROM attack_feedback f
                    JOIN attack_timeline a ON f.attack_id = a.id
                    WHERE {attack_filter}
                    AND a.start_time >= DATEADD(hour, -?, SYSDATETIME())
                    GROUP BY f.label
                    """,
                    params + [since_hours],
                )
                for label, count in cursor.fetchall():
                    if label:
                        feedback_counts[str(label).lower()] = int(count or 0)

            metrics = compute_metrics(total_anomalies, feedback_counts)
            recommended, delta, reason = recommend_threshold(
                self.current_threshold,
                metrics,
                min_feedback=self.min_feedback,
            )
            snapshot = CalibrationSnapshot(
                attack_type=self.attack_type,
                scope=self.scope,
                bssid=self.bssid,
                since_hours=since_hours,
                computed_at=time.time(),
                min_feedback=self.min_feedback,
                current_threshold=self.current_threshold,
                recommended_threshold=recommended,
                threshold_delta=delta,
                reason=reason,
                metrics=metrics,
            )
            return snapshot


def main() -> None:
    parser = argparse.ArgumentParser(description="Feedback calibration for streaming anomalies")
    parser.add_argument("command", choices=["refresh"])
    parser.add_argument("--since", default="24h", help="Time window (e.g., 24h, 7d)")
    parser.add_argument("--attack-type", default="anomaly_stream")
    parser.add_argument("--scope", default="global")
    parser.add_argument("--bssid", default="")
    parser.add_argument("--min-feedback", type=int, default=DEFAULT_MIN_FEEDBACK)
    parser.add_argument("--threshold", type=float, default=None, help="Current threshold override")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    from nexus.config import get_nexus_config

    config = get_nexus_config()
    now_ts = time.time()
    since_ts = _parse_offset(args.since, now_ts)
    since_hours = max(1, int((now_ts - since_ts) / 3600))
    current_threshold = args.threshold
    if current_threshold is None:
        current_threshold = _safe_float(os.getenv("WICAP_ANOMALY_SCORE_THRESHOLD")) or 70.0

    calibrator = FeedbackCalibrator(
        connection_string=config.get_sql_connection_string(),
        attack_type=args.attack_type,
        scope=args.scope.strip().lower() or "global",
        bssid=args.bssid.strip().lower() or None,
        min_feedback=args.min_feedback,
        current_threshold=current_threshold,
    )
    snapshot = calibrator.refresh(since_hours=since_hours)
    store = CalibrationStore()
    path = store.save(snapshot)
    logger.info(
        "Calibration saved: %s (delta=%s, precision=%.2f, recall_proxy=%.2f)",
        path,
        snapshot.threshold_delta,
        snapshot.metrics.precision,
        snapshot.metrics.recall_proxy,
    )


if __name__ == "__main__":
    main()
