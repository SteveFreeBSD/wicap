"""
BLE triangulation helpers for multi-sensor location estimates.

Uses RSSI-based distance heuristics + weighted centroid. This is intended as a
lightweight, explainable baseline that can be improved later with calibration
and environment-specific tuning.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

try:
    import pyodbc
except Exception:  # pragma: no cover - optional dependency
    pyodbc = None

from nexus.config import NexusConfig, get_nexus_config
from nexus.utils import json_compat

logger = logging.getLogger(__name__)

DEFAULT_PATH_LOSS_EXPONENT = 2.2
DEFAULT_TX_POWER = -59.0
DEFAULT_MIN_DISTANCE = 0.5
DEFAULT_MAX_DISTANCE = 200.0


def rssi_to_distance(
    rssi: float | None,
    tx_power: float = DEFAULT_TX_POWER,
    path_loss_exponent: float = DEFAULT_PATH_LOSS_EXPONENT,
    min_distance: float = DEFAULT_MIN_DISTANCE,
    max_distance: float = DEFAULT_MAX_DISTANCE,
) -> float | None:
    """
    Convert RSSI to an approximate distance using a log-distance path loss model.

    distance = 10 ^ ((tx_power - rssi) / (10 * n))
    """
    if rssi is None:
        return None
    try:
        rssi_value = float(rssi)
    except (TypeError, ValueError):
        return None
    if path_loss_exponent <= 0:
        return None
    distance = 10 ** ((tx_power - rssi_value) / (10 * path_loss_exponent))
    if min_distance is not None:
        distance = max(min_distance, distance)
    if max_distance is not None:
        distance = min(max_distance, distance)
    return distance


def estimate_location(
    readings: Iterable[dict],
    *,
    tx_power: float = DEFAULT_TX_POWER,
    path_loss_exponent: float = DEFAULT_PATH_LOSS_EXPONENT,
    min_distance: float = DEFAULT_MIN_DISTANCE,
    max_distance: float = DEFAULT_MAX_DISTANCE,
) -> dict | None:
    """
    Estimate a location from sensor readings using weighted centroid.

    readings: list of dicts with lat, lon, rssi, sensor_id, sample_count
    """
    weighted_points = []
    for reading in readings:
        lat = reading.get("lat")
        lon = reading.get("lon")
        rssi = reading.get("rssi")
        sample_count = reading.get("sample_count") or 1

        if lat is None or lon is None:
            continue
        distance = rssi_to_distance(
            rssi,
            tx_power=tx_power,
            path_loss_exponent=path_loss_exponent,
            min_distance=min_distance,
            max_distance=max_distance,
        )
        if distance is None:
            continue

        weight = float(sample_count) / max(distance, min_distance) ** 2
        weighted_points.append(
            {
                "lat": float(lat),
                "lon": float(lon),
                "distance": float(distance),
                "weight": weight,
                "sensor_id": reading.get("sensor_id"),
                "rssi": rssi,
                "sample_count": sample_count,
            }
        )

    if len(weighted_points) < 2:
        return None

    total_weight = sum(p["weight"] for p in weighted_points)
    if total_weight <= 0:
        return None

    lat_est = sum(p["lat"] * p["weight"] for p in weighted_points) / total_weight
    lon_est = sum(p["lon"] * p["weight"] for p in weighted_points) / total_weight
    accuracy_m = sum(p["distance"] * p["weight"] for p in weighted_points) / total_weight

    return {
        "lat": lat_est,
        "lon": lon_est,
        "accuracy_m": accuracy_m,
        "sensor_count": len(weighted_points),
        "sample_count": sum(p["sample_count"] for p in weighted_points),
        "sensors": weighted_points,
        "algorithm": "weighted_centroid_v1",
    }


@dataclass
class BLETriangulator:
    config: NexusConfig | None = None
    tx_power: float = DEFAULT_TX_POWER
    path_loss_exponent: float = DEFAULT_PATH_LOSS_EXPONENT
    min_distance: float = DEFAULT_MIN_DISTANCE
    max_distance: float = DEFAULT_MAX_DISTANCE

    def __post_init__(self) -> None:
        if self.config is None:
            self.config = get_nexus_config()

    def _connect(self) -> pyodbc.Connection:
        if pyodbc is None:
            raise RuntimeError("pyodbc is required for BLE triangulation")
        return pyodbc.connect(self.config.get_sql_connection_string(), timeout=10)

    def ensure_schema(self, conn) -> None:
        cursor = conn.cursor()
        cursor.execute(
            """
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='rf_location_estimates' AND xtype='U')
            CREATE TABLE rf_location_estimates (
                protocol VARCHAR(8) NOT NULL,
                target_id NVARCHAR(64) NOT NULL,
                lat DECIMAL(9,6) NOT NULL,
                lon DECIMAL(9,6) NOT NULL,
                accuracy_m FLOAT NULL,
                sensor_count INT NOT NULL,
                sample_count INT NOT NULL,
                window_start DATETIME2 NULL,
                window_end DATETIME2 NULL,
                algorithm NVARCHAR(64) NULL,
                sensors NVARCHAR(MAX) NULL,
                updated_at DATETIME2 DEFAULT SYSDATETIME(),
                CONSTRAINT PK_rf_location_estimates PRIMARY KEY (protocol, target_id)
            )
            """
        )
        cursor.execute(
            """
            IF NOT EXISTS (
                SELECT 1 FROM sys.indexes
                WHERE name = 'IX_rf_location_estimates_protocol' AND object_id = OBJECT_ID('rf_location_estimates')
            )
            CREATE INDEX IX_rf_location_estimates_protocol ON rf_location_estimates(protocol, updated_at DESC)
            """
        )
        conn.commit()

    def compute_estimates(
        self,
        conn,
        *,
        since_minutes: int = 10,
        min_sensors: int = 2,
    ) -> list[dict]:
        cursor = conn.cursor()
        cursor.execute("SELECT OBJECT_ID('bt_observations', 'U')")
        if cursor.fetchone()[0] is None:
            logger.info("bt_observations table missing; skipping BLE triangulation.")
            return []
        cursor.execute("SELECT OBJECT_ID('sensor_registry', 'U')")
        if cursor.fetchone()[0] is None:
            logger.info("sensor_registry table missing; skipping BLE triangulation.")
            return []

        since_ts = time.time() - max(0, since_minutes) * 60
        cursor.execute(
            """
            SELECT
                obs.addr,
                obs.sensor_id,
                AVG(CAST(obs.rssi AS FLOAT)) AS rssi_avg,
                COUNT(*) AS sample_count,
                MIN(obs.ts_epoch) AS window_start,
                MAX(obs.ts_epoch) AS window_end,
                sr.location_lat,
                sr.location_lon
            FROM bt_observations AS obs
            JOIN sensor_registry AS sr
              ON sr.sensor_id = obs.sensor_id
            WHERE obs.ts_epoch >= ?
              AND obs.rssi IS NOT NULL
              AND sr.location_lat IS NOT NULL
              AND sr.location_lon IS NOT NULL
            GROUP BY obs.addr, obs.sensor_id, sr.location_lat, sr.location_lon
            """,
            (since_ts,),
        )

        by_target: dict[str, dict] = {}
        for row in cursor.fetchall():
            addr = row[0]
            reading = {
                "sensor_id": row[1],
                "rssi": row[2],
                "sample_count": row[3],
                "window_start": float(row[4]) if row[4] is not None else since_ts,
                "window_end": float(row[5]) if row[5] is not None else time.time(),
                "lat": row[6],
                "lon": row[7],
            }
            bucket = by_target.setdefault(addr, {"readings": [], "window_start": reading["window_start"], "window_end": reading["window_end"]})
            bucket["readings"].append(reading)
            bucket["window_start"] = min(bucket["window_start"], reading["window_start"])
            bucket["window_end"] = max(bucket["window_end"], reading["window_end"])

        estimates: list[dict] = []
        for addr, payload in by_target.items():
            readings = payload["readings"]
            result = estimate_location(
                readings,
                tx_power=self.tx_power,
                path_loss_exponent=self.path_loss_exponent,
                min_distance=self.min_distance,
                max_distance=self.max_distance,
            )
            if not result:
                continue
            if result["sensor_count"] < min_sensors:
                continue
            estimates.append(
                {
                    "protocol": "bt",
                    "target_id": addr,
                    "lat": result["lat"],
                    "lon": result["lon"],
                    "accuracy_m": result["accuracy_m"],
                    "sensor_count": result["sensor_count"],
                    "sample_count": result["sample_count"],
                    "window_start": datetime.fromtimestamp(payload["window_start"]),
                    "window_end": datetime.fromtimestamp(payload["window_end"]),
                    "algorithm": result["algorithm"],
                    "sensors": json_compat.dumps(result["sensors"]),
                }
            )

        return estimates

    def save_estimates(self, conn, estimates: list[dict]) -> int:
        if not estimates:
            return 0
        cursor = conn.cursor()
        self.ensure_schema(conn)

        cursor.execute(
            """
            IF OBJECT_ID('tempdb..#RFLocationStaging') IS NULL
                CREATE TABLE #RFLocationStaging (
                    protocol VARCHAR(8),
                    target_id NVARCHAR(64),
                    lat DECIMAL(9,6),
                    lon DECIMAL(9,6),
                    accuracy_m FLOAT,
                    sensor_count INT,
                    sample_count INT,
                    window_start DATETIME2,
                    window_end DATETIME2,
                    algorithm NVARCHAR(64),
                    sensors NVARCHAR(MAX)
                )
            ELSE
                TRUNCATE TABLE #RFLocationStaging
            """
        )

        rows = [
            (
                est["protocol"],
                est["target_id"],
                est["lat"],
                est["lon"],
                est["accuracy_m"],
                est["sensor_count"],
                est["sample_count"],
                est["window_start"],
                est["window_end"],
                est.get("algorithm"),
                est.get("sensors"),
            )
            for est in estimates
        ]

        cursor.fast_executemany = True
        cursor.executemany(
            "INSERT INTO #RFLocationStaging VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        cursor.execute(
            """
            MERGE rf_location_estimates AS target
            USING #RFLocationStaging AS source
            ON target.protocol = source.protocol AND target.target_id = source.target_id
            WHEN MATCHED THEN
                UPDATE SET
                    lat = source.lat,
                    lon = source.lon,
                    accuracy_m = source.accuracy_m,
                    sensor_count = source.sensor_count,
                    sample_count = source.sample_count,
                    window_start = source.window_start,
                    window_end = source.window_end,
                    algorithm = source.algorithm,
                    sensors = source.sensors,
                    updated_at = SYSDATETIME()
            WHEN NOT MATCHED THEN
                INSERT (
                    protocol, target_id, lat, lon, accuracy_m, sensor_count, sample_count,
                    window_start, window_end, algorithm, sensors, updated_at
                )
                VALUES (
                    source.protocol, source.target_id, source.lat, source.lon, source.accuracy_m,
                    source.sensor_count, source.sample_count, source.window_start, source.window_end,
                    source.algorithm, source.sensors, SYSDATETIME()
                );
            """
        )
        conn.commit()
        return len(estimates)

    def run(
        self,
        *,
        since_minutes: int = 10,
        min_sensors: int = 2,
        dry_run: bool = False,
    ) -> int:
        with self._connect() as conn:
            self.ensure_schema(conn)
            estimates = self.compute_estimates(conn, since_minutes=since_minutes, min_sensors=min_sensors)
            if dry_run:
                logger.info("BLE triangulation dry-run: %d estimates", len(estimates))
                return len(estimates)
            saved = self.save_estimates(conn, estimates)
            logger.info("BLE triangulation saved %d estimates", saved)
            return saved


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Compute BLE location estimates")
    parser.add_argument("--since-minutes", type=int, default=10, help="Lookback window in minutes")
    parser.add_argument("--min-sensors", type=int, default=2, help="Minimum sensors required per device")
    parser.add_argument("--tx-power", type=float, default=DEFAULT_TX_POWER, help="Tx power at 1m (dBm)")
    parser.add_argument("--path-loss", type=float, default=DEFAULT_PATH_LOSS_EXPONENT, help="Path loss exponent")
    parser.add_argument("--dry-run", action="store_true", help="Compute estimates without saving")
    args = parser.parse_args()

    triangulator = BLETriangulator(
        tx_power=args.tx_power,
        path_loss_exponent=args.path_loss,
    )
    triangulator.run(
        since_minutes=args.since_minutes,
        min_sensors=args.min_sensors,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
