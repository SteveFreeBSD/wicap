"""
Sensor Registry persistence for distributed sensors.

Stores sensor registration, heartbeat, and counters in SQL Server.
"""

import logging
import re
from dataclasses import asdict
from datetime import datetime

try:
    import pyodbc
except ImportError:
    pyodbc = None

from nexus.config import NexusConfig, get_nexus_config
from nexus.intel.remote_sensor import SensorInfo

logger = logging.getLogger(__name__)

_COORD_RE = re.compile(r"^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$")


def parse_location_coords(location: str | None) -> tuple[float, float] | None:
    if not location:
        return None
    match = _COORD_RE.match(location)
    if not match:
        return None
    lat = float(match.group(1))
    lon = float(match.group(2))
    if lat < -90 or lat > 90:
        return None
    if lon < -180 or lon > 180:
        return None
    return lat, lon


class SensorRegistry:
    def __init__(self, config: NexusConfig | None = None) -> None:
        self.config = config or get_nexus_config()

    def _connect(self) -> "pyodbc.Connection":
        if pyodbc is None:
            raise RuntimeError("pyodbc is required for sensor registry")
        return pyodbc.connect(self.config.get_sql_connection_string(), timeout=10)

    def ensure_schema(self) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='sensor_registry' AND xtype='U')
                CREATE TABLE sensor_registry (
                    sensor_id CHAR(8) NOT NULL PRIMARY KEY,
                    name NVARCHAR(64),
                    interface NVARCHAR(32),
                    location NVARCHAR(128),
                    location_lat DECIMAL(9,6) NULL,
                    location_lon DECIMAL(9,6) NULL,
                    status VARCHAR(16) NOT NULL,
                    connected_at DATETIME2 NOT NULL,
                    last_heartbeat DATETIME2 NOT NULL,
                    frames_received INT DEFAULT 0,
                    alerts_received INT DEFAULT 0,
                    frames_sent INT DEFAULT 0,
                    alerts_sent INT DEFAULT 0,
                    events_received INT DEFAULT 0,
                    last_event_at DATETIME2 NULL,
                    inserted_at DATETIME2 DEFAULT SYSDATETIME()
                )
                """
            )
            cursor.execute(
                """
                IF COL_LENGTH('sensor_registry', 'events_received') IS NULL
                ALTER TABLE sensor_registry ADD events_received INT DEFAULT 0
                """
            )
            cursor.execute(
                """
                IF COL_LENGTH('sensor_registry', 'last_event_at') IS NULL
                ALTER TABLE sensor_registry ADD last_event_at DATETIME2 NULL
                """
            )
            cursor.execute(
                """
                IF COL_LENGTH('sensor_registry', 'location_lat') IS NULL
                ALTER TABLE sensor_registry ADD location_lat DECIMAL(9,6) NULL
                """
            )
            cursor.execute(
                """
                IF COL_LENGTH('sensor_registry', 'location_lon') IS NULL
                ALTER TABLE sensor_registry ADD location_lon DECIMAL(9,6) NULL
                """
            )
            cursor.execute(
                """
                IF NOT EXISTS (
                    SELECT 1 FROM sys.indexes
                    WHERE name = 'IX_sensor_registry_status' AND object_id = OBJECT_ID('sensor_registry')
                )
                CREATE INDEX IX_sensor_registry_status ON sensor_registry(status, last_heartbeat DESC)
                """
            )
            conn.commit()

    def register(self, info: SensorInfo) -> None:
        self._upsert(info, status="online", heartbeat_ts=info.last_heartbeat)

    def heartbeat(self, info: SensorInfo, payload: dict) -> None:
        self._upsert(
            info,
            status="online",
            heartbeat_ts=info.last_heartbeat,
            frames_sent=payload.get("frames_sent"),
            alerts_sent=payload.get("alerts_sent"),
        )

    def disconnect(self, info: SensorInfo) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE sensor_registry
                SET status = ?, last_heartbeat = SYSDATETIME()
                WHERE sensor_id = ?
                """,
                ("offline", info.sensor_id),
            )
            conn.commit()

    def record_event(self, sensor_id: str) -> None:
        """Increment event count for a sensor."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE sensor_registry
                SET events_received = ISNULL(events_received, 0) + 1,
                    last_event_at = SYSDATETIME()
                WHERE sensor_id = ?
                """,
                (sensor_id,),
            )
            conn.commit()

    def _upsert(
        self,
        info: SensorInfo,
        status: str,
        heartbeat_ts: float,
        frames_sent: int | None = None,
        alerts_sent: int | None = None,
        events_received: int | None = None,
        last_event_at: float | None = None,
    ) -> None:
        connected_at = datetime.fromtimestamp(info.connected_at)
        last_heartbeat = datetime.fromtimestamp(heartbeat_ts)
        frames_sent = int(frames_sent) if frames_sent is not None else 0
        alerts_sent = int(alerts_sent) if alerts_sent is not None else 0
        events_received_value = int(events_received) if events_received is not None else None
        last_event_value = (
            datetime.fromtimestamp(last_event_at) if last_event_at is not None else None
        )
        coords = parse_location_coords(info.location)
        location_lat = coords[0] if coords else None
        location_lon = coords[1] if coords else None

        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                MERGE sensor_registry AS target
                USING (
                    SELECT ? AS sensor_id,
                           ? AS name,
                           ? AS interface,
                           ? AS location,
                           ? AS location_lat,
                           ? AS location_lon,
                           ? AS status,
                           ? AS connected_at,
                           ? AS last_heartbeat,
                           ? AS frames_received,
                           ? AS alerts_received,
                           ? AS frames_sent,
                           ? AS alerts_sent,
                           ? AS events_received,
                           ? AS last_event_at
                ) AS source
                ON target.sensor_id = source.sensor_id
                WHEN MATCHED THEN
                    UPDATE SET
                        name = source.name,
                        interface = source.interface,
                        location = source.location,
                        location_lat = source.location_lat,
                        location_lon = source.location_lon,
                        status = source.status,
                        connected_at = source.connected_at,
                        last_heartbeat = source.last_heartbeat,
                        frames_received = source.frames_received,
                        alerts_received = source.alerts_received,
                        frames_sent = source.frames_sent,
                        alerts_sent = source.alerts_sent,
                        events_received = COALESCE(source.events_received, target.events_received),
                        last_event_at = COALESCE(source.last_event_at, target.last_event_at)
                WHEN NOT MATCHED THEN
                    INSERT (
                        sensor_id, name, interface, location, location_lat, location_lon,
                        status, connected_at, last_heartbeat, frames_received,
                        alerts_received, frames_sent, alerts_sent,
                        events_received, last_event_at
                    )
                    VALUES (
                        source.sensor_id, source.name, source.interface, source.location,
                        source.location_lat, source.location_lon, source.status,
                        source.connected_at, source.last_heartbeat, source.frames_received,
                        source.alerts_received, source.frames_sent, source.alerts_sent,
                        COALESCE(source.events_received, 0), source.last_event_at
                    );
                """,
                (
                    info.sensor_id,
                    info.name,
                    info.interface,
                    info.location,
                    location_lat,
                    location_lon,
                    status,
                    connected_at,
                    last_heartbeat,
                    info.frames_received,
                    info.alerts_received,
                    frames_sent,
                    alerts_sent,
                    events_received_value,
                    last_event_value,
                ),
            )
            conn.commit()


def sensor_info_to_dict(info: SensorInfo) -> dict:
    data = asdict(info)
    data["connected_at"] = datetime.fromtimestamp(info.connected_at).isoformat()
    data["last_heartbeat"] = datetime.fromtimestamp(info.last_heartbeat).isoformat()
    return data
