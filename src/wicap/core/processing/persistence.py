"""
Persistence Manager

Handles database insertion logic with batching for performance.
This isolates database operations from the main processor,
addressing complexity and race conditions in soak tests.
"""
import hashlib
import json
import logging
import math
import time
from datetime import datetime
from typing import Any

import pyodbc

from nexus.intel.incident_manager import IncidentManager
from nexus.utils import json_compat

logger = logging.getLogger('wicap.processing.persistence')


def _clip_text(value: object | None, max_len: int) -> str | None:
    if value is None:
        return None
    # Strip invalid Unicode surrogates and control chars that can break ODBC/NVARCHAR writes.
    raw = str(value).replace("\x00", "")
    text = "".join(
        ch for ch in raw
        if (ch in ("\t", "\n", "\r")) or (ord(ch) >= 32 and not (0xD800 <= ord(ch) <= 0xDFFF))
    )
    return text[:max_len] if len(text) > max_len else text


def _clip_signature(value: object | None, max_len: int = 256) -> str:
    text = str(value or "")
    if len(text) <= max_len:
        return text
    digest = hashlib.sha256(text.encode()).hexdigest()[:16]
    keep = max_len - len(digest) - 1
    return f"{text[:max(0, keep)]}#{digest}"


def _coerce_int(value: object | None, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _coerce_float(value: object | None, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        result = float(value)
        if not math.isfinite(result):
            return default
        return result
    except Exception:
        return default


def _normalize_bool_like(value: object | None) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if int(value) in (0, 1):
            return bool(int(value))
        return None
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y", "on"}:
            return True
        if normalized in {"false", "0", "no", "n", "off"}:
            return False
    return None


def _sanitize_event_for_sql(event: dict) -> dict:
    """Normalize payload fields that can trigger SQL computed-column cast failures."""
    sanitized = dict(event)
    fingerprint = sanitized.get("fingerprint")
    if isinstance(fingerprint, dict) and "is_wifi6" in fingerprint:
        fingerprint_copy = dict(fingerprint)
        wifi6 = _normalize_bool_like(fingerprint_copy.get("is_wifi6"))
        if wifi6 is None:
            fingerprint_copy.pop("is_wifi6", None)
        else:
            fingerprint_copy["is_wifi6"] = wifi6
        sanitized["fingerprint"] = fingerprint_copy
    return sanitized


def _sanitize_alert_row(row: dict[str, Any]) -> dict[str, Any]:
    """Coerce and clip alert fields to match SQL table constraints."""
    ts_epoch = _coerce_float(row.get("ts_epoch"), time.time())
    first_seen = row.get("first_seen")
    last_seen = row.get("last_seen")
    if not isinstance(first_seen, datetime):
        first_seen = datetime.fromtimestamp(ts_epoch)
    if not isinstance(last_seen, datetime):
        last_seen = datetime.fromtimestamp(ts_epoch)
    channel = row.get("channel")
    channel_value = None if channel is None else _coerce_int(channel, 0)
    return {
        "alert_id": _clip_text(row.get("alert_id"), 8) or "",
        "alert_signature": _clip_signature(row.get("alert_signature"), 256),
        "alert_type": _clip_text(row.get("alert_type"), 50) or "unknown",
        "severity": max(1, min(5, _coerce_int(row.get("severity"), 1))),
        "title": _clip_text(row.get("title"), 200),
        "description": _clip_text(row.get("description"), 500),
        "ts_epoch": ts_epoch,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "source_mac": _clip_text(row.get("source_mac"), 17),
        "target_mac": _clip_text(row.get("target_mac"), 17),
        "bssid": _clip_text(row.get("bssid"), 17),
        "ssid": _clip_text(row.get("ssid"), 64),
        "channel": channel_value,
        "event_count": max(1, _coerce_int(row.get("event_count"), 1)),
        "incident_id": _clip_text(row.get("incident_id"), 32),
    }


def _format_alert_title(alert_type: str) -> str:
    if not alert_type:
        return "Alert"
    return alert_type.replace("_", " ").title()


def build_wids_alert_row(event: dict) -> dict | None:
    event_type = str(event.get("event_type", ""))
    if not event_type.startswith("wids_"):
        return None

    alert_type = _clip_text(event_type.replace("wids_", "", 1), 50) or "unknown"
    keys = event.get("keys") or {}
    alert_meta = event.get("alert") or {}

    severity = alert_meta.get("severity")
    if severity is None:
        score = _coerce_float(event.get("score"), 0.0)
        severity = max(1, min(5, int(round(score / 10.0))))
    severity = max(1, min(5, _coerce_int(severity, 1)))

    title = _clip_text(alert_meta.get("title") or _format_alert_title(alert_type), 200)
    description = _clip_text(alert_meta.get("description"), 500)
    event_count = max(1, _coerce_int(alert_meta.get("event_count"), 1))

    ts_epoch = _coerce_float(event.get("ts_epoch"), time.time())
    ts_dt = datetime.fromtimestamp(ts_epoch)

    source_mac = _clip_text(keys.get("sa"), 17)
    target_mac = _clip_text(keys.get("da"), 17)
    bssid = _clip_text(keys.get("bssid"), 17)
    ssid = _clip_text(keys.get("ssid"), 64)
    channel = _coerce_int(event.get("channel"), 0)

    raw_signature = "|".join([
        alert_type or "",
        bssid or "",
        ssid or "",
        source_mac or "",
        target_mac or "",
        str(channel or ""),
    ])
    alert_id = hashlib.sha256(raw_signature.encode()).hexdigest()[:8]
    signature = _clip_signature(raw_signature)

    return {
        "alert_id": alert_id,
        "alert_signature": signature,
        "alert_type": alert_type,
        "severity": severity,
        "title": title,
        "description": description,
        "ts_epoch": ts_epoch,
        "first_seen": ts_dt,
        "last_seen": ts_dt,
        "source_mac": source_mac,
        "target_mac": target_mac,
        "bssid": bssid,
        "ssid": ssid,
        "channel": channel,
        "event_count": event_count,
    }


def _normalize_service_set(value: str | None) -> set:
    if not value:
        return set()
    if isinstance(value, list):
        return {str(v) for v in value if v}
    if isinstance(value, str):
        try:
            parsed = json_compat.loads(value)
            if isinstance(parsed, list):
                return {str(v) for v in parsed if v}
        except Exception:
            pass
    return set()


def _diff_services(old_value: str | None, new_value: str | None) -> tuple[set, set]:
    old_set = _normalize_service_set(old_value)
    new_set = _normalize_service_set(new_value)
    return new_set - old_set, old_set - new_set


def build_ble_alert_row(
    alert_type: str,
    addr: str,
    description: str,
    ts_epoch: float,
    local_name: str | None = None,
    severity: int = 2,
) -> dict:
    alert_type_norm = _clip_text(alert_type, 50) or "unknown"
    source_mac = _clip_text(addr, 17)
    local_name_norm = _clip_text(local_name, 64)
    description_norm = _clip_text(description, 500)
    raw_signature = "|".join(
        [alert_type_norm, source_mac or "", local_name_norm or "", description_norm or ""]
    )
    alert_id = hashlib.sha256(raw_signature.encode()).hexdigest()[:8]
    signature = _clip_signature(raw_signature)
    ts_dt = datetime.fromtimestamp(_coerce_float(ts_epoch, time.time()))
    title = _clip_text(alert_type_norm.replace("_", " ").title(), 200)

    return {
        "alert_id": alert_id,
        "alert_signature": signature,
        "alert_type": alert_type_norm,
        "severity": max(1, min(5, int(severity))),
        "title": title,
        "description": description_norm,
        "ts_epoch": _coerce_float(ts_epoch, time.time()),
        "first_seen": ts_dt,
        "last_seen": ts_dt,
        "source_mac": source_mac,
        "target_mac": None,
        "bssid": None,
        "ssid": local_name_norm,
        "channel": None,
        "event_count": 1,
    }


class PersistenceManager:
    """Manages database persistence with batching and connection pooling.

    This class handles all SQL Server operations, including:
    - Batch insertion using staging tables
    - Connection management
    - Schema migration
    - Table creation/validation
    """

    def __init__(self, connection_string: str, batch_size: int = 100):
        """Initialize persistence manager.

        Args:
            connection_string: SQL Server connection string
            batch_size: Number of events to batch before inserting
        """
        self.connection_string = connection_string
        self.batch_size = batch_size
        self._conn: pyodbc.Connection | None = None
        self._batch: list[dict] = []
        self._bt_batch: list[dict] = []
        self._incident_grouping_suspended_until: float = 0.0

    def connect(self) -> bool:
        """Establish database connection.

        Returns:
            True if connection successful, False otherwise
        """
        if self._conn is not None:
            return True

        try:
            self._conn = pyodbc.connect(self.connection_string, timeout=10)
            self._ensure_schema()
            logger.info("SQL connection established")
            return True
        except Exception as e:
            logger.error(f"SQL connection failed: {e}")
            return False

    def disconnect(self) -> None:
        """Close database connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def add_event(self, event: dict) -> None:
        """Add event to batch.

        Args:
            event: Event dictionary to add
        """
        self._batch.append(event)
        if len(self._batch) >= self.batch_size:
            self.flush()

    def add_bt_event(self, event: dict) -> None:
        """Add Bluetooth event to BT batch."""
        self._bt_batch.append(event)
        if len(self._bt_batch) >= self.batch_size:
            self.flush()

    def get_batch_size(self) -> int:
        """Get current batch size (combined)."""
        return len(self._batch) + len(self._bt_batch)

    def flush(self) -> int:
        """Flush accumulated events to database.

        Returns:
            Number of events inserted
        """
        if not self._batch and not self._bt_batch:
            return 0

        if not self._conn:
            if not self.connect():
                logger.error("Cannot flush: database connection failed")
                self._batch.clear()
                self._bt_batch.clear()
                return 0

        wifi_count = len(self._batch)
        bt_count = len(self._bt_batch)
        count = wifi_count + bt_count
        cursor = self._conn.cursor()

        try:
            if self._batch:
                try:
                    self._flush_batch(cursor)
                except Exception as wifi_error:
                    logger.error("WiFi flush stage failed: %s", wifi_error)
                    raise

            if self._bt_batch:
                try:
                    self._flush_bt_batch(cursor)
                except Exception as bt_error:
                    logger.error("Bluetooth flush stage failed: %s", bt_error)
                    raise

            self._conn.commit()
            if wifi_count and bt_count:
                logger.info("Flushed %d WiFi and %d BT events to SQL", wifi_count, bt_count)
            elif wifi_count:
                logger.info("Flushed %d WiFi events to SQL", wifi_count)
            elif bt_count:
                logger.info("Flushed %d BT events to SQL", bt_count)
            return count
        except Exception as e:
            logger.error(f"Failed to flush batch: {e}")
            self._conn.rollback()
            return 0
        finally:
            self._batch.clear()
            self._bt_batch.clear()

    def _flush_batch(self, cursor) -> None:
        """Flush batch using staging table MERGE pattern for high performance.

        Args:
            cursor: Database cursor
        """
        prepared_rows: list[tuple[tuple, dict]] = []
        for event in self._batch:
            sanitized_event = _sanitize_event_for_sql(event)
            # Ensure event_id
            event_id = sanitized_event.get('event_id', '')
            if not event_id:
                content = json.dumps(sanitized_event, sort_keys=True, separators=(',', ':'))
                event_id = hashlib.sha256(content.encode()).hexdigest()

            prepared_rows.append(((
                event_id,
                _coerce_float(sanitized_event.get('ts_epoch'), 0.0),
                _clip_text(sanitized_event.get('event_type', 'unknown'), 50) or 'unknown',
                _coerce_int(sanitized_event.get('channel'), 0),
                _coerce_int(sanitized_event.get('score'), 0),
                json_compat.dumps(sanitized_event)
            ), sanitized_event))

        rows = [row for row, _ in prepared_rows]
        merged_events: list[dict] = [event for _, event in prepared_rows]

        self._ensure_batch_staging(cursor)
        try:
            self._bulk_insert_batch_rows(cursor, rows)
            self._merge_batch_staging(cursor)
        except Exception as bulk_error:
            logger.warning(
                "Bulk WiFi staging insert failed (%s); retrying row-by-row for %d rows",
                bulk_error,
                len(rows),
            )
            merged_events = []
            dropped = 0
            cursor.fast_executemany = False
            for row, event in prepared_rows:
                try:
                    cursor.execute("TRUNCATE TABLE #BatchStaging")
                    cursor.execute(
                        "INSERT INTO #BatchStaging VALUES (?, ?, ?, ?, ?, ?)",
                        row,
                    )
                    self._merge_batch_staging(cursor)
                    merged_events.append(event)
                except Exception as row_error:
                    dropped += 1
                    logger.error(
                        "Dropping invalid WiFi row event_id=%s event_type=%s ts=%s: %s",
                        row[0],
                        row[2],
                        row[1],
                        row_error,
                    )
            if dropped:
                logger.warning(
                    "Dropped %d/%d WiFi rows due to SQL type/constraint violations",
                    dropped,
                    len(rows),
                )

        alert_rows = self._collect_wids_alerts(merged_events)
        if alert_rows:
            self._flush_wids_alerts(cursor, alert_rows)

    def _ensure_batch_staging(self, cursor) -> None:
        cursor.execute(
            """
            IF OBJECT_ID('tempdb..#BatchStaging') IS NULL
                CREATE TABLE #BatchStaging (
                    event_id CHAR(64) PRIMARY KEY,
                    ts_epoch DECIMAL(19,9),
                    event_type VARCHAR(50),
                    channel INT,
                    score INT,
                    payload NVARCHAR(MAX)
                )
            ELSE
                TRUNCATE TABLE #BatchStaging
            """
        )

    def _bulk_insert_batch_rows(self, cursor, rows: list[tuple]) -> None:
        cursor.fast_executemany = True
        cursor.setinputsizes([
            (pyodbc.SQL_CHAR, 64, 0),      # event_id CHAR(64)
            (pyodbc.SQL_DECIMAL, 19, 9),   # ts_epoch DECIMAL(19,9)
            (pyodbc.SQL_VARCHAR, 50, 0),   # event_type VARCHAR(50)
            (pyodbc.SQL_INTEGER, 0, 0),    # channel INT
            (pyodbc.SQL_INTEGER, 0, 0),    # score INT
            (pyodbc.SQL_WVARCHAR, 0, 0),   # payload NVARCHAR(MAX) - 0 = MAX
        ])
        cursor.executemany(
            "INSERT INTO #BatchStaging VALUES (?, ?, ?, ?, ?, ?)",
            rows
        )

    def _merge_batch_staging(self, cursor) -> None:
        cursor.execute("""
            MERGE curated_events AS target
            USING #BatchStaging AS source
            ON target.event_id = source.event_id
            WHEN NOT MATCHED THEN
                INSERT (event_id, ts_epoch, event_type, channel, score, payload)
                VALUES (source.event_id, source.ts_epoch, source.event_type, source.channel, source.score, source.payload);
        """)

    def _ensure_schema(self) -> None:
        """Ensure database schema exists and is up to date.

        This is a simplified version - full schema management should be
        handled by migrations or a separate schema manager.
        """
        if not self._conn:
            return

        cursor = self._conn.cursor()

        try:
            # Check if table exists
            cursor.execute("""
                SELECT 1 FROM sys.tables WHERE name = 'curated_events'
            """)
            table_exists = cursor.fetchone() is not None

            if not table_exists:
                # Create basic table (full schema should be in migrations)
                cursor.execute("""
                    CREATE TABLE curated_events (
                        id BIGINT IDENTITY,
                        event_id CHAR(64) NOT NULL,
                        ts_epoch DECIMAL(19,9) NOT NULL,
                        event_type VARCHAR(50) NOT NULL,
                        channel INT NOT NULL,
                        score INT NOT NULL,
                        payload NVARCHAR(MAX) NOT NULL,
                        inserted_at DATETIME2 DEFAULT SYSDATETIME(),
                        CONSTRAINT PK_curated_events PRIMARY KEY (event_id)
                    )
                """)
                self._conn.commit()
                logger.info("Created SQL table curated_events")

            self._ensure_attack_alerts_table(cursor)
            self._ensure_bt_tables(cursor)
        except Exception as e:
            logger.error(f"Schema check failed: {e}")

    def _ensure_attack_alerts_table(self, cursor) -> None:
        alerts_sql = """
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='attack_alerts' AND xtype='U')
        CREATE TABLE attack_alerts (
            alert_id NVARCHAR(8) NOT NULL,
            alert_signature NVARCHAR(256),
            alert_type NVARCHAR(50) NOT NULL,
            severity INT NOT NULL,
            title NVARCHAR(200),
            description NVARCHAR(500),
            ts_epoch DECIMAL(19,9) NOT NULL,
            first_seen DATETIME2 NULL,
            last_seen DATETIME2 NULL,
            source_mac NVARCHAR(17),
            target_mac NVARCHAR(17),
            bssid NVARCHAR(17),
            ssid NVARCHAR(64),
            channel INT,
            event_count INT DEFAULT 1,
            acknowledged BIT DEFAULT 0,
            acknowledged_at DATETIME2 NULL,
            inserted_at DATETIME2 DEFAULT SYSDATETIME(),
            CONSTRAINT PK_attack_alerts PRIMARY KEY (alert_id)
        )
        """
        cursor.execute(alerts_sql)
        cursor.execute(
            """
            IF COL_LENGTH('attack_alerts', 'alert_signature') IS NULL
            ALTER TABLE attack_alerts ADD alert_signature NVARCHAR(256)
            """
        )
        cursor.execute(
            """
            IF COL_LENGTH('attack_alerts', 'first_seen') IS NULL
            ALTER TABLE attack_alerts ADD first_seen DATETIME2 NULL
            """
        )
        cursor.execute(
            """
            IF COL_LENGTH('attack_alerts', 'last_seen') IS NULL
            ALTER TABLE attack_alerts ADD last_seen DATETIME2 NULL
            """
        )
        cursor.execute(
            """
            IF COL_LENGTH('attack_alerts', 'acknowledged_at') IS NULL
            ALTER TABLE attack_alerts ADD acknowledged_at DATETIME2 NULL
            """
        )
        cursor.execute(
            """
            IF COL_LENGTH('attack_alerts', 'ts_epoch') IS NULL
            ALTER TABLE attack_alerts ADD ts_epoch DECIMAL(19,9) NOT NULL DEFAULT 0
            """
        )
        cursor.execute(
            """
            IF NOT EXISTS (
                SELECT 1 FROM sys.indexes
                WHERE name = 'IX_attack_alerts_last_seen' AND object_id = OBJECT_ID('attack_alerts')
            )
            CREATE INDEX IX_attack_alerts_last_seen ON attack_alerts(ts_epoch DESC)
            """
        )

    def _collect_wids_alerts(self, events: list[dict]) -> list[dict]:
        alerts_by_id: dict[str, dict] = {}
        for event in events:
            row = build_wids_alert_row(event)
            if not row:
                continue
            alert_id = row["alert_id"]
            existing = alerts_by_id.get(alert_id)
            if not existing:
                alerts_by_id[alert_id] = row
                continue

            existing["severity"] = max(existing["severity"], row["severity"])
            existing["event_count"] += row["event_count"]
            if row["description"]:
                existing["description"] = row["description"]
            if row["title"]:
                existing["title"] = row["title"]
            if row["ts_epoch"] > existing["ts_epoch"]:
                existing["ts_epoch"] = row["ts_epoch"]
                existing["last_seen"] = row["last_seen"]
            if row["first_seen"] < existing["first_seen"]:
                existing["first_seen"] = row["first_seen"]
            alerts_by_id[alert_id] = existing

        return list(alerts_by_id.values())

    def _flush_wids_alerts(self, cursor, alert_rows: list[dict]) -> None:
        sanitized_alert_rows: list[dict[str, Any]] = [_sanitize_alert_row(row) for row in alert_rows]
        if not sanitized_alert_rows:
            return

        for row in sanitized_alert_rows:
            row["incident_id"] = None

        now = time.time()
        if now >= self._incident_grouping_suspended_until:
            im = IncidentManager(cursor)
            for row in sanitized_alert_rows:
                try:
                    # Assign to incident (creates/updates parent incident record)
                    row["incident_id"] = im.assign_incident(row)
                except Exception as e:
                    self._incident_grouping_suspended_until = now + 300.0
                    logger.warning(
                        "Incident allocation skipped for alert_id=%s (suspending 300s): %s",
                        row.get("alert_id"),
                        e,
                    )
                    break
        else:
            remaining = int(self._incident_grouping_suspended_until - now)
            logger.debug("Incident grouping suspended for %ss due to prior SQL errors.", remaining)

        rows = [
            (
                row["alert_id"],
                row["alert_signature"],
                row["alert_type"],
                row["severity"],
                row["title"],
                row["description"],
                row["ts_epoch"],
                row["first_seen"],
                row["last_seen"],
                row["source_mac"],
                row["target_mac"],
                row["bssid"],
                row["ssid"],
                row["channel"],
                row["event_count"],
                _clip_text(row.get("incident_id"), 32)
            )
            for row in sanitized_alert_rows
        ]

        self._ensure_alert_staging(cursor)
        try:
            self._bulk_insert_alert_rows(cursor, rows)
            self._merge_alert_staging(cursor)
        except Exception as bulk_error:
            logger.warning(
                "Bulk alert staging insert failed (%s); retrying row-by-row for %d alerts",
                bulk_error,
                len(rows),
            )
            dropped = 0
            cursor.fast_executemany = False
            for row in rows:
                try:
                    cursor.execute("TRUNCATE TABLE #AlertStaging")
                    cursor.execute(
                        "INSERT INTO #AlertStaging VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        row,
                    )
                    self._merge_alert_staging(cursor)
                except Exception as row_error:
                    dropped += 1
                    logger.error(
                        "Dropping invalid alert row alert_id=%s alert_type=%s ts=%s: %s",
                        row[0],
                        row[2],
                        row[6],
                        row_error,
                    )
            if dropped:
                logger.warning(
                    "Dropped %d/%d alert rows due to SQL type/constraint violations",
                    dropped,
                    len(rows),
                )

    def _ensure_alert_staging(self, cursor) -> None:
        cursor.execute(
            """
            IF OBJECT_ID('tempdb..#AlertStaging') IS NULL
                CREATE TABLE #AlertStaging (
                    alert_id NVARCHAR(8) PRIMARY KEY,
                    alert_signature NVARCHAR(256),
                    alert_type NVARCHAR(50),
                    severity INT,
                    title NVARCHAR(200),
                    description NVARCHAR(500),
                    ts_epoch DECIMAL(19,9),
                    first_seen DATETIME2,
                    last_seen DATETIME2,
                    source_mac NVARCHAR(17),
                    target_mac NVARCHAR(17),
                    bssid NVARCHAR(17),
                    ssid NVARCHAR(64),
                    channel INT,
                    event_count INT,
                    incident_id NVARCHAR(32)
                )
            ELSE
                TRUNCATE TABLE #AlertStaging
            """
        )

    def _bulk_insert_alert_rows(self, cursor, rows: list[tuple]) -> None:
        cursor.fast_executemany = True
        timestamp_type = pyodbc.SQL_TYPE_TIMESTAMP
        cursor.setinputsizes([
            (pyodbc.SQL_WVARCHAR, 8, 0),   # alert_id NVARCHAR(8)
            (pyodbc.SQL_WVARCHAR, 256, 0), # alert_signature NVARCHAR(256)
            (pyodbc.SQL_WVARCHAR, 50, 0),  # alert_type NVARCHAR(50)
            (pyodbc.SQL_INTEGER, 0, 0),    # severity INT
            (pyodbc.SQL_WVARCHAR, 200, 0), # title NVARCHAR(200)
            (pyodbc.SQL_WVARCHAR, 500, 0), # description NVARCHAR(500)
            (pyodbc.SQL_DECIMAL, 19, 9),   # ts_epoch DECIMAL(19,9)
            (timestamp_type, 0, 0), # first_seen DATETIME2
            (timestamp_type, 0, 0), # last_seen DATETIME2
            (pyodbc.SQL_WVARCHAR, 17, 0),  # source_mac NVARCHAR(17)
            (pyodbc.SQL_WVARCHAR, 17, 0),  # target_mac NVARCHAR(17)
            (pyodbc.SQL_WVARCHAR, 17, 0),  # bssid NVARCHAR(17)
            (pyodbc.SQL_WVARCHAR, 64, 0),  # ssid NVARCHAR(64)
            (pyodbc.SQL_INTEGER, 0, 0),    # channel INT
            (pyodbc.SQL_INTEGER, 0, 0),    # event_count INT
            (pyodbc.SQL_WVARCHAR, 32, 0),  # incident_id NVARCHAR(32)
        ])
        cursor.executemany(
            "INSERT INTO #AlertStaging VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows
        )

    def _merge_alert_staging(self, cursor) -> None:
        cursor.execute(
            """
            MERGE attack_alerts AS target
            USING #AlertStaging AS source
            ON target.alert_id = source.alert_id
            WHEN MATCHED THEN
                UPDATE SET
                    alert_signature = source.alert_signature,
                    alert_type = source.alert_type,
                    severity = CASE WHEN source.severity > target.severity THEN source.severity ELSE target.severity END,
                    title = source.title,
                    description = source.description,
                    ts_epoch = source.ts_epoch,
                    first_seen = COALESCE(target.first_seen, source.first_seen),
                    last_seen = source.last_seen,
                    source_mac = source.source_mac,
                    target_mac = source.target_mac,
                    bssid = source.bssid,
                    ssid = source.ssid,
                    channel = source.channel,
                    event_count = ISNULL(target.event_count, 0) + ISNULL(source.event_count, 1),
                    acknowledged = 0,
                    acknowledged_at = NULL,
                    incident_id = COALESCE(target.incident_id, source.incident_id)
            WHEN NOT MATCHED THEN
                INSERT (
                    alert_id,
                    alert_signature,
                    alert_type,
                    severity,
                    title,
                    description,
                    ts_epoch,
                    first_seen,
                    last_seen,
                    source_mac,
                    target_mac,
                    bssid,
                    ssid,
                    channel,
                    event_count,
                    acknowledged,
                    acknowledged_at,
                    incident_id
                )
                VALUES (
                    source.alert_id,
                    source.alert_signature,
                    source.alert_type,
                    source.severity,
                    source.title,
                    source.description,
                    source.ts_epoch,
                    source.first_seen,
                    source.last_seen,
                    source.source_mac,
                    source.target_mac,
                    source.bssid,
                    source.ssid,
                    source.channel,
                    source.event_count,
                    0,
                    NULL,
                    source.incident_id
                );
            """
        )

    def _flush_bt_batch(self, cursor) -> None:
        """Flush Bluetooth events to devices and observations tables."""
        if not self._bt_batch:
            return

        # Prepare Observations
        obs_rows = []
        device_updates = {}  # Addr -> dict of latest info
        connection_updates = {}

        for event in self._bt_batch:
            bt = event.get('bt', {})
            addr = _clip_text(bt.get('addr'), 17)
            if not addr:
                continue

            ts = _coerce_float(event.get('ts_epoch'), time.time())
            ts_dt = datetime.fromtimestamp(ts)
            rssi = _coerce_int(bt.get('rssi'), 0) if bt.get('rssi') is not None else None
            sensor_id = _clip_text(event.get("sensor_id"), 8)
            channel = _coerce_int(event.get('channel'), 0) if event.get('channel') is not None else None
            adv_type = _clip_text(bt.get('adv_type'), 32)
            company_id = _clip_text(bt.get('company_id'), 6)
            local_name = _clip_text(bt.get('local_name'), 128)

            # Observation Row
            obs_rows.append((
                addr,
                sensor_id,
                ts,
                rssi,
                channel,
                adv_type,
                company_id,
                json_compat.dumps(bt.get('service_uuids')),
                local_name
            ))

            # Device Profile Update (keep latest info)
            if addr not in device_updates:
                device_updates[addr] = {
                    't_first': ts_dt,
                    't_last': ts_dt,
                    'rssi_sum': 0,
                    'rssi_count': 0,
                    'rssi_max': -200,
                    'rssi_last': rssi,
                    'vendor': _clip_text(event.get('vendor'), 100), # if enriched
                    'addr_type': _clip_text(bt.get('addr_type'), 16),
                    'services': set(bt.get('service_uuids') or []),
                    'names': set(),
                    'manufacturer_data_hash': _clip_text(bt.get('manufacturer_data_hash'), 64),
                }

            d = device_updates[addr]
            if ts_dt < d['t_first']:
                d['t_first'] = ts_dt
            if ts_dt > d['t_last']:
                d['t_last'] = ts_dt

            if rssi is not None:
                d['rssi_sum'] += rssi
                d['rssi_count'] += 1
                if rssi > d['rssi_max']:
                    d['rssi_max'] = rssi
                d['rssi_last'] = rssi

            if local_name:
                d['names'].add(local_name)
            if bt.get('service_uuids'):
                d['services'].update(bt['service_uuids'])
            if bt.get('manufacturer_data_hash'):
                d['manufacturer_data_hash'] = _clip_text(bt['manufacturer_data_hash'], 64)

            access_address = bt.get('access_address')
            if access_address:
                access_lower = str(access_address).lower()
                if access_lower not in ("0x8e89bed6", "8e89bed6"):
                    peer_addr = bt.get('peer_addr')
                    conn_key = (addr, peer_addr, access_address)
                    if conn_key not in connection_updates:
                        connection_updates[conn_key] = {
                            "first_seen": ts_dt,
                            "last_seen": ts_dt,
                        }
                    else:
                        if ts_dt < connection_updates[conn_key]["first_seen"]:
                            connection_updates[conn_key]["first_seen"] = ts_dt
                        if ts_dt > connection_updates[conn_key]["last_seen"]:
                            connection_updates[conn_key]["last_seen"] = ts_dt

        # 1. Bulk Insert Observations
        if obs_rows:
            obs_sql = """
                INSERT INTO bt_observations
                (addr, sensor_id, ts_epoch, rssi, channel, adv_type, company_id, service_uuids, local_name)
                VALUES (?,?,?,?,?,?,?,?,?)
                """
            try:
                cursor.fast_executemany = True
                cursor.setinputsizes([
                    (pyodbc.SQL_CHAR, 17, 0),      # addr
                    (pyodbc.SQL_CHAR, 8, 0),       # sensor_id
                    (pyodbc.SQL_DECIMAL, 19, 9),   # ts_epoch
                    (pyodbc.SQL_INTEGER, 0, 0),    # rssi
                    (pyodbc.SQL_INTEGER, 0, 0),    # channel
                    (pyodbc.SQL_WVARCHAR, 32, 0),  # adv_type
                    (pyodbc.SQL_WVARCHAR, 6, 0),   # company_id
                    (pyodbc.SQL_WVARCHAR, 0, 0),   # service_uuids
                    (pyodbc.SQL_WVARCHAR, 128, 0), # local_name
                ])
                cursor.executemany(obs_sql, obs_rows)
            except Exception as obs_error:
                logger.warning(
                    "BT observation bulk insert failed (%s); retrying row-by-row for %d rows",
                    obs_error,
                    len(obs_rows),
                )
                dropped_obs = 0
                cursor.fast_executemany = False
                for row in obs_rows:
                    try:
                        cursor.execute(obs_sql, row)
                    except Exception as row_error:
                        dropped_obs += 1
                        logger.error(
                            "Dropping invalid BT observation addr=%s ts=%s: %s",
                            row[0],
                            row[2],
                            row_error,
                        )
                if dropped_obs:
                    logger.warning(
                        "Dropped %d/%d BT observations due to SQL type/constraint violations",
                        dropped_obs,
                        len(obs_rows),
                    )

        # 2. Merge Devices
        # Need a staging table for efficient merge
        staging_rows = []
        for addr, d in device_updates.items():
            name = next(iter(d['names'])) if d['names'] else None
            services = list(d['services']) if d['services'] else None
            staging_rows.append((
                addr,
                d['addr_type'],
                d['vendor'],
                d['t_first'],
                d['t_last'],
                d['rssi_sum'],
                d['rssi_count'],
                d['rssi_max'],
                d['rssi_last'],
                json.dumps(services) if services else None,
                name,
                d.get('manufacturer_data_hash'),
            ))

        if not staging_rows:
            return

        cursor.execute(
            """
            IF OBJECT_ID('tempdb..#BTDeviceStaging') IS NULL
                CREATE TABLE #BTDeviceStaging (
                    addr CHAR(17) PRIMARY KEY,
                    addr_type VARCHAR(16),
                    vendor NVARCHAR(100),
                    t_first DATETIME2,
                    t_last DATETIME2,
                    rssi_sum INT,
                    rssi_count INT,
                    rssi_max INT,
                    rssi_last INT,
                    services NVARCHAR(MAX),
                    local_name NVARCHAR(128),
                    manufacturer_data_hash CHAR(64)
                )
            ELSE
                TRUNCATE TABLE #BTDeviceStaging
            """
        )

        valid_staging_rows: list[tuple] = list(staging_rows)
        timestamp_type = pyodbc.SQL_TYPE_TIMESTAMP
        staging_sql = "INSERT INTO #BTDeviceStaging VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
        try:
            cursor.fast_executemany = True
            cursor.setinputsizes([
                (pyodbc.SQL_CHAR, 17, 0),      # addr
                (pyodbc.SQL_VARCHAR, 16, 0),   # addr_type
                (pyodbc.SQL_WVARCHAR, 100, 0), # vendor
                (timestamp_type, 0, 0),        # t_first
                (timestamp_type, 0, 0),        # t_last
                (pyodbc.SQL_INTEGER, 0, 0),    # rssi_sum
                (pyodbc.SQL_INTEGER, 0, 0),    # rssi_count
                (pyodbc.SQL_INTEGER, 0, 0),    # rssi_max
                (pyodbc.SQL_INTEGER, 0, 0),    # rssi_last
                (pyodbc.SQL_WVARCHAR, 0, 0),   # services
                (pyodbc.SQL_WVARCHAR, 128, 0), # local_name
                (pyodbc.SQL_CHAR, 64, 0),      # manufacturer_data_hash
            ])
            cursor.executemany(staging_sql, staging_rows)
        except Exception as staging_error:
            logger.warning(
                "BT device staging bulk insert failed (%s); retrying row-by-row for %d rows",
                staging_error,
                len(staging_rows),
            )
            valid_staging_rows = []
            dropped_devices = 0
            cursor.fast_executemany = False
            for row in staging_rows:
                try:
                    cursor.execute(staging_sql, row)
                    valid_staging_rows.append(row)
                except Exception as row_error:
                    dropped_devices += 1
                    logger.error(
                        "Dropping invalid BT device row addr=%s last_seen=%s: %s",
                        row[0],
                        row[4],
                        row_error,
                    )
            if dropped_devices:
                logger.warning(
                    "Dropped %d/%d BT device rows due to SQL type/constraint violations",
                    dropped_devices,
                    len(staging_rows),
                )

        if not valid_staging_rows:
            return

        # Load existing device state for change detection
        old_state: dict[str, dict[str, str | None]] = {}
        try:
            cursor.execute(
                """
                SELECT b.addr, b.local_name, b.services, b.manufacturer_data_hash
                FROM bt_devices AS b
                JOIN #BTDeviceStaging AS s ON b.addr = s.addr
                """
            )
            for row in cursor.fetchall():
                old_state[row[0]] = {
                    "local_name": row[1],
                    "services": row[2],
                    "manufacturer_data_hash": row[3],
                }
        except Exception:
            old_state = {}

        # Generate BLE identity change alerts before merge
        bt_alert_rows: list[dict] = []
        for row in valid_staging_rows:
            addr = row[0]
            local_name = row[10]
            services = row[9]
            manufacturer_data_hash = row[11]
            previous = old_state.get(addr)
            if not previous:
                continue

            old_name = previous.get("local_name")
            if old_name and local_name and old_name != local_name:
                bt_alert_rows.append(
                    build_ble_alert_row(
                        "ble_name_change",
                        addr,
                        f"Local name changed from '{old_name}' to '{local_name}'",
                        row[4].timestamp(),
                        local_name=local_name,
                        severity=2,
                    )
                )

            added, removed = _diff_services(previous.get("services"), services)
            if added or removed:
                parts = []
                if added:
                    parts.append("added: " + ", ".join(sorted(added)))
                if removed:
                    parts.append("removed: " + ", ".join(sorted(removed)))
                bt_alert_rows.append(
                    build_ble_alert_row(
                        "ble_services_change",
                        addr,
                        "Service UUIDs changed (" + "; ".join(parts) + ")",
                        row[4].timestamp(),
                        local_name=local_name,
                        severity=3,
                    )
                )

            old_hash = previous.get("manufacturer_data_hash")
            if old_hash and manufacturer_data_hash and old_hash != manufacturer_data_hash:
                bt_alert_rows.append(
                    build_ble_alert_row(
                        "ble_fingerprint_change",
                        addr,
                        "Manufacturer data fingerprint changed",
                        row[4].timestamp(),
                        local_name=local_name,
                        severity=4,
                    )
                )

        cursor.execute("""
            MERGE bt_devices AS target
            USING #BTDeviceStaging AS source
            ON target.addr = source.addr
            WHEN MATCHED THEN
                UPDATE SET
                    last_seen = CASE WHEN source.t_last > target.last_seen THEN source.t_last ELSE target.last_seen END,
                    rssi_sample_count = ISNULL(target.rssi_sample_count, 0) + source.rssi_count,
                    rssi_avg = CASE
                        WHEN (ISNULL(target.rssi_sample_count, 0) + source.rssi_count) > 0 THEN
                            CAST(
                                (ISNULL(target.rssi_avg, 0) * ISNULL(target.rssi_sample_count, 0) + source.rssi_sum)
                                / NULLIF(ISNULL(target.rssi_sample_count, 0) + source.rssi_count, 0)
                                AS INT
                            )
                        ELSE target.rssi_avg
                    END,
                    rssi_max = CASE WHEN source.rssi_max > ISNULL(target.rssi_max, -200) THEN source.rssi_max ELSE target.rssi_max END,
                    rssi_last = source.rssi_last,
                    rssi_last_seen = source.t_last,
                    vendor = COALESCE(target.vendor, source.vendor),
                    addr_type = COALESCE(target.addr_type, source.addr_type),
                    local_name = COALESCE(source.local_name, target.local_name),
                    services = COALESCE(source.services, target.services),
                    manufacturer_data_hash = COALESCE(source.manufacturer_data_hash, target.manufacturer_data_hash),
                    updated_at = SYSDATETIME()
            WHEN NOT MATCHED THEN
                INSERT (
                    addr, addr_type, vendor, first_seen, last_seen,
                    rssi_sample_count, rssi_avg, rssi_max, rssi_last, rssi_last_seen,
                    services, local_name, manufacturer_data_hash
                )
                VALUES (
                    source.addr, source.addr_type, source.vendor, source.t_first, source.t_last,
                    source.rssi_count,
                    CASE WHEN source.rssi_count > 0 THEN CAST(source.rssi_sum / NULLIF(source.rssi_count, 0) AS INT) ELSE NULL END,
                    source.rssi_max, source.rssi_last, source.t_last,
                    source.services, source.local_name, source.manufacturer_data_hash
                );
        """)

        if bt_alert_rows:
            self._flush_wids_alerts(cursor, bt_alert_rows)

        if connection_updates:
            conn_rows = [
                (
                    _clip_text(addr, 17),
                    _clip_text(peer_addr, 17),
                    _clip_text(access_address, 10),
                    meta["first_seen"],
                    meta["last_seen"],
                )
                for (addr, peer_addr, access_address), meta in connection_updates.items()
            ]
            cursor.execute(
                """
                IF OBJECT_ID('tempdb..#BTConnectionStaging') IS NULL
                    CREATE TABLE #BTConnectionStaging (
                        addr CHAR(17),
                        peer_addr CHAR(17),
                        access_address CHAR(10),
                        first_seen DATETIME2,
                        last_seen DATETIME2
                    )
                ELSE
                    TRUNCATE TABLE #BTConnectionStaging
                """
            )
            timestamp_type = pyodbc.SQL_TYPE_TIMESTAMP
            conn_sql = "INSERT INTO #BTConnectionStaging VALUES (?,?,?,?,?)"
            try:
                cursor.fast_executemany = True
                cursor.setinputsizes([
                    (pyodbc.SQL_CHAR, 17, 0),      # addr
                    (pyodbc.SQL_CHAR, 17, 0),      # peer_addr
                    (pyodbc.SQL_CHAR, 10, 0),      # access_address
                    (timestamp_type, 0, 0),        # first_seen
                    (timestamp_type, 0, 0),        # last_seen
                ])
                cursor.executemany(conn_sql, conn_rows)
            except Exception as conn_error:
                logger.warning(
                    "BT connection staging bulk insert failed (%s); retrying row-by-row for %d rows",
                    conn_error,
                    len(conn_rows),
                )
                dropped_connections = 0
                cursor.fast_executemany = False
                for row in conn_rows:
                    try:
                        cursor.execute(conn_sql, row)
                    except Exception as row_error:
                        dropped_connections += 1
                        logger.error(
                            "Dropping invalid BT connection row addr=%s peer=%s access=%s: %s",
                            row[0],
                            row[1],
                            row[2],
                            row_error,
                        )
                if dropped_connections:
                    logger.warning(
                        "Dropped %d/%d BT connection rows due to SQL type/constraint violations",
                        dropped_connections,
                        len(conn_rows),
                    )
            cursor.execute(
                """
                MERGE bt_connections AS target
                USING #BTConnectionStaging AS source
                ON target.addr = source.addr
                   AND ISNULL(target.peer_addr, '') = ISNULL(source.peer_addr, '')
                   AND ISNULL(target.access_address, '') = ISNULL(source.access_address, '')
                WHEN MATCHED THEN
                    UPDATE SET
                        first_seen = CASE
                            WHEN target.first_seen IS NULL OR source.first_seen < target.first_seen
                                THEN source.first_seen
                            ELSE target.first_seen
                        END,
                        last_seen = CASE
                            WHEN target.last_seen IS NULL OR source.last_seen > target.last_seen
                                THEN source.last_seen
                            ELSE target.last_seen
                        END
                WHEN NOT MATCHED THEN
                    INSERT (addr, peer_addr, access_address, first_seen, last_seen)
                    VALUES (source.addr, source.peer_addr, source.access_address, source.first_seen, source.last_seen);
                """
            )

    def _ensure_bt_tables(self, cursor) -> None:
        """Ensure Bluetooth tables exist."""
        # 12.1 Bluetooth Devices
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='bt_devices' AND xtype='U')
            CREATE TABLE bt_devices (
                addr CHAR(17) NOT NULL PRIMARY KEY,
                addr_type VARCHAR(16),
                vendor NVARCHAR(100),
                device_type VARCHAR(32),
                first_seen DATETIME2 DEFAULT SYSDATETIME(),
                last_seen DATETIME2 DEFAULT SYSDATETIME(),
                rssi_avg INT,
                rssi_max INT,
                rssi_last INT,
                rssi_sample_count INT DEFAULT 0,
                rssi_last_seen DATETIME2,
                services NVARCHAR(MAX),
                local_name NVARCHAR(128),
                manufacturer_data_hash CHAR(64),
                updated_at DATETIME2 DEFAULT SYSDATETIME()
            )
        """)
        cursor.execute(
            """
            IF COL_LENGTH('bt_devices', 'manufacturer_data_hash') IS NULL
                ALTER TABLE bt_devices ADD manufacturer_data_hash CHAR(64)
            """
        )

        # 12.2 Bluetooth Observations
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='bt_observations' AND xtype='U')
            CREATE TABLE bt_observations (
                id BIGINT IDENTITY PRIMARY KEY,
                addr CHAR(17) NOT NULL,
                sensor_id CHAR(8),
                ts_epoch DECIMAL(19,9) NOT NULL,
                rssi INT,
                channel INT,
                adv_type VARCHAR(32),
                company_id CHAR(6),
                service_uuids NVARCHAR(MAX),
                local_name NVARCHAR(128),
                inserted_at DATETIME2 DEFAULT SYSDATETIME()
            )
        """)

        # 12.3 Bluetooth Connections (future use)
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='bt_connections' AND xtype='U')
            CREATE TABLE bt_connections (
                id BIGINT IDENTITY PRIMARY KEY,
                addr CHAR(17) NOT NULL,
                peer_addr CHAR(17),
                access_address CHAR(10),
                first_seen DATETIME2,
                last_seen DATETIME2,
                inserted_at DATETIME2 DEFAULT SYSDATETIME()
            )
        """)

        # Indexes
        cursor.execute("""
            IF NOT EXISTS (
                SELECT 1 FROM sys.indexes
                WHERE name = 'IX_bt_observations_addr' AND object_id = OBJECT_ID('bt_observations')
            )
                CREATE INDEX IX_bt_observations_addr ON bt_observations(addr, ts_epoch DESC);
        """)
        cursor.execute("""
            IF NOT EXISTS (
                SELECT 1 FROM sys.indexes
                WHERE name = 'IX_bt_observations_time' AND object_id = OBJECT_ID('bt_observations')
            )
                CREATE INDEX IX_bt_observations_time ON bt_observations(ts_epoch);
        """)
