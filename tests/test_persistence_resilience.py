from datetime import datetime, timezone

import src.wicap.core.processing.persistence as persistence_mod
from src.wicap.core.processing.persistence import (
    PersistenceManager,
    _sanitize_alert_row,
    _sanitize_event_for_sql,
)


class _FallbackCursor:
    def __init__(self):
        self.fast_executemany = False
        self.batch_row_inserts = []
        self.alert_row_inserts = []

    def execute(self, query, *params):
        upper_q = query.upper()
        row = params[0] if params else None
        if "INSERT INTO #BATCHSTAGING VALUES" in upper_q and row is not None:
            self.batch_row_inserts.append(row)
            if row[0] == "bad":
                raise RuntimeError("bad batch row")
        if "INSERT INTO #ALERTSTAGING VALUES" in upper_q and row is not None:
            self.alert_row_inserts.append(row)
            if row[0] == "badid":
                raise RuntimeError("bad alert row")
        return None

    def executemany(self, *_args, **_kwargs):
        raise RuntimeError("force bulk failure")

    def setinputsizes(self, *_args, **_kwargs):
        return None

    def fetchall(self):
        return []


def test_sanitize_event_for_sql_normalizes_wifi6_flag():
    ev_true = {"fingerprint": {"is_wifi6": "YES"}}
    out_true = _sanitize_event_for_sql(ev_true)
    assert out_true["fingerprint"]["is_wifi6"] is True

    ev_invalid = {"fingerprint": {"is_wifi6": "maybe"}}
    out_invalid = _sanitize_event_for_sql(ev_invalid)
    assert "is_wifi6" not in out_invalid["fingerprint"]


def test_sanitize_alert_row_coerces_and_clips():
    row = {
        "alert_id": "toolongid123",
        "alert_signature": "s" * 400,
        "alert_type": "t" * 80,
        "severity": "bad",
        "title": "x" * 400,
        "description": "d" * 700,
        "ts_epoch": "nan",
        "first_seen": "not-a-datetime",
        "last_seen": None,
        "source_mac": "AA:BB:CC:DD:EE:FF:11",
        "target_mac": "11:22:33:44:55:66:77",
        "bssid": "66:55:44:33:22:11:99",
        "ssid": "s" * 200,
        "channel": "bad",
        "event_count": "bad",
        "incident_id": "i" * 64,
    }
    out = _sanitize_alert_row(row)
    assert len(out["alert_id"]) == 8
    assert len(out["alert_signature"]) <= 256
    assert len(out["alert_type"]) == 50
    assert out["severity"] == 1
    assert len(out["title"]) == 200
    assert len(out["description"]) == 500
    assert isinstance(out["first_seen"], datetime)
    assert isinstance(out["last_seen"], datetime)
    assert out["channel"] == 0
    assert out["event_count"] == 1
    assert len(out["incident_id"]) == 32


def test_flush_batch_falls_back_to_row_mode_and_drops_bad_rows():
    pm = PersistenceManager("DRIVER={dummy};SERVER=dummy")
    pm._batch = [
        {"event_id": "good", "ts_epoch": 1.0, "event_type": "other", "channel": 1, "score": 1},
        {"event_id": "bad", "ts_epoch": 2.0, "event_type": "other", "channel": 1, "score": 1},
    ]

    cursor = _FallbackCursor()
    pm._flush_batch(cursor)
    attempted_ids = [row[0] for row in cursor.batch_row_inserts]
    assert attempted_ids == ["good", "bad"]


def test_flush_wids_alerts_falls_back_to_row_mode_and_drops_bad_rows(monkeypatch):
    class _NoopIncidentManager:
        def __init__(self, _cursor):
            pass

        def assign_incident(self, _row):
            return None

    monkeypatch.setattr(persistence_mod, "IncidentManager", _NoopIncidentManager)

    pm = PersistenceManager("DRIVER={dummy};SERVER=dummy")
    cursor = _FallbackCursor()
    now = datetime.now(timezone.utc)
    rows = [
        {
            "alert_id": "goodid1",
            "alert_signature": "sig1",
            "alert_type": "ble_name_change",
            "severity": 2,
            "title": "Title",
            "description": "Desc",
            "ts_epoch": 1700000000.0,
            "first_seen": now,
            "last_seen": now,
            "source_mac": "AA:BB:CC:DD:EE:FF",
            "target_mac": None,
            "bssid": None,
            "ssid": "Demo",
            "channel": 37,
            "event_count": 1,
        },
        {
            "alert_id": "badid",
            "alert_signature": "sig2",
            "alert_type": "ble_name_change",
            "severity": 2,
            "title": "Title",
            "description": "Desc",
            "ts_epoch": 1700000001.0,
            "first_seen": now,
            "last_seen": now,
            "source_mac": "AA:BB:CC:DD:EE:11",
            "target_mac": None,
            "bssid": None,
            "ssid": "Demo2",
            "channel": 38,
            "event_count": 1,
        },
    ]

    pm._flush_wids_alerts(cursor, rows)
    attempted_ids = [row[0] for row in cursor.alert_row_inserts]
    assert attempted_ids == ["goodid1", "badid"]
