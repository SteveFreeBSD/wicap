from datetime import datetime, timezone

import src.wicap.core.processing.persistence as persistence_mod
from src.wicap.core.processing.persistence import PersistenceManager


class _DummyCursor:
    def __init__(self):
        self.fast_executemany = False
        self.execute_calls = 0
        self.executemany_calls = 0

    def execute(self, *args, **kwargs):
        self.execute_calls += 1
        return None

    def executemany(self, *args, **kwargs):
        self.executemany_calls += 1
        return None

    def setinputsizes(self, *args, **kwargs):
        return None


def test_incident_grouping_suspends_after_failure(monkeypatch):
    pm = PersistenceManager("DRIVER={dummy};SERVER=dummy")
    cursor = _DummyCursor()

    class _FailingIncidentManager:
        init_calls = 0

        def __init__(self, _cursor):
            _FailingIncidentManager.init_calls += 1

        def assign_incident(self, _row):
            raise RuntimeError("boom")

    monkeypatch.setattr(persistence_mod, "IncidentManager", _FailingIncidentManager)

    now = datetime.now(timezone.utc)
    rows = [
        {
            "alert_id": "abc12345",
            "alert_signature": "sig",
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
        }
    ]

    pm._flush_wids_alerts(cursor, rows)
    first_suspend = pm._incident_grouping_suspended_until
    assert first_suspend > 0
    assert _FailingIncidentManager.init_calls == 1

    pm._flush_wids_alerts(cursor, rows)
    assert _FailingIncidentManager.init_calls == 1
