from datetime import datetime, timezone

from nexus.intel.digest_report import DigestSnapshot, collect_digest, format_digest_markdown


class _FakeCursor:
    def __init__(self):
        self._call = 0
        self.description = None
        self._fetchall_data = []
        self._fetchone_data = None

    def execute(self, *_args, **_kwargs):
        self._call += 1
        if self._call == 1:
            self._fetchone_data = (42,)
        elif self._call == 2:
            self._fetchone_data = (3,)
        elif self._call == 3:
            self._fetchone_data = (1,)
        elif self._call == 4:
            self._fetchone_data = (7,)
        elif self._call == 5:
            self._fetchone_data = (2,)
        elif self._call == 6:
            self._fetchone_data = (4,)
        elif self._call == 7:
            self.description = [("alert_type",), ("cnt",)]
            self._fetchall_data = [("deauth_flood", 5), ("baseline_new_ssid", 2)]
        elif self._call == 8:
            self.description = [
                ("incident_id",),
                ("title",),
                ("severity",),
                ("alert_count",),
                ("first_seen",),
                ("last_seen",),
            ]
            now = datetime.now(timezone.utc)
            self._fetchall_data = [("inc-1", "Test", 3, 4, now, now)]
        return self

    def fetchone(self):
        return self._fetchone_data

    def fetchall(self):
        return list(self._fetchall_data)


class _FakeConn:
    def __init__(self):
        self.cursor_obj = _FakeCursor()

    def cursor(self):
        return self.cursor_obj


def test_format_digest_markdown():
    snapshot = DigestSnapshot(
        start_ts=1.0,
        end_ts=2.0,
        generated_at=3.0,
        totals={"events": 10, "new_wifi_devices": 2, "new_bt_devices": 1, "wids_alerts": 3, "baseline_drift": 1, "anomalies": 2},
        top_alerts=[{"alert_type": "deauth_flood", "cnt": 5}],
        incidents=[{"incident_id": "inc-1", "title": "Test", "severity": 3, "alert_count": 2}],
    )
    output = format_digest_markdown(snapshot)
    assert "WICAP Daily Digest" in output
    assert "Events: 10" in output
    assert "deauth_flood" in output


def test_collect_digest_with_fake_connection():
    conn = _FakeConn()
    snapshot = collect_digest(conn, 1.0, 2.0)
    assert snapshot.totals["events"] == 42
    assert snapshot.totals["new_wifi_devices"] == 3
    assert snapshot.totals["new_bt_devices"] == 1
