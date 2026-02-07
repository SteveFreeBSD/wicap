
from src.wicap.core.processing.persistence import PersistenceManager, _coerce_float


class _DummyCursor:
    def __init__(self):
        self.fast_executemany = False
        self.executed_many = []

    def execute(self, *args, **kwargs):
        return None

    def executemany(self, query, rows):
        self.executed_many.append((query, list(rows)))
        return None

    def setinputsizes(self, *args, **kwargs):
        return None

    def fetchall(self):
        return []


def test_coerce_float_rejects_nan_and_inf():
    assert _coerce_float("nan", 1.25) == 1.25
    assert _coerce_float(float("inf"), 2.5) == 2.5
    assert _coerce_float("-inf", 3.75) == 3.75
    assert _coerce_float("42.5", 0.0) == 42.5


def test_bt_flush_sanitizes_non_numeric_fields():
    pm = PersistenceManager("DRIVER={dummy};SERVER=dummy")
    pm._bt_batch = [
        {
            "ts_epoch": "nan",
            "channel": "bad-channel",
            "sensor_id": "sensor-id-too-long",
            "bt": {
                "addr": "AA:BB:CC:DD:EE:FF",
                "rssi": "bad-rssi",
                "adv_type": "ADV_IND" * 20,
                "company_id": 65535,
                "service_uuids": ["0x180f"],
                "local_name": "N" * 300,
                "addr_type": "randomized-public-too-long",
                "manufacturer_data_hash": "f" * 200,
            },
            "vendor": "V" * 200,
        }
    ]

    cursor = _DummyCursor()
    pm._flush_bt_batch(cursor)

    assert cursor.executed_many, "Expected bt_observations insert"
    query, rows = cursor.executed_many[0]
    assert "INSERT INTO bt_observations" in query
    row = rows[0]

    assert row[0] == "AA:BB:CC:DD:EE:FF"
    assert len(row[1]) == 8  # sensor_id CHAR(8)
    assert isinstance(row[2], float)
    assert isinstance(row[3], int)
    assert row[4] == 0  # bad channel coerced
    assert len(row[5]) == 32
    assert len(row[6]) <= 6
    assert len(row[8]) == 128
