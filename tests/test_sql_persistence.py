
import os
import sys
import unittest
from unittest.mock import MagicMock

# Add src to path
sys.path.append(os.path.abspath("src"))

from wicap.core.processing.persistence import PersistenceManager


class TestPersistenceManager(unittest.TestCase):
    def setUp(self):
        self.pm = PersistenceManager("DRIVER={SQL Server};SERVER=test", batch_size=2)
        self.pm._conn = MagicMock()
        self.cursor = MagicMock()
        self.pm._conn.cursor.return_value = self.cursor

    def test_add_bt_event_flush(self):
        # 1. Add events
        evt1 = {
            "protocol": "bt",
            "ts_epoch": 1700000000.0,
            "bt": {
                "addr": "AA:BB:CC:DD:EE:FF",
                "rssi": -80,
                "adv_type": "ADV_IND",
                "company_id": "0x004C",
                "service_uuids": ["0xFE9F"]
            },
            "vendor": "Apple",
            "channel": 37
        }

        self.pm.add_bt_event(evt1)
        self.assertEqual(len(self.pm._bt_batch), 1)

        evt2 = dict(evt1)
        evt2["bt"]["addr"] = "11:22:33:44:55:66"

        # Trigger flush (batch_size=2)
        self.pm.add_bt_event(evt2)

        # Verify flush called
        self.assertEqual(len(self.pm._bt_batch), 0)

        # Verify SQL calls
        # We expect calls to execute() for staging table creation and merge,
        # and executemany() for observation insert and staging inserts.

        calls = self.cursor.execute.call_args_list
        queries = [str(c[0][0]) for c in calls]

        # Check for key SQL fragments
        self.assertTrue(any("CREATE TABLE #BTDeviceStaging" in q for q in queries))
        self.assertTrue(any("MERGE bt_devices" in q for q in queries))

        # Check executemany was called for observation insert
        exec_many_calls = [str(c[0][0]) for c in self.cursor.executemany.call_args_list]
        self.assertTrue(any("INSERT INTO bt_observations" in q for q in exec_many_calls))

        # Check fast_executemany was set
        self.assertTrue(self.cursor.fast_executemany)

if __name__ == "__main__":
    unittest.main()
