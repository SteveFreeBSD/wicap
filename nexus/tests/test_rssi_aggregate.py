#!/usr/bin/env python3
"""
Unit tests for RSSI aggregate math.
"""

import unittest
from datetime import datetime, timedelta

from nexus.scavenger.persistence import _merge_rssi_stats


class TestRssiAggregate(unittest.TestCase):
    def test_merge_with_no_existing(self):
        now = datetime.now()
        result = _merge_rssi_stats(None, None, None, None, None, [-50, -40], now)
        self.assertEqual(result[0], -45)
        self.assertEqual(result[1], -40)
        self.assertEqual(result[2], -40)
        self.assertEqual(result[3], 2)
        self.assertEqual(result[4], now)

    def test_running_average(self):
        now = datetime.now()
        result = _merge_rssi_stats(-60, -30, -70, 4, now, [-50, -70], now + timedelta(seconds=1))
        self.assertEqual(result[0], -60)
        self.assertEqual(result[1], -30)
        self.assertEqual(result[2], -70)
        self.assertEqual(result[3], 6)
        self.assertEqual(result[4], now + timedelta(seconds=1))

    def test_empty_samples_no_change(self):
        now = datetime.now()
        result = _merge_rssi_stats(-55, -40, -60, 10, now, [], None)
        self.assertEqual(result[0], -55)
        self.assertEqual(result[1], -40)
        self.assertEqual(result[2], -60)
        self.assertEqual(result[3], 10)
        self.assertEqual(result[4], now)

    def test_max_updates(self):
        now = datetime.now()
        result = _merge_rssi_stats(-65, -50, -70, 5, now, [-40], now + timedelta(seconds=5))
        self.assertEqual(result[1], -40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
