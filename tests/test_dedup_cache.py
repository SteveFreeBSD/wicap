
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from src.wicap.core.processing.deduplicator import DedupCache


class TestDeduplicator(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.cache_path = self.test_dir / "dedup_cache.json"

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_deduplication_basic(self):
        cache = DedupCache(self.cache_path, window_sec=60)

        event1 = {
            'event_type': 'test',
            'keys': {'bssid': 'aa:bb:cc', 'ssid': 'test'},
            'channel': 1,
            'ts_epoch': 1000,
            'score': 10
        }

        # First seen - should keep
        self.assertTrue(cache.should_keep(event1))

        # Same event, same score - should suppress
        self.assertFalse(cache.should_keep(event1))

        # Better score - should keep
        event2 = event1.copy()
        event2['score'] = 20
        self.assertTrue(cache.should_keep(event2))

        # Lower score - should suppress
        event2['score'] = 5
        self.assertFalse(cache.should_keep(event2))

    def test_persistence(self):
        cache = DedupCache(self.cache_path)

        event = {
            'event_type': 'test',
            'keys': {'bssid': 'aa:bb:cc'},
            'channel': 1,
            'ts_epoch': time.time()
        }

        cache.should_keep(event)
        cache.save()

        # Reload
        new_cache = DedupCache(self.cache_path)
        # Should remember the event
        self.assertFalse(new_cache.should_keep(event))
