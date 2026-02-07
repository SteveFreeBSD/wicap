
import os

# Adjust path to import from src
import sys
import unittest
from unittest.mock import patch

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import ScoutConfig
from scout import Scout


class TestNeuroAdaptiveGovernor(unittest.TestCase):
    def setUp(self):
        # Mock configuration
        self.config = ScoutConfig()
        self.config.scout_dwell_ms = 150 # Base dwell 150ms

        # Mock Scout instance partial
        # We don't want to init the whole scout (it requires root/hardware)
        # So we just instantiate it and mock what we need, or better, subclass it
        # But Scout.__init__ does a lot. Let's patch dependencies.

        with patch('scout.PidFile'), patch('scout.EventQueueWriter'), patch('scout.get_capture_backend'), patch('scout.EventLogger'):
             self.scout = Scout()
             self.scout.config = self.config
             self.scout.channel_reputation = {}

    def test_elastic_dwell_silence(self):
        """Test that silence causes dwell time to shrink."""
        # Setup: Channel 1, dead silence
        self.scout.channel_reputation[1] = {
            'hits': 0, 'visits': 10, 'last_visit': 0,
            'avg_yield': 0.0 # 0 pps
        }

        dwell = self.scout._calculate_dynamic_dwell(1)

        # Expect min dwell (50ms)
        self.assertEqual(dwell, 0.050)

    def test_elastic_dwell_action(self):
        """Test that high activity dilates dwell time."""
        # Setup: Channel 6, heavy traffic (40 pps)
        self.scout.channel_reputation[6] = {
            'hits': 1000, 'visits': 10, 'last_visit': 0,
            'avg_yield': 40.0
        }

        dwell = self.scout._calculate_dynamic_dwell(6)

        # Base 0.150 * (1 + 40/20) = 0.150 * 3 = 0.450s
        self.assertAlmostEqual(dwell, 0.450, places=3)

    def test_elastic_dwell_max_cap(self):
        """Test that dwell time is capped at 1.0s."""
        # Setup: Channel 11, insane traffic (1000 pps)
        self.scout.channel_reputation[11] = {
            'hits': 9999, 'visits': 10, 'last_visit': 0,
            'avg_yield': 1000.0
        }

        dwell = self.scout._calculate_dynamic_dwell(11)
        self.assertEqual(dwell, 1.0)

    def test_elastic_dwell_initial(self):
        """Test that unknown channels get base dwell."""
        # No history for channel 36
        dwell = self.scout._calculate_dynamic_dwell(36)

        # Base 150ms
        self.assertEqual(dwell, 0.150)

if __name__ == '__main__':
    unittest.main()
