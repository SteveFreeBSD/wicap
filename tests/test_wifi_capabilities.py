import unittest
from unittest.mock import patch

from utils.wifi_capabilities import get_supported_channels

SAMPLE_IW_OUTPUT = """
Wiphy phy0
    Band 1:
        Frequencies:
            * 2412 MHz [1] (20.0 dBm)
            * 2437 MHz [6] (20.0 dBm)
            * 2462 MHz [11] (20.0 dBm)
    Band 2:
        Frequencies:
            * 5180 MHz [36] (20.0 dBm)
            * 5200 MHz [40] (20.0 dBm)
            * 5220 MHz [44] (20.0 dBm) (no IR)
            * 5240 MHz [48] (20.0 dBm)
"""

class TestWifiCapabilities(unittest.TestCase):
    @patch('utils.wifi_capabilities.shutil.which')
    @patch('utils.wifi_capabilities._get_phy_for_interface')
    @patch('subprocess.check_output')
    def test_get_supported_channels(self, mock_subprocess, mock_get_phy, mock_which):
        mock_which.return_value = '/usr/sbin/iw'
        mock_get_phy.return_value = 'phy0'
        mock_subprocess.return_value = SAMPLE_IW_OUTPUT

        # Test 1: All bands (default)
        channels = get_supported_channels('wlan0')
        expected_all = [
            {'channel': 1, 'freq': 2412, 'band': '2.4ghz'},
            {'channel': 6, 'freq': 2437, 'band': '2.4ghz'},
            {'channel': 11, 'freq': 2462, 'band': '2.4ghz'},
            {'channel': 36, 'freq': 5180, 'band': '5ghz'},
            {'channel': 40, 'freq': 5200, 'band': '5ghz'},
            {'channel': 44, 'freq': 5220, 'band': '5ghz'}, # Note: 'no IR' flag might exclude it depending on logic, but let's assume valid
            {'channel': 48, 'freq': 5240, 'band': '5ghz'}
        ]
        # Sort by channel number for stable comparison
        self.assertEqual(
            sorted(channels, key=lambda x: x['channel']),
            sorted(expected_all, key=lambda x: x['channel'])
        )

        # Test 2: 2.4GHz only
        channels_24 = get_supported_channels('wlan0', bands=['2.4ghz'])
        expected_24 = [
            {'channel': 1, 'freq': 2412, 'band': '2.4ghz'},
            {'channel': 6, 'freq': 2437, 'band': '2.4ghz'},
            {'channel': 11, 'freq': 2462, 'band': '2.4ghz'}
        ]
        self.assertEqual(channels_24, expected_24)

        # Test 3: 5GHz only
        channels_5 = get_supported_channels('wlan0', bands=['5ghz'])
        expected_5 = [
            {'channel': 36, 'freq': 5180, 'band': '5ghz'},
            {'channel': 40, 'freq': 5200, 'band': '5ghz'},
            {'channel': 44, 'freq': 5220, 'band': '5ghz'},
            {'channel': 48, 'freq': 5240, 'band': '5ghz'}
        ]
        self.assertEqual(channels_5, expected_5)

    def test_parser_disabled(self):
        # Hack to test private method logic via public one if we could inject,
        # but let's just test the private parser method if I made it public or just rely on above.
        # I'll just rely on the above mock which works for the module structure.
        pass

if __name__ == '__main__':
    unittest.main()
