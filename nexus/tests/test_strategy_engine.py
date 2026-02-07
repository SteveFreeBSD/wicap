
import unittest

from nexus.strategy_engine import StrategyEngine


class TestStrategyEngine(unittest.TestCase):
    def setUp(self):
        self.engine = StrategyEngine()

    def test_vendor_lookup_netgear(self):
        # Known Netgear OUI
        bssid = "A0:04:60:11:22:33"
        vendor = self.engine._infer_vendor(bssid, "UnknownSSID")
        self.assertEqual(vendor, "Netgear")

    def test_vendor_lookup_tplink(self):
        # Known TP-Link OUI
        bssid = "14:CC:20:AA:BB:CC"
        vendor = self.engine._infer_vendor(bssid, "UnknownSSID")
        self.assertEqual(vendor, "TP-Link")

    def test_vendor_fallback_ssid(self):
        # Unknown OUI, but SSID says Netgear
        bssid = "00:11:22:33:44:55"
        vendor = self.engine._infer_vendor(bssid, "My_NETGEAR_5G")
        self.assertEqual(vendor, "Netgear")

    def test_semantic_analysis_coffee(self):
        ssid = "Starbucks_WiFi"
        semantics = self.engine._extract_semantics(ssid)
        self.assertIn("starbucks", semantics)
        # Should include related words if map is working, but basic check first

    def test_date_pattern_detection(self):
        ssid = "Conference2024"
        plan = self.engine.generate_plan(ssid, "00:00:00:00:00:00", 50)

        # Should have a date/year specific round
        strategies = [r.strategy for r in plan]
        self.assertIn('year_hybrid', strategies)

        # Check that 2024 is used in the config
        year_round = next(r for r in plan if r.strategy == 'year_hybrid')
        self.assertIn('2024', year_round.config['years'])

    def test_generate_plan_high_priority_ape(self):
        ssid = "Target_Network"
        # High priority > 70
        plan = self.engine.generate_plan(ssid, "00:00:00:00:00:00", 80)

        strategies = [r.strategy for r in plan]
        self.assertIn('ape_mode', strategies)

    def test_generate_plan_vendor_specific(self):
        # Netgear OUI
        bssid = "A0:04:60:11:22:33"
        plan = self.engine.generate_plan("Netgear-IoT", bssid, 50)

        strategies = [r.strategy for r in plan]
        # Should contain a mask attack with Netgear mask
        self.assertIn('mask', strategies)
        mask_round = next(r for r in plan if r.strategy == 'mask')
        self.assertIn('?d?d?d?d?d', mask_round.config['mask'])

if __name__ == '__main__':
    unittest.main()
