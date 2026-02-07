
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from nexus.attack_analyzer import AttackAnalyzer
from nexus.config import NexusConfig


class TestAttackAnalyzer(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock(spec=NexusConfig)
        self.config.get_sql_connection_string.return_value = "DRIVER={SQL Server};"
        self.analyzer = AttackAnalyzer(self.config)

    @patch('nexus.attack_analyzer.subprocess.run')
    @patch('nexus.attack_analyzer.pyodbc.connect')
    def test_deauth_flood_detection(self, mock_connect, mock_run):
        # 1. Setup Mock Output (simulating 60 deauths in 10 seconds = 6 fps)
        lines = []
        base_ts = 1700000000.0
        for i in range(60):
            # Format: timestamp type subtype ...
            lines.append(f"{base_ts + i*0.1} 00 0c ...")

        mock_run.return_value.stdout = "\n".join(lines)

        # 2. Run
        pcap = Path("dummy.pcap")

        # Need to patch Path.exists to true?
        # The analyzer checks if exists.
        with patch.object(Path, 'exists') as mock_exists:
            mock_exists.return_value = True
            attacks = self.analyzer.analyze_file(pcap)

        # 3. Verify
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0].attack_type, 'deauth_flood')
        self.assertEqual(attacks[0].event_count, 60)
        self.assertGreater(attacks[0].confidence, 80)

        # Verify persistence called
        mock_connect.assert_called_once()

    @patch('nexus.attack_analyzer.subprocess.run')
    def test_no_flood(self, mock_run):
        # 10 lines only (low rate)
        lines = [f"1700000{i}.0 data" for i in range(10)]
        mock_run.return_value.stdout = "\n".join(lines)

        with patch.object(Path, 'exists') as mock_exists:
            mock_exists.return_value = True
            attacks = self.analyzer.analyze_file(Path("clean.pcap"))

        self.assertEqual(len(attacks), 0)

if __name__ == '__main__':
    unittest.main()
