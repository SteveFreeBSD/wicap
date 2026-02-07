import os
import sys
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from nexus.intel.evidence import EvidenceCollector


def test_evidence_collector_init():
    collector = EvidenceCollector(capture_dir="tests/mock_captures")
    assert collector.has_editcap is True # Assumes editcap is installed in environment

def test_find_files_in_range():
    # Setup mock files
    mock_dir = Path("tests/mock_captures")
    mock_dir.mkdir(parents=True, exist_ok=True)

    # Create empty files
    # timestamp 1000
    (mock_dir / "dwell_20260101_100000_ch1.pcapng").touch()
    # timestamp 1030
    (mock_dir / "dwell_20260101_100030_ch1.pcapng").touch()
    # timestamp 2000 (far away)
    (mock_dir / "dwell_20260101_110000_ch1.pcapng").touch()

    collector = EvidenceCollector(capture_dir=str(mock_dir))

    # Test Request for 10:00:10 to 10:00:20 (Should match first file)
    # 2026-01-01 10:00:00 => 1767261600
    base_ts = 1767261600.0

    # Files:
    # 1. 1767261600 (Starts at 0s, ends ~30-45s)
    # 2. 1767261630 (Starts at 30s)

    # Query: 10s to 20s
    files = collector._find_files_in_range(base_ts + 10, base_ts + 20)
    assert len(files) >= 1
    assert "dwell_20260101_100000_ch1.pcapng" in str(files[0])

    # Query: 25s to 35s (Should match both, as 1st ends ~30-45, 2nd starts 30)
    files = collector._find_files_in_range(base_ts + 25, base_ts + 35)
    assert len(files) >= 2

    # Cleanup
    import shutil
    shutil.rmtree(str(mock_dir))
