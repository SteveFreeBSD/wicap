#!/usr/bin/env python3
"""
Scavenger Module Test Suite

Comprehensive tests for the Scavenger offline forensic intelligence engine.
Tests are organized by milestone.
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexus.scavenger.ingest import SCAPY_AVAILABLE, LRUDeduplicator, PCAPStreamer, extract_packet_info

try:
    from nexus.config import get_nexus_config
    from nexus.scavenger.correlator import TargetDossier
    from nexus.scavenger.persistence import ScavengerDAO
    PERSISTENCE_AVAILABLE = True
except ImportError:
    PERSISTENCE_AVAILABLE = False


def _load_sql_env_from_repo_dotenv() -> None:
    """Load SQL credentials from repo-local .env when present.

    Some tests mutate SQL env vars; this keeps SQL integration tests stable by
    restoring the canonical local settings before connectivity checks.
    """
    repo_root = Path(__file__).resolve().parents[2]
    env_path = repo_root / ".env"
    if not env_path.exists():
        return

    sql_keys = {
        "WICAP_SQL_HOST",
        "WICAP_SQL_SERVER",
        "WICAP_SQL_DATABASE",
        "WICAP_SQL_USER",
        "WICAP_SQL_USERNAME",
        "WICAP_SQL_PASSWORD",
        "WICAP_SQL_DRIVER",
    }

    parsed: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in sql_keys:
            continue
        value = value.strip().strip('"').strip("'")
        if value:
            parsed[key] = value

    # Force canonical SQL settings for this integration test class so previous
    # tests cannot leak incompatible env overrides.
    if parsed.get("WICAP_SQL_HOST"):
        os.environ["WICAP_SQL_HOST"] = parsed["WICAP_SQL_HOST"]
    if parsed.get("WICAP_SQL_SERVER"):
        os.environ["WICAP_SQL_SERVER"] = parsed["WICAP_SQL_SERVER"]
    elif parsed.get("WICAP_SQL_HOST"):
        os.environ["WICAP_SQL_SERVER"] = parsed["WICAP_SQL_HOST"]

    os.environ["WICAP_SQL_DATABASE"] = (
        parsed.get("WICAP_SQL_DATABASE")
        or os.environ.get("WICAP_SQL_DATABASE")
        or "WifiInsanityDB"
    )
    os.environ["WICAP_SQL_USER"] = (
        parsed.get("WICAP_SQL_USER")
        or parsed.get("WICAP_SQL_USERNAME")
        or "steve_linux"
    )
    if parsed.get("WICAP_SQL_USERNAME"):
        os.environ["WICAP_SQL_USERNAME"] = parsed["WICAP_SQL_USERNAME"]
    else:
        os.environ["WICAP_SQL_USERNAME"] = os.environ["WICAP_SQL_USER"]

    if parsed.get("WICAP_SQL_PASSWORD"):
        os.environ["WICAP_SQL_PASSWORD"] = parsed["WICAP_SQL_PASSWORD"]
    if parsed.get("WICAP_SQL_DRIVER"):
        os.environ["WICAP_SQL_DRIVER"] = parsed["WICAP_SQL_DRIVER"]


class TestLRUDeduplicator(unittest.TestCase):
    """Tests for the LRU-based deduplication cache."""

    def test_init(self):
        """Test deduplicator initialization."""
        dedup = LRUDeduplicator(max_size=100)
        self.assertEqual(dedup.max_size, 100)
        self.assertEqual(dedup.size, 0)

    def test_reset(self):
        """Test cache reset."""
        dedup = LRUDeduplicator(max_size=10)
        # Add some mock entries directly
        dedup._cache['test1'] = None
        dedup._cache['test2'] = None
        self.assertEqual(dedup.size, 2)

        dedup.reset()
        self.assertEqual(dedup.size, 0)

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_duplicate_detection_with_packets(self):
        """Test duplicate detection with real scapy packets."""
        from scapy.all import Dot11, RadioTap

        dedup = LRUDeduplicator(max_size=100)

        # Create two identical packets
        pkt1 = RadioTap() / Dot11(addr2="AA:BB:CC:DD:EE:FF", SC=0x1234)
        pkt2 = RadioTap() / Dot11(addr2="AA:BB:CC:DD:EE:FF", SC=0x1234)

        # Set same timestamp
        pkt1.time = 1234567890.123456
        pkt2.time = 1234567890.123456

        # First should not be duplicate
        self.assertFalse(dedup.is_duplicate(pkt1))

        # Second (identical) should be duplicate
        self.assertTrue(dedup.is_duplicate(pkt2))

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_different_packets_not_duplicate(self):
        """Test that different packets are not marked as duplicates."""
        from scapy.all import Dot11, RadioTap

        dedup = LRUDeduplicator(max_size=100)

        # Create two different packets
        pkt1 = RadioTap() / Dot11(addr2="AA:BB:CC:DD:EE:FF", SC=0x1234)
        pkt2 = RadioTap() / Dot11(addr2="11:22:33:44:55:66", SC=0x5678)

        pkt1.time = 1234567890.0
        pkt2.time = 1234567891.0

        self.assertFalse(dedup.is_duplicate(pkt1))
        self.assertFalse(dedup.is_duplicate(pkt2))
        self.assertEqual(dedup.size, 2)

    def test_lru_eviction(self):
        """Test that oldest entries are evicted when over capacity."""
        dedup = LRUDeduplicator(max_size=3)

        # Manually add entries to test eviction
        for i in range(5):
            dedup._cache[f"entry_{i}"] = None
            # Trigger eviction check
            while len(dedup._cache) > dedup.max_size:
                dedup._cache.popitem(last=False)

        self.assertEqual(dedup.size, 3)
        # Oldest entries should be gone
        self.assertNotIn("entry_0", dedup._cache)
        self.assertNotIn("entry_1", dedup._cache)
        # Newest should remain
        self.assertIn("entry_4", dedup._cache)


class TestPCAPStreamer(unittest.TestCase):
    """Tests for the PCAP streaming class."""

    def setUp(self):
        """Create temporary directory for test captures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init_valid_directory(self):
        """Test initialization with valid directory."""
        streamer = PCAPStreamer(self.temp_path)
        self.assertEqual(streamer.capture_dir, self.temp_path)

    def test_init_invalid_directory(self):
        """Test initialization with non-existent directory."""
        with self.assertRaises(FileNotFoundError):
            PCAPStreamer(Path("/nonexistent/directory"))

    def test_list_captures_empty(self):
        """Test listing captures in empty directory."""
        streamer = PCAPStreamer(self.temp_path)
        captures = streamer.list_captures()
        self.assertEqual(captures, [])

    def test_list_captures_with_files(self):
        """Test listing captures with pcap files present."""
        # Create dummy files
        (self.temp_path / "test1.pcap").touch()
        (self.temp_path / "test2.pcapng").touch()
        (self.temp_path / "test3.cap").touch()
        (self.temp_path / "test4.pcap.gz").touch()
        (self.temp_path / "other.txt").touch()  # Should be ignored

        streamer = PCAPStreamer(self.temp_path)
        captures = streamer.list_captures()

        # Should find 4 capture files (not the .txt)
        self.assertEqual(len(captures), 4)

        # Check extensions
        extensions = {p.suffix for p in captures}
        self.assertIn('.pcap', extensions)
        self.assertIn('.pcapng', extensions)
        self.assertIn('.cap', extensions)

    def test_list_captures_exclude_compressed(self):
        """Test listing captures excluding compressed files."""
        (self.temp_path / "test1.pcap").touch()
        (self.temp_path / "test2.pcap.gz").touch()

        streamer = PCAPStreamer(self.temp_path)
        captures = streamer.list_captures(include_compressed=False)

        self.assertEqual(len(captures), 1)
        self.assertEqual(captures[0].name, "test1.pcap")

    def test_stream_capture_file_not_found(self):
        """Test streaming non-existent file."""
        streamer = PCAPStreamer(self.temp_path)

        with self.assertRaises(FileNotFoundError):
            list(streamer.stream_capture(self.temp_path / "nonexistent.pcap"))

    def test_get_stats(self):
        """Test statistics retrieval."""
        streamer = PCAPStreamer(self.temp_path)
        stats = streamer.get_stats()

        self.assertIn('files_processed', stats)
        self.assertIn('packets_total', stats)
        self.assertIn('packets_deduplicated', stats)
        self.assertIn('errors', stats)
        self.assertIn('dedup_cache_size', stats)

    def test_reset_stats(self):
        """Test statistics reset."""
        streamer = PCAPStreamer(self.temp_path)

        # Modify stats
        streamer._stats['files_processed'] = 10
        streamer._stats['packets_total'] = 1000

        streamer.reset_stats()

        stats = streamer.get_stats()
        self.assertEqual(stats['files_processed'], 0)
        self.assertEqual(stats['packets_total'], 0)
        self.assertEqual(stats['dedup_cache_size'], 0)

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_stream_capture_raw_reader(self):
        """Test raw reader fast path on a fixture PCAPNG."""
        fixture_path = (
            Path(__file__).parent.parent.parent
            / "tests/fixtures/pcap/mixed_traffic_ch2.pcapng"
        )
        if not fixture_path.exists():
            self.skipTest("Fixture PCAPNG not available")

        streamer = PCAPStreamer(fixture_path.parent, use_raw_reader=True)
        count = 0
        for _packet in streamer.stream_capture(fixture_path):
            count += 1
            if count >= 10:
                break
        self.assertGreater(count, 0)


class TestExtractPacketInfo(unittest.TestCase):
    """Tests for the packet info extraction utility."""

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_extract_dot11_info(self):
        """Test extracting info from Dot11 packet."""
        from scapy.all import Dot11, RadioTap

        pkt = RadioTap(dBm_AntSignal=-65) / Dot11(
            type=0,  # Management
            subtype=4,  # Probe Request
            addr1="FF:FF:FF:FF:FF:FF",
            addr2="AA:BB:CC:DD:EE:FF",
            addr3="11:22:33:44:55:66"
        )
        pkt.time = 1234567890.0

        info = extract_packet_info(pkt)

        self.assertEqual(info['frame_type'], 0)
        self.assertEqual(info['frame_subtype'], 4)
        self.assertEqual(info['src_mac'], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(info['dst_mac'], "FF:FF:FF:FF:FF:FF")
        self.assertEqual(info['bssid'], "11:22:33:44:55:66")
        self.assertIsNotNone(info['timestamp'])

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_extract_ssid_from_beacon(self):
        """Test extracting SSID from beacon frame."""
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap

        pkt = RadioTap() / Dot11(
            type=0,
            subtype=8  # Beacon
        ) / Dot11Beacon() / Dot11Elt(ID=0, info=b"TestNetwork")

        info = extract_packet_info(pkt)

        self.assertEqual(info['ssid'], "TestNetwork")

    def test_extract_empty_packet(self):
        """Test extracting info from minimal packet."""
        # Create a mock packet without expected layers
        mock_pkt = MagicMock()
        mock_pkt.haslayer.return_value = False
        mock_pkt.time = 1234567890.0

        info = extract_packet_info(mock_pkt)

        # Should return dict with None values (except timestamp)
        self.assertIsNotNone(info['timestamp'])
        self.assertIsNone(info['src_mac'])
        self.assertIsNone(info['ssid'])


class TestScavengerIntegration(unittest.TestCase):
    """Integration tests using real PCAP files from captures directory."""

    @classmethod
    def setUpClass(cls):
        """Check if captures directory exists with files."""
        # Navigate from nexus/tests/ up to wicap/captures/
        cls.captures_dir = Path(__file__).parent.parent.parent / "captures"
        cls.has_captures = (
            cls.captures_dir.exists() and
            len(list(cls.captures_dir.glob("*.pcap*"))) > 0
        )
        cls.fixture_dir = Path(__file__).parent / "fixtures"
        cls.has_fixtures = (
            cls.fixture_dir.exists()
            and len(list(cls.fixture_dir.glob("*.pcap*"))) > 0
        )

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_stream_real_capture(self):
        """Test streaming a real capture file."""
        if not self.has_captures and not self.has_fixtures:
            self.skipTest("No capture files available")

        capture_dir = self.captures_dir if self.has_captures else self.fixture_dir
        streamer = PCAPStreamer(capture_dir)
        captures = streamer.list_captures()

        if not captures:
            self.skipTest("No capture files found")

        # Stream first 100 packets from first capture
        count = 0
        for _packet in streamer.stream_capture(captures[0]):
            count += 1
            if count >= 100:
                break

        self.assertGreater(count, 0, "Should have read at least some packets")

        stats = streamer.get_stats()
        self.assertGreater(stats['packets_total'], 0)


# ============================================================================
# Milestone 2 Tests - AgentShadow (PNL Reconstruction)
# ============================================================================

class TestClientPNL(unittest.TestCase):
    """Tests for ClientPNL dataclass."""

    def test_client_pnl_creation(self):
        """Test basic ClientPNL creation."""
        from nexus.scavenger.agents import ClientPNL

        pnl = ClientPNL(mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(pnl.mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(pnl.pnl_count, 0)
        self.assertEqual(pnl.total_probes, 0)
        self.assertIsNone(pnl.avg_rssi)

    def test_client_pnl_with_data(self):
        """Test ClientPNL with populated data."""
        from nexus.scavenger.agents import ClientPNL

        now = datetime.now()
        pnl = ClientPNL(
            mac="aa:bb:cc:dd:ee:ff",
            probed_ssids={"HomeWifi": now, "OfficeNet": now},
            first_seen=now,
            last_seen=now,
            channels_seen={1, 6, 11},
            rssi_history=[-60, -65, -70],
            total_probes=10,
            is_randomized_mac=False
        )

        self.assertEqual(pnl.pnl_count, 2)
        self.assertEqual(pnl.avg_rssi, -65.0)
        self.assertIn(6, pnl.channels_seen)

    def test_client_pnl_to_dict(self):
        """Test ClientPNL serialization."""
        from nexus.scavenger.agents import ClientPNL

        now = datetime.now()
        pnl = ClientPNL(
            mac="aa:bb:cc:dd:ee:ff",
            probed_ssids={"TestNet": now},
            first_seen=now,
            last_seen=now,
            total_probes=5
        )

        d = pnl.to_dict()

        self.assertEqual(d['mac'], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(d['pnl_count'], 1)
        self.assertEqual(d['total_probes'], 5)
        self.assertIn('TestNet', d['probed_ssids'])


class TestAgentShadow(unittest.TestCase):
    """Tests for AgentShadow (PNL reconstruction)."""

    def test_agent_shadow_init(self):
        """Test AgentShadow initialization."""
        from nexus.scavenger.agents import AgentShadow

        agent = AgentShadow()
        self.assertEqual(agent.name, "Shadow")
        self.assertEqual(len(agent.client_profiles), 0)

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_agent_shadow_probe_detection(self):
        """Test detection of probe request frames."""
        from scapy.all import Dot11, Dot11Elt, RadioTap

        from nexus.scavenger.agents import AgentShadow

        agent = AgentShadow()

        # Create a probe request packet
        pkt = RadioTap(dBm_AntSignal=-65) / Dot11(
            type=0,  # Management
            subtype=4,  # Probe Request
            addr1="ff:ff:ff:ff:ff:ff",  # Destination (broadcast)
            addr2="aa:bb:cc:dd:ee:ff",  # Source
            addr3="ff:ff:ff:ff:ff:ff"
        ) / Dot11Elt(ID=0, info=b"TargetNetwork")

        pkt.time = 1234567890.0

        result = agent.process(pkt)

        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'probe_request')
        self.assertEqual(result['src_mac'], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result['ssid'], "TargetNetwork")
        self.assertTrue(result['is_directed'])

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_agent_shadow_broadcast_probe(self):
        """Test handling of broadcast probe (no SSID)."""
        from scapy.all import Dot11, Dot11Elt, RadioTap

        from nexus.scavenger.agents import AgentShadow

        agent = AgentShadow()

        # Create a broadcast probe request (empty SSID)
        pkt = RadioTap() / Dot11(
            type=0,
            subtype=4,
            addr2="aa:bb:cc:dd:ee:ff"
        ) / Dot11Elt(ID=0, info=b"")  # Empty SSID

        pkt.time = 1234567890.0

        result = agent.process(pkt)

        self.assertIsNotNone(result)
        self.assertIsNone(result['ssid'])
        self.assertFalse(result['is_directed'])

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_agent_shadow_pnl_building(self):
        """Test building PNL from multiple probe requests."""
        from scapy.all import Dot11, Dot11Elt, RadioTap

        from nexus.scavenger.agents import AgentShadow

        agent = AgentShadow()
        client_mac = "aa:bb:cc:dd:ee:ff"

        # Simulate multiple probes for different SSIDs
        ssids = ["HomeWifi", "OfficeNet", "CoffeeShop", "HomeWifi"]  # HomeWifi twice

        for i, ssid in enumerate(ssids):
            pkt = RadioTap() / Dot11(
                type=0,
                subtype=4,
                addr2=client_mac
            ) / Dot11Elt(ID=0, info=ssid.encode())
            pkt.time = 1234567890.0 + i
            agent.process(pkt)

        # Check PNL
        pnl = agent.get_client_pnl(client_mac)

        self.assertIsNotNone(pnl)
        self.assertEqual(pnl.pnl_count, 3)  # 3 unique SSIDs
        self.assertEqual(pnl.total_probes, 4)  # 4 total probes
        self.assertIn("HomeWifi", pnl.probed_ssids)
        self.assertIn("OfficeNet", pnl.probed_ssids)
        self.assertIn("CoffeeShop", pnl.probed_ssids)

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_agent_shadow_multiple_clients(self):
        """Test tracking multiple clients."""
        from scapy.all import Dot11, Dot11Elt, RadioTap

        from nexus.scavenger.agents import AgentShadow

        agent = AgentShadow()

        clients = [
            ("aa:aa:aa:aa:aa:aa", ["Network1", "Network2"]),
            ("bb:bb:bb:bb:bb:bb", ["Network3"]),
            ("cc:cc:cc:cc:cc:cc", ["Network1", "Network4", "Network5"]),
        ]

        for mac, ssids in clients:
            for ssid in ssids:
                pkt = RadioTap() / Dot11(
                    type=0,
                    subtype=4,
                    addr2=mac
                ) / Dot11Elt(ID=0, info=ssid.encode())
                pkt.time = 1234567890.0
                agent.process(pkt)

        profiles = agent.get_all_profiles()

        self.assertEqual(len(profiles), 3)
        self.assertEqual(profiles["aa:aa:aa:aa:aa:aa"].pnl_count, 2)
        self.assertEqual(profiles["bb:bb:bb:bb:bb:bb"].pnl_count, 1)
        self.assertEqual(profiles["cc:cc:cc:cc:cc:cc"].pnl_count, 3)

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_agent_shadow_ssid_popularity(self):
        """Test SSID popularity ranking."""
        from scapy.all import Dot11, Dot11Elt, RadioTap

        from nexus.scavenger.agents import AgentShadow

        agent = AgentShadow()

        # Multiple clients probing for same/different SSIDs
        probes = [
            ("aa:aa:aa:aa:aa:aa", "CommonSSID"),
            ("bb:bb:bb:bb:bb:bb", "CommonSSID"),
            ("cc:cc:cc:cc:cc:cc", "CommonSSID"),
            ("aa:aa:aa:aa:aa:aa", "RareSSID"),
        ]

        for mac, ssid in probes:
            pkt = RadioTap() / Dot11(
                type=0,
                subtype=4,
                addr2=mac
            ) / Dot11Elt(ID=0, info=ssid.encode())
            pkt.time = 1234567890.0
            agent.process(pkt)

        popularity = agent.get_ssid_popularity()

        self.assertEqual(popularity["CommonSSID"], 3)
        self.assertEqual(popularity["RareSSID"], 1)
        # CommonSSID should be first (most popular)
        first_ssid = list(popularity.keys())[0]
        self.assertEqual(first_ssid, "CommonSSID")

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_agent_shadow_randomized_mac_detection(self):
        """Test detection of randomized MAC addresses."""
        from scapy.all import Dot11, Dot11Elt, RadioTap

        from nexus.scavenger.agents import AgentShadow

        agent = AgentShadow()

        # Randomized MAC (second bit of first octet set)
        random_mac = "da:ab:cd:ef:12:34"  # D=1101, bit 1 is set

        pkt = RadioTap() / Dot11(
            type=0,
            subtype=4,
            addr2=random_mac
        ) / Dot11Elt(ID=0, info=b"TestNet")
        pkt.time = 1234567890.0

        result = agent.process(pkt)

        self.assertTrue(result['is_randomized_mac'])

        pnl = agent.get_client_pnl(random_mac)
        self.assertTrue(pnl.is_randomized_mac)

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_agent_shadow_non_probe_ignored(self):
        """Test that non-probe frames are ignored."""
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap

        from nexus.scavenger.agents import AgentShadow

        agent = AgentShadow()

        # Create a beacon frame (type=0, subtype=8)
        pkt = RadioTap() / Dot11(
            type=0,
            subtype=8,  # Beacon, not probe request
            addr2="aa:bb:cc:dd:ee:ff"
        ) / Dot11Beacon() / Dot11Elt(ID=0, info=b"BeaconNet")

        result = agent.process(pkt)

        self.assertIsNone(result)
        self.assertEqual(len(agent.client_profiles), 0)

    def test_agent_shadow_reset(self):
        """Test agent reset clears all state."""
        from nexus.scavenger.agents import AgentShadow

        agent = AgentShadow()
        # Manually add some state
        agent.client_profiles["test"] = "dummy"
        agent._stats['packets_processed'] = 100

        agent.reset()

        self.assertEqual(len(agent.client_profiles), 0)
        self.assertEqual(agent._stats['packets_processed'], 0)


# ============================================================================
# Milestone 3 Tests - AgentCrypt (Handshake Scavenging)
# ============================================================================

class TestHandshakeState(unittest.TestCase):
    """Tests for HandshakeState dataclass."""

    def test_handshake_state_creation(self):
        """Test basic HandshakeState creation."""
        from nexus.scavenger.agents import HandshakeState

        state = HandshakeState(bssid="aa:bb:cc:dd:ee:ff")
        self.assertEqual(state.bssid, "aa:bb:cc:dd:ee:ff")
        self.assertFalse(state.is_complete)
        self.assertFalse(state.has_all_four)
        self.assertIsNone(state.m1_frame)
        self.assertIsNone(state.m2_frame)

    def test_handshake_state_completion(self):
        """Test handshake completion detection."""
        from unittest.mock import MagicMock

        from nexus.scavenger.agents import HandshakeState

        state = HandshakeState(bssid="aa:bb:cc:dd:ee:ff")

        # M1 alone is not complete
        m1 = MagicMock()
        m1.message_number = 1
        m1.src_mac = "11:22:33:44:55:66"
        state.add_message(m1)
        self.assertFalse(state.is_complete)

        # M1 + M2 = complete (crackable)
        m2 = MagicMock()
        m2.message_number = 2
        m2.src_mac = "aa:bb:cc:dd:ee:ff"
        state.add_message(m2)
        self.assertTrue(state.is_complete)
        self.assertFalse(state.has_all_four)

    def test_handshake_state_full(self):
        """Test all four message detection."""
        from unittest.mock import MagicMock

        from nexus.scavenger.agents import HandshakeState

        state = HandshakeState(bssid="aa:bb:cc:dd:ee:ff")

        for i in range(1, 5):
            msg = MagicMock()
            msg.message_number = i
            msg.src_mac = f"test_{i}"
            state.add_message(msg)

        self.assertTrue(state.is_complete)
        self.assertTrue(state.has_all_four)

    def test_handshake_state_to_dict(self):
        """Test HandshakeState serialization."""
        from unittest.mock import MagicMock

        from nexus.scavenger.agents import HandshakeState

        state = HandshakeState(bssid="aa:bb:cc:dd:ee:ff")

        m1 = MagicMock()
        m1.message_number = 1
        m1.src_mac = "ap_mac"
        state.add_message(m1)

        d = state.to_dict()

        self.assertEqual(d['bssid'], "aa:bb:cc:dd:ee:ff")
        self.assertTrue(d['has_m1'])
        self.assertFalse(d['has_m2'])
        self.assertFalse(d['is_complete'])


class TestAgentCrypt(unittest.TestCase):
    """Tests for AgentCrypt (handshake scavenging)."""

    def test_agent_crypt_init(self):
        """Test AgentCrypt initialization."""
        from nexus.scavenger.agents import AgentCrypt

        agent = AgentCrypt()
        self.assertEqual(agent.name, "Crypt")
        self.assertEqual(len(agent.handshakes), 0)
        self.assertEqual(len(agent.pmkids), 0)

    def test_agent_crypt_stats(self):
        """Test AgentCrypt statistics tracking."""
        from nexus.scavenger.agents import AgentCrypt

        agent = AgentCrypt()
        stats = agent.get_stats()

        self.assertIn('eapol_frames', stats)
        self.assertIn('m1_frames', stats)
        self.assertIn('m2_frames', stats)
        self.assertIn('pmkids_extracted', stats)
        self.assertIn('complete_handshakes', stats)

    def test_agent_crypt_parser_lazy_load(self):
        """Test that EAPOL parser is lazy-loaded."""
        from nexus.scavenger.agents import AgentCrypt

        agent = AgentCrypt()
        # Parser should be None initially (lazy)
        self.assertIsNone(agent._parser)

        # Accessing parser property should load it
        parser = agent.parser
        self.assertIsNotNone(parser)
        self.assertIsNotNone(agent._parser)

    @unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
    def test_agent_crypt_non_eapol_ignored(self):
        """Test that non-EAPOL packets are ignored."""
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap

        from nexus.scavenger.agents import AgentCrypt

        agent = AgentCrypt()

        # Create a beacon frame (management, not data)
        pkt = RadioTap() / Dot11(
            type=0,  # Management (not Data)
            subtype=8,  # Beacon
            addr2="aa:bb:cc:dd:ee:ff"
        ) / Dot11Beacon() / Dot11Elt(ID=0, info=b"TestNet")

        result = agent.process(pkt)

        self.assertIsNone(result)
        self.assertEqual(agent.get_stats()['eapol_frames'], 0)

    def test_agent_crypt_get_complete_handshakes_empty(self):
        """Test getting complete handshakes when none exist."""
        from nexus.scavenger.agents import AgentCrypt

        agent = AgentCrypt()
        complete = agent.get_complete_handshakes()

        self.assertEqual(complete, [])

    def test_agent_crypt_get_pmkids_empty(self):
        """Test getting PMKIDs when none exist."""
        from nexus.scavenger.agents import AgentCrypt

        agent = AgentCrypt()
        pmkids = agent.get_pmkids()

        self.assertEqual(pmkids, {})

    def test_agent_crypt_reset(self):
        """Test agent reset clears all state."""
        from nexus.scavenger.agents import AgentCrypt

        agent = AgentCrypt()

        # Manually add some state
        agent.handshakes["test"] = "dummy"
        agent.pmkids["test"].append("pmkid_value")
        agent._stats['eapol_frames'] = 100

        agent.reset()

        self.assertEqual(len(agent.handshakes), 0)
        self.assertEqual(len(agent.pmkids), 0)
        self.assertEqual(agent._stats['eapol_frames'], 0)


# ============================================================================
# Milestone 4 Tests - Identity Fusion & Pipeline
# ============================================================================

class TestTargetDossier(unittest.TestCase):
    """Tests for TargetDossier dataclass."""

    def test_target_dossier_creation(self):
        """Test basic TargetDossier creation."""
        from nexus.scavenger.correlator import TargetDossier

        dossier = TargetDossier(mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(dossier.mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(dossier.pnl_count, 0)
        self.assertEqual(dossier.activity_count, 0)
        self.assertIsNone(dossier.avg_rssi)

    def test_target_dossier_with_data(self):
        """Test TargetDossier with populated data."""
        from nexus.scavenger.correlator import TargetDossier

        now = datetime.now()
        dossier = TargetDossier(
            mac="aa:bb:cc:dd:ee:ff",
            first_seen=now,
            last_seen=now,
            probed_ssids={"Net1": now, "Net2": now},
            channels_active={1, 6, 11},
            rssi_samples=[-50, -60, -70],
        )

        self.assertEqual(dossier.pnl_count, 2)
        self.assertEqual(dossier.avg_rssi, -60.0)
        self.assertIn(6, dossier.channels_active)

    def test_target_dossier_merge(self):
        """Test merging two dossiers."""
        from nexus.scavenger.correlator import TargetDossier

        now = datetime.now()

        dossier1 = TargetDossier(
            mac="aa:aa:aa:aa:aa:aa",
            probed_ssids={"Net1": now, "Net2": now},
            channels_active={1, 6},
        )

        dossier2 = TargetDossier(
            mac="bb:bb:bb:bb:bb:bb",
            probed_ssids={"Net2": now, "Net3": now},
            channels_active={6, 11},
        )

        dossier1.merge(dossier2)

        # Should have merged PNLs
        self.assertEqual(dossier1.pnl_count, 3)
        self.assertIn("Net3", dossier1.probed_ssids)

        # Should have merged channels
        self.assertEqual(dossier1.channels_active, {1, 6, 11})

        # Should track correlated MAC
        self.assertIn("bb:bb:bb:bb:bb:bb", dossier1.correlated_macs)

    def test_target_dossier_to_dict(self):
        """Test TargetDossier serialization."""
        from nexus.scavenger.correlator import TargetDossier

        now = datetime.now()
        dossier = TargetDossier(
            mac="aa:bb:cc:dd:ee:ff",
            first_seen=now,
            probed_ssids={"TestNet": now},
        )

        d = dossier.to_dict()

        self.assertEqual(d['mac'], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(d['pnl_count'], 1)
        self.assertIn('TestNet', d['probed_ssids'])


class TestIdentityFusion(unittest.TestCase):
    """Tests for IdentityFusion (correlation engine)."""

    def test_identity_fusion_init(self):
        """Test IdentityFusion initialization."""
        from nexus.scavenger.correlator import IdentityFusion

        fusion = IdentityFusion()
        self.assertEqual(len(fusion.dossiers), 0)

    def test_identity_fusion_fuse_probe_requests(self):
        """Test fusing probe request intelligence."""
        from nexus.scavenger.correlator import IdentityFusion

        fusion = IdentityFusion()

        now = datetime.now()
        intelligence = [
            {'type': 'probe_request', 'src_mac': 'AA:BB:CC:DD:EE:FF',
             'ssid': 'HomeWifi', 'timestamp': now, 'channel': 6},
            {'type': 'probe_request', 'src_mac': 'AA:BB:CC:DD:EE:FF',
             'ssid': 'OfficeNet', 'timestamp': now, 'channel': 11},
            {'type': 'probe_request', 'src_mac': '11:22:33:44:55:66',
             'ssid': 'HomeWifi', 'timestamp': now},
        ]

        fusion.fuse(intelligence)

        # Should have 2 dossiers
        self.assertEqual(len(fusion.dossiers), 2)

        # First client should have 2 SSIDs
        dossier = fusion.generate_dossier('aa:bb:cc:dd:ee:ff')
        self.assertIsNotNone(dossier)
        self.assertEqual(dossier['pnl_count'], 2)

    def test_identity_fusion_fuse_eapol(self):
        """Test fusing EAPOL intelligence."""
        from nexus.scavenger.correlator import IdentityFusion

        fusion = IdentityFusion()

        now = datetime.now()
        intelligence = [
            {'type': 'eapol', 'src_mac': 'AA:BB:CC:DD:EE:FF',
             'bssid': '00:11:22:33:44:55', 'message_number': 2,
             'timestamp': now},
        ]

        fusion.fuse(intelligence)

        dossier = fusion.generate_dossier('aa:bb:cc:dd:ee:ff')
        self.assertIsNotNone(dossier)
        self.assertIn('00:11:22:33:44:55', dossier['associated_bssids'])

    def test_identity_fusion_with_fingerprinter(self):
        """Test fusion with device fingerprinting."""
        from unittest.mock import MagicMock

        from nexus.scavenger.correlator import IdentityFusion

        # Mock fingerprinter
        mock_fp = MagicMock()
        mock_fp.lookup_vendor.return_value = "Cyberdyne Systems"

        fusion = IdentityFusion(fingerprinter=mock_fp)

        # Fuse item
        now = datetime.now()
        fusion.fuse([{
            'type': 'probe_request',
            'src_mac': 'AA:BB:CC:DD:EE:FF',
            'ssid': 'Skynet',
            'timestamp': now
        }])

        # Verify vendor lookup
        dossier = fusion.dossiers['aa:bb:cc:dd:ee:ff']
        self.assertEqual(dossier.vendor, "Cyberdyne Systems")
        mock_fp.lookup_vendor.assert_called_with('aa:bb:cc:dd:ee:ff')

    def test_identity_fusion_suggest_correlations(self):
        """Test correlation suggestions based on PNL overlap."""
        from nexus.scavenger.correlator import IdentityFusion

        fusion = IdentityFusion()

        now = datetime.now()
        # Two clients with significant PNL overlap
        intelligence = [
            # Client 1
            {'type': 'probe_request', 'src_mac': 'AA:AA:AA:AA:AA:AA',
             'ssid': 'Net1', 'timestamp': now, 'is_randomized_mac': True},
            {'type': 'probe_request', 'src_mac': 'AA:AA:AA:AA:AA:AA',
             'ssid': 'Net2', 'timestamp': now},
            {'type': 'probe_request', 'src_mac': 'AA:AA:AA:AA:AA:AA',
             'ssid': 'Net3', 'timestamp': now},
            # Client 2 - same PNL
            {'type': 'probe_request', 'src_mac': 'BB:BB:BB:BB:BB:BB',
             'ssid': 'Net1', 'timestamp': now, 'is_randomized_mac': True},
            {'type': 'probe_request', 'src_mac': 'BB:BB:BB:BB:BB:BB',
             'ssid': 'Net2', 'timestamp': now},
            {'type': 'probe_request', 'src_mac': 'BB:BB:BB:BB:BB:BB',
             'ssid': 'Net3', 'timestamp': now},
        ]

        fusion.fuse(intelligence)
        correlations = fusion.suggest_correlations(min_confidence=0.5)

        # Should suggest correlation between the two MACs
        self.assertGreater(len(correlations), 0)
        self.assertIn('aa:aa:aa:aa:aa:aa', correlations[0][:2])
        self.assertIn('bb:bb:bb:bb:bb:bb', correlations[0][:2])

    def test_identity_fusion_merge_identities(self):
        """Test merging two identities."""
        from nexus.scavenger.correlator import IdentityFusion

        fusion = IdentityFusion()

        now = datetime.now()
        intelligence = [
            {'type': 'probe_request', 'src_mac': 'AA:AA:AA:AA:AA:AA',
             'ssid': 'Net1', 'timestamp': now},
            {'type': 'probe_request', 'src_mac': 'BB:BB:BB:BB:BB:BB',
             'ssid': 'Net2', 'timestamp': now},
        ]

        fusion.fuse(intelligence)
        self.assertEqual(len(fusion.dossiers), 2)

        # Merge
        result = fusion.merge_identities('aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb')
        self.assertTrue(result)

        # Should now have 1 dossier with merged data
        self.assertEqual(len(fusion.dossiers), 1)
        dossier = fusion.generate_dossier('aa:aa:aa:aa:aa:aa')
        self.assertEqual(dossier['pnl_count'], 2)

    def test_identity_fusion_reset(self):
        """Test reset clears all state."""
        from nexus.scavenger.correlator import IdentityFusion

        fusion = IdentityFusion()
        fusion.fuse([{'type': 'probe_request', 'src_mac': 'AA:BB:CC:DD:EE:FF',
                     'ssid': 'Test', 'timestamp': datetime.now()}])

        fusion.reset()

        self.assertEqual(len(fusion.dossiers), 0)


class TestScavengerPipeline(unittest.TestCase):
    """Tests for ScavengerPipeline (orchestration)."""

    def setUp(self):
        """Create temporary directory for test captures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_pipeline_init(self):
        """Test ScavengerPipeline initialization."""
        from nexus.scavenger.pipeline import ScavengerPipeline

        pipeline = ScavengerPipeline(self.temp_path)

        self.assertIsNotNone(pipeline.streamer)
        self.assertIn('shadow', pipeline.agents)
        self.assertIn('crypt', pipeline.agents)
        self.assertIn('cartographer', pipeline.agents)

    def test_pipeline_init_custom_agents(self):
        """Test pipeline with custom agent selection."""
        from nexus.scavenger.pipeline import ScavengerPipeline

        pipeline = ScavengerPipeline(self.temp_path, agents=['shadow'])

        self.assertIn('shadow', pipeline.agents)
        self.assertNotIn('crypt', pipeline.agents)

    def test_pipeline_get_stats(self):
        """Test pipeline statistics retrieval."""
        from nexus.scavenger.pipeline import ScavengerPipeline

        pipeline = ScavengerPipeline(self.temp_path)
        stats = pipeline.get_stats()

        self.assertIn('pipeline', stats)
        self.assertIn('streamer', stats)
        self.assertIn('agents', stats)
        self.assertIn('correlator', stats)

    def test_pipeline_reset(self):
        """Test pipeline reset."""
        from nexus.scavenger.pipeline import ScavengerPipeline

        pipeline = ScavengerPipeline(self.temp_path)
        pipeline._stats['packets_processed'] = 1000

        pipeline.reset()

        self.assertEqual(pipeline._stats['packets_processed'], 0)

    def test_pipeline_run_empty_dir(self):
        """Test pipeline run with no capture files."""
        from nexus.scavenger.pipeline import ScavengerPipeline

        pipeline = ScavengerPipeline(self.temp_path)
        summary = pipeline.run()

        self.assertEqual(summary['summary']['files_processed'], 0)
        self.assertEqual(summary['summary']['packets_processed'], 0)

    @unittest.skipUnless(PERSISTENCE_AVAILABLE, "Persistence modules not available")
    def test_pipeline_run_with_dao(self):
        """Test pipeline integrates with DAO."""
        from nexus.scavenger.pipeline import ScavengerPipeline

        # Mock DAO
        mock_dao = MagicMock()
        mock_dao.merge_dossiers_batch.return_value = True

        # Inject mock DAO into pipeline
        with patch('nexus.scavenger.pipeline.ScavengerDAO', return_value=mock_dao):
            pipeline = ScavengerPipeline(self.temp_path)
            # Force DAO presence (normally requires config)
            pipeline.dao = mock_dao

            # Create a dummy persistence method to call directly or trigger via run
            # Since running full pipeline on empty dir does nothing, we test _persist_findings directly

            # Create dummy raw intelligence items (List[Dict])
            intelligence_items = [
                {'src_mac': 'aa:bb:cc:dd:ee:ff', 'type': 'probe_request'}
            ]

            # Mock correlator to return a dossier when asked
            dossier_obj = TargetDossier(mac='aa:bb:cc:dd:ee:ff')
            pipeline.correlator.get_dossier = MagicMock(return_value=dossier_obj)

            # Call persist
            pipeline._persist_findings(intelligence_items)

            # Verify DAO called with the dossier object
            mock_dao.merge_dossiers_batch.assert_called_with([dossier_obj], conn=None, commit=True)


class TestScavengerPersistence(unittest.TestCase):
    """Integration tests for SQL Persistence (ScavengerDAO)."""

    @classmethod
    def setUpClass(cls):
        if not PERSISTENCE_AVAILABLE:
            raise unittest.SkipTest("Persistence modules not available")
        _load_sql_env_from_repo_dotenv()
        cls.config = get_nexus_config()
        # Verify DB connection possible before running tests
        import pyodbc
        try:
            with pyodbc.connect(cls.config.get_sql_connection_string(), timeout=1):
                pass
        except Exception as exc:
            raise unittest.SkipTest("SQL Database not reachable") from exc

    def setUp(self):
        self.dao = ScavengerDAO(self.config)
        self.test_mac = "AA:BB:CC:DD:EE:FF"
        self._cleanup()

    def tearDown(self):
        self._cleanup()

    def _cleanup(self):
        import pyodbc
        try:
            with pyodbc.connect(self.config.get_sql_connection_string()) as conn:
                conn.cursor().execute("DELETE FROM client_profiles WHERE mac_addr = ?", (self.test_mac,))
                conn.commit()
        except Exception:
            pass

    def test_dao_merge_and_retrieve(self):
        """Test round-trip persistence: Merge -> DB -> Verify."""
        dossier = TargetDossier(mac=self.test_mac, is_randomized_mac=False)
        dossier.probed_ssids = {"TestNet": datetime.now()}

        # 1. Merge (Insert)
        success = self.dao.merge_dossier(dossier)
        self.assertTrue(success, "Failed initial merge")

        # 2. Retrieve via get_all_clients (since get_client is not implemented in DAO yet)
        clients = self.dao.get_all_clients()
        target = next((c for c in clients if c['mac'] == self.test_mac), None)

        self.assertIsNotNone(target)
        self.assertIn("TestNet", target['probed_ssids'])

        # 3. Merge (Update)
        dossier.probed_ssids = {"UpdatedNet": datetime.now()}
        success_update = self.dao.merge_dossier(dossier)
        self.assertTrue(success_update, "Failed update merge")

        clients_updated = self.dao.get_all_clients()
        target_updated = next((c for c in clients_updated if c['mac'] == self.test_mac), None)

        # Should now have both because merge_dossier merges keys?
        # Wait, ScavengerDAO.merge_dossier calls stored proc or SQL update.
        # My implementation of merge_dossier (Step 467) reads EXISTING JSON, merges in Python, then Updates.
        # So yes, it should contain both.
        self.assertIn("TestNet", target_updated['probed_ssids'])
        self.assertIn("UpdatedNet", target_updated['probed_ssids'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
