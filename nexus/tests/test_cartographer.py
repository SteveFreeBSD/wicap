#!/usr/bin/env python3
"""
Unit tests for AgentCartographer association inference.
"""

import unittest

from nexus.scavenger.agents import SCAPY_AVAILABLE, AgentCartographer


@unittest.skipUnless(SCAPY_AVAILABLE, "scapy not available")
class TestAgentCartographer(unittest.TestCase):
    """Validate association inference rules."""

    def test_assoc_request_extraction(self):
        """Extract association from AssoReq."""
        from scapy.all import Dot11, Dot11AssoReq, Dot11Elt, RadioTap

        pkt = RadioTap() / Dot11(
            type=0,
            subtype=0,
            addr1="00:11:22:33:44:55",
            addr2="aa:bb:cc:dd:ee:ff",
            addr3="00:11:22:33:44:55",
        ) / Dot11AssoReq() / Dot11Elt(ID=0, info=b"TestNet")

        agent = AgentCartographer()
        result = agent.process(pkt)

        self.assertIsNotNone(result)
        self.assertEqual(result["client_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result["bssid"], "00:11:22:33:44:55")
        self.assertEqual(result["assoc_type"], "assoc_req")

    def test_data_frame_to_ap(self):
        """Infer association from data frame (ToDS=1, FromDS=0)."""
        from scapy.all import Dot11, RadioTap

        pkt = RadioTap() / Dot11(
            type=2,
            subtype=0,
            FCfield=0x01,
            addr1="00:11:22:33:44:55",
            addr2="aa:bb:cc:dd:ee:ff",
            addr3="ff:ff:ff:ff:ff:ff",
        )

        agent = AgentCartographer()
        result = agent.process(pkt)

        self.assertIsNotNone(result)
        self.assertEqual(result["client_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result["bssid"], "00:11:22:33:44:55")
        self.assertEqual(result["assoc_type"], "data")

    def test_wds_frame_skipped(self):
        """Skip WDS frames (ToDS=1, FromDS=1)."""
        from scapy.all import Dot11, RadioTap

        pkt = RadioTap() / Dot11(
            type=2,
            subtype=0,
            FCfield=0x03,
        )

        agent = AgentCartographer()
        result = agent.process(pkt)

        self.assertIsNone(result)

    def test_broadcast_skipped(self):
        """Skip broadcast/multicast client MACs."""
        from scapy.all import Dot11, Dot11AssoReq, RadioTap

        pkt = RadioTap() / Dot11(
            type=0,
            subtype=0,
            addr1="00:11:22:33:44:55",
            addr2="ff:ff:ff:ff:ff:ff",
            addr3="00:11:22:33:44:55",
        ) / Dot11AssoReq()

        agent = AgentCartographer()
        result = agent.process(pkt)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
