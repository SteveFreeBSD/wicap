"""Performance smoke checks (fast, fixture-based)."""

import time
from pathlib import Path

import pytest


@pytest.mark.perf_smoke
def test_fixture_parse_throughput_scapy() -> None:
    """Ensure fixture PCAP parses within a generous ceiling."""
    scapy = pytest.importorskip("scapy.utils")
    reader_cls = getattr(scapy, "PcapNgReader", None)
    if reader_cls is None:
        pytest.skip("PcapNgReader unavailable in scapy")

    pcap_path = Path("tests/fixtures/pcap/mixed_traffic_ch2.pcapng")
    assert pcap_path.exists()

    start = time.perf_counter()
    packet_count = 0
    with reader_cls(str(pcap_path)) as reader:
        for _ in reader:
            packet_count += 1
    elapsed = time.perf_counter() - start

    assert packet_count > 0
    assert elapsed < 15.0
