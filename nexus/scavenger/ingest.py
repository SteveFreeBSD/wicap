"""
Scavenger Ingest Module ("The Maw")
Responsible for efficiently handling and streaming PCAP data.

Uses scapy for memory-efficient packet streaming with deduplication.
"""

import gzip
import hashlib
import os
from collections import OrderedDict
from collections.abc import Generator
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import Dot11, Packet, PcapNgReader, PcapReader, RadioTap, Raw
    from scapy.layers.dot11 import Dot11Elt
    from scapy.utils import RawPcapNgReader, RawPcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = None
    RawPcapReader = None
    RawPcapNgReader = None

try:
    from nexus.utils import rust_ext
except ImportError:
    rust_ext = None

try:
    import xxhash
except ImportError:  # pragma: no cover - optional dependency
    xxhash = None


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _channel_from_frequency(freq: float | None) -> int | None:
    """Convert center frequency (MHz) to Wi-Fi channel number."""
    if freq is None:
        return None
    try:
        value = float(freq)
    except (TypeError, ValueError):
        return None
    if 2412 <= value <= 2484:
        if value == 2484:
            return 14
        return int((value - 2407) // 5)
    if 5000 <= value <= 5895:
        return int((value - 5000) // 5)
    if 5955 <= value <= 7115:
        return int((value - 5950) // 5)
    return None


class LRUDeduplicator:
    """
    LRU-based deduplication cache with configurable max size.
    Uses sliding window to prevent memory growth on large captures.
    """

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self._cache: OrderedDict[str, None] = OrderedDict()

    def _compute_signature(self, packet: 'Packet') -> str | None:
        """
        Compute unique signature for a packet based on:
        - Source MAC (if available)
        - Sequence number (if available)
        - Timestamp
        - First 32 bytes of payload
        """
        try:
            parts = []

            # Extract source MAC from Dot11 layer if available
            if packet.haslayer(Dot11):
                dot11 = packet.getlayer(Dot11)
                if hasattr(dot11, 'addr2') and dot11.addr2:
                    parts.append(dot11.addr2)
                if hasattr(dot11, 'SC') and dot11.SC is not None:
                    # SC contains sequence number (upper 12 bits) and fragment (lower 4 bits)
                    seq_num = dot11.SC >> 4
                    parts.append(str(seq_num))

            # Add timestamp
            if hasattr(packet, 'time'):
                parts.append(f"{packet.time:.6f}")

            # Add first 32 bytes of raw packet as fallback uniqueness
            raw = bytes(packet)[:32]
            parts.append(raw.hex())

            if not parts:
                return None

            signature = "|".join(parts).encode()
            if rust_ext is not None:
                return rust_ext.xxh64_hex(signature)
            if xxhash is not None:
                return xxhash.xxh64(signature).hexdigest()
            return hashlib.md5(signature).hexdigest()[:16]

        except Exception:
            return None

    def is_duplicate(self, packet: 'Packet') -> bool:
        """Check if packet is a duplicate. Updates cache if not."""
        sig = self._compute_signature(packet)

        if sig is None:
            # Cannot compute signature, assume not duplicate
            return False

        if sig in self._cache:
            # Move to end (most recently seen)
            self._cache.move_to_end(sig)
            return True

        # Add to cache
        self._cache[sig] = None

        # Evict oldest if over capacity
        while len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

        return False

    def reset(self) -> None:
        """Clear the deduplication cache."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Current number of entries in cache."""
        return len(self._cache)


class PCAPStreamer:
    """
    Unified loader to stream-read PCAP files without exploding RAM.
    Uses scapy's PcapReader for memory-efficient streaming.

    Supports:
    - .pcap (libpcap format)
    - .pcapng (pcap next generation)
    - .pcap.gz / .pcapng.gz (gzip compressed)
    """

    SUPPORTED_EXTENSIONS = {'.pcap', '.pcapng', '.cap'}

    def __init__(self, capture_dir: Path, use_raw_reader: bool | None = None):
        """
        Initialize streamer with a capture directory.

        Args:
            capture_dir: Path to directory containing PCAP files
            use_raw_reader: Use RawPcapReader/RawPcapNgReader when available

        Raises:
            FileNotFoundError: If capture directory doesn't exist
            ImportError: If scapy is not available
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is not installed. Please install it to use Scavenger.")

        self.capture_dir = Path(capture_dir)
        if not self.capture_dir.exists():
            raise FileNotFoundError(f"Capture directory not found: {capture_dir}")

        self._deduplicator = LRUDeduplicator()
        if use_raw_reader is None:
            use_raw_reader = _env_flag("WICAP_SCAVENGER_RAW_READER", default=False)
        self._use_raw_reader = bool(use_raw_reader)
        self._stats = {
            'files_processed': 0,
            'packets_total': 0,
            'packets_deduplicated': 0,
            'errors': []
        }

    def list_captures(self, include_compressed: bool = True) -> list[Path]:
        """
        List all valid PCAP files in the directory.

        Args:
            include_compressed: Also include .gz compressed files

        Returns:
            Sorted list of PCAP file paths
        """
        captures = []

        for ext in self.SUPPORTED_EXTENSIONS:
            captures.extend(self.capture_dir.glob(f"*{ext}"))
            if include_compressed:
                captures.extend(self.capture_dir.glob(f"*{ext}.gz"))

        return sorted(captures)

    def _open_pcap(self, pcap_path: Path):
        """
        Open a PCAP file, handling compression and format detection.

        Returns appropriate reader (PcapReader or PcapNgReader).
        """
        path_str = str(pcap_path)

        # Handle gzip compression
        if path_str.endswith('.gz'):
            # Decompress to temp and read
            # Note: For very large files, consider streaming decompression
            return PcapReader(gzip.open(pcap_path, 'rb'))

        # Detect format based on extension
        if '.pcapng' in path_str:
            return PcapNgReader(path_str)
        else:
            return PcapReader(path_str)

    def _open_pcap_raw(self, pcap_path: Path):
        """Open a PCAP file with raw readers when possible."""
        if RawPcapReader is None or RawPcapNgReader is None:
            return None
        path_str = str(pcap_path)
        if path_str.endswith('.gz'):
            return None
        if '.pcapng' in path_str:
            return RawPcapNgReader(path_str)
        return RawPcapReader(path_str)

    def _raw_timestamp(self, meta, reader) -> float | None:
        """Compute timestamp from raw reader metadata."""
        if meta is None:
            return None
        if hasattr(meta, "sec"):
            divisor = 1_000_000_000 if getattr(reader, "nano", False) else 1_000_000
            return float(meta.sec) + (float(meta.usec) / divisor)
        if getattr(meta, "tshigh", None) is not None and getattr(meta, "tslow", None) is not None:
            raw_ts = (int(meta.tshigh) << 32) | int(meta.tslow)
            tsresol = getattr(meta, "tsresol", None) or 1_000_000
            return raw_ts / float(tsresol)
        return None

    def _raw_to_packet(self, raw_bytes: bytes, linktype: int | None) -> 'Packet':
        """Convert raw bytes to a scapy Packet based on linktype."""
        # Common DLT values for 802.11 capture formats
        if linktype == 127:  # DLT_IEEE802_11_RADIO
            return RadioTap(raw_bytes)
        if linktype == 105:  # DLT_IEEE802_11
            return Dot11(raw_bytes)
        return Raw(raw_bytes)

    def stream_capture(
        self,
        pcap_path: Path,
        filter_80211_only: bool = True
    ) -> Generator['Packet', None, None]:
        """
        Yields packets from a single PCAP file using scapy.

        This is memory-efficient - packets are read one at a time.

        Args:
            pcap_path: Path to PCAP file
            filter_80211_only: Only yield 802.11 frames (skip non-wireless)

        Yields:
            scapy Packet objects

        Raises:
            FileNotFoundError: If PCAP file doesn't exist
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        raw_reader = None
        reader = None
        try:
            raw_reader = self._open_pcap_raw(pcap_path) if self._use_raw_reader else None
            if raw_reader is not None:
                for raw_bytes, meta in raw_reader:
                    self._stats['packets_total'] += 1
                    linktype = getattr(meta, "linktype", None) or getattr(raw_reader, "linktype", None)
                    packet = self._raw_to_packet(raw_bytes, linktype)
                    ts = self._raw_timestamp(meta, raw_reader)
                    if ts is not None:
                        packet.time = ts

                    if filter_80211_only:
                        if not (packet.haslayer(Dot11) or packet.haslayer(RadioTap)):
                            continue

                    yield packet
                return

            reader = self._open_pcap(pcap_path)
            for packet in reader:
                self._stats['packets_total'] += 1

                # Optional: Filter to 802.11 frames only
                if filter_80211_only:
                    if not (packet.haslayer(Dot11) or packet.haslayer(RadioTap)):
                        continue

                yield packet

        except Exception as e:
            self._stats['errors'].append(f"{pcap_path.name}: {str(e)}")
            return
        finally:
            if raw_reader is not None:
                try:
                    raw_reader.close()
                except Exception:
                    pass
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
            self._stats['files_processed'] += 1

    def stream_capture_deduplicated(
        self,
        pcap_path: Path,
        filter_80211_only: bool = True
    ) -> Generator['Packet', None, None]:
        """
        Yields unique packets from a PCAP, filtering out duplicates.

        Duplicates are common in multi-radio captures where the same
        frame is captured by multiple interfaces.

        Args:
            pcap_path: Path to PCAP file
            filter_80211_only: Only yield 802.11 frames

        Yields:
            Unique scapy Packet objects
        """
        for packet in self.stream_capture(pcap_path, filter_80211_only):
            if not self._deduplicator.is_duplicate(packet):
                yield packet
            else:
                self._stats['packets_deduplicated'] += 1

    def stream_all_captures(
        self,
        deduplicate: bool = True,
        filter_80211_only: bool = True
    ) -> Generator[tuple[Path, 'Packet'], None, None]:
        """
        Stream packets from all PCAP files in the capture directory.

        Args:
            deduplicate: Enable cross-file deduplication
            filter_80211_only: Only yield 802.11 frames

        Yields:
            Tuples of (source_file, packet)
        """
        # Reset deduplication cache for fresh run
        self._deduplicator.reset()
        self._stats = {
            'files_processed': 0,
            'packets_total': 0,
            'packets_deduplicated': 0,
            'errors': []
        }

        captures = self.list_captures()

        for pcap_path in captures:
            stream_fn = (
                self.stream_capture_deduplicated if deduplicate
                else self.stream_capture
            )

            for packet in stream_fn(pcap_path, filter_80211_only):
                yield (pcap_path, packet)

    def get_stats(self) -> dict:
        """Return processing statistics."""
        return {
            **self._stats,
            'dedup_cache_size': self._deduplicator.size
        }

    def reset_stats(self) -> None:
        """Reset processing statistics and deduplication cache."""
        self._deduplicator.reset()
        self._stats = {
            'files_processed': 0,
            'packets_total': 0,
            'packets_deduplicated': 0,
            'errors': []
        }


def extract_packet_info(packet: 'Packet') -> dict:
    """
    Extract common information from an 802.11 packet.

    Utility function for agents to use.

    Returns:
        Dict with keys: timestamp, src_mac, dst_mac, bssid, frame_type,
                       frame_subtype, channel, rssi, ssid (if available)
    """
    info = {
        'timestamp': None,
        'src_mac': None,
        'dst_mac': None,
        'bssid': None,
        'frame_type': None,
        'frame_subtype': None,
        'channel': None,
        'rssi': None,
        'ssid': None,
    }

    try:
        # Timestamp
        if hasattr(packet, 'time'):
            info['timestamp'] = datetime.fromtimestamp(float(packet.time))

        # RadioTap info (RSSI, channel)
        if packet.haslayer(RadioTap):
            rt = packet.getlayer(RadioTap)
            if hasattr(rt, 'dBm_AntSignal'):
                info['rssi'] = rt.dBm_AntSignal
            frequency = getattr(rt, "ChannelFrequency", None)
            channel = _channel_from_frequency(frequency)
            if channel is not None:
                info['channel'] = channel

        # Dot11 info
        if packet.haslayer(Dot11):
            dot11 = packet.getlayer(Dot11)
            info['frame_type'] = dot11.type
            info['frame_subtype'] = dot11.subtype

            # Address fields depend on frame type
            # addr1 = destination, addr2 = source, addr3 = bssid (usually)
            info['dst_mac'] = dot11.addr1
            info['src_mac'] = dot11.addr2
            info['bssid'] = dot11.addr3

        # Extract SSID from Information Elements (for beacons, probe reqs/resp)
        if packet.haslayer(Dot11Elt):
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:  # SSID element
                    try:
                        info['ssid'] = elt.info.decode('utf-8', errors='ignore')
                    except (UnicodeDecodeError, AttributeError):
                        pass
                    break
                elt = elt.payload.getlayer(Dot11Elt)

    except Exception:
        pass

    return info
