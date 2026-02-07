"""
NEXUS Handshake Extractor

Extracts WPA/WPA2 handshakes and PMKIDs from PCAP files.
Processes the captures directory and populates the handshakes table.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import EAPOL, Dot11, PcapReader
    from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import pyodbc
    PYODBC_AVAILABLE = True
except ImportError:
    PYODBC_AVAILABLE = False

from .config import NexusConfig, get_nexus_config
from .eapol_parser import EAPOLKeyFrame, EAPOLParser, HandshakeCapture

logger = logging.getLogger('nexus.handshake_extractor')


def _row_value(row, key, default=None):
    if isinstance(row, dict):
        return row.get(key, default)
    return getattr(row, key, default)


def _has_complete_flags(msg_flags: int) -> bool:
    has_m1 = bool(msg_flags & 1)
    has_m2 = bool(msg_flags & 2)
    has_m3 = bool(msg_flags & 4)
    return (has_m1 and has_m2) or (has_m2 and has_m3)


def _storage_handshake_type_from_fields(
    msg_flags: int,
    anonce: bytes | None,
    snonce: bytes | None,
    mic: bytes | None,
    eapol_data: bytes | None,
    pmkid: str | None,
) -> str:
    if _has_complete_flags(msg_flags) and anonce and mic and eapol_data:
        return '4way_full'
    if pmkid:
        return 'pmkid'
    if anonce and snonce and mic:
        return '4way_partial'
    return 'incomplete'


def _storage_handshake_type(capture: HandshakeCapture) -> str:
    return _storage_handshake_type_from_fields(
        capture.msg_flags,
        capture.anonce,
        capture.snonce,
        capture.mic,
        capture.eapol_m2,
        capture.pmkid,
    )


def _capture_quality(capture: HandshakeCapture) -> int:
    storage_type = _storage_handshake_type(capture)
    if storage_type == '4way_full':
        return 3
    if storage_type == 'pmkid':
        return 2
    if storage_type == '4way_partial':
        return 1
    return 0


def _row_quality(row) -> int:
    msg_flags = _row_value(row, 'msg_flags', 0) or 0
    anonce = _row_value(row, 'anonce')
    snonce = _row_value(row, 'snonce')
    mic = _row_value(row, 'mic')
    eapol_data = _row_value(row, 'eapol_data')
    pmkid = _row_value(row, 'pmkid')
    storage_type = _storage_handshake_type_from_fields(
        msg_flags,
        anonce,
        snonce,
        mic,
        eapol_data,
        pmkid,
    )
    if storage_type == '4way_full':
        return 3
    if storage_type == 'pmkid':
        return 2
    if storage_type == '4way_partial':
        return 1
    return 0


def _is_exact_duplicate(capture: HandshakeCapture, row) -> bool:
    storage_type = _storage_handshake_type(capture)
    if storage_type == 'pmkid':
        existing_pmkid = _row_value(row, 'pmkid')
        return bool(existing_pmkid and capture.pmkid and existing_pmkid.lower() == capture.pmkid.lower())
    if storage_type in ('4way_full', '4way_partial'):
        return (
            _row_value(row, 'anonce') == capture.anonce
            and _row_value(row, 'snonce') == capture.snonce
            and _row_value(row, 'mic') == capture.mic
        )
    return False


def _select_handshake_action(capture: HandshakeCapture, existing_rows: list) -> tuple[str, object | None]:
    if not existing_rows:
        return ('insert', None)

    for row in existing_rows:
        if _is_exact_duplicate(capture, row):
            return ('skip', None)

    capture_quality = _capture_quality(capture)
    best_row = max(
        existing_rows,
        key=lambda r: (_row_quality(r), -int(_row_value(r, 'id', 0) or 0)),
    )
    if capture_quality > _row_quality(best_row):
        return ('update', best_row)

    return ('skip', None)

@dataclass
class ExtractionResult:
    """Result of handshake extraction from a PCAP file."""
    pcap_file: str
    frame_count: int
    eapol_frames: int
    handshakes_found: int
    pmkids_found: int
    errors: list[str]
    duration_sec: float


class HandshakeExtractor:
    """
    Extract WPA handshakes and PMKIDs from PCAP files.

    Processes dwell_*.pcapng files from the captures directory,
    identifies 4-way handshakes, and stores them for cracking.
    """

    def __init__(self, config: NexusConfig | None = None):
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is required for handshake extraction: pip install scapy")

        self.config = config or get_nexus_config()
        self.parser = EAPOLParser()
        self._conn: pyodbc.Connection | None = None

        # Handshake state: (bssid, client_mac) -> HandshakeCapture
        self._handshakes: dict[tuple[str, str], HandshakeCapture] = {}

        # SSID cache: bssid -> ssid (populated from beacons)
        self._ssid_cache: dict[str, str] = {}

    def _get_connection(self) -> 'pyodbc.Connection':
        """Get or create SQL connection."""
        if not PYODBC_AVAILABLE:
            raise ImportError("pyodbc is required for SQL storage")
        needs_reconnect = self._conn is None
        if not needs_reconnect:
            try:
                needs_reconnect = getattr(self._conn, 'closed', False)
            except Exception:
                needs_reconnect = True
        if needs_reconnect:
            self._conn = pyodbc.connect(
                self.config.get_sql_connection_string(),
                autocommit=False
            )
        return self._conn

    def close(self) -> None:
        """Close SQL connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def process_pcap(self, filepath: Path) -> ExtractionResult:
        """
        Process a single PCAP file for handshakes.

        Args:
            filepath: Path to PCAP/PCAPNG file

        Returns:
            ExtractionResult with extraction statistics
        """
        import time
        start_time = time.time()

        errors = []
        frame_count = 0
        eapol_count = 0

        # Reset state for this file
        self._handshakes.clear()

        try:
            # Use PcapReader for streaming (memory efficient)
            logger.info(f"Processing {filepath.name}...")

            reader = PcapReader(str(filepath))
            try:
                for packet in reader:
                    frame_count += 1

                    try:
                        eapol_frame = self._process_packet(packet, str(filepath))
                        if eapol_frame:
                            eapol_count += 1
                    except Exception as e:
                        errors.append(f"Frame {frame_count}: {e}")
                        if len(errors) > 100:
                            errors.append("... (truncated)")
                            break
            finally:
                try:
                    reader.close()
                except Exception:
                    pass

        except Exception as e:
            errors.append(f"Failed to read PCAP: {e}")
            logger.error(f"Failed to process {filepath}: {e}")

        # Count complete handshakes and PMKIDs
        handshakes_found = sum(1 for hs in self._handshakes.values() if hs.has_complete_handshake)
        pmkids_found = sum(1 for hs in self._handshakes.values() if hs.pmkid)

        duration = time.time() - start_time

        result = ExtractionResult(
            pcap_file=str(filepath),
            frame_count=frame_count,
            eapol_frames=eapol_count,
            handshakes_found=handshakes_found,
            pmkids_found=pmkids_found,
            errors=errors[:20],  # Limit error list
            duration_sec=duration,
        )

        # Store completed handshakes
        if PYODBC_AVAILABLE:
            self._store_handshakes(filepath)

        return result

    def _process_packet(self, packet, pcap_file: str) -> EAPOLKeyFrame | None:
        """
        Process a single packet looking for EAPOL-Key frames.

        Returns the parsed EAPOLKeyFrame if found, None otherwise.
        """
        # Check if packet has 802.11 layer
        if not packet.haslayer(Dot11):
            return None

        dot11 = packet.getlayer(Dot11)

        # Extract addresses based on To/From DS
        # For data frames: To-DS=0, From-DS=1 means AP->STA
        # To-DS=1, From-DS=0 means STA->AP
        to_ds = dot11.FCfield & 0x01
        from_ds = (dot11.FCfield >> 1) & 0x01

        if to_ds and not from_ds:
            # STA -> AP: addr1=BSSID, addr2=STA, addr3=DA
            bssid = self._format_mac(dot11.addr1)
            src_mac = self._format_mac(dot11.addr2)
            dst_mac = self._format_mac(dot11.addr3) if dot11.addr3 else bssid
        elif not to_ds and from_ds:
            # AP -> STA: addr1=DA/STA, addr2=BSSID, addr3=SA
            bssid = self._format_mac(dot11.addr2)
            dst_mac = self._format_mac(dot11.addr1)
            src_mac = self._format_mac(dot11.addr3) if dot11.addr3 else bssid
        else:
            # WDS or unknown
            bssid = self._format_mac(dot11.addr1) if dot11.addr1 else None
            src_mac = self._format_mac(dot11.addr2) if dot11.addr2 else None
            dst_mac = self._format_mac(dot11.addr3) if dot11.addr3 else None

        if not bssid or not src_mac:
            return None

        # Check for beacon/probe response to cache SSIDs
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            self._extract_ssid_from_beacon(packet, bssid)
            return None

        # Check for EAPOL layer
        if not packet.haslayer(EAPOL):
            return None

        # Get raw EAPOL data
        eapol_layer = packet.getlayer(EAPOL)
        raw_eapol = bytes(eapol_layer)

        timestamp = float(packet.time) if hasattr(packet, 'time') else 0.0

        # Parse the EAPOL-Key frame
        eapol_frame = self.parser.parse_eapol_key(
            data=raw_eapol,
            timestamp=timestamp,
            src_mac=src_mac,
            dst_mac=dst_mac,
            bssid=bssid,
        )

        if eapol_frame and eapol_frame.message_number > 0:
            # Determine client MAC (non-BSSID party)
            client_mac = src_mac if src_mac != bssid else dst_mac

            # Create or update handshake capture
            key = (bssid, client_mac)
            if key not in self._handshakes:
                ssid = self._ssid_cache.get(bssid)
                self._handshakes[key] = HandshakeCapture(
                    bssid=bssid,
                    ssid=ssid,
                    client_mac=client_mac,
                    pcap_file=pcap_file,
                )

            self._handshakes[key].add_message(eapol_frame)

            # Update SSID if we learn it later
            if not self._handshakes[key].ssid and bssid in self._ssid_cache:
                self._handshakes[key].ssid = self._ssid_cache[bssid]

            logger.debug(
                f"EAPOL M{eapol_frame.message_number}: "
                f"{bssid} <-> {client_mac}"
            )

        return eapol_frame

    def _extract_ssid_from_beacon(self, packet, bssid: str) -> None:
        """Extract SSID from beacon/probe response and cache it."""
        try:
            # The Dot11Elt layers contain Information Elements
            elt = packet.getlayer(Dot11).payload
            while elt:
                if hasattr(elt, 'ID') and elt.ID == 0:  # SSID IE
                    if hasattr(elt, 'info'):
                        ssid = elt.info
                        if isinstance(ssid, bytes):
                            try:
                                ssid = ssid.decode('utf-8', errors='replace')
                            except (UnicodeDecodeError, AttributeError):
                                ssid = ssid.hex()
                        if ssid and ssid.strip():
                            self._ssid_cache[bssid] = ssid
                            return
                if hasattr(elt, 'payload'):
                    elt = elt.payload
                else:
                    break
        except Exception:
            pass

    def _format_mac(self, mac) -> str | None:
        """Format MAC address to standard format (XX:XX:XX:XX:XX:XX)."""
        if not mac:
            return None
        if isinstance(mac, str):
            return mac.upper()
        if isinstance(mac, bytes):
            return ':'.join(f'{b:02X}' for b in mac)
        return str(mac).upper()

    def _store_handshakes(self, pcap_file: Path) -> int:
        """Store extracted handshakes to SQL database."""
        stored = 0
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            for (bssid, client_mac), capture in self._handshakes.items():
                if not capture.is_crackable:
                    continue

                cursor.execute("""
                    SELECT id, ssid, msg_flags, anonce, snonce, mic, eapol_data,
                           pmkid, hashcat_hash, capture_time, pcap_file
                    FROM handshakes
                    WHERE bssid = ? AND client_mac = ?
                """, (bssid, client_mac))

                existing_rows = cursor.fetchall()
                action, best_row = _select_handshake_action(capture, existing_rows)
                if action == 'skip':
                    logger.debug(f"Handshake already exists: {bssid} <-> {client_mac}")
                    continue

                hashcat_hash = capture.to_hashcat_22000()
                capture_time = (
                    datetime.fromtimestamp(capture.first_seen)
                    if capture.first_seen else datetime.now()
                )

                if action == 'insert':
                    storage_type = _storage_handshake_type(capture)
                    cursor.execute("""
                        INSERT INTO handshakes (
                            bssid, ssid, client_mac, handshake_type, msg_flags,
                            anonce, snonce, mic, eapol_data, pmkid,
                            capture_time, pcap_file, hashcat_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        bssid,
                        capture.ssid,
                        client_mac,
                        storage_type,
                        capture.msg_flags,
                        capture.anonce,
                        capture.snonce,
                        capture.mic,
                        capture.eapol_m2,
                        capture.pmkid,
                        capture_time,
                        str(pcap_file),
                        hashcat_hash,
                    ))
                    stored += 1
                    logger.info(
                        f"Stored {storage_type} handshake: {bssid} "
                        f"({capture.ssid or 'unknown'}) <-> {client_mac}"
                    )
                    continue

                msg_flags = (_row_value(best_row, 'msg_flags', 0) or 0) | capture.msg_flags
                anonce = capture.anonce or _row_value(best_row, 'anonce')
                snonce = capture.snonce or _row_value(best_row, 'snonce')
                mic = capture.mic or _row_value(best_row, 'mic')
                eapol_data = capture.eapol_m2 or _row_value(best_row, 'eapol_data')
                pmkid = capture.pmkid or _row_value(best_row, 'pmkid')
                ssid = capture.ssid or _row_value(best_row, 'ssid')
                hashcat_hash = hashcat_hash or _row_value(best_row, 'hashcat_hash')
                storage_type = _storage_handshake_type_from_fields(
                    msg_flags,
                    anonce,
                    snonce,
                    mic,
                    eapol_data,
                    pmkid,
                )

                cursor.execute("""
                    UPDATE handshakes
                    SET ssid = ?, handshake_type = ?, msg_flags = ?,
                        anonce = ?, snonce = ?, mic = ?, eapol_data = ?, pmkid = ?,
                        capture_time = ?, pcap_file = ?, hashcat_hash = ?
                    WHERE id = ?
                """, (
                    ssid,
                    storage_type,
                    msg_flags,
                    anonce,
                    snonce,
                    mic,
                    eapol_data,
                    pmkid,
                    capture_time,
                    str(pcap_file),
                    hashcat_hash,
                    _row_value(best_row, 'id'),
                ))
                stored += 1
                logger.info(
                    f"Updated handshake {storage_type}: {bssid} "
                    f"({ssid or 'unknown'}) <-> {client_mac}"
                )

            conn.commit()

        except Exception as e:
            logger.error(f"Failed to store handshakes: {e}")
            conn.rollback()
            raise
        finally:
            cursor.close()

        return stored

    def process_all_pending(self, limit: int = 100) -> list[ExtractionResult]:
        """
        Process all pending PCAP files in the captures directory.

        Args:
            limit: Maximum number of files to process

        Returns:
            List of ExtractionResult for each processed file
        """
        results = []

        # Find all dwell_*.pcapng files
        captures_dir = self.config.captures_dir
        if not captures_dir.exists():
            logger.warning(f"Captures directory not found: {captures_dir}")
            return results

        pcap_files = sorted(captures_dir.glob('dwell_*.pcapng'))

        if not pcap_files:
            logger.info("No PCAP files found to process")
            return results

        logger.info(f"Found {len(pcap_files)} PCAP files")

        for i, filepath in enumerate(pcap_files[:limit]):
            try:
                result = self.process_pcap(filepath)
                results.append(result)

                logger.info(
                    f"[{i+1}/{min(len(pcap_files), limit)}] {filepath.name}: "
                    f"{result.frame_count} frames, {result.eapol_frames} EAPOL, "
                    f"{result.handshakes_found} handshakes, {result.pmkids_found} PMKIDs"
                )
            except Exception as e:
                logger.error(f"Failed to process {filepath}: {e}")
                results.append(ExtractionResult(
                    pcap_file=str(filepath),
                    frame_count=0,
                    eapol_frames=0,
                    handshakes_found=0,
                    pmkids_found=0,
                    errors=[str(e)],
                    duration_sec=0,
                ))

        return results

    def get_stats(self) -> dict:
        """Get handshake extraction statistics from database."""
        if not PYODBC_AVAILABLE:
            return {'error': 'pyodbc not available'}

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN handshake_type = 'pmkid' THEN 1 ELSE 0 END) as pmkid_count,
                    SUM(CASE WHEN handshake_type = '4way_full' THEN 1 ELSE 0 END) as full_count,
                    SUM(CASE WHEN handshake_type = '4way_partial' THEN 1 ELSE 0 END) as partial_count,
                    SUM(CASE WHEN crack_status = 'cracked' THEN 1 ELSE 0 END) as cracked_count,
                    SUM(CASE WHEN crack_status = 'pending' THEN 1 ELSE 0 END) as pending_count,
                    COUNT(DISTINCT bssid) as unique_networks
                FROM handshakes
            """)

            row = cursor.fetchone()
            return {
                'total_handshakes': row.total or 0,
                'pmkid_captures': row.pmkid_count or 0,
                'full_handshakes': row.full_count or 0,
                'partial_handshakes': row.partial_count or 0,
                'cracked': row.cracked_count or 0,
                'pending': row.pending_count or 0,
                'unique_networks': row.unique_networks or 0,
            }
        finally:
            cursor.close()

    def export_handshake(
        self,
        handshake_id: int,
        output_file: Path | None = None
    ) -> str | None:
        """
        Export a handshake in hashcat 22000 format.

        Args:
            handshake_id: Database ID of the handshake
            output_file: Optional file to write to

        Returns:
            Hashcat hash string, or None if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT hashcat_hash FROM handshakes WHERE id = ?",
                (handshake_id,)
            )
            row = cursor.fetchone()

            if not row or not row.hashcat_hash:
                return None

            hash_str = row.hashcat_hash

            if output_file:
                output_file.write_text(hash_str + '\n')
                logger.info(f"Exported to {output_file}")

            return hash_str

        finally:
            cursor.close()


def main() -> None:
    """CLI entry point for handshake extraction."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    parser = argparse.ArgumentParser(description='NEXUS Handshake Extractor')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # process command
    proc_parser = subparsers.add_parser('process', help='Process PCAP files')
    proc_parser.add_argument('--pcap', type=Path, help='Specific PCAP file to process')
    proc_parser.add_argument('--limit', type=int, default=100, help='Max files to process')

    # stats command
    subparsers.add_parser('stats', help='Show handshake statistics')

    # export command
    export_parser = subparsers.add_parser('export', help='Export handshake for cracking')
    export_parser.add_argument('--id', type=int, required=True, help='Handshake ID')
    export_parser.add_argument('--output', type=Path, help='Output file')

    # list command
    list_parser = subparsers.add_parser('list', help='List captured handshakes')
    list_parser.add_argument('--limit', type=int, default=50, help='Max to show')

    args = parser.parse_args()

    if not SCAPY_AVAILABLE:
        print("❌ scapy is required: pip install scapy")
        return 1

    config = get_nexus_config()
    extractor = HandshakeExtractor(config)

    try:
        if args.command == 'process':
            if args.pcap:
                result = extractor.process_pcap(args.pcap)
                print(f"\n📦 Processed: {result.pcap_file}")
                print(f"   Frames: {result.frame_count}")
                print(f"   EAPOL frames: {result.eapol_frames}")
                print(f"   Handshakes: {result.handshakes_found}")
                print(f"   PMKIDs: {result.pmkids_found}")
                print(f"   Duration: {result.duration_sec:.2f}s")
                if result.errors:
                    print(f"   Errors: {len(result.errors)}")
            else:
                results = extractor.process_all_pending(limit=args.limit)
                total_hs = sum(r.handshakes_found for r in results)
                total_pmkid = sum(r.pmkids_found for r in results)
                print(f"\n✅ Processed {len(results)} files")
                print(f"   Total handshakes: {total_hs}")
                print(f"   Total PMKIDs: {total_pmkid}")

        elif args.command == 'stats':
            stats = extractor.get_stats()
            print("\n📊 Handshake Statistics")
            print(f"   Total captures: {stats['total_handshakes']}")
            print(f"   PMKID captures: {stats['pmkid_captures']}")
            print(f"   Full handshakes: {stats['full_handshakes']}")
            print(f"   Partial handshakes: {stats['partial_handshakes']}")
            print(f"   Cracked: {stats['cracked']}")
            print(f"   Pending: {stats['pending']}")
            print(f"   Unique networks: {stats['unique_networks']}")

        elif args.command == 'export':
            hash_str = extractor.export_handshake(args.id, args.output)
            if hash_str:
                print(f"✅ Hash: {hash_str}")
            else:
                print(f"❌ Handshake {args.id} not found or no hash available")

        elif args.command == 'list':
            conn = extractor._get_connection()
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT TOP ({args.limit}) id, bssid, ssid, client_mac, handshake_type,
                       crack_status, capture_time
                FROM handshakes
                ORDER BY capture_time DESC
            """)

            print(f"\n{'ID':>5} {'BSSID':<18} {'SSID':<20} {'Type':<10} {'Status':<10}")
            print("-" * 70)
            for row in cursor.fetchall():
                ssid = (row.ssid or '<unknown>')[:19]
                print(f"{row.id:>5} {row.bssid:<18} {ssid:<20} {row.handshake_type:<10} {row.crack_status:<10}")
            cursor.close()

        else:
            parser.print_help()

    finally:
        extractor.close()


if __name__ == '__main__':
    main()
