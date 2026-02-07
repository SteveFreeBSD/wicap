"""
NEXUS Attack Analyzer
Component for analyzing capture files to detect active attacks and threats.
"""

import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import pyodbc

from .config import NexusConfig

logger = logging.getLogger('nexus.attack_analyzer')

@dataclass
class DetectedAttack:
    attack_type: str
    severity: int
    confidence: int
    start_time: datetime
    end_time: datetime
    target_bssid: str | None
    attacker_mac: str | None
    event_count: int
    description: str
    evidence: dict[str, Any]

class AttackAnalyzer:
    def __init__(self, config: NexusConfig):
        self.config = config

    def analyze_file(self, pcap_path: Path) -> list[DetectedAttack]:
        """Analyze a single pcap file for attack signatures."""
        attacks = []

        if not pcap_path.exists():
            return []

        # 1. Deauth Flood Detection
        deauth_attacks = self._detect_deauth_flood(pcap_path)
        attacks.extend(deauth_attacks)

        # 2. Rogue AP / Evil Twin (Basic Check)
        # rogue_attacks = self._detect_rogue_ap(pcap_path)
        # (Requires baseline knowledge, skipping for stateless analyzer MVP)

        # Persist results
        if attacks:
            self._persist_attacks(attacks, pcap_path)

        return attacks

    def _detect_deauth_flood(self, pcap_path: Path) -> list[DetectedAttack]:
        """
        Detect spikes in Deauthentication frames.
        Criteria: > 50 deauths in the capture file (assuming 30s dwell).
        """
        # tcpdump filter: type mgt subtype deauth
        try:
            # -n: no dns, -e: link-level header (macs), -tt: timestamp
            # We want source/dest macs.
            cmd = [
                'tcpdump', '-r', str(pcap_path), '-n', '-e', '-tt',
                'type mgt subtype deauth'
            ]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            lines = result.stdout.strip().split('\n')

            if not lines or lines == ['']:
                return []

            count = len(lines)
            if count < 50:
                return []

            # Analyze targets
            # tcpdump output format (802.11): ... SA:xx:xx:xx:xx:xx:xx DA:xx:xx:xx:xx:xx:xx ...
            # We parse simplified counts.
            min_ts = float('inf')
            max_ts = 0

            for line in lines:
                parts = line.split()
                try:
                    ts = float(parts[0])
                    min_ts = min(min_ts, ts)
                    max_ts = max(max_ts, ts)

                    # Parse MACs (rough heuristic looking for SA: and DA: or generic positions)
                    # 802.11 headers are variable.
                    # tcpdump -e usually shows SA:xx... BSSID:xx... DA:xx...
                    # Let's count totals for now.
                except (ValueError, IndexError):
                    pass

            duration = max(1.0, max_ts - min_ts)
            rate = count / duration

            if rate > 5.0: # > 5 deauths/sec
                logger.warning(f"🚨 Deauth Flood detected in {pcap_path.name}: {count} frames ({rate:.1f}/s)")

                return [DetectedAttack(
                    attack_type='deauth_flood',
                    severity=4, # High
                    confidence=90,
                    start_time=datetime.fromtimestamp(min_ts),
                    end_time=datetime.fromtimestamp(max_ts),
                    target_bssid=None, # Broad detection
                    attacker_mac=None,
                    event_count=count,
                    description=f"Deauthentication flood: {count} frames in {duration:.1f}s ({rate:.1f} fps)",
                    evidence={'file': pcap_path.name, 'rate': rate}
                )]
        except Exception as e:
            logger.error(f"Deauth analysis failed: {e}")

        return []

    def _persist_attacks(self, attacks: list[DetectedAttack], pcap_path: Path):
        """Write detections to DB."""
        try:
            with pyodbc.connect(self.config.get_sql_connection_string()) as conn:
                cursor = conn.cursor()
                for a in attacks:
                    cursor.execute("""
                        INSERT INTO attack_timeline
                        (attack_type, severity, confidence, target_bssid, attacker_mac,
                         start_time, end_time, duration_sec, event_count, description, evidence_pcaps, inserted_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, SYSDATETIME())
                    """, (
                        a.attack_type, a.severity, a.confidence, a.target_bssid, a.attacker_mac,
                        a.start_time, a.end_time, int((a.end_time - a.start_time).total_seconds()),
                        a.event_count, a.description, json.dumps([str(pcap_path)])
                    ))
                conn.commit()
                logger.info(f"Recorded {len(attacks)} attack events from {pcap_path.name}")
        except Exception as e:
            logger.error(f"Failed to persist attacks: {e}")
