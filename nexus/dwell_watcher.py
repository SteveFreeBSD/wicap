"""
DwellWatcher: Automated Handshake Extraction Daemon
Monitors capture directory for new dwell files and processes them.
"""

import concurrent.futures
import json
import logging
import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

import pyodbc

from .attack_analyzer import AttackAnalyzer
from .config import NexusConfig
from .password_auditor_enhanced import EnhancedPasswordAuditor
from .scavenger.pipeline import ScavengerPipeline

logger = logging.getLogger('nexus.dwell_watcher')

class DwellWatcher:
    """
    Watches for new dwell_*.pcapng files, extracts handshakes using hcxpcapngtool,
    and ingests them into the database.
    """

    def __init__(self, config: NexusConfig):
        self.config = config
        self.captures_dir = config.captures_dir
        self.state_file = config.base_dir / "dwell_state.json"
        self.processed_files: set[str] = self._load_state()
        if getattr(config, "dwell_baseline_on_start", False):
            self.baseline_existing()
        self.auditor = EnhancedPasswordAuditor(config)
        self.attack_analyzer = AttackAnalyzer(config)
        # Thread pool for async Scavenger analysis
        # Use available CPUs for parallel analysis
        self.scavenger_executor = concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4)

    def _load_state(self) -> set[str]:
        """Load set of processed filenames from JSON state."""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    data = json.load(f)
                    return set(data.get('processed_files', []))
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
        return set()

    def _save_state(self):
        """Save processed files to JSON state."""
        try:
            temp_state = self.state_file.with_suffix('.tmp')
            with open(temp_state, 'w') as f:
                json.dump({'processed_files': list(self.processed_files)}, f, indent=2)
            shutil.move(str(temp_state), str(self.state_file))
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def baseline_existing(self) -> int:
        """Mark existing dwell captures as processed to avoid backlog ingestion."""
        if not self.captures_dir.exists():
            logger.warning(f"Captures dir not found: {self.captures_dir}")
            return 0

        existing = [p.name for p in self.captures_dir.glob("dwell_*.pcapng")]
        new_entries = [name for name in existing if name not in self.processed_files]
        if not new_entries:
            return 0

        self.processed_files.update(new_entries)
        self._save_state()
        logger.info(f"Baselined {len(new_entries)} existing capture files.")
        return len(new_entries)

    def watch(self, interval: int = 60) -> None:
        """Main loop: Poll -> Process -> Sleep."""
        logger.info("👁️ DwellWatcher started.")
        logger.info(f"   📂 Watching: {self.captures_dir}")
        logger.info(f"   💾 State: {self.state_file}")

        try:
            while True:
                self._run_cycle()
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Stopping watcher...")

    def _run_cycle(self):
        new_files = self._scan_files()
        if not new_files:
            return

        # Optimization: Process Newest First (LIFO)
        # Limit batch size to prevent blocking the loop for too long
        BATCH_SIZE = 20
        batch = new_files[:BATCH_SIZE]

        logger.info(f"🔎 Found {len(new_files)} unprocessed files. Processing batch of {len(batch)} (Newest First)...")
        count_imported = 0

        for pcap_path in batch:
            if self._process_file(pcap_path):
                count_imported += 1

        if count_imported > 0:
            logger.info(f"🚀 Triggering prioritized audit for {count_imported} new sources...")
            # Trigger quick audit on new stuff
            try:
                self.auditor.prioritize_and_audit_pending(limit=5, max_total_time_sec=300)
            except Exception as e:
                logger.error(f"Audit trigger failed: {e}")

    def _scan_files(self) -> list[Path]:
        """Return list of new .pcapng files sorted by time (Newest First)."""
        if not self.captures_dir.exists():
            logger.warning(f"Captures dir not found: {self.captures_dir}")
            return []

        files = []
        for p in self.captures_dir.glob("dwell_*.pcapng"):
            if p.name not in self.processed_files:
                files.append(p)

        # Sort desc (Newest first) to ensure real-time responsiveness
        return sorted(files, key=lambda f: f.stat().st_mtime, reverse=True)

    def _process_file(self, pcap_path: Path) -> bool:
        """Extract handshakes from pcap and insert to DB."""
        temp_hash_file = self.config.base_dir / "temp.22000"
        success = False

        try:
            # 0. Stability Check (avoid partial reads)
            try:
                s1 = pcap_path.stat().st_size
                time.sleep(1.0)
                s2 = pcap_path.stat().st_size
                if s1 != s2:
                    logger.debug(f"⏳ File {pcap_path.name} is growing, deferring...")
                    return False
            except FileNotFoundError:
                return False

            # Mark as processed immediately to prevent loops if it crashes later
            # (If it crashes, we assume bad file and don't retry infinite times)
            self.processed_files.add(pcap_path.name)
            self._save_state()

            # 0.5 Run Attack Analysis
            try:
                self.attack_analyzer.analyze_file(pcap_path)
            except Exception as e:
                logger.error(f"Attack analysis failed for {pcap_path.name}: {e}")

            # 0.6 Run Scavenger Analysis (Async)
            try:
                self.scavenger_executor.submit(self._run_scavenger, pcap_path)
            except Exception as e:
                logger.error(f"Failed to submit to scavenger: {e}")

            # 1. Run hcxpcapngtool
            cmd = ['hcxpcapngtool', '-o', str(temp_hash_file), str(pcap_path)]
            # Run quietly unless debug
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=False)

            if not temp_hash_file.exists() or temp_hash_file.stat().st_size == 0:
                logger.debug(f"No handshakes found in {pcap_path.name}")
                return False

            # 2. Read and Parse
            with open(temp_hash_file) as f:
                lines = f.readlines()

            imported_count = 0
            with pyodbc.connect(self.config.get_sql_connection_string()) as conn:
                cursor = conn.cursor()

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # 22000 format: SIGNATURE*TYPE*PMKID*MAC_AP*MAC_STA*SSID_HEX*...
                    parts = line.split('*')
                    if len(parts) < 6:
                        continue

                    # Parse fields
                    try:
                        parts[0] # WPA
                        hs_type_code = parts[1] # 01=PMKID, 02=EAPOL
                        parts[2]
                        mac_ap_raw = parts[3]
                        mac_sta_raw = parts[4]
                        ssid_hex = parts[5]

                        mac_ap = ':'.join(mac_ap_raw[i:i+2] for i in range(0,12,2)).upper()
                        mac_sta = ':'.join(mac_sta_raw[i:i+2] for i in range(0,12,2)).upper()

                        try:
                            ssid = bytes.fromhex(ssid_hex).decode('utf-8')
                        except (ValueError, UnicodeDecodeError):
                            ssid = f"Unknown_{ssid_hex[:6]}"

                        # Handshake Type
                        hs_type = 'pmkid' if hs_type_code == '01' else '4way'

                        # Check exist
                        cursor.execute("SELECT id FROM handshakes WHERE hashcat_hash = ?", (line,))
                        if cursor.fetchone():
                            continue # Skip duplicate

                        # Capture Time from file mtime
                        capture_time = datetime.fromtimestamp(pcap_path.stat().st_mtime)

                        # Priority Score
                        # Assuming logic: priority 50 + boosts
                        # We can use auditor.compute_priority_score (public method)
                        score = self.auditor.compute_priority_score(ssid, -60, False) # Assume -60 rssi default

                        # Insert
                        cursor.execute("""
                            INSERT INTO handshakes
                            (bssid, ssid, client_mac, handshake_type, hashcat_hash, capture_time, priority_score, crack_status, dwell_file, msg_flags)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, 0)
                        """, (mac_ap, ssid, mac_sta, hs_type, line, capture_time, score, str(pcap_path)))

                        imported_count += 1

                    except Exception as e:
                        logger.warning(f"Error parsing hash line: {e}")
                        continue

                conn.commit()

            if imported_count > 0:
                logger.info(f"✅ Imported {imported_count} handshakes from {pcap_path.name}")
                success = True
            else:
                logger.info(f"🔹 No new unique handshakes in {pcap_path.name}")

        except Exception as e:
            logger.error(f"Error processing {pcap_path.name}: {e}")
        finally:
            # Cleanup
            if temp_hash_file.exists():
                temp_hash_file.unlink()

        return success

    def _run_scavenger(self, pcap_path: Path):
        """Run Scavenger analysis on the file."""
        try:
            logger.info(f"🦅 Scavenging {pcap_path.name}...")
            # Run Shadow (PNL), Crypt (Handshakes), and Cartographer (Associations) agents
            pipeline = ScavengerPipeline(
                capture_dir=pcap_path.parent,
                config=self.config,
                agents=['shadow', 'crypt', 'cartographer']
            )
            # Run on specific file; disable dedup for single-file stream
            result = pipeline.run(pcap_files=[pcap_path], deduplicate=False)

            cartographer = pipeline.agents.get("cartographer")
            if cartographer and pipeline.dao:
                associations = cartographer.export_associations()
                if associations:
                    pipeline.dao.merge_associations_batch(associations)

            logger.info(f"🦅 Scavenged {pcap_path.name}: {result}")
        except Exception as e:
            logger.error(f"Scavenger failed for {pcap_path.name}: {e}")
