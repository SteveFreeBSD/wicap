"""
Scavenger Pipeline - Main Orchestration

Coordinates PCAP ingestion through agent processing to correlation.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from nexus.device_fingerprint import DeviceFingerprinter
from nexus.scavenger.agents import AgentCartographer, AgentCrypt, AgentShadow, AgentSnoopy
from nexus.scavenger.correlator import IdentityFusion
from nexus.scavenger.ingest import PCAPStreamer
from nexus.scavenger.persistence import ScavengerDAO


class ScavengerPipeline:
    """
    Main orchestration pipeline for Scavenger.

    Coordinates:
    1. PCAP ingestion via PCAPStreamer
    2. Agent processing (Shadow, Crypt, Cartographer, Snoopy)
    3. Intelligence fusion via IdentityFusion
    """

    def __init__(
        self,
        capture_dir: Path,
        config: Any = None,
        agents: list[str] = None
    ):
        """
        Initialize the Scavenger pipeline.

        Args:
            capture_dir: Directory containing PCAP files
            config: Optional NexusConfig for settings
            agents: List of agent names to enable
                   Default: 'shadow', 'crypt', 'cartographer'
                   Options: 'shadow', 'crypt', 'cartographer', 'snoopy'
        """
        self.capture_dir = Path(capture_dir)
        self.config = config

        # Initialize streamer
        self.streamer = PCAPStreamer(self.capture_dir)

        # Initialize agents based on config
        enabled_agents = agents or ['shadow', 'crypt', 'cartographer']
        self._agents: dict[str, Any] = {}

        if 'shadow' in enabled_agents:
            self._agents['shadow'] = AgentShadow()
        if 'crypt' in enabled_agents:
            self._agents['crypt'] = AgentCrypt()
        if 'cartographer' in enabled_agents:
            self._agents['cartographer'] = AgentCartographer()
        if 'snoopy' in enabled_agents:
            self._agents['snoopy'] = AgentSnoopy()

        # Initialize fingerprinter if config available
        fingerprinter = None
        if self.config:
            try:
                fingerprinter = DeviceFingerprinter(self.config)
            except Exception as e:
                print(f"Warning: Failed to initialize DeviceFingerprinter: {e}")

        # Initialize correlator with fingerprinter
        self.correlator = IdentityFusion(fingerprinter=fingerprinter)

        # Initialize persistence [NEW]
        self.dao = None
        if self.config:
            try:
                self.dao = ScavengerDAO(self.config)
            except Exception as e:
                print(f"Warning: Failed to initialize Scavenger persistence: {e}")

        # Processing state
        self._intelligence_buffer: list[dict[str, Any]] = []
        self._rssi_offsets: dict[str, int] = {}
        self._stats = {
            'files_processed': 0,
            'packets_processed': 0,
            'intelligence_extracted': 0,
            'start_time': None,
            'end_time': None,
        }

    @property
    def agents(self) -> dict[str, Any]:
        """Get active agents."""
        return self._agents

    def run(
        self,
        pcap_files: list[Path] = None,
        deduplicate: bool = True,
        progress_callback=None,
        db_conn: Any | None = None,
    ) -> dict[str, Any]:
        """
        Process PCAPs through the pipeline.

        Args:
            pcap_files: Specific files to process (default: all in capture_dir)
            deduplicate: Enable packet deduplication
            progress_callback: Optional callback(packets_processed, file_name)
            db_conn: Optional DB connection to reuse for persistence

        Returns:
            Summary dict with statistics and key findings
        """
        self._stats['start_time'] = datetime.now()

        # Get files to process
        if pcap_files is None:
            pcap_files = self.streamer.list_captures()

        try:
            # Process each file
            for pcap_path in pcap_files:
                self._stats['files_processed'] += 1

                # Stream packets
                stream = (
                    self.streamer.stream_capture_deduplicated(pcap_path)
                    if deduplicate else
                    self.streamer.stream_capture(pcap_path)
                )

                file_intelligence = []

                for packet in stream:
                    self._stats['packets_processed'] += 1

                    # Run through each agent
                    for _agent_name, agent in self._agents.items():
                        result = agent.process(packet)
                        if result:
                            file_intelligence.append(result)
                            self._stats['intelligence_extracted'] += 1

                    # Progress callback
                    if progress_callback and self._stats['packets_processed'] % 1000 == 0:
                        progress_callback(
                            self._stats['packets_processed'],
                            pcap_path.name
                        )

                # Fuse intelligence for this file immediately
                if file_intelligence:
                    self.correlator.fuse(file_intelligence)

                    # Persist to DB if DAO available
                    if self.dao:
                        self._persist_findings(file_intelligence, db_conn=db_conn)

        except StopIteration:
            pass # Max packets reached
        except KeyboardInterrupt:
            print("Stopped by user")
        finally:
            # Final pass (in case anything buffered) - now handled per file
            pass

        self._stats['end_time'] = datetime.now()

        return self._generate_summary()

    def _persist_findings(
        self,
        intelligence_items: list[dict[str, Any]],
        db_conn: Any | None = None,
    ) -> None:
        """Persist fuse results to SQL."""
        if not self.dao:
            return

        commit = db_conn is None

        # 1. Persist Handshakes (from agents)
        # AgentCrypt keeps state. We need to check its new handshakes.
        if 'crypt' in self._agents:
            crypt = self._agents['crypt']
            for _bssid, hs in crypt.handshakes.items():
                # We simply try to save all; DAO handles duplicates
                self.dao.save_handshake(hs, conn=db_conn, commit=commit)

        # 2. Persist Dossiers (from correlator)
        # We assume correlator state is updated. We persist all touched dossiers?
        # IdentityFusion doesn't track "dirty" dossiers easily.
        # But we can iterate all dossiers for now (if < 1000 clients, fast).
        # For optimization, we could track which MACs were touched in this batch.
        # IdentityFusion.fuse processes intelligence -> updates dossiers.
        # We can extract MACs from intelligence_items and only save those!

        touched_macs = set()
        for item in intelligence_items:
            if 'src_mac' in item:
                touched_macs.add(item['src_mac'])

        dossiers = []
        for mac in touched_macs:
            dossier = self.correlator.get_dossier(mac)
            if dossier:
                dossiers.append(dossier)
        if dossiers:
            self.dao.merge_dossiers_batch(dossiers, conn=db_conn, commit=commit)

        # 3. Persist RSSI aggregates from AgentShadow profiles
        shadow = self._agents.get('shadow')
        if shadow:
            samples = []
            offsets: dict[str, int] = {}
            for mac in touched_macs:
                profile = shadow.get_client_pnl(mac)
                if not profile or not profile.rssi_history:
                    continue
                history_len = len(profile.rssi_history)
                offset = self._rssi_offsets.get(mac, 0)
                if offset > history_len:
                    offset = history_len
                new_samples = profile.rssi_history[offset:]
                if not new_samples:
                    continue
                samples.append((mac, new_samples, profile.last_seen))
                offsets[mac] = history_len
            if samples and self.dao.merge_rssi_aggregates(samples, conn=db_conn, commit=commit):
                self._rssi_offsets.update(offsets)

    def _generate_summary(self) -> dict[str, Any]:
        """Generate a summary of the processing run."""
        duration = None
        if self._stats['start_time'] and self._stats['end_time']:
            duration = (self._stats['end_time'] - self._stats['start_time']).total_seconds()

        # Get agent-specific stats
        agent_stats = {}
        for name, agent in self._agents.items():
            agent_stats[name] = agent.get_stats()

        # Get key findings
        shadow = self._agents.get('shadow')
        crypt = self._agents.get('crypt')

        top_ssids = []
        if shadow:
            popularity = shadow.get_ssid_popularity()
            top_ssids = list(popularity.items())[:10]

        complete_handshakes = []
        pmkids = {}
        if crypt:
            complete_handshakes = crypt.get_complete_handshakes()
            pmkids = crypt.get_pmkids()

        return {
            'summary': {
                'files_processed': self._stats['files_processed'],
                'packets_processed': self._stats['packets_processed'],
                'intelligence_extracted': self._stats['intelligence_extracted'],
                'duration_seconds': duration,
                'packets_per_second': (
                    self._stats['packets_processed'] / duration
                    if duration and duration > 0 else 0
                ),
            },
            'agents': agent_stats,
            'correlator': self.correlator.get_stats(),
            'findings': {
                'unique_clients': len(shadow.client_profiles) if shadow else 0,
                'top_probed_ssids': top_ssids,
                'complete_handshakes': complete_handshakes,
                'pmkids_found': sum(len(v) for v in pmkids.values()),
                'suggested_correlations': len(
                    self.correlator.suggest_correlations(min_confidence=0.5)
                ),
            }
        }

    def get_client_pnl(self, mac: str) -> dict[str, Any] | None:
        """Get PNL for a specific client."""
        shadow = self._agents.get('shadow')
        if shadow:
            pnl = shadow.get_client_pnl(mac)
            return pnl.to_dict() if pnl else None
        return None

    def get_handshake_state(self, bssid: str) -> dict[str, Any] | None:
        """Get handshake state for a BSSID."""
        crypt = self._agents.get('crypt')
        if crypt:
            state = crypt.get_handshake_state(bssid)
            return state.to_dict() if state else None
        return None

    def get_dossier(self, mac: str) -> dict[str, Any] | None:
        """Get intelligence dossier for a MAC."""
        return self.correlator.generate_dossier(mac)

    def export_dossiers(self, output_path: Path) -> int:
        """
        Export all dossiers to JSON file.

        Args:
            output_path: Path to output file

        Returns:
            Number of dossiers exported
        """
        return self.correlator.export_all(str(output_path))

    def export_summary(self, output_path: Path) -> None:
        """Export run summary to JSON file."""
        summary = self._generate_summary()

        # Convert datetime objects
        summary['summary']['start_time'] = (
            self._stats['start_time'].isoformat()
            if self._stats['start_time'] else None
        )
        summary['summary']['end_time'] = (
            self._stats['end_time'].isoformat()
            if self._stats['end_time'] else None
        )

        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)

    def reset(self) -> None:
        """Reset all pipeline state."""
        for agent in self._agents.values():
            agent.reset()
        self.correlator.reset()
        self.streamer.reset_stats()
        self._intelligence_buffer.clear()
        self._rssi_offsets.clear()
        self._stats = {
            'files_processed': 0,
            'packets_processed': 0,
            'intelligence_extracted': 0,
            'start_time': None,
            'end_time': None,
        }

    def get_stats(self) -> dict[str, Any]:
        """Get current pipeline statistics."""
        return {
            'pipeline': self._stats.copy(),
            'streamer': self.streamer.get_stats(),
            'agents': {
                name: agent.get_stats()
                for name, agent in self._agents.items()
            },
            'correlator': self.correlator.get_stats(),
        }
