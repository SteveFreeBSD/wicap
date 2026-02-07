"""
Investigation Workflow - Alert Context and Evidence Export

Provides tools to turn WIDS alerts into actionable investigations:
1. Alert enrichment with device history and network context
2. Timeline reconstruction around the alert
3. Evidence export (JSON report, PCAP slices)
"""

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class TimelineEvent:
    """A single event in an investigation timeline."""
    timestamp: float
    event_type: str
    description: str
    source_mac: str | None = None
    target_mac: str | None = None
    bssid: str | None = None
    ssid: str | None = None
    channel: int | None = None
    severity: int = 1
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Investigation:
    """An investigation case with context and timeline."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    alert_type: str = ""
    created_at: float = field(default_factory=time.time)
    status: str = "open"  # open, in_progress, closed
    severity: int = 1

    # Context
    primary_mac: str | None = None
    primary_bssid: str | None = None
    primary_ssid: str | None = None

    # Timeline
    timeline: list[TimelineEvent] = field(default_factory=list)

    # Evidence
    pcap_files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            'timeline': [e.to_dict() for e in self.timeline],
        }

    def add_event(self, event: TimelineEvent) -> None:
        self.timeline.append(event)
        self.timeline.sort(key=lambda x: x.timestamp)


class InvestigatorEngine:
    """
    Engine for creating and managing investigations from alerts.
    """

    def __init__(self, captures_dir: Path | None = None):
        self.captures_dir = captures_dir or Path("captures")
        self._investigations: dict[str, Investigation] = {}
        self._alert_to_investigation: dict[str, str] = {}  # alert_id -> investigation_id

    def create_investigation(
        self,
        alert_type: str,
        title: str,
        primary_mac: str | None = None,
        primary_bssid: str | None = None,
        primary_ssid: str | None = None,
        severity: int = 1,
    ) -> Investigation:
        """Create a new investigation from an alert."""
        inv = Investigation(
            title=title,
            alert_type=alert_type,
            primary_mac=primary_mac,
            primary_bssid=primary_bssid,
            primary_ssid=primary_ssid,
            severity=severity,
        )
        self._investigations[inv.id] = inv
        logger.info(f"Created investigation {inv.id}: {title}")
        return inv

    def from_alert(self, alert_data: dict) -> Investigation:
        """Create investigation from a WIDS alert."""
        alert_type = alert_data.get('alert_type', 'unknown')

        # Create descriptive title
        if alert_type == 'deauth_flood':
            title = "Deauth Flood Investigation"
        elif alert_type == 'evil_twin':
            ssid = alert_data.get('ssid', 'Unknown')
            title = f"Evil Twin Investigation: {ssid}"
        elif alert_type == 'crypto_downgrade':
            ssid = alert_data.get('ssid', 'Unknown')
            title = f"Crypto Downgrade Investigation: {ssid}"
        else:
            title = f"Security Investigation: {alert_type}"

        inv = self.create_investigation(
            alert_type=alert_type,
            title=title,
            primary_mac=alert_data.get('source_mac'),
            primary_bssid=alert_data.get('bssid'),
            primary_ssid=alert_data.get('ssid'),
            severity=alert_data.get('severity', 3),
        )

        # Add the triggering alert as first timeline event
        inv.add_event(TimelineEvent(
            timestamp=alert_data.get('timestamp', time.time()),
            event_type=f"alert_{alert_type}",
            description=alert_data.get('title', 'Alert triggered'),
            source_mac=alert_data.get('source_mac'),
            target_mac=alert_data.get('target_mac'),
            bssid=alert_data.get('bssid'),
            ssid=alert_data.get('ssid'),
            channel=alert_data.get('channel'),
            severity=alert_data.get('severity', 3),
        ))

        if 'id' in alert_data:
            self._alert_to_investigation[alert_data['id']] = inv.id

        return inv

    def add_context_events(
        self,
        investigation_id: str,
        events: list[dict],
    ) -> None:
        """Add contextual events to an investigation timeline."""
        if investigation_id not in self._investigations:
            return

        inv = self._investigations[investigation_id]

        for event_data in events:
            inv.add_event(TimelineEvent(
                timestamp=event_data.get('timestamp', time.time()),
                event_type=event_data.get('event_type', 'unknown'),
                description=event_data.get('description', ''),
                source_mac=event_data.get('source_mac'),
                target_mac=event_data.get('target_mac'),
                bssid=event_data.get('bssid'),
                ssid=event_data.get('ssid'),
                channel=event_data.get('channel'),
                metadata=event_data.get('metadata', {}),
            ))

    def attach_pcap(self, investigation_id: str, pcap_path: str) -> bool:
        """Attach a PCAP file as evidence."""
        if investigation_id not in self._investigations:
            return False

        self._investigations[investigation_id].pcap_files.append(pcap_path)
        logger.info(f"Attached PCAP {pcap_path} to investigation {investigation_id}")
        return True

    def add_note(self, investigation_id: str, note: str) -> bool:
        """Add an investigator note."""
        if investigation_id not in self._investigations:
            return False

        self._investigations[investigation_id].notes.append(note)
        return True

    def close_investigation(self, investigation_id: str) -> bool:
        """Close an investigation."""
        if investigation_id not in self._investigations:
            return False

        self._investigations[investigation_id].status = "closed"
        logger.info(f"Closed investigation {investigation_id}")
        return True

    def get_investigation(self, investigation_id: str) -> Investigation | None:
        """Get an investigation by ID."""
        return self._investigations.get(investigation_id)

    def get_all_investigations(self, status: str | None = None) -> list[Investigation]:
        """Get all investigations, optionally filtered by status."""
        investigations = list(self._investigations.values())

        if status:
            investigations = [i for i in investigations if i.status == status]

        return sorted(investigations, key=lambda x: x.created_at, reverse=True)

    def export_json(self, investigation_id: str) -> str | None:
        """Export investigation as JSON string."""
        inv = self.get_investigation(investigation_id)
        if not inv:
            return None

        return json.dumps(inv.to_dict(), indent=2)

    def export_to_file(self, investigation_id: str, output_path: Path) -> bool:
        """Export investigation to a JSON file."""
        json_str = self.export_json(investigation_id)
        if not json_str:
            return False

        try:
            output_path.write_text(json_str)
            logger.info(f"Exported investigation {investigation_id} to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False

    def get_stats(self) -> dict:
        """Get investigation statistics."""
        all_inv = list(self._investigations.values())
        return {
            'total': len(all_inv),
            'open': len([i for i in all_inv if i.status == 'open']),
            'in_progress': len([i for i in all_inv if i.status == 'in_progress']),
            'closed': len([i for i in all_inv if i.status == 'closed']),
        }
