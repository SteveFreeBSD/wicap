"""
Unit tests for Investigation Workflow.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import tempfile
from pathlib import Path

import pytest

from nexus.intel.investigator import Investigation, InvestigatorEngine, TimelineEvent


class TestTimelineEvent:
    """Test TimelineEvent dataclass."""

    def test_to_dict(self):
        event = TimelineEvent(
            timestamp=1000.0,
            event_type='deauth',
            description='Deauth frame detected',
            source_mac='AA:BB:CC:DD:EE:FF',
            channel=6,
        )
        d = event.to_dict()
        assert d['timestamp'] == 1000.0
        assert d['event_type'] == 'deauth'
        assert d['source_mac'] == 'AA:BB:CC:DD:EE:FF'


class TestInvestigation:
    """Test Investigation dataclass."""

    def test_add_event_sorts_by_timestamp(self):
        inv = Investigation(title='Test')

        inv.add_event(TimelineEvent(timestamp=300.0, event_type='e3', description='Third'))
        inv.add_event(TimelineEvent(timestamp=100.0, event_type='e1', description='First'))
        inv.add_event(TimelineEvent(timestamp=200.0, event_type='e2', description='Second'))

        assert len(inv.timeline) == 3
        assert inv.timeline[0].timestamp == 100.0
        assert inv.timeline[1].timestamp == 200.0
        assert inv.timeline[2].timestamp == 300.0

    def test_to_dict(self):
        inv = Investigation(
            title='Test Investigation',
            alert_type='deauth_flood',
            severity=4,
        )
        d = inv.to_dict()
        assert d['title'] == 'Test Investigation'
        assert d['alert_type'] == 'deauth_flood'
        assert d['severity'] == 4
        assert 'timeline' in d


class TestInvestigatorEngine:
    """Test InvestigatorEngine functionality."""

    @pytest.fixture
    def engine(self):
        return InvestigatorEngine()

    def test_create_investigation(self, engine):
        inv = engine.create_investigation(
            alert_type='deauth_flood',
            title='Test Deauth Investigation',
            primary_mac='AA:BB:CC:DD:EE:FF',
            severity=4,
        )

        assert inv.id is not None
        assert inv.title == 'Test Deauth Investigation'
        assert inv.alert_type == 'deauth_flood'
        assert inv.status == 'open'

    def test_from_alert(self, engine):
        alert = {
            'id': 'alert123',
            'alert_type': 'evil_twin',
            'title': 'Evil Twin Detected',
            'ssid': 'TestNetwork',
            'bssid': '11:22:33:44:55:66',
            'severity': 3,
            'timestamp': 1000.0,
        }

        inv = engine.from_alert(alert)

        assert inv.alert_type == 'evil_twin'
        assert 'Evil Twin' in inv.title
        assert inv.primary_ssid == 'TestNetwork'
        assert len(inv.timeline) == 1

    def test_add_context_events(self, engine):
        inv = engine.create_investigation(
            alert_type='test',
            title='Test',
        )

        events = [
            {'timestamp': 100.0, 'event_type': 'probe', 'description': 'Probe request'},
            {'timestamp': 200.0, 'event_type': 'assoc', 'description': 'Association'},
        ]

        engine.add_context_events(inv.id, events)

        retrieved = engine.get_investigation(inv.id)
        assert len(retrieved.timeline) == 2

    def test_attach_pcap(self, engine):
        inv = engine.create_investigation(alert_type='test', title='Test')

        result = engine.attach_pcap(inv.id, '/path/to/capture.pcapng')

        assert result is True
        assert '/path/to/capture.pcapng' in inv.pcap_files

    def test_add_note(self, engine):
        inv = engine.create_investigation(alert_type='test', title='Test')

        result = engine.add_note(inv.id, 'This looks suspicious')

        assert result is True
        assert 'This looks suspicious' in inv.notes

    def test_close_investigation(self, engine):
        inv = engine.create_investigation(alert_type='test', title='Test')
        assert inv.status == 'open'

        result = engine.close_investigation(inv.id)

        assert result is True
        assert inv.status == 'closed'

    def test_get_all_investigations(self, engine):
        engine.create_investigation(alert_type='test', title='Test 1')
        engine.create_investigation(alert_type='test', title='Test 2')

        all_inv = engine.get_all_investigations()
        assert len(all_inv) == 2

    def test_get_investigations_by_status(self, engine):
        inv1 = engine.create_investigation(alert_type='test', title='Test 1')
        engine.create_investigation(alert_type='test', title='Test 2')
        engine.close_investigation(inv1.id)

        open_inv = engine.get_all_investigations(status='open')
        closed_inv = engine.get_all_investigations(status='closed')

        assert len(open_inv) == 1
        assert len(closed_inv) == 1

    def test_export_json(self, engine):
        inv = engine.create_investigation(
            alert_type='test',
            title='Export Test',
        )

        json_str = engine.export_json(inv.id)

        assert json_str is not None
        assert 'Export Test' in json_str
        assert '"timeline"' in json_str

    def test_export_to_file(self, engine):
        inv = engine.create_investigation(alert_type='test', title='File Export Test')

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = Path(f.name)

        try:
            result = engine.export_to_file(inv.id, output_path)
            assert result is True
            assert output_path.exists()

            content = output_path.read_text()
            assert 'File Export Test' in content
        finally:
            output_path.unlink(missing_ok=True)

    def test_get_stats(self, engine):
        engine.create_investigation(alert_type='test', title='Open 1')
        inv2 = engine.create_investigation(alert_type='test', title='Closed 1')
        engine.close_investigation(inv2.id)

        stats = engine.get_stats()

        assert stats['total'] == 2
        assert stats['open'] == 1
        assert stats['closed'] == 1
