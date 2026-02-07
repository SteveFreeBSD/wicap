from unittest.mock import MagicMock

import pytest

from nexus.intel.incident_manager import IncidentManager


@pytest.fixture
def mock_cursor():
    return MagicMock()

def test_assign_incident_creates_new_if_none_active(mock_cursor):
    im = IncidentManager(mock_cursor)

    # Mock finding active incident -> None
    mock_cursor.fetchone.return_value = None

    alert = {
        'alert_id': 'a1',
        'alert_signature': 'Sig1',
        'source_mac': '00:11:22:33:44:55',
        'ts_epoch': 1000.0,
        'title': 'Test Alert'
    }

    inc_id = im.assign_incident(alert)

    assert inc_id is not None
    # Should attempt to insert new incident
    assert mock_cursor.execute.call_count >= 1
    # Verify INSERT INTO incidents was called
    args, _ = mock_cursor.execute.call_args_list[-1]
    assert "INSERT INTO incidents" in args[0]

def test_assign_incident_reuses_active_within_window(mock_cursor):
    im = IncidentManager(mock_cursor)

    # 1. First alert creates incident
    mock_cursor.fetchone.return_value = None # No existing
    alert1 = {'alert_signature': 'Sig1', 'source_mac': 'src1', 'ts_epoch': 1000.0}
    inc_id1 = im.assign_incident(alert1)

    # Reset mock to simulate "finding" the just-created incident
    # But IncidentManager uses internal cache first.
    # So second alert should hit cache.

    alert2 = {'alert_signature': 'Sig1', 'source_mac': 'src1', 'ts_epoch': 1100.0} # +100s
    inc_id2 = im.assign_incident(alert2)

    assert inc_id1 == inc_id2
    # Should update incident, not insert new
    # Check that UPDATE incidents was called
    calls = [str(c) for c in mock_cursor.execute.call_args_list]
    assert any("UPDATE incidents" in c for c in calls)

def test_assign_incident_creates_new_if_window_expired(mock_cursor):
    im = IncidentManager(mock_cursor)

    # 1. First alert
    mock_cursor.fetchone.return_value = None
    alert1 = {'alert_signature': 'Sig1', 'source_mac': 'src1', 'ts_epoch': 1000.0}
    inc_id1 = im.assign_incident(alert1)

    # 2. Second alert much later (e.g. 1 hour = 3600s)
    # Incident window is 30 mins (1800s)
    alert2 = {'alert_signature': 'Sig1', 'source_mac': 'src1', 'ts_epoch': 1000.0 + 3600.0}

    inc_id2 = im.assign_incident(alert2)

    assert inc_id1 != inc_id2
    # Should have inserted a second incident (different ID)
    insert_calls = [str(c) for c in mock_cursor.execute.call_args_list if "INSERT INTO incidents" in str(c)]
    assert len(insert_calls) == 2


def test_assign_incident_clips_long_key_fields(mock_cursor):
    im = IncidentManager(mock_cursor)
    mock_cursor.fetchone.return_value = None

    long_sig = "S" * 1000
    alert = {
        "alert_signature": long_sig,
        "source_mac": "AA:BB:CC:DD:EE:FF:11",
        "target_mac": "11:22:33:44:55:66:77",
        "bssid": "66:55:44:33:22:11:99",
        "title": "T" * 2000,
        "severity": "bad",
        "ts_epoch": 1000.0,
    }

    im.assign_incident(alert)

    first_call_args, _ = mock_cursor.execute.call_args_list[0]
    params = first_call_args[1]
    assert len(params[0]) == 256
    assert len(params[1]) == 17
    assert len(params[2]) == 17
    assert len(params[3]) == 17

    insert_calls = [c for c in mock_cursor.execute.call_args_list if "INSERT INTO incidents" in str(c)]
    assert insert_calls
    insert_args, _ = insert_calls[-1]
    insert_params = insert_args[1]
    assert len(insert_params[2]) == 200
    assert insert_params[1] == 1
