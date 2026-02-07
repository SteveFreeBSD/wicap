import json
from pathlib import Path

import pytest

EXPECTED_EVENT_TYPES = {
    "deauth",
    "deauth_spike",
    "hidden_ssid",
    "new_bssid",
    "new_ssid",
    "open_network",
    "probe_directed",
    "strong_rssi",
    "telemetry_pulse",
}


@pytest.mark.unit
def test_replay_fixture_event_types_complete():
    events_dir = Path(__file__).parent / "fixtures" / "events"
    assert events_dir.exists(), "Fixture events directory missing"

    observed = set()
    for path in events_dir.glob("*.expected.jsonl"):
        with open(path) as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                event_type = data.get("event_type")
                if event_type:
                    observed.add(event_type)

    missing = EXPECTED_EVENT_TYPES - observed
    assert not missing, f"Missing event types in fixtures: {sorted(missing)}"
