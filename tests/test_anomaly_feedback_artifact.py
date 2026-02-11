from __future__ import annotations

import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
WICAP_UI_ROOT = REPO_ROOT / "wicap-ui"
if str(WICAP_UI_ROOT) not in sys.path:
    sys.path.insert(0, str(WICAP_UI_ROOT))

from app.services.anomaly_feedback import FEEDBACK_CONTRACT_VERSION, append_anomaly_feedback_event


def test_append_anomaly_feedback_event_writes_contract_jsonl(tmp_path: Path, monkeypatch) -> None:
    output_path = tmp_path / "wicap_anomaly_feedback.jsonl"
    monkeypatch.setenv("WICAP_ANOMALY_FEEDBACK_PATH", str(output_path))

    path = append_anomaly_feedback_event(
        alert_id="atk-42",
        label="confirmed",
        note="operator verified this anomaly",
        attack_id=42,
        attack_type="anomaly_stream",
        bssid="AA:BB:CC:DD:EE:FF",
    )
    assert path == output_path
    assert output_path.exists()

    lines = [line for line in output_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["feedback_contract_version"] == FEEDBACK_CONTRACT_VERSION
    assert payload["alert_id"] == "atk-42"
    assert payload["label"] == "confirmed"
    assert payload["attack_id"] == 42
    assert payload["attack_type"] == "anomaly_stream"
    assert payload["bssid"] == "aa:bb:cc:dd:ee:ff"
    assert payload["source"] == "api_alert_feedback"

