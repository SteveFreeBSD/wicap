from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def test_export_wicap_network_events_script_generates_outputs(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "export_wicap_network_events.py"
    input_path = tmp_path / "curated_events.jsonl"
    output_path = tmp_path / "wicap_network_events.jsonl"
    conn_path = tmp_path / "conn.jsonl"
    eve_path = tmp_path / "eve.jsonl"
    input_path.write_text(
        json.dumps(
            {
                "ts_epoch": 1768800000.0,
                "event_type": "deauth",
                "protocol": "wifi",
                "score": 90,
                "keys": {
                    "bssid": "aa:bb:cc:dd:ee:ff",
                    "ssid": "lab-net",
                    "sa_ip": "10.0.0.10",
                    "da_ip": "10.0.0.20",
                },
                "payload": {"src_port": 5353, "dest_port": 53},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--conn-output",
            str(conn_path),
            "--eve-output",
            str(eve_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert output_path.exists()
    assert conn_path.exists()
    assert eve_path.exists()
