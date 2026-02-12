from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _write_runtime_files(captures_dir: Path, *, curated_event: dict[str, object]) -> None:
    captures_dir.mkdir(parents=True, exist_ok=True)
    queue_path = captures_dir / "event_queue.jsonl"
    curated_path = captures_dir / "curated_events.jsonl"
    state_path = captures_dir / "processor.state.json"
    queue_path.write_text(json.dumps({"event_type": "telemetry_pulse"}) + "\n", encoding="utf-8")
    curated_path.write_text(json.dumps(curated_event) + "\n", encoding="utf-8")
    state_path.write_text(json.dumps({"byte_offset": 0}), encoding="utf-8")


def test_run_agentic_rollout_gate_passes_with_assistant_report_and_shadow_data(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "run_agentic_rollout_gate.py"
    captures_dir = tmp_path / "captures"
    _write_runtime_files(
        captures_dir,
        curated_event={
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
        },
    )
    assistant_report = tmp_path / "assistant_rollout.json"
    assistant_report.write_text(
        json.dumps({"overall_pass": True, "promotion": {"ready": True}}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--captures-dir",
            str(captures_dir),
            "--assistant-rollout-report",
            str(assistant_report),
            "--shadow-work-dir",
            str(tmp_path / "shadow"),
            "--require-shadow-data",
            "--enforce",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert bool(payload["overall_pass"]) is True
    assert payload["gates"]["local_runtime"]["status"] == "pass"
    assert payload["gates"]["assistant_rollout"]["status"] == "pass"
    assert payload["gates"]["shadow_validation"]["status"] == "pass"


def test_run_agentic_rollout_gate_enforce_fails_when_assistant_gate_fails(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "run_agentic_rollout_gate.py"
    captures_dir = tmp_path / "captures"
    _write_runtime_files(
        captures_dir,
        curated_event={
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
        },
    )
    assistant_report = tmp_path / "assistant_rollout_fail.json"
    assistant_report.write_text(
        json.dumps({"overall_pass": False, "promotion": {"ready": False}}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--captures-dir",
            str(captures_dir),
            "--assistant-rollout-report",
            str(assistant_report),
            "--shadow-work-dir",
            str(tmp_path / "shadow"),
            "--enforce",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert bool(payload["overall_pass"]) is False
    assert payload["gates"]["assistant_rollout"]["status"] == "fail"


def test_run_agentic_rollout_gate_enforce_fails_when_shadow_gate_required_and_fails(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "run_agentic_rollout_gate.py"
    captures_dir = tmp_path / "captures"
    _write_runtime_files(
        captures_dir,
        curated_event={
            "ts_epoch": 1768800000.0,
            "event_type": "telemetry_pulse",
            "protocol": "runtime",
            "score": 0,
        },
    )
    assistant_report = tmp_path / "assistant_rollout.json"
    assistant_report.write_text(
        json.dumps({"overall_pass": True, "promotion": {"ready": True}}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--captures-dir",
            str(captures_dir),
            "--assistant-rollout-report",
            str(assistant_report),
            "--shadow-work-dir",
            str(tmp_path / "shadow"),
            "--require-shadow-data",
            "--min-conn-coverage",
            "1.0",
            "--enforce",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert bool(payload["overall_pass"]) is False
    assert payload["gates"]["shadow_validation"]["status"] in {"fail", "insufficient_data"}


def test_run_agentic_rollout_gate_shadow_failure_is_informational_when_not_required(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "run_agentic_rollout_gate.py"
    captures_dir = tmp_path / "captures"
    _write_runtime_files(
        captures_dir,
        curated_event={
            "ts_epoch": 1768800000.0,
            "event_type": "telemetry_pulse",
            "protocol": "runtime",
            "score": 0,
        },
    )
    assistant_report = tmp_path / "assistant_rollout.json"
    assistant_report.write_text(
        json.dumps({"overall_pass": True, "promotion": {"ready": True}}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--captures-dir",
            str(captures_dir),
            "--assistant-rollout-report",
            str(assistant_report),
            "--shadow-work-dir",
            str(tmp_path / "shadow"),
            "--enforce",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert bool(payload["overall_pass"]) is True
    assert payload["gates"]["shadow_validation"]["status"] in {"fail", "insufficient_data"}
