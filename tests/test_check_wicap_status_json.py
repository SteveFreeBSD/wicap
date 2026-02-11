from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_check_wicap_status_emits_json_local_only(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "check_wicap_status.py"
    captures_dir = tmp_path / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--local-only",
            "--json",
            "--captures-dir",
            str(captures_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert "generated_at" in payload
    assert "local" in payload
    assert payload["sql"] is None
    assert isinstance(payload["local"], dict)


def test_check_wicap_status_validates_control_intent_json(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "check_wicap_status.py"
    captures_dir = tmp_path / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)
    intent_path = tmp_path / "intent.json"
    intent_path.write_text(
        json.dumps(
            {
                "control_intent_version": "wicap.control.v1",
                "decision_id": "decision-json-test",
                "ts": "2026-02-11T08:00:00Z",
                "policy_profile": "observe-v1",
                "recommended_action": "status_check",
                "safety_class": "safe",
                "required_prechecks": ["local_status_ready"],
                "verification_steps": ["check_status_json"],
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--local-only",
            "--json",
            "--captures-dir",
            str(captures_dir),
            "--validate-control-intent-json",
            str(intent_path),
            "--enforce-control-intent",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    validation = payload["control_intent_validation"]
    assert validation["accepted"] is True
    assert validation["error"] is None
    assert validation["plane_evaluation"]["denied_by"] is None


def test_check_wicap_status_control_intent_enforce_rejects_invalid_payload(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "check_wicap_status.py"
    captures_dir = tmp_path / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)
    intent_path = tmp_path / "intent-invalid.json"
    intent_path.write_text(
        json.dumps(
            {
                "control_intent_version": "wicap.control.v1",
                "decision_id": "decision-json-test-invalid",
                "ts": "2026-02-11T08:00:00Z",
                "policy_profile": "observe-v1",
                "recommended_action": "drop_everything",
                "safety_class": "safe",
                "required_prechecks": [],
                "verification_steps": [],
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--local-only",
            "--json",
            "--captures-dir",
            str(captures_dir),
            "--validate-control-intent-json",
            str(intent_path),
            "--enforce-control-intent",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    validation = payload["control_intent_validation"]
    assert validation["accepted"] is False
    assert any("not allowlisted" in reason for reason in validation["reasons"])
