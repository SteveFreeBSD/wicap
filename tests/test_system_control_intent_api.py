from __future__ import annotations

import json

import app.main as main_mod
from app.services import state
from fastapi.testclient import TestClient

client = TestClient(main_mod.app)


def _configure_internal_auth(monkeypatch) -> None:
    monkeypatch.setattr(state, "INTERNAL_SECRET", "test-secret")
    monkeypatch.setattr(state, "INTERNAL_SECRET_REQUIRED", True)
    monkeypatch.setattr(state, "INTERNAL_ALLOWLIST", ["testclient"])


def _intent(action: str) -> dict[str, object]:
    return {
        "control_intent_version": "wicap.control.v1",
        "decision_id": "decision-100",
        "ts": "2026-02-11T08:00:00Z",
        "policy_profile": "observe-v1",
        "recommended_action": action,
        "safety_class": "safe",
        "required_prechecks": ["local_status_ready"],
        "verification_steps": ["check_status_json"],
    }


def test_control_intent_endpoint_accepts_valid_intent_with_execute_false(monkeypatch, tmp_path) -> None:
    _configure_internal_auth(monkeypatch)
    monkeypatch.setenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE", "observe-v1")
    monkeypatch.setenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE_VERSION", "2026.02")
    monkeypatch.setenv("WICAP_CONTROL_ELEVATED_PLANE_ENABLED", "false")
    audit_path = tmp_path / "control-intents.jsonl"
    monkeypatch.setenv("WICAP_CONTROL_AUDIT_PATH", str(audit_path))

    response = client.post(
        "/api/system/control-intent?execute=false",
        headers={"X-WICAP-SECRET": "test-secret"},
        json=_intent("status_check"),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] is True
    assert payload["dispatch"]["status"] == "skipped"
    assert payload["plane_evaluation"]["denied_by"] is None
    assert payload["profile_version"] == "2026.02"
    assert payload["policy_eval"]["profile_version"] == "2026.02"
    assert audit_path.exists()
    first_line = audit_path.read_text(encoding="utf-8").splitlines()[0]
    audit_payload = json.loads(first_line)
    assert audit_payload["accepted"] is True
    assert audit_payload["recommended_action"] == "status_check"


def test_control_intent_endpoint_rejects_non_allowlisted_action(monkeypatch, tmp_path) -> None:
    _configure_internal_auth(monkeypatch)
    monkeypatch.setenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE", "observe-v1")
    monkeypatch.setenv("WICAP_CONTROL_AUDIT_PATH", str(tmp_path / "audit.jsonl"))

    response = client.post(
        "/api/system/control-intent",
        headers={"X-WICAP-SECRET": "test-secret"},
        json=_intent("drop_all_tables"),
    )
    assert response.status_code == 403
    payload = response.json()
    assert payload["accepted"] is False
    assert payload["plane_evaluation"]["denied_by"] == "tool_policy_plane"
    assert payload["denied_by"] == "tool_policy_plane"
    assert any("not allowlisted" in reason for reason in payload["reasons"])


def test_control_intent_endpoint_rejects_elevated_action_when_disabled(monkeypatch, tmp_path) -> None:
    _configure_internal_auth(monkeypatch)
    monkeypatch.setenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE", "observe-v1")
    monkeypatch.setenv("WICAP_CONTROL_ELEVATED_PLANE_ENABLED", "false")
    monkeypatch.setenv("WICAP_CONTROL_AUDIT_PATH", str(tmp_path / "audit-elevated.jsonl"))

    response = client.post(
        "/api/system/control-intent",
        headers={"X-WICAP-SECRET": "test-secret"},
        json=_intent("compose_up"),
    )
    assert response.status_code == 403
    payload = response.json()
    assert payload["accepted"] is False
    assert payload["plane_evaluation"]["denied_by"] == "elevated_plane"
    assert any("elevated plane disabled" in reason for reason in payload["reasons"])
