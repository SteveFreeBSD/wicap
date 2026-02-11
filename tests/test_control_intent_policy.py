from __future__ import annotations

import json

from app.services import control_intent as control_intent_service


def _valid_intent(*, action: str = "status_check", policy_profile: str = "observe-v1") -> dict[str, object]:
    return {
        "control_intent_version": "wicap.control.v1",
        "decision_id": "decision-001",
        "ts": "2026-02-11T08:00:00Z",
        "policy_profile": policy_profile,
        "recommended_action": action,
        "safety_class": "safe",
        "required_prechecks": ["local_status_ready"],
        "verification_steps": ["check_status_json"],
    }


def test_evaluate_control_intent_accepts_valid_payload(monkeypatch) -> None:
    monkeypatch.setenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE", "observe-v1")
    monkeypatch.setenv("WICAP_CONTROL_RUNTIME_PLANE_ENABLED", "true")
    monkeypatch.setenv("WICAP_CONTROL_TOOL_POLICY_PLANE_ENABLED", "true")
    monkeypatch.setenv("WICAP_CONTROL_ELEVATED_PLANE_ENABLED", "false")

    accepted, reasons, plane = control_intent_service.evaluate_control_intent(_valid_intent())
    assert accepted is True
    assert reasons == []
    assert plane["denied_by"] is None
    assert plane["requires_elevated"] is False


def test_evaluate_control_intent_rejects_policy_mismatch(monkeypatch) -> None:
    monkeypatch.setenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE", "assist-v1")
    accepted, reasons, plane = control_intent_service.evaluate_control_intent(
        _valid_intent(policy_profile="observe-v1")
    )
    assert accepted is False
    assert any("policy_profile mismatch" in reason for reason in reasons)
    assert plane["denied_by"] == "tool_policy_plane"


def test_evaluate_control_intent_rejects_elevated_action_when_plane_disabled(monkeypatch) -> None:
    monkeypatch.setenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE", "observe-v1")
    monkeypatch.setenv("WICAP_CONTROL_ELEVATED_PLANE_ENABLED", "false")
    accepted, reasons, plane = control_intent_service.evaluate_control_intent(
        _valid_intent(action="compose_up")
    )
    assert accepted is False
    assert any("elevated plane disabled" in reason for reason in reasons)
    assert plane["denied_by"] == "elevated_plane"


def test_append_control_intent_audit_writes_jsonl(monkeypatch, tmp_path) -> None:
    audit_path = tmp_path / "control-intent-audit.jsonl"
    monkeypatch.setenv("WICAP_CONTROL_AUDIT_PATH", str(audit_path))
    written = control_intent_service.append_control_intent_audit(
        {
            "decision_id": "decision-abc",
            "accepted": True,
            "reasons": [],
            "plane_evaluation": {"runtime_plane": True, "tool_policy_plane": True, "elevated_plane": True},
        }
    )
    assert written == audit_path
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["decision_id"] == "decision-abc"
    assert payload["accepted"] is True
    assert "recorded_at" in payload
