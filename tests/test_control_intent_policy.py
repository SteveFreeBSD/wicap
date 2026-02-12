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


def _valid_intent_v2(*, action: str = "status_check", policy_profile: str = "observe-v1") -> dict[str, object]:
    return {
        "control_intent_version": "wicap.control.v2",
        "decision_id": "decision-002",
        "ts": "2026-02-11T08:00:00Z",
        "policy_profile": policy_profile,
        "recommended_action": action,
        "safety_class": "safe",
        "required_prechecks": ["local_status_ready"],
        "verification_steps": ["check_status_json"],
        "policy_trace": {
            "trace_id": "trace-2",
            "plane_decisions": {
                "runtime_plane": True,
                "tool_policy_plane": True,
                "elevated_plane": True,
            },
            "deny_reasons": [],
            "budget_state": {
                "action_budget_used": 0,
                "action_budget_max": 10,
                "elevated_action_budget_used": 0,
                "elevated_action_budget_max": 2,
            },
        },
        "failover": {
            "auth_profile": "primary",
            "attempt": 0,
            "cooldown_until": None,
            "failure_class": "none",
        },
        "mission": {
            "graph_id": "default",
            "step_id": "observe",
            "step_type": "observe",
            "terminal_state": "running",
        },
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


def test_validate_control_intent_v2_requires_nested_objects() -> None:
    contract = control_intent_service.load_control_contract(version="v2")
    valid, errors = control_intent_service.validate_control_intent(_valid_intent_v2(), contract=contract)
    assert valid is True
    assert errors == []

    invalid_payload = _valid_intent_v2()
    invalid_payload.pop("failover")
    valid_invalid, errors_invalid = control_intent_service.validate_control_intent(invalid_payload, contract=contract)
    assert valid_invalid is False
    assert any("failover" in reason for reason in errors_invalid)
