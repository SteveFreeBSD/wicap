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


def _intent_v2(action: str) -> dict[str, object]:
    return {
        "control_intent_version": "wicap.control.v2",
        "decision_id": "decision-200",
        "ts": "2026-02-11T08:00:00Z",
        "policy_profile": "observe-v1",
        "recommended_action": action,
        "safety_class": "safe",
        "required_prechecks": ["local_status_ready"],
        "verification_steps": ["check_status_json"],
        "policy_trace": {
            "trace_id": "trace-1",
            "plane_decisions": {
                "runtime_plane": True,
                "tool_policy_plane": True,
                "elevated_plane": True,
            },
            "deny_reasons": [],
            "budget_state": {
                "action_budget_used": 0,
                "action_budget_max": 3,
                "elevated_action_budget_used": 0,
                "elevated_action_budget_max": 1,
            },
        },
        "failover": {
            "auth_profile": "primary",
            "attempt": 0,
            "cooldown_until": None,
            "failure_class": "none",
        },
        "mission": {
            "graph_id": "g1",
            "step_id": "observe",
            "step_type": "observe",
            "terminal_state": "running",
        },
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


def test_control_intent_v2_endpoint_accepts_valid_payload(monkeypatch, tmp_path) -> None:
    _configure_internal_auth(monkeypatch)
    monkeypatch.setenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE", "observe-v1")
    monkeypatch.setenv("WICAP_CONTROL_AUDIT_PATH", str(tmp_path / "audit-v2.jsonl"))

    response = client.post(
        "/api/system/control-intent/v2?execute=false",
        headers={"X-WICAP-SECRET": "test-secret"},
        json=_intent_v2("status_check"),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] is True
    assert isinstance(payload.get("policy_trace"), dict)
    assert isinstance(payload.get("failover"), dict)
    assert isinstance(payload.get("mission"), dict)


def test_system_policy_explain_and_failover_state_endpoints(monkeypatch, tmp_path) -> None:
    _configure_internal_auth(monkeypatch)
    failover_path = tmp_path / "failover_state.json"
    failover_path.write_text(
        json.dumps(
            {
                "auth_profile": "backup",
                "attempt": 2,
                "cooldown_until": "2026-02-12T00:10:00Z",
                "failure_class": "rate_limit",
                "updated_ts": "2026-02-12T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("WICAP_CONTROL_FAILOVER_STATE_PATH", str(failover_path))

    policy = client.get(
        "/api/system/policy-explain",
        headers={"X-WICAP-SECRET": "test-secret"},
    )
    assert policy.status_code == 200
    policy_payload = policy.json()
    assert "control_plane" in policy_payload
    assert "active_contracts" in policy_payload

    failover = client.get(
        "/api/system/failover-state",
        headers={"X-WICAP-SECRET": "test-secret"},
    )
    assert failover.status_code == 200
    failover_payload = failover.json()
    assert failover_payload["auth_profile"] == "backup"
    assert failover_payload["failure_class"] == "rate_limit"
