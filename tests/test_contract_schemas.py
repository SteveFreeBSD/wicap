from __future__ import annotations

import json
from pathlib import Path


_CONTRACT_DIR = Path(__file__).resolve().parents[1] / "ops" / "contracts"
_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "contracts"


def _read_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_wicap_event_contract_shape_and_core_fields() -> None:
    contract = _read_json(_CONTRACT_DIR / "wicap.event.v1.json")

    assert contract.get("schema") == "wicap.event.v1"
    assert contract.get("event_contract_version") == "wicap.event.v1"

    required = contract.get("required_top_level_fields")
    assert isinstance(required, list)
    required_set = {str(item) for item in required}
    for key in {
        "event_contract_version",
        "ts",
        "source",
        "category",
        "signature",
        "severity",
        "sensor_id",
        "evidence_ref",
    }:
        assert key in required_set

    allowed_sources = contract.get("allowed_sources")
    assert isinstance(allowed_sources, list)
    assert {str(item) for item in allowed_sources} >= {"wifi", "ble", "runtime", "service"}

    flow_fields = contract.get("flow_fields")
    assert isinstance(flow_fields, dict)
    required_when_present = flow_fields.get("required_when_present")
    assert isinstance(required_when_present, list)
    assert {str(item) for item in required_when_present} >= {"src_ip", "dest_ip", "proto"}


def test_wicap_control_contract_shape_and_allowlist_fields() -> None:
    contract = _read_json(_CONTRACT_DIR / "wicap.control.v1.json")

    assert contract.get("schema") == "wicap.control.v1"
    assert contract.get("control_intent_version") == "wicap.control.v1"

    required = contract.get("required_top_level_fields")
    assert isinstance(required, list)
    required_set = {str(item) for item in required}
    for key in {
        "control_intent_version",
        "decision_id",
        "ts",
        "policy_profile",
        "recommended_action",
        "safety_class",
        "required_prechecks",
        "verification_steps",
    }:
        assert key in required_set

    allowlisted_actions = contract.get("allowlisted_actions")
    assert isinstance(allowlisted_actions, list)
    assert {str(item) for item in allowlisted_actions} >= {"status_check", "compose_up", "shutdown"}

    allowed_restart_services = contract.get("allowed_restart_services")
    assert isinstance(allowed_restart_services, list)
    assert {str(item) for item in allowed_restart_services} >= {
        "wicap-ui",
        "wicap-processor",
        "wicap-scout",
        "wicap-redis",
    }

    max_verification_steps = contract.get("max_verification_steps")
    assert isinstance(max_verification_steps, int)
    assert max_verification_steps > 0


def test_contract_fixtures_match_contract_files() -> None:
    for name in ("wicap.event.v1.json", "wicap.control.v1.json"):
        contract = _read_json(_CONTRACT_DIR / name)
        fixture = _read_json(_FIXTURE_DIR / name)
        assert fixture == contract
