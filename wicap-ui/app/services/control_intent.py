"""Control intent contract loading and validation."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONTROL_CONTRACT_PATH = REPO_ROOT / "ops" / "contracts" / "wicap.control.v1.json"
DEFAULT_CONTROL_CONTRACT_V2_PATH = REPO_ROOT / "ops" / "contracts" / "wicap.control.v2.json"
DEFAULT_AUDIT_PATH = REPO_ROOT / "captures" / "control_intent_audit.jsonl"

_ENV_RUNTIME_PLANE_ENABLED = "WICAP_CONTROL_RUNTIME_PLANE_ENABLED"
_ENV_TOOL_POLICY_PLANE_ENABLED = "WICAP_CONTROL_TOOL_POLICY_PLANE_ENABLED"
_ENV_ELEVATED_PLANE_ENABLED = "WICAP_CONTROL_ELEVATED_PLANE_ENABLED"
_ENV_ACTIVE_POLICY_PROFILE = "WICAP_CONTROL_ACTIVE_POLICY_PROFILE"
_ENV_ACTIVE_POLICY_PROFILE_VERSION = "WICAP_CONTROL_ACTIVE_POLICY_PROFILE_VERSION"
_ENV_AUDIT_PATH = "WICAP_CONTROL_AUDIT_PATH"
_ENV_ACTION_COOLDOWN_UNTIL = "WICAP_CONTROL_ACTION_COOLDOWN_UNTIL"

_FALLBACK_CONTRACT: dict[str, Any] = {
    "schema": "wicap.control.v1",
    "control_intent_version": "wicap.control.v1",
    "required_top_level_fields": [
        "control_intent_version",
        "decision_id",
        "ts",
        "policy_profile",
        "recommended_action",
        "safety_class",
        "required_prechecks",
        "verification_steps",
    ],
    "allowed_policy_profiles": ["observe-v1", "assist-v1", "autonomous-v1"],
    "allowed_safety_classes": ["safe", "caution", "blocked"],
    "allowlisted_actions": ["status_check", "compose_up", "shutdown"],
    "allowlisted_action_prefixes": ["restart_service:"],
    "allowed_restart_services": ["wicap-ui", "wicap-processor", "wicap-scout", "wicap-redis"],
    "max_verification_steps": 10,
    "optional_top_level_fields": [
        "confidence",
        "reasoning_class",
        "profile_version",
        "runbook_generation_id",
        "cooldown_until",
        "policy_eval",
    ],
}

_FALLBACK_CONTRACT_V2: dict[str, Any] = {
    "schema": "wicap.control.v2",
    "control_intent_version": "wicap.control.v2",
    "required_top_level_fields": [
        "control_intent_version",
        "decision_id",
        "ts",
        "policy_profile",
        "recommended_action",
        "safety_class",
        "required_prechecks",
        "verification_steps",
        "policy_trace",
        "failover",
        "mission",
    ],
    "allowed_policy_profiles": ["observe-v1", "assist-v1", "autonomous-v1"],
    "allowed_safety_classes": ["safe", "caution", "blocked"],
    "allowlisted_actions": ["status_check", "compose_up", "shutdown"],
    "allowlisted_action_prefixes": ["restart_service:"],
    "allowed_restart_services": ["wicap-ui", "wicap-processor", "wicap-scout", "wicap-redis"],
    "max_verification_steps": 10,
    "optional_top_level_fields": [
        "confidence",
        "reasoning_class",
        "profile_version",
        "runbook_generation_id",
        "cooldown_until",
        "policy_eval",
    ],
    "required_policy_trace_fields": ["trace_id", "plane_decisions", "deny_reasons", "budget_state"],
    "required_failover_fields": ["auth_profile", "attempt", "cooldown_until", "failure_class"],
    "required_mission_fields": ["graph_id", "step_id", "step_type", "terminal_state"],
}


def _parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return bool(default)
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False
    return bool(default)


def _runtime_plane_enabled() -> bool:
    return _parse_bool(os.environ.get(_ENV_RUNTIME_PLANE_ENABLED), default=True)


def _tool_policy_plane_enabled() -> bool:
    return _parse_bool(os.environ.get(_ENV_TOOL_POLICY_PLANE_ENABLED), default=True)


def _elevated_plane_enabled() -> bool:
    return _parse_bool(os.environ.get(_ENV_ELEVATED_PLANE_ENABLED), default=False)


def _active_policy_profile() -> str:
    return os.environ.get(_ENV_ACTIVE_POLICY_PROFILE, "observe-v1").strip() or "observe-v1"


def _active_policy_profile_version() -> str:
    return os.environ.get(_ENV_ACTIVE_POLICY_PROFILE_VERSION, "1").strip() or "1"


def _cooldown_until_marker() -> str | None:
    value = os.environ.get(_ENV_ACTION_COOLDOWN_UNTIL, "").strip()
    return value or None


def _action_requires_elevated(action: str) -> bool:
    normalized = str(action).strip().lower()
    if normalized in {"compose_up", "shutdown"}:
        return True
    return normalized.startswith("restart_service:")


def _plane_evaluation(
    *,
    runtime_enabled: bool,
    tool_policy_enabled: bool,
    elevated_enabled: bool,
    requires_elevated: bool,
    denied_by: str | None,
    profile_version: str,
    cooldown_until: str | None,
) -> dict[str, Any]:
    return {
        "runtime_plane": runtime_enabled,
        "tool_policy_plane": tool_policy_enabled,
        "elevated_plane": elevated_enabled if requires_elevated else True,
        "requires_elevated": requires_elevated,
        "denied_by": denied_by,
        "profile_version": str(profile_version).strip() or "1",
        "cooldown_until": cooldown_until,
    }


def _fallback_contract(version: str) -> dict[str, Any]:
    normalized = str(version).strip().lower()
    if normalized == "v2":
        return dict(_FALLBACK_CONTRACT_V2)
    return dict(_FALLBACK_CONTRACT)


@lru_cache(maxsize=8)
def load_control_contract(path: str | None = None, *, version: str = "v1") -> dict[str, Any]:
    """Load control intent contract JSON with fallback defaults."""
    normalized_version = str(version).strip().lower()
    if path:
        contract_path = Path(path).resolve()
    elif normalized_version == "v2":
        contract_path = DEFAULT_CONTROL_CONTRACT_V2_PATH
    else:
        contract_path = DEFAULT_CONTROL_CONTRACT_PATH
    if not contract_path.exists():
        return _fallback_contract(normalized_version)
    try:
        payload = json.loads(contract_path.read_text(encoding="utf-8"))
    except Exception:
        return _fallback_contract(normalized_version)
    if not isinstance(payload, dict):
        return _fallback_contract(normalized_version)
    return payload


def validate_control_intent(
    intent: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Validate one control intent payload against policy contract."""
    payload = intent if isinstance(intent, dict) else {}
    spec = contract if isinstance(contract, dict) else load_control_contract()
    errors: list[str] = []

    required_fields = spec.get("required_top_level_fields", [])
    required = [str(item).strip() for item in required_fields] if isinstance(required_fields, list) else []
    for field in required:
        if field and field not in payload:
            errors.append(f"missing required field: {field}")

    version = str(payload.get("control_intent_version", "")).strip()
    expected_version = str(spec.get("control_intent_version", "")).strip()
    if expected_version and version != expected_version:
        errors.append(f"unsupported control_intent_version: {version or '<missing>'}")

    action = str(payload.get("recommended_action", "")).strip()
    allowlisted_actions = {
        str(item).strip()
        for item in (spec.get("allowlisted_actions", []) if isinstance(spec.get("allowlisted_actions"), list) else [])
        if str(item).strip()
    }
    allowlisted_prefixes = [
        str(item).strip()
        for item in (spec.get("allowlisted_action_prefixes", []) if isinstance(spec.get("allowlisted_action_prefixes"), list) else [])
        if str(item).strip()
    ]
    allowed_restart_services = {
        str(item).strip()
        for item in (
            spec.get("allowed_restart_services", [])
            if isinstance(spec.get("allowed_restart_services"), list)
            else []
        )
        if str(item).strip()
    }

    if action in allowlisted_actions:
        pass
    elif any(action.startswith(prefix) for prefix in allowlisted_prefixes):
        if ":" not in action:
            errors.append("restart action is missing service suffix")
        else:
            service = action.split(":", 1)[1].strip()
            if service not in allowed_restart_services:
                errors.append(f"restart service is not allowlisted: {service or '<missing>'}")
    else:
        errors.append(f"recommended_action is not allowlisted: {action or '<missing>'}")

    policy_profile = str(payload.get("policy_profile", "")).strip()
    allowed_profiles = {
        str(item).strip()
        for item in (
            spec.get("allowed_policy_profiles", [])
            if isinstance(spec.get("allowed_policy_profiles"), list)
            else []
        )
        if str(item).strip()
    }
    if policy_profile not in allowed_profiles:
        errors.append(f"policy_profile is not allowed: {policy_profile or '<missing>'}")

    safety_class = str(payload.get("safety_class", "")).strip()
    allowed_safety = {
        str(item).strip()
        for item in (
            spec.get("allowed_safety_classes", [])
            if isinstance(spec.get("allowed_safety_classes"), list)
            else []
        )
        if str(item).strip()
    }
    if safety_class not in allowed_safety:
        errors.append(f"safety_class is not allowed: {safety_class or '<missing>'}")

    required_prechecks = payload.get("required_prechecks", [])
    if not isinstance(required_prechecks, list):
        errors.append("required_prechecks must be a list")

    verification_steps = payload.get("verification_steps", [])
    if not isinstance(verification_steps, list):
        errors.append("verification_steps must be a list")
    else:
        max_steps = int(spec.get("max_verification_steps", 10))
        if len(verification_steps) > max_steps:
            errors.append(
                f"verification_steps exceeds max_verification_steps ({len(verification_steps)} > {max_steps})"
            )

    profile_version = payload.get("profile_version")
    if profile_version is not None and not str(profile_version).strip():
        errors.append("profile_version must be non-empty when provided")

    runbook_generation_id = payload.get("runbook_generation_id")
    if runbook_generation_id is not None and not str(runbook_generation_id).strip():
        errors.append("runbook_generation_id must be non-empty when provided")

    cooldown_until = payload.get("cooldown_until")
    if cooldown_until is not None:
        text = str(cooldown_until).strip()
        if not text:
            errors.append("cooldown_until must be non-empty when provided")

    policy_eval = payload.get("policy_eval")
    if policy_eval is not None and not isinstance(policy_eval, dict):
        errors.append("policy_eval must be an object when provided")

    required_policy_trace_fields = spec.get("required_policy_trace_fields")
    if isinstance(required_policy_trace_fields, list):
        trace = payload.get("policy_trace")
        if not isinstance(trace, dict):
            errors.append("policy_trace must be an object")
        else:
            for field in required_policy_trace_fields:
                key = str(field).strip()
                if key and key not in trace:
                    errors.append(f"policy_trace missing required field: {key}")

    required_failover_fields = spec.get("required_failover_fields")
    if isinstance(required_failover_fields, list):
        failover = payload.get("failover")
        if not isinstance(failover, dict):
            errors.append("failover must be an object")
        else:
            for field in required_failover_fields:
                key = str(field).strip()
                if key and key not in failover:
                    errors.append(f"failover missing required field: {key}")

    required_mission_fields = spec.get("required_mission_fields")
    if isinstance(required_mission_fields, list):
        mission = payload.get("mission")
        if not isinstance(mission, dict):
            errors.append("mission must be an object")
        else:
            for field in required_mission_fields:
                key = str(field).strip()
                if key and key not in mission:
                    errors.append(f"mission missing required field: {key}")

    return len(errors) == 0, errors


def evaluate_control_intent(
    intent: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
    active_policy_profile: str | None = None,
) -> tuple[bool, list[str], dict[str, Any]]:
    """Apply schema + policy-plane gates and return decision with metadata."""
    payload = intent if isinstance(intent, dict) else {}
    valid, errors = validate_control_intent(payload, contract=contract)
    reasons = list(errors)

    runtime_enabled = _runtime_plane_enabled()
    tool_policy_enabled = _tool_policy_plane_enabled()
    elevated_enabled = _elevated_plane_enabled()
    requires_elevated = _action_requires_elevated(str(payload.get("recommended_action", "")))
    denied_by: str | None = None

    if not runtime_enabled:
        denied_by = "runtime_plane"
        reasons.append("runtime plane disabled")
    elif not tool_policy_enabled:
        denied_by = "tool_policy_plane"
        reasons.append("tool policy plane disabled")

    expected_policy_profile = (active_policy_profile or _active_policy_profile()).strip()
    profile_version = str(payload.get("profile_version") or _active_policy_profile_version()).strip() or "1"
    cooldown_until = str(payload.get("cooldown_until") or _cooldown_until_marker() or "").strip() or None
    if expected_policy_profile:
        actual_profile = str(payload.get("policy_profile", "")).strip()
        if actual_profile != expected_policy_profile:
            denied_by = denied_by or "tool_policy_plane"
            reasons.append(
                f"policy_profile mismatch: expected {expected_policy_profile}, got {actual_profile or '<missing>'}"
            )

    if requires_elevated and not elevated_enabled:
        denied_by = denied_by or "elevated_plane"
        reasons.append("elevated plane disabled for requested action")

    if not valid and denied_by is None:
        denied_by = "tool_policy_plane"

    accepted = len(reasons) == 0
    plane_metadata = _plane_evaluation(
        runtime_enabled=runtime_enabled,
        tool_policy_enabled=tool_policy_enabled,
        elevated_enabled=elevated_enabled,
        requires_elevated=requires_elevated,
        denied_by=None if accepted else denied_by,
        profile_version=profile_version,
        cooldown_until=cooldown_until,
    )
    # Expose provided policy_eval payload for explainability/audit parity.
    if isinstance(payload.get("policy_eval"), dict):
        plane_metadata["intent_policy_eval"] = dict(payload.get("policy_eval", {}))
    return accepted, reasons, plane_metadata


def control_intent_audit_path() -> Path:
    raw = os.environ.get(_ENV_AUDIT_PATH, "").strip()
    if raw:
        return Path(raw).expanduser()
    return DEFAULT_AUDIT_PATH


def append_control_intent_audit(record: dict[str, Any]) -> Path:
    """Append one control intent decision record to JSONL audit log."""
    path = control_intent_audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = dict(record)
    line.setdefault("recorded_at", datetime.now(timezone.utc).isoformat())
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, sort_keys=True) + "\n")
    return path
