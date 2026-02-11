"""Anomaly feedback artifact append helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_FEEDBACK_PATH = REPO_ROOT / "captures" / "wicap_anomaly_feedback.jsonl"
FEEDBACK_CONTRACT_VERSION = "wicap.feedback.v1"


def _captures_root() -> Path:
    raw = (
        os.environ.get("WICAP_ANOMALY_FEEDBACK_CAPTURE_DIR", "").strip()
        or os.environ.get("WICAP_CAPTURE_DIR", "").strip()
        or os.environ.get("WICAP_CAPTURES_DIR", "").strip()
    )
    if raw:
        return Path(raw).expanduser()
    return REPO_ROOT / "captures"


def feedback_artifact_path() -> Path:
    raw = os.environ.get("WICAP_ANOMALY_FEEDBACK_PATH", "").strip()
    if raw:
        return Path(raw).expanduser()
    return _captures_root() / DEFAULT_FEEDBACK_PATH.name


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def append_anomaly_feedback_event(
    *,
    alert_id: str,
    label: str,
    note: str | None = None,
    attack_id: int | None = None,
    attack_type: str | None = None,
    bssid: str | None = None,
    source: str = "api_alert_feedback",
) -> Path:
    """Append one feedback event in `wicap.feedback.v1` JSONL format."""
    path = feedback_artifact_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    payload: dict[str, Any] = {
        "feedback_contract_version": FEEDBACK_CONTRACT_VERSION,
        "ts": _now_iso_utc(),
        "source": str(source).strip() or "api_alert_feedback",
        "alert_id": str(alert_id).strip(),
        "label": str(label).strip().lower(),
    }
    if attack_id is not None:
        payload["attack_id"] = int(attack_id)
    if attack_type:
        payload["attack_type"] = str(attack_type).strip()
    if bssid:
        payload["bssid"] = str(bssid).strip().lower()
    if note:
        payload["note"] = str(note).strip()[:256]

    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
    return path

