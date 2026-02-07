"""
Alert consolidation and suppression policy for WICAP UI.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_ML_CONFIDENCE_MIN = 80
DEFAULT_ML_WINDOW_SEC = 900
DEFAULT_SUPPRESSION_CACHE_SEC = 60

_DAY_LOOKUP = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def _normalize_token(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().lower()


def _normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().lower()


def _parse_days(days: Iterable[str] | None) -> set[int] | None:
    if not days:
        return None
    normalized = set()
    for day in days:
        key = day.strip().lower()[:3]
        if key in _DAY_LOOKUP:
            normalized.add(_DAY_LOOKUP[key])
    return normalized or None


@dataclass
class SuppressionRule:
    rule_id: str
    alert_type: str | None
    bssid: str | None
    ssid: str | None
    source: str | None
    days: set[int] | None
    start_hour: int | None
    end_hour: int | None
    reason: str

    def matches(self, alert: dict[str, Any], now_ts: float) -> bool:
        if self.alert_type and _normalize_token(alert.get("alert_type")) != self.alert_type:
            return False
        if self.source and _normalize_token(alert.get("source")) != self.source:
            return False
        if self.bssid and _normalize_mac(alert.get("bssid")) != self.bssid:
            return False
        if self.ssid and _normalize_token(alert.get("ssid")) != self.ssid:
            return False
        if self.days or self.start_hour is not None or self.end_hour is not None:
            ts = alert.get("timestamp") or now_ts
            dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
            if self.days and dt.weekday() not in self.days:
                return False
            if self.start_hour is not None and self.end_hour is not None:
                hour = dt.hour
                if self.start_hour <= self.end_hour:
                    if not (self.start_hour <= hour < self.end_hour):
                        return False
                else:
                    if not (hour >= self.start_hour or hour < self.end_hour):
                        return False
        return True


_SUPPRESSION_CACHE: dict[str, Any] = {
    "loaded_at": 0.0,
    "path": None,
    "rules": [],
}


def _load_rules_from_file(path: Path) -> list[SuppressionRule]:
    try:
        with open(path) as handle:
            data = json.load(handle)
    except Exception:
        return []
    rules: list[SuppressionRule] = []
    if not isinstance(data, list):
        return rules
    for idx, raw in enumerate(data):
        if not isinstance(raw, dict):
            continue
        rule_id = str(raw.get("id") or f"rule-{idx}")
        rules.append(
            SuppressionRule(
                rule_id=rule_id,
                alert_type=_normalize_token(raw.get("alert_type")),
                bssid=_normalize_mac(raw.get("bssid")),
                ssid=_normalize_token(raw.get("ssid")),
                source=_normalize_token(raw.get("source")),
                days=_parse_days(raw.get("days")),
                start_hour=raw.get("start_hour"),
                end_hour=raw.get("end_hour"),
                reason=str(raw.get("reason") or "suppressed"),
            )
        )
    return rules


def load_suppression_rules(
    path: str | None = None,
    *,
    cache_sec: int = DEFAULT_SUPPRESSION_CACHE_SEC,
) -> list[SuppressionRule]:
    now_ts = time.time()
    if path is None:
        path = os.getenv("WICAP_ALERT_SUPPRESSION_PATH", "./captures/alert_suppression.json")
    path_obj = Path(path)
    cache_path = _SUPPRESSION_CACHE.get("path")
    if cache_path == path and now_ts - _SUPPRESSION_CACHE.get("loaded_at", 0.0) < cache_sec:
        return list(_SUPPRESSION_CACHE.get("rules", []))
    rules = _load_rules_from_file(path_obj) if path_obj.exists() else []
    _SUPPRESSION_CACHE.update({"loaded_at": now_ts, "path": path, "rules": rules})
    return list(rules)


def filter_suppressed(
    alerts: Iterable[dict[str, Any]],
    rules: Iterable[SuppressionRule],
    *,
    enabled: bool = True,
    now_ts: float | None = None,
) -> tuple[list[dict[str, Any]], int]:
    if not enabled:
        return list(alerts), 0
    ts = now_ts if now_ts is not None else time.time()
    filtered = []
    suppressed = 0
    for alert in alerts:
        if any(rule.matches(alert, ts) for rule in rules):
            suppressed += 1
            continue
        filtered.append(alert)
    return filtered, suppressed


def _same_target(a: dict[str, Any], b: dict[str, Any]) -> bool:
    a_bssid = _normalize_mac(a.get("bssid"))
    b_bssid = _normalize_mac(b.get("bssid"))
    if a_bssid and b_bssid and a_bssid == b_bssid:
        return True
    a_ssid = _normalize_token(a.get("ssid"))
    b_ssid = _normalize_token(b.get("ssid"))
    if a_ssid and b_ssid and a_ssid == b_ssid:
        return True
    return False


def _is_overlap(alert: dict[str, Any], ml_alert: dict[str, Any], window_sec: int) -> bool:
    if not _same_target(alert, ml_alert):
        return False
    alert_ts = alert.get("timestamp")
    ml_ts = ml_alert.get("timestamp")
    if alert_ts is None or ml_ts is None:
        return False
    try:
        return abs(float(alert_ts) - float(ml_ts)) <= window_sec
    except (TypeError, ValueError):
        return False


def consolidate_alerts(
    ml_alerts: Iterable[dict[str, Any]],
    rule_alerts: Iterable[dict[str, Any]],
    *,
    confidence_min: int = DEFAULT_ML_CONFIDENCE_MIN,
    window_sec: int = DEFAULT_ML_WINDOW_SEC,
    enabled: bool = True,
) -> list[dict[str, Any]]:
    ml_list = list(ml_alerts)
    rule_list = list(rule_alerts)
    if not enabled:
        return ml_list + rule_list
    high_ml = [
        alert
        for alert in ml_list
        if isinstance(alert.get("confidence"), (int, float))
        and float(alert.get("confidence")) >= confidence_min
    ]
    if not high_ml:
        return ml_list + rule_list
    consolidated = [
        alert
        for alert in rule_list
        if not any(_is_overlap(alert, ml_alert, window_sec) for ml_alert in high_ml)
    ]
    return ml_list + consolidated


def apply_alert_policy(alerts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts_list = list(alerts)
    ml_alerts = [alert for alert in alerts_list if alert.get("source") == "attack_timeline"]
    rule_alerts = [alert for alert in alerts_list if alert.get("source") != "attack_timeline"]
    consolidation_enabled = _env_bool("WICAP_ALERT_CONSOLIDATION_ENABLED", True)
    confidence_min = int(os.getenv("WICAP_ALERT_ML_CONFIDENCE_MIN", str(DEFAULT_ML_CONFIDENCE_MIN)))
    window_sec = int(os.getenv("WICAP_ALERT_ML_WINDOW_SEC", str(DEFAULT_ML_WINDOW_SEC)))

    rules = load_suppression_rules(
        cache_sec=int(os.getenv("WICAP_ALERT_SUPPRESSION_CACHE_SEC", str(DEFAULT_SUPPRESSION_CACHE_SEC))),
    )
    suppression_enabled = _env_bool("WICAP_ALERT_SUPPRESSION_ENABLED", True)
    ml_alerts, _ = filter_suppressed(ml_alerts, rules, enabled=suppression_enabled)
    rule_alerts, _ = filter_suppressed(rule_alerts, rules, enabled=suppression_enabled)

    return consolidate_alerts(
        ml_alerts,
        rule_alerts,
        confidence_min=confidence_min,
        window_sec=window_sec,
        enabled=consolidation_enabled,
    )
