"""Fail-open OTLP export helpers with redaction and bounded queueing."""

from __future__ import annotations

import json
import os
import re
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

_REDACTED = "[REDACTED]"
_SENSITIVE_KEY_RE = re.compile(
    r"(?:pass|passwd|password|secret|token|api[_-]?key|authorization|cookie|session|ssid|bssid|mac|email|phone|lat|lon|gps|src_ip|dest_ip)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?:bearer\s+[a-z0-9\-._~+/]+=*|-----BEGIN [A-Z ]+-----|x-api-key|access_token|refresh_token)",
    re.IGNORECASE,
)
_PROFILE_ALIASES = {
    "": "disabled",
    "off": "disabled",
    "none": "disabled",
    "disabled": "disabled",
    "self-hosted": "self_hosted",
    "self_hosted": "self_hosted",
    "selfhosted": "self_hosted",
    "vendor": "vendor",
    "cloud": "cloud",
}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass(slots=True)
class OtlpExportConfig:
    profile: str
    endpoint: str | None
    headers: dict[str, str]
    timeout_seconds: float
    max_queue: int
    max_batch: int
    retry_backoff_seconds: float
    max_backoff_seconds: float
    enabled: bool
    errors: list[str]
    warnings: list[str]

    @property
    def is_valid(self) -> bool:
        return self.enabled and not self.errors and bool(self.endpoint)


def _is_sensitive_key(key: object) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(str(key)))


def _redact_string(value: str) -> tuple[str, int]:
    if _SENSITIVE_VALUE_RE.search(value):
        return _REDACTED, 1
    return value, 0


def redact_payload(value: object) -> tuple[object, int]:
    """Recursively redact sensitive fields in mapping/list payloads."""
    if isinstance(value, Mapping):
        redactions = 0
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                out[key_text] = _REDACTED
                redactions += 1
                continue
            redacted, count = redact_payload(item)
            out[key_text] = redacted
            redactions += int(count)
        return out, int(redactions)
    if isinstance(value, list):
        redactions = 0
        out: list[Any] = []
        for item in value:
            redacted, count = redact_payload(item)
            out.append(redacted)
            redactions += int(count)
        return out, int(redactions)
    if isinstance(value, tuple):
        redacted, count = redact_payload(list(value))
        return tuple(redacted), int(count)
    if isinstance(value, str):
        return _redact_string(value)
    return value, 0


def _now_unix_nanos() -> int:
    return int(time.time_ns())


def _iso_to_unix_nanos(ts: object) -> int:
    if isinstance(ts, (int, float)):
        return int(float(ts) * 1_000_000_000)
    if isinstance(ts, str):
        text = ts.strip()
        if text:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(text)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return int(parsed.timestamp() * 1_000_000_000)
            except ValueError:
                pass
    return _now_unix_nanos()


def _attributes_to_otlp(attributes: Mapping[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key, value in attributes.items():
        key_text = str(key).strip()
        if not key_text:
            continue
        if isinstance(value, bool):
            wrapped = {"boolValue": bool(value)}
        elif isinstance(value, int):
            wrapped = {"intValue": int(value)}
        elif isinstance(value, float):
            wrapped = {"doubleValue": float(value)}
        else:
            wrapped = {"stringValue": str(value)}
        out.append({"key": key_text, "value": wrapped})
    return out


def _record_to_otlp_log(record: Mapping[str, Any]) -> dict[str, Any]:
    payload = record.get("event")
    body = payload if isinstance(payload, Mapping) else {}
    attributes = {
        "wicap.telemetry.kind": str(record.get("kind", "event")),
        "wicap.telemetry.category": str(body.get("category", "")),
        "wicap.telemetry.signature": str(body.get("signature", "")),
        "wicap.telemetry.sensor_id": str(body.get("sensor_id", "")),
        "wicap.telemetry.source": str(body.get("source", "")),
    }
    return {
        "timeUnixNano": str(_iso_to_unix_nanos(body.get("ts"))),
        "severityText": "INFO",
        "body": {"stringValue": json.dumps(body, separators=(",", ":"), sort_keys=True)},
        "attributes": _attributes_to_otlp(attributes),
    }


def build_otlp_logs_request(
    records: Sequence[Mapping[str, Any]],
    *,
    service_name: str = "wicap",
    scope_name: str = "wicap.event_processor",
) -> dict[str, Any]:
    logs = [_record_to_otlp_log(record) for record in records]
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": _attributes_to_otlp(
                        {
                            "service.name": service_name,
                            "service.namespace": "wicap",
                        }
                    )
                },
                "scopeLogs": [
                    {
                        "scope": {"name": scope_name},
                        "logRecords": logs,
                    }
                ],
            }
        ]
    }


class ResilientOTLPExporter:
    """Bounded, fail-open OTLP exporter with retry backoff."""

    def __init__(
        self,
        *,
        endpoint: str | None,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float = 1.5,
        max_queue: int = 2000,
        max_batch: int = 200,
        retry_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = 30.0,
        session: Any = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.endpoint = str(endpoint or "").strip()
        self.enabled = bool(self.endpoint)
        self.headers = {str(k): str(v) for k, v in dict(headers or {}).items() if str(k).strip()}
        self.timeout_seconds = max(0.1, float(timeout_seconds))
        self.max_queue = max(1, int(max_queue))
        self.max_batch = max(1, int(max_batch))
        self.retry_backoff_seconds = max(0.1, float(retry_backoff_seconds))
        self.max_backoff_seconds = max(self.retry_backoff_seconds, float(max_backoff_seconds))
        self._session = session
        self._clock = clock
        self._queue: deque[dict[str, Any]] = deque()
        self._dropped = 0
        self._redactions = 0
        self._sent = 0
        self._failed_batches = 0
        self._failure_streak = 0
        self._next_retry_after = 0.0

    def _post_json(self, payload: Mapping[str, Any]) -> None:
        if self._session is None:
            import requests

            self._session = requests.Session()
        response = self._session.post(
            self.endpoint,
            json=payload,
            headers=self.headers or None,
            timeout=self.timeout_seconds,
        )
        status = int(getattr(response, "status_code", 0) or 0)
        if status < 200 or status >= 300:
            text = str(getattr(response, "text", "") or "")
            raise RuntimeError(f"otlp_http_status_{status}:{text[:160]}")

    def enqueue(self, payload: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
        if not self.enabled:
            return self.stats()
        redacted_payload, redactions = redact_payload(dict(payload))
        record = {"kind": str(kind or "event"), "event": redacted_payload}
        while len(self._queue) >= self.max_queue:
            self._queue.popleft()
            self._dropped += 1
        self._queue.append(record)
        self._redactions += int(redactions)
        return self.stats()

    def flush(self, *, max_batches: int = 1) -> dict[str, Any]:
        if not self.enabled:
            return self.stats()
        now = float(self._clock())
        if now < self._next_retry_after:
            out = self.stats()
            out["skipped_backoff"] = True
            return out

        batches_sent = 0
        for _ in range(max(1, int(max_batches))):
            if not self._queue:
                break
            size = min(len(self._queue), int(self.max_batch))
            batch = [self._queue[idx] for idx in range(size)]
            payload = build_otlp_logs_request(batch)
            try:
                self._post_json(payload)
            except Exception:
                self._failed_batches += 1
                self._failure_streak += 1
                backoff = min(
                    self.max_backoff_seconds,
                    self.retry_backoff_seconds * float(2 ** min(self._failure_streak - 1, 6)),
                )
                self._next_retry_after = now + backoff
                break
            for _ in range(size):
                self._queue.popleft()
            self._sent += size
            batches_sent += 1
            self._failure_streak = 0
            self._next_retry_after = 0.0

        out = self.stats()
        out["batches_sent"] = int(batches_sent)
        return out

    def stats(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.enabled),
            "queue_depth": int(len(self._queue)),
            "dropped_total": int(self._dropped),
            "redaction_total": int(self._redactions),
            "sent_total": int(self._sent),
            "failed_batches": int(self._failed_batches),
            "next_retry_after_epoch": round(float(self._next_retry_after), 4),
        }


def _parse_headers_from_env(raw: str) -> dict[str, str]:
    text = str(raw or "").strip()
    if not text:
        return {}
    if text.startswith("{"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            return {str(k): str(v) for k, v in payload.items() if str(k).strip()}
        return {}

    out: dict[str, str] = {}
    for pair in text.split(","):
        key, sep, value = pair.partition("=")
        if not sep:
            continue
        key_text = key.strip()
        value_text = value.strip()
        if key_text:
            out[key_text] = value_text
    return out


def _normalize_profile(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return _PROFILE_ALIASES.get(normalized, normalized)


def resolve_otlp_export_config(env: Mapping[str, str] | None = None) -> OtlpExportConfig:
    mapping = dict(env or os.environ)
    profile = _normalize_profile(str(mapping.get("WICAP_OTLP_PROFILE", "")))
    endpoint = str(mapping.get("WICAP_OTLP_HTTP_ENDPOINT", "")).strip() or None
    headers = _parse_headers_from_env(str(mapping.get("WICAP_OTLP_HEADERS", "")))

    warnings: list[str] = []
    errors: list[str] = []

    if profile == "disabled" and endpoint:
        profile = "self_hosted"

    timeout_seconds = 1.5
    try:
        timeout_seconds = max(0.1, float(mapping.get("WICAP_OTLP_TIMEOUT_SECONDS", "1.5")))
    except (TypeError, ValueError):
        warnings.append("invalid timeout, defaulted to 1.5s")

    max_queue = 2000
    max_batch = 200
    retry_backoff_seconds = 1.0
    max_backoff_seconds = 30.0
    try:
        max_queue = max(1, int(mapping.get("WICAP_OTLP_MAX_QUEUE", "2000")))
    except (TypeError, ValueError):
        warnings.append("invalid max queue, defaulted to 2000")
    try:
        max_batch = max(1, int(mapping.get("WICAP_OTLP_MAX_BATCH", "200")))
    except (TypeError, ValueError):
        warnings.append("invalid max batch, defaulted to 200")
    try:
        retry_backoff_seconds = max(0.1, float(mapping.get("WICAP_OTLP_RETRY_BACKOFF_SECONDS", "1.0")))
    except (TypeError, ValueError):
        warnings.append("invalid retry backoff, defaulted to 1.0s")
    try:
        max_backoff_seconds = max(
            retry_backoff_seconds,
            float(mapping.get("WICAP_OTLP_MAX_BACKOFF_SECONDS", "30.0")),
        )
    except (TypeError, ValueError):
        warnings.append("invalid max backoff, defaulted to 30.0s")

    bearer = str(mapping.get("WICAP_OTLP_AUTH_BEARER", "")).strip()
    api_key = str(mapping.get("WICAP_OTLP_API_KEY", "")).strip()
    header_keys = {str(key).strip().lower() for key in headers.keys()}
    if bearer and "authorization" not in header_keys:
        headers["Authorization"] = f"Bearer {bearer}"
    if api_key and "x-api-key" not in header_keys:
        headers["x-api-key"] = api_key

    if profile not in {"disabled", "self_hosted", "vendor", "cloud"}:
        errors.append(f"unknown profile '{profile}'")

    enabled = profile != "disabled"
    if enabled and not endpoint:
        errors.append("endpoint is required for enabled OTLP profile")

    parsed = urlparse(endpoint) if endpoint else None
    if endpoint and parsed is not None:
        scheme = str(parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            errors.append("endpoint must use http or https")
        host = str(parsed.hostname or "").strip().lower()
        if profile in {"vendor", "cloud"} and scheme != "https" and host not in _LOCAL_HOSTS:
            errors.append("vendor/cloud profiles require https endpoint (except localhost)")

    has_auth = any(key in {"authorization", "x-api-key"} for key in header_keys) or bool(
        headers.get("Authorization") or headers.get("x-api-key")
    )
    if profile in {"vendor", "cloud"} and not has_auth:
        errors.append("vendor/cloud profiles require auth via bearer token, api key, or headers")
    if profile == "self_hosted" and not has_auth:
        warnings.append("self_hosted profile configured without auth headers")

    return OtlpExportConfig(
        profile=profile,
        endpoint=endpoint,
        headers=headers,
        timeout_seconds=float(timeout_seconds),
        max_queue=int(max_queue),
        max_batch=int(max_batch),
        retry_backoff_seconds=float(retry_backoff_seconds),
        max_backoff_seconds=float(max_backoff_seconds),
        enabled=bool(enabled),
        errors=errors,
        warnings=warnings,
    )


def build_resilient_otlp_exporter(*, session: Any = None) -> ResilientOTLPExporter:
    config = resolve_otlp_export_config()
    return ResilientOTLPExporter(
        endpoint=config.endpoint if config.is_valid else None,
        headers=config.headers,
        timeout_seconds=float(config.timeout_seconds),
        max_queue=int(config.max_queue),
        max_batch=int(config.max_batch),
        retry_backoff_seconds=float(config.retry_backoff_seconds),
        max_backoff_seconds=float(config.max_backoff_seconds),
        session=session,
    )
