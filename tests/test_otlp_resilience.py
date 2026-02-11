from __future__ import annotations

import json

from src.wicap.telemetry.otlp_resilience import (
    ResilientOTLPExporter,
    build_otlp_logs_request,
    redact_payload,
    resolve_otlp_export_config,
)


class _Response:
    def __init__(self, status_code: int = 200, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class _Session:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.raise_error = False
        self.status_code = 200

    def post(self, endpoint, json=None, headers=None, timeout=None):  # type: ignore[no-untyped-def]
        self.calls.append(
            {
                "endpoint": endpoint,
                "json": json,
                "headers": headers,
                "timeout": timeout,
            }
        )
        if self.raise_error:
            raise RuntimeError("collector unavailable")
        return _Response(status_code=self.status_code, text="ok")


def test_redact_payload_masks_nested_sensitive_fields() -> None:
    payload = {
        "category": "network_anomaly",
        "token": "abc",
        "nested": {
            "password": "hunter2",
            "authorization": "Bearer deadbeef",
            "safe": "ok",
        },
        "flow": {"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "proto": "tcp"},
    }
    redacted, count = redact_payload(payload)
    assert isinstance(redacted, dict)
    assert int(count) >= 4
    assert redacted["token"] == "[REDACTED]"
    assert redacted["nested"]["password"] == "[REDACTED]"
    assert redacted["nested"]["authorization"] == "[REDACTED]"
    assert redacted["flow"]["src_ip"] == "[REDACTED]"
    assert redacted["flow"]["dest_ip"] == "[REDACTED]"
    assert redacted["nested"]["safe"] == "ok"


def test_resilient_exporter_drops_oldest_when_queue_is_bounded() -> None:
    session = _Session()
    exporter = ResilientOTLPExporter(
        endpoint="http://collector:4318/v1/logs",
        max_queue=2,
        max_batch=10,
        session=session,
    )
    exporter.enqueue({"id": "one"}, kind="network_event")
    exporter.enqueue({"id": "two"}, kind="network_event")
    exporter.enqueue({"id": "three"}, kind="network_event")

    stats = exporter.stats()
    assert int(stats["queue_depth"]) == 2
    assert int(stats["dropped_total"]) == 1

    exporter.flush(max_batches=1)
    assert len(session.calls) == 1
    payload = session.calls[0]["json"]
    records = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    bodies = [json.loads(str(item["body"]["stringValue"])) for item in records]
    ids = {str(item.get("id", "")) for item in bodies}
    assert "one" not in ids
    assert {"two", "three"}.issubset(ids)


def test_resilient_exporter_backoff_and_recovery() -> None:
    clock = {"now": 100.0}

    def _clock() -> float:
        return float(clock["now"])

    session = _Session()
    session.raise_error = True
    exporter = ResilientOTLPExporter(
        endpoint="http://collector:4318/v1/logs",
        retry_backoff_seconds=5.0,
        max_backoff_seconds=30.0,
        session=session,
        clock=_clock,
    )
    exporter.enqueue({"id": "x"}, kind="network_event")
    first = exporter.flush(max_batches=1)
    assert int(first["failed_batches"]) == 1
    assert int(first["queue_depth"]) == 1

    second = exporter.flush(max_batches=1)
    assert bool(second.get("skipped_backoff")) is True
    assert int(second["queue_depth"]) == 1

    clock["now"] = 106.0
    session.raise_error = False
    third = exporter.flush(max_batches=1)
    assert bool(third.get("skipped_backoff", False)) is False
    assert int(third["queue_depth"]) == 0
    assert int(third["sent_total"]) == 1


def test_build_otlp_logs_request_shapes_resource_and_log_records() -> None:
    payload = build_otlp_logs_request(
        [
            {
                "kind": "network_event",
                "event": {"ts": "2026-02-12T00:00:00Z", "category": "runtime_event", "signature": "sig-1"},
            }
        ],
        service_name="wicap",
    )
    assert "resourceLogs" in payload
    resource_logs = payload["resourceLogs"]
    assert isinstance(resource_logs, list)
    assert resource_logs
    scope_logs = resource_logs[0]["scopeLogs"]
    assert scope_logs
    log_records = scope_logs[0]["logRecords"]
    assert log_records
    assert log_records[0]["severityText"] == "INFO"


def test_resolve_otlp_export_config_vendor_requires_auth() -> None:
    config = resolve_otlp_export_config(
        {
            "WICAP_OTLP_PROFILE": "vendor",
            "WICAP_OTLP_HTTP_ENDPOINT": "https://otlp.example.com/v1/logs",
        }
    )
    assert config.enabled is True
    assert config.is_valid is False
    assert any("require auth" in item for item in config.errors)


def test_resolve_otlp_export_config_cloud_injects_bearer_auth() -> None:
    config = resolve_otlp_export_config(
        {
            "WICAP_OTLP_PROFILE": "cloud",
            "WICAP_OTLP_HTTP_ENDPOINT": "https://otlp.example.com/v1/logs",
            "WICAP_OTLP_AUTH_BEARER": "token-value",
        }
    )
    assert config.is_valid is True
    assert str(config.headers.get("Authorization", "")).startswith("Bearer ")


def test_resolve_otlp_export_config_endpoint_only_defaults_to_self_hosted() -> None:
    config = resolve_otlp_export_config({"WICAP_OTLP_HTTP_ENDPOINT": "http://localhost:4318/v1/logs"})
    assert config.profile == "self_hosted"
    assert config.is_valid is True
