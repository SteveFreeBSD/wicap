from __future__ import annotations

from pathlib import Path


def test_compose_includes_optional_otel_collector_profile() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    compose_text = (repo_root / "docker-compose.yml").read_text(encoding="utf-8")
    assert "otel-collector:" in compose_text
    assert 'profiles: ["otel"]' in compose_text
    assert "./ops/otel/collector-config.yaml:/etc/otelcol/config.yaml:ro" in compose_text
    assert '"4317:4317"' in compose_text
    assert '"4318:4318"' in compose_text


def test_otel_collector_config_has_otlp_receiver_and_required_processors() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config_text = (repo_root / "ops" / "otel" / "collector-config.yaml").read_text(encoding="utf-8")
    assert "receivers:" in config_text
    assert "otlp:" in config_text
    assert "endpoint: 0.0.0.0:4317" in config_text
    assert "endpoint: 0.0.0.0:4318" in config_text
    assert "memory_limiter:" in config_text
    assert "resourcedetection:" in config_text
    assert "batch:" in config_text
    assert "traces:" in config_text
    assert "metrics:" in config_text
    assert "logs:" in config_text
