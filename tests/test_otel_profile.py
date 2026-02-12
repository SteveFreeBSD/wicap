from __future__ import annotations

from pathlib import Path


def test_compose_includes_optional_otel_collector_profile() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    compose_text = (repo_root / "docker-compose.yml").read_text(encoding="utf-8")
    assert "otel-collector:" in compose_text
    assert 'profiles: ["otel", "observability"]' in compose_text
    assert "./ops/otel/collector-config.yaml:/etc/otelcol/config.yaml:ro" in compose_text
    assert '"4317:4317"' in compose_text
    assert '"4318:4318"' in compose_text


def test_compose_includes_intel_worker_and_observability_services() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    compose_text = (repo_root / "docker-compose.yml").read_text(encoding="utf-8")
    assert "intel-worker:" in compose_text
    assert 'profiles: ["intel"]' in compose_text
    assert "scripts/run_intel_worker.py" in compose_text
    assert "jaeger:" in compose_text
    assert 'profiles: ["observability"]' in compose_text


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
    assert "otlp/jaeger:" in config_text
    assert "traces:" in config_text
    assert "metrics:" in config_text
    assert "logs:" in config_text


def test_configuration_docs_include_otlp_profile_and_auth_variables() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config_text = (repo_root / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    required = [
        "WICAP_OTLP_PROFILE",
        "WICAP_OTLP_HTTP_ENDPOINT",
        "WICAP_OTLP_HEADERS",
        "WICAP_OTLP_AUTH_BEARER",
        "WICAP_OTLP_API_KEY",
    ]
    for key in required:
        assert key in config_text
