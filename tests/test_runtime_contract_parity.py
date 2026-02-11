from __future__ import annotations

import json
from pathlib import Path
import re


_REDIS_PORT_RE = re.compile(r"redis-server\s+--port\s+(\d+)")
_CONTAINER_NAME_RE = re.compile(r"^\s*container_name:\s*([A-Za-z0-9._-]+)\s*$", re.MULTILINE)


def test_runtime_contract_matches_compose_services_and_ports() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    compose_path = repo_root / "docker-compose.yml"
    contract_path = repo_root / "ops" / "runtime-contract.v1.json"

    compose_text = compose_path.read_text(encoding="utf-8")
    contract = json.loads(contract_path.read_text(encoding="utf-8"))

    container_names = set(_CONTAINER_NAME_RE.findall(compose_text))
    services = contract.get("services", [])
    assert isinstance(services, list)
    for service in services:
        assert isinstance(service, dict)
        name = str(service.get("name", "")).strip()
        assert name
        assert name in container_names

    redis_match = _REDIS_PORT_RE.search(compose_text)
    assert redis_match is not None
    redis_port = int(redis_match.group(1))

    ports = contract.get("ports", [])
    assert isinstance(ports, list)
    required_ports = {
        int(item["port"])
        for item in ports
        if isinstance(item, dict) and bool(item.get("required", True))
    }
    assert redis_port in required_ports
