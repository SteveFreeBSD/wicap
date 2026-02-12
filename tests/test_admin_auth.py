import app.main as main_mod
import pytest
from app.services import admin as admin_service
from app.services import state
from fastapi import HTTPException
from fastapi.testclient import TestClient

client = TestClient(main_mod.app)


def _configure_admin_auth(monkeypatch, secret="test-secret", allowlist=None, required=True):
    if allowlist is None:
        allowlist = ["testclient"]
    monkeypatch.setattr(state, "INTERNAL_SECRET", secret)
    monkeypatch.setattr(state, "INTERNAL_SECRET_REQUIRED", required)
    monkeypatch.setattr(state, "INTERNAL_ALLOWLIST", allowlist)


def test_admin_requires_secret(monkeypatch, tmp_path):
    _configure_admin_auth(monkeypatch)
    monkeypatch.setattr(admin_service, "CAPTURE_DIR", tmp_path)

    resp = client.get("/api/admin/captures")
    assert resp.status_code == 401


def test_admin_rejects_wrong_secret(monkeypatch, tmp_path):
    _configure_admin_auth(monkeypatch)
    monkeypatch.setattr(admin_service, "CAPTURE_DIR", tmp_path)

    resp = client.get("/api/admin/captures", headers={"X-WICAP-SECRET": "wrong"})
    assert resp.status_code == 401


def test_admin_allows_correct_secret(monkeypatch, tmp_path):
    _configure_admin_auth(monkeypatch)
    monkeypatch.setattr(admin_service, "CAPTURE_DIR", tmp_path)

    resp = client.get("/api/admin/captures", headers={"X-WICAP-SECRET": "test-secret"})
    assert resp.status_code == 200


def test_admin_allowlist_blocks_unknown_host(monkeypatch, tmp_path):
    _configure_admin_auth(monkeypatch, allowlist=["127.0.0.1"])
    monkeypatch.setattr(admin_service, "CAPTURE_DIR", tmp_path)

    resp = client.get("/api/admin/captures", headers={"X-WICAP-SECRET": "test-secret"})
    assert resp.status_code == 403


def test_internal_allowlist_allows_client_within_cidr(monkeypatch):
    _configure_admin_auth(monkeypatch, allowlist=["192.168.0.0/24"])

    request = type(
        "RequestStub",
        (),
        {
            "client": type("ClientStub", (), {"host": "192.168.0.42"})(),
            "headers": {"X-WICAP-SECRET": "test-secret"},
        },
    )()

    state._validate_internal_access(request)


def test_internal_allowlist_rejects_client_outside_cidr(monkeypatch):
    _configure_admin_auth(monkeypatch, allowlist=["192.168.0.0/24"])

    request = type(
        "RequestStub",
        (),
        {
            "client": type("ClientStub", (), {"host": "10.10.10.20"})(),
            "headers": {"X-WICAP-SECRET": "test-secret"},
        },
    )()

    with pytest.raises(HTTPException) as excinfo:
        state._validate_internal_access(request)
    assert excinfo.value.status_code == 403
