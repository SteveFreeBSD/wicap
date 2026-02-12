
from src.wicap.core import preflight


def test_resolve_ble_interface_returns_none_when_disabled(monkeypatch):
    monkeypatch.setenv("WICAP_BT_ENABLED", "false")
    monkeypatch.delenv("WICAP_BT_INTERFACE", raising=False)
    assert preflight.resolve_ble_interface() is None


def test_resolve_ble_interface_keeps_configured_existing_path(monkeypatch):
    monkeypatch.setenv("WICAP_BT_ENABLED", "true")
    monkeypatch.setenv("WICAP_BT_INTERFACE", "/dev/ttyACM0")
    monkeypatch.delenv("WICAP_BT_INTERFACE_GLOB", raising=False)
    monkeypatch.delenv("WICAP_BT_SERIAL", raising=False)

    monkeypatch.setattr(preflight.os.path, "exists", lambda path: path == "/dev/ttyACM0")
    assert preflight.resolve_ble_interface() == "/dev/ttyACM0"


def test_resolve_ble_interface_falls_back_to_ttyacm_when_configured_missing(monkeypatch):
    monkeypatch.setenv("WICAP_BT_ENABLED", "true")
    monkeypatch.setenv("WICAP_BT_INTERFACE", "/dev/serial/by-id/missing")
    monkeypatch.delenv("WICAP_BT_INTERFACE_GLOB", raising=False)
    monkeypatch.delenv("WICAP_BT_SERIAL", raising=False)

    monkeypatch.setattr(preflight.os.path, "exists", lambda _path: False)

    def fake_glob(pattern: str):
        if pattern == "/dev/ttyACM*":
            return ["/dev/ttyACM0"]
        return []

    monkeypatch.setattr(preflight.glob, "glob", fake_glob)
    assert preflight.resolve_ble_interface() == "/dev/ttyACM0"


def test_resolve_wifi_interface_blocks_management_interface_by_default(monkeypatch):
    monkeypatch.delenv("WICAP_ALLOW_MANAGEMENT_INTERFACE", raising=False)
    monkeypatch.delenv("WICAP_INTERFACE_MAC", raising=False)
    monkeypatch.delenv("WICAP_INTERFACE_REGEX", raising=False)
    monkeypatch.delenv("WICAP_INTERFACE_EXCLUDE_REGEX", raising=False)
    monkeypatch.setattr(preflight, "list_wireless_interfaces", lambda: ["wlo1"])
    monkeypatch.setattr(preflight, "_default_route_interface", lambda: "wlo1")

    assert preflight.resolve_wifi_interface(preferred="auto") is None


def test_resolve_wifi_interface_allows_management_with_explicit_override(monkeypatch):
    monkeypatch.setenv("WICAP_ALLOW_MANAGEMENT_INTERFACE", "true")
    monkeypatch.delenv("WICAP_INTERFACE_MAC", raising=False)
    monkeypatch.delenv("WICAP_INTERFACE_REGEX", raising=False)
    monkeypatch.delenv("WICAP_INTERFACE_EXCLUDE_REGEX", raising=False)
    monkeypatch.setattr(preflight, "list_wireless_interfaces", lambda: ["wlo1"])
    monkeypatch.setattr(preflight, "_default_route_interface", lambda: "wlo1")

    assert preflight.resolve_wifi_interface(preferred="auto") == "wlo1"
