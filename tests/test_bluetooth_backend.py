import time
from pathlib import Path

import pytest

from src.wicap.core.capture.bluetooth_backend import BluetoothCaptureBackend


class _DummyStderr:
    def __init__(self, text: str):
        self._text = text

    def read(self) -> str:
        return self._text


class _DummyProcess:
    def __init__(self, return_code: int, stderr: str):
        self._return_code = return_code
        self.stderr = _DummyStderr(stderr)

    def poll(self):
        return self._return_code


def test_start_capture_fails_fast_when_pyserial_missing(monkeypatch, tmp_path: Path):
    backend = BluetoothCaptureBackend("auto", tmp_path)
    monkeypatch.setattr(
        BluetoothCaptureBackend,
        "_missing_runtime_modules",
        classmethod(lambda cls: ["pyserial"]),
    )

    with pytest.raises(RuntimeError, match="pyserial"):
        backend.start_capture()


def test_check_health_suspends_restarts_on_fatal_startup_error(tmp_path: Path):
    backend = BluetoothCaptureBackend("/dev/ttyACM0", tmp_path)
    backend.process = _DummyProcess(
        1,
        "pyserial not found, please run: python3 -m pip install -r requirements.txt",
    )

    assert backend.check_health() is False
    assert backend.process is None
    assert backend._suspend_until_ts > time.time()


def test_resolve_extcap_interface_requires_discovery_for_raw_device_paths(monkeypatch, tmp_path: Path):
    backend = BluetoothCaptureBackend("/dev/ttyACM0", tmp_path)
    monkeypatch.setattr(backend, "_list_extcap_interfaces", lambda: [])
    assert backend._resolve_extcap_interface() == ""

    backend.interface = "/dev/ttyACM0-None"
    assert backend._resolve_extcap_interface() == "/dev/ttyACM0-None"
