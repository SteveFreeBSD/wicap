import json
import os
import time

import pytest

from config import ScoutConfig
from event_processor import EventProcessor
from event_queue import EventQueueWriter, build_event_dict


@pytest.mark.unit
def test_event_queue_rotation_and_retention(tmp_path):
    config = ScoutConfig(captures_dir=tmp_path)
    config.queue_max_bytes = 200
    config.queue_max_files = 1

    writer = EventQueueWriter(config, run_id="test")
    for i in range(10):
        writer.write_event(
            event_type="beacon",
            channel=1,
            score=i,
            dwell_triggered=False,
            bssid=f"AA:BB:CC:DD:EE:{i:02X}",
            ssid=f"Test{i}",
            rssi_dbm=-50,
        )
    writer.close()

    rotated = list(tmp_path.glob("event_queue_*.jsonl"))
    assert rotated
    assert len(rotated) <= 1
    assert (tmp_path / "event_queue.jsonl").exists()


@pytest.mark.unit
def test_processor_selects_rotated_queue_first(tmp_path):
    config = ScoutConfig(captures_dir=tmp_path)
    processor = EventProcessor(config, push_to_sql=False)

    rotated_old = tmp_path / "event_queue_20260101_000000.jsonl"
    rotated_new = tmp_path / "event_queue_20260102_000000.jsonl"
    rotated_old.write_text("{}\n")
    rotated_new.write_text("{}\n")
    os.utime(rotated_old, (1, 1))
    os.utime(rotated_new, (2, 2))

    processor.state.queue_file = "event_queue.jsonl"
    processor.state.byte_offset = 0

    selected = processor._select_queue_path()
    assert selected.name == rotated_old.name
    assert processor.state.queue_file == rotated_old.name


@pytest.mark.unit
def test_processor_detects_rotation_with_offset(tmp_path):
    config = ScoutConfig(captures_dir=tmp_path)
    processor = EventProcessor(config, push_to_sql=False)

    active = tmp_path / "event_queue.jsonl"
    active.write_text("x\n")
    rotated = tmp_path / "event_queue_20260103_000000.jsonl"
    rotated.write_text("{}\n")
    os.utime(rotated, (3, 3))

    processor.state.queue_file = "event_queue.jsonl"
    processor.state.byte_offset = 100

    selected = processor._select_queue_path()
    assert selected.name == rotated.name
    assert processor.state.queue_file == rotated.name


@pytest.mark.unit
def test_backpressure_drops_telemetry_pulse(tmp_path):
    config = ScoutConfig(captures_dir=tmp_path)
    config.queue_max_bytes = 1024
    config.queue_max_files = 1
    config.queue_backpressure_max_bytes = 1
    config.queue_backpressure_action = "drop_pulse"

    writer = EventQueueWriter(config, run_id="test")
    writer._backpressure_check_every = 1

    writer.write_event(
        event_type="beacon",
        channel=1,
        score=1,
        dwell_triggered=False,
        bssid="AA:BB:CC:DD:EE:00",
        ssid="Test",
        rssi_dbm=-50,
    )
    before = writer.event_count
    writer.write_event(
        event_type="telemetry_pulse",
        channel=1,
        score=0,
        dwell_triggered=False,
    )

    assert writer.event_count == before
    writer.close()


@pytest.mark.unit
def test_backpressure_allows_non_pulse(tmp_path):
    config = ScoutConfig(captures_dir=tmp_path)
    config.queue_max_bytes = 1024
    config.queue_max_files = 1
    config.queue_backpressure_max_bytes = 1
    config.queue_backpressure_action = "drop_pulse"

    writer = EventQueueWriter(config, run_id="test")
    writer._backpressure_check_every = 1

    writer.write_event(
        event_type="beacon",
        channel=1,
        score=1,
        dwell_triggered=False,
        bssid="AA:BB:CC:DD:EE:00",
        ssid="Test",
        rssi_dbm=-50,
    )
    before = writer.event_count
    writer.write_event(
        event_type="open_network",
        channel=6,
        score=2,
        dwell_triggered=False,
        bssid="AA:BB:CC:DD:EE:01",
        ssid="Test2",
        rssi_dbm=-40,
    )

    assert writer.event_count == before + 1
    writer.close()


@pytest.mark.unit
def test_write_event_dict(tmp_path):
    config = ScoutConfig(captures_dir=tmp_path)
    writer = EventQueueWriter(config, run_id="test")

    event = build_event_dict(
        run_id="remote-run",
        event_type="beacon",
        channel=6,
        score=1,
        dwell_triggered=False,
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNet",
        rssi_dbm=-40,
    )
    writer.write_event_dict(event)
    writer.close()

    lines = (tmp_path / "event_queue.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["event_id"] == event["event_id"]
    assert payload["keys"]["ssid"] == "TestNet"


@pytest.mark.unit
def test_dedup_cache_cap_respects_config(tmp_path):
    config = ScoutConfig(captures_dir=tmp_path)
    config.dedup_max_entries = 2
    processor = EventProcessor(config, push_to_sql=False)

    now = time.time()
    # Inject directly into dedup cache
    processor.dedup_cache._dedup_window = {
        f"key{i}": {"ts": now + i, "score": i} for i in range(5)
    }
    # Persist (triggers trim)
    processor.dedup_cache.save()

    assert len(processor.dedup_cache._dedup_window) == 2
