from __future__ import annotations

import json

from config import ScoutConfig
from event_processor import EventProcessor


class _BrokenExporter:
    enabled = True

    def enqueue(self, payload, *, kind):  # type: ignore[no-untyped-def]
        raise RuntimeError("enqueue failed")

    def flush(self, *, max_batches=1):  # type: ignore[no-untyped-def]
        raise RuntimeError("flush failed")


def test_event_processor_otlp_fail_open_keeps_processing(tmp_path) -> None:
    config = ScoutConfig(captures_dir=tmp_path)
    processor = EventProcessor(config, push_to_sql=False)
    processor._otlp_exporter = _BrokenExporter()
    processor._otlp_warned = False

    queue_path = tmp_path / "event_queue.jsonl"
    queue_path.write_text(
        json.dumps(
            {
                "run_id": "replay-otlp",
                "ts_epoch": 1768800000.0,
                "event_type": "telemetry_pulse",
                "channel": 1,
                "score": 0,
                "keys": {"bssid": "00:11:22:33:44:55", "ssid": "Test"},
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )

    new_count, curated_count, suppressed_count = processor.process_batch()
    assert int(new_count) == 1
    assert int(curated_count) == 1
    assert int(suppressed_count) == 0
    assert (tmp_path / "curated_events.jsonl").exists()
