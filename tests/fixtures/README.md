WICAP Replay Fixtures
=====================

This directory contains deterministic replay fixtures used by `replay_driver`.

Layout
------
- `pcap/`: Input captures used for replay.
- `events/`: Golden curated event outputs (`*.expected.jsonl`).
- `manifest.json`: Batch definition for CI and local runs.

Manifest Schema
---------------
Each fixture entry supports:
- `name`: Unique fixture name.
- `pcap`: Path to the capture file.
- `expected`: Path to the golden JSONL output.
- `description`: Short human-readable summary.
- `run_id` (optional): Override replay run ID.
- `channel` (optional): Force channel if filename lacks `_chX`.

Updating Fixtures
-----------------
1) Replace or add a PCAP under `pcap/`.
2) Update `manifest.json` to reference the new fixture.
3) Regenerate the expected output:

```
python3 -m replay_driver --pcap tests/fixtures/pcap/<file>.pcapng --snapshot
```

Coverage
--------
The current fixtures cover all scout event types emitted by the pipeline:
- `mixed_traffic_ch2`: new_ssid, new_bssid, hidden_ssid, probe_directed, strong_rssi, telemetry_pulse
- `open_hidden_deauth_ch6`: open_network, hidden_ssid, deauth_spike
- `deauth_single_ch1`: deauth

Notes
-----
- Replay run IDs are derived from the PCAP file contents, so outputs are
  stable across machines as long as the file is unchanged.
