# Tool Ecosystem + Similar Projects (2026)

This document captures the external ecosystem patterns WICAP should copy (and
what to avoid) so we remain competitive without rebuilding mature tooling.

This is research input, not a runbook. Canonical execution steps live in
`docs/ROADMAP.md`, `docs/CONTRIBUTING.md`, and `docs/TESTING.md`.

Last updated: 2026-01-18

---

## 1. Categories of “Best in Class” Projects

### 1.1 Wireless IDS / WIDS Platforms

**Kismet** (WIDS, alerts, distributed sensors, exports)
- Repo/docs: https://github.com/kismetwireless/kismet-docs
- Alerts/WIDS model (stateful + throttled): https://github.com/kismetwireless/kismet-docs/blob/master/readme/070-alerts.md
- Remote capture over websockets: https://github.com/kismetwireless/kismet-docs/blob/master/readme/080-remote_capture.md

**nzyme** (purpose-built wireless threat detection platform)
- Repo: https://github.com/nzymedefense/nzyme

Key patterns to import into WICAP:
- Stateful detections (trend monitors), not just one-off signatures.
- Alert throttling/burst so UI/DB remain usable under attack/noise.
- Distributed sensors feeding a central server (auth + single inbound protocol).

### 1.2 Packet Capture + Indexing / Investigation UX

**Arkime** (large-scale capture + indexing + export)
- Repo: https://github.com/arkime/arkime

Key pattern:
- The “investigator loop”: alert → context → query → export evidence.

### 1.3 Deep Protocol Analysis Frameworks

**Zeek** (scriptable analysis/policy layer)
- Repo: https://github.com/zeek/zeek

Key pattern:
- A composable detector/policy layer beats monolithic “if/else” logic when the
  system grows.

### 1.4 High-Fidelity Decoders (Do Not Rebuild)

**Wireshark / tshark**
- Wireshark: https://www.wireshark.org/
- Tshark docs: https://www.wireshark.org/docs/man-pages/tshark.html

Key pattern:
- Treat Wireshark dissectors as the reference decoder for 802.11 details and
  newer IEs. Use parity tests when adding alternate decoders.

### 1.5 Handshake / WPA Workflows (Interop Standards)

**hcxdumptool / hcxtools**
- hcxdumptool: https://github.com/ZerBea/hcxdumptool
- hcxtools: https://github.com/ZerBea/hcxtools

**Hashcat mode 22000** (widely used interop format)
- Overview: https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2

Key pattern:
- Align exports and terminology to hc22000/hcxtools conventions; keep active TX
  modes opt-in and explicitly authorized.

### 1.6 Wireless Client Capability Profiling (Identity Signals)

**WLAN Pi Profiler** (AssocReq capability decoding)
- Repo: https://github.com/WLAN-Pi/wlanpi-profiler

Key pattern:
- AssocReq frames are a rich, stable source of device capability fingerprints
  (PHY/bands/11k/11r/11v/etc). Passive capture when available; active “fake AP”
  profiling must remain gated.

### 1.7 QA Discipline for Untrusted Inputs

**Suricata** (replay validation, regression mindset, fuzzing)
- Repo: https://github.com/OISF/suricata

Key pattern:
- “Ship with QA”: replay test corpus + output validation + regression tests.

### 1.8 Unified Recon & Offensive Tooling

**bettercap** (unified 802.11 + BLE recon)
- Repo: https://github.com/bettercap/bettercap

Key pattern:
- Modular protocol plugins (ble, wifi, hid) and an event bus architecture.
- Go-based, single binary, highly portable.


---

## 2. What “Winning” Systems Do Differently

### 2.1 They Separate Concerns

- Capture is not parsing; parsing is not detection; detection is not UI.
- They keep a stable event schema that downstream tools can consume.

WICAP mapping:
- Capture: `scout.py`
- Queue: `event_queue.py` (and/or Redis)
- Enrichment/dedup: `event_processor.py`
- PCAP intelligence: `nexus/scavenger/*`
- UI: `wicap-ui/app/main.py`

### 2.2 They Treat Alerts as a Product

- Alert spam is a product failure; throttle/burst are table stakes.
- They store enough evidence (pointers) to support investigation.

WICAP mapping:
- Use `attack_timeline` as the canonical alert sink.
- Ensure each alert has: severity/confidence, evidence pointers, and a stable
  drilldown path.

### 2.3 They Test Detections With Replay

- Real Wi‑Fi is noisy; replay fixtures are the only reliable regression gate.

WICAP mapping:
- Preserve and expand the deterministic replay harness (`replay_driver.py`) and
  fixtures under `tests/fixtures/pcap/`.

---

## 3. “Edge” Ideas That Can Differentiate WICAP

These are optional. They should remain gated and should not contaminate the hot
path until proven.

1) Identity lattice for randomized MACs (probabilistic linking with explicit confidence).
2) Graph-first UI investigations (device↔AP↔alert overlays).
3) Streaming sketches (count-min, heavy hitters) to avoid raw time-series storage.
4) Bandit-style dwell optimization (passive-only) to maximize capture yield.

---

## 4. Practical Guidance (What Not To Rebuild)

- Do not re-implement Wireshark dissectors in Python; use `tshark` where fidelity matters.
- Do not create parallel “roadmap” trees; keep canonical roadmap in `docs/ROADMAP.md`.
- Do not store raw per-packet telemetry in SQL unless there is a clear query need.

---

## 5. Historical Enhancement Inspirations (From Git History)

These notes were preserved from `PROMPTS/enhancement_roadmap.md` (2026-01-18).
They are context only, not action items. Validate before acting on them.

- Poseidon: SDN + ML classification ideas for identity fusion.
- AirSentinel: hybrid live + offline analysis workflow.
- OpenWIPS-ng: distributed sensors + remote capture model.
- Sniffnet: Rust performance patterns for packet processing.
- WiFi-arsenal: geolocation and triangulation ideas.
