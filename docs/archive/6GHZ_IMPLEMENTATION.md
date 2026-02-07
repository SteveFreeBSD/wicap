# WICAP 6GHz (Wi‑Fi 6E) Design / Implementation Notes (WIP)

Status: This document describes a frequency-based design for 6GHz support. Treat
it as work-in-progress unless the corresponding code paths are present and
tested in your current branch.

## Overview
This document details the architectural changes implemented to support Wifi 6 (802.11ax) and 6GHz (Wifi 6E) spectrum in WICAP. The implementation ensures robust channel hopping, frequency-based dwell management, and accurate event telemetry across all bands (2.4GHz, 5GHz, 6GHz).

## 1. Frequency-Based Architecture
To support 6GHz channels that share ID numbers with 2.4GHz (e.g., Channel 1 exists in both), WICAP has migrated from a Channel ID-based system to a Frequency-based system.

### Key Components
- **Auto-Discovery (`utils/wifi_capabilities.py`)**: 
  - Queries `iw phy <phy> info` to detect supported frequencies.
  - Returns explicit `{channel, freq, band}` objects.
  - Automatically identifies 6GHz range (5925–7125 MHz).
- **Hopping Logic (`scout.py`)**:
  - Uses `iw dev <iface> set freq <freq>` commands instead of `set channel`.
  - Determines hopping sequence using an interleaved strategy to ensure coverage of all detected channels.
- **Event Telemetry**:
  - All events now include `band` and `freq` fields in their JSON payload.
  - SQL schema updated with computed columns (`payload_band`, `payload_freq`) for efficient querying.

## 2. Neuro-Adaptive Governor Update
The "intelligent dwell" system has been refactored to track reputation by **Frequency** rather than Channel ID.
- **Old Behavior**: Channel 1 (2.4G) history would pollute Channel 1 (6G) decisions.
- **New Behavior**: 
  - `2412 MHz` (2.4G) maintains separate ROI metrics.
  - `5955 MHz` (6G) maintains separate ROI metrics.
  - High-value 6GHz targets will trigger dilated dwells independently of 2.4GHz crowding.

## 3. Configuration
Enable 6GHz support in `.env` or `docker-compose.yml`:
```bash
WICAP_BANDS=all
# or
WICAP_BANDS=2.4ghz,5ghz,6ghz
```
*Note: This requires hardware support (Intel AX210 or similar) passed through to the container.*

## 4. Verification
Run the verification suite to confirm hopping logic:
```bash
python3 -m pytest tests/test_frequency_hopping.py -v
```
This test suite mocks the hardware layer to verify that the software makes correct frequency-switching calls and maintains separate reputation tables.
