# Test Surface Guide

This directory contains the canonical automated test surface for WICAP.

## Automated (CI / review gate)

- `test_*.py` files: primary pytest suite.
- Entry command: `pytest -q` or `./scripts/review_gate.sh`.

## Manual Harnesses (operator-invoked)

- `tests/integration_tests.py`: live DB integration flow.
- `tests/ui_tests.py`: endpoint smoke checks against a running UI (includes Bluetooth page + API endpoints).
- `tests/soak_test.py`: soak harness called by `scripts/run_soak.sh`.
- `scripts/verify_bt_capture.py`: hardware BLE capture sanity check.

## Playwright Coverage

- `tests/test_e2e_ui.py`: core dashboard/navigation e2e checks.
- `tests/test_bluetooth_ui.py`: Bluetooth page/dossier e2e checks, including confidence/readability, behavior metrics, rotation-correlation, and timeline/recurrence rendering.

## Hygiene Rules

- Keep one-off proof scripts and ad-hoc experiments out of `tests/`.
- Archive historical plans under `docs/archive/` instead of duplicating runbooks.
- Prefer updating `docs/TESTING.md` over adding standalone testing docs.
