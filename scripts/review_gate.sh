#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "[review-gate] Running full pytest suite"
pytest -q

echo "[review-gate] Checking documentation links"
python3 scripts/check_docs_links.py

echo "[review-gate] Checking dead/legacy markers"
python3 scripts/check_dead_markers.py

echo "[review-gate] Checking repository hygiene"
python3 scripts/check_repo_hygiene.py

if command -v wicap-assist >/dev/null 2>&1; then
  echo "[review-gate] Validating runtime contract"
  wicap-assist contract-check --enforce
else
  echo "[review-gate] Skipping runtime contract check (wicap-assist not installed)"
fi

echo "[review-gate] PASS"
