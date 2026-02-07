# WICAP Documentation Index

This is the single entrypoint for WICAP documentation. If you are unsure where
to start, start here.

## Start Here

- Project status + next milestones: `docs/ROADMAP.md`
- Enhancement backlog + priorities: `docs/ROADMAP.md` (Sections 2-5)
- System architecture: `docs/ARCHITECTURE.md`
- Bluetooth integration roadmap: `docs/BLUETOOTH.md`
- Ghost Hunter anomaly detection: `docs/ANOMALY_DETECTION.md`
- Network baseline drift (S3.3): `docs/BASELINE_DRIFT.md`
- Remote sensors: `docs/REMOTE_SENSORS.md`
- How to contribute safely (workflow + pitfalls): `docs/CONTRIBUTING.md`
- Configuration (env vars, required secrets): `docs/CONFIGURATION.md`
- Production hardening checklist: `docs/PRODUCTION_HARDENING.md`
- Testing (unit/replay/e2e/soak): `docs/TESTING.md`
- Backfill CLI (WiFi + BLE): `docs/BACKFILL.md`
- Soak test reports: `docs/reports/soak/`
- Soak readiness work slices: `docs/WORKSLICES_SOAK.md`
- Ops outputs (digest + evidence bundles): `docs/TESTING.md` (Section 4.5)
- Report governance (where reports live + naming): `docs/reports/README.md`

## Deploy / Operate

- Docker deployment: `docs/DOCKER.md`
- Offline development / air-gapped workflow: `docs/OFFLINE_DEV.md`

## Archive (Historical / WIP)

- Legacy scavenger roadmap: `docs/archive/scavenger_roadmap_v10.md`
- Wi‑Fi 6E / 6GHz design notes (WIP): `docs/archive/6GHZ_IMPLEMENTATION.md`

## Research (Design Inputs, Not Runbooks)

- PCAP intelligence extraction: `docs/research/pcap-intelligence.md`
- Tool ecosystem + similar projects: `docs/research/tool-ecosystem.md`

## Component Docs (Local to Each Module)

- UI: `wicap-ui/README.md`
- UI design tokens: `wicap-ui/docs/components.md`
- Map intelligence architecture: `docs/map_enhancement_walkthrough.md`
- Rust extension: `native/wicap_rust/README.md`
- Replay fixtures: `tests/fixtures/README.md`

These component docs are implementation notes only. They must not contain
roadmaps, status reports, or duplicate runbooks. If in doubt, put the content
in `docs/` and link back from the module.

## Canonical Sources of Truth

- Roadmap + current priorities: `docs/ROADMAP.md`
- Change history: `CHANGELOG.md`

## Documentation Governance (No Drift)

- `docs/` is the only canonical documentation tree.
- `onboarding/` contains **snapshots for agents** and is not authoritative.
- If a snapshot or bundle disagrees with `docs/`, always follow `docs/`.
- Keep single-roadmap policy: extend `docs/ROADMAP.md`, do not create new roadmaps.
- Reports must live under `docs/reports/` and follow `docs/reports/README.md`.

## What Not To Do

- Do not reintroduce `PROMPTS/` as a parallel documentation tree.
- Do not add new roadmaps in random folders; extend `docs/ROADMAP.md` instead.
- Do not copy docs into onboarding bundles; onboarding should reference canonical docs.
