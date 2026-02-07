# WICAP - WiFi Capture and Analysis Platform

WICAP is a system for real-time WiFi traffic analysis, handshake capture, and
network intelligence. It consists of a capture core and a FastAPI dashboard UI.

## Why WICAP

- Real-time WiFi capture, scoring, and enrichment pipeline
- Operational dashboard with live telemetry and incident views
- Offline-capable Docker builds using vendored Python wheels for air-gapped or metered environments

## Responsible Use

WICAP is intended for authorized security testing and network operations in
environments you own or have explicit permission to assess. You are responsible
for complying with applicable laws and policies.

## Documentation

Start here: `docs/INDEX.md`
(`docs/` is canonical; `onboarding/` contains snapshots only.)
Reports and checklists live under `docs/reports/` only.

Key docs:
- Roadmap / next milestones: `docs/ROADMAP.md`
- Configuration (env vars, required secrets): `docs/CONFIGURATION.md`
- Testing (unit/replay/e2e/soak): `docs/TESTING.md`
- Docker deployment: `docs/DOCKER.md`
- Offline / metered workflow: `docs/OFFLINE_DEV.md`
- Contributing workflow: `docs/CONTRIBUTING.md`

## Project Files (GitHub)

- License: `LICENSE` (see also `THIRD_PARTY_NOTICES.md`)
- Contributing: `CONTRIBUTING.md` (canonical: `docs/CONTRIBUTING.md`)
- Security: `SECURITY.md`
- Support: `SUPPORT.md`
- Code of Conduct: `CODE_OF_CONDUCT.md`

## Architecture (High Level)

- Capture: `scout.py`
- Queue: `event_queue.py` (and/or Redis)
- Processing/enrichment: `event_processor.py`
- Forensics/intel: `nexus/`
- UI: `wicap-ui/`

## Getting Started

### Prerequisites
*   Docker & Docker Compose
*   Compatible WiFi Adapter (Monitor Mode capable)
*   SQL Server instance (or container)

### Installation
1.  Clone the repository.
2.  Configure required environment variables (see `docs/CONFIGURATION.md`).
3.  Run the stack (see `docs/DOCKER.md` for details):

```bash
docker compose up -d --build
```

### Offline / Air-Gapped Setup

If internet is unavailable or metered, pre-seed dependency wheels and build from local artifacts:

```bash
./scripts/setup_offline.sh
docker compose up -d --build
```

See `docs/OFFLINE_DEV.md` for the full offline workflow.

### Access
*   **Dashboard**: [http://localhost:8080](http://localhost:8080)
*   **API Documentation**: [http://localhost:8080/docs](http://localhost:8080/docs)

## Quick Start (Host, Non-Docker)

```bash
# Starts core capture + processor; requires root for capture.
sudo -E python3 start_wicap.py --push-to-sql
```

Then open: http://localhost:8080

See `docs/TESTING.md` for replay and soak commands.
