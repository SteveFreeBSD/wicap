# WICAP Docker Deployment Guide

This document covers building, running, and managing WICAP in Docker containers.

## Prerequisites

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Docker Engine | 24.0+ | `docker --version` |
| Docker Compose | 2.0+ | `docker compose version` |
| Wireless Adapter | Monitor mode capable | `iw list` |

## Quick Start

```bash
# Build and start
docker compose up -d --build
```

Redis startup is health-gated; `scout`/`processor`/`ui` wait for Redis `PING`
success before starting.

## Services

- `wicap-scout`: live capture (host networking + privileged)
- `wicap-processor`: event processor + watcher (bridge network)
- `wicap-ui`: dashboard (port `8080`)
- `wicap-redis`: durable event queue (port `127.0.0.1:6380->6379`)

## Configuration

Single source of truth for env vars: `docs/CONFIGURATION.md`.

### Environment Variables

`docker-compose.yml` uses `env_file: .env` for all services. Create a `.env` file for sensitive configuration:

```bash
# .env (git-ignored)
WICAP_SQL_HOST=192.168.1.100
WICAP_SQL_PASSWORD=your_password
WICAP_INTERNAL_SECRET=change-me
WICAP_INTERNAL_SECRET_REQUIRED=true
WICAP_INTERNAL_ALLOWLIST=127.0.0.1,::1
TZ=America/Chicago
```

### Volume Mounts

| Host Path | Container Path | Purpose |
|-----------|----------------|---------|
| `./captures` | `/app/captures` | Handshake files, pcapng |
| `./logs` | `/app/logs` | Application logs |
| `./nexus` | `/app/nexus` | NEXUS module code |

## Building

### Standard Build
```bash
docker compose build
```

### No-Cache Rebuild
```bash
docker compose build --no-cache
```

### Build with Progress Output
```bash
docker compose build --progress=plain
```

## Running

### Foreground (see output)
```bash
docker compose up
```

### Background (detached)
```bash
docker compose up -d
```

### View Logs
```bash
docker compose logs -f wicap-scout
docker compose logs -f wicap-processor
docker compose logs -f wicap-ui
```

### Stop
```bash
docker compose down
```

## Offline Review / Soak Validation

For CTO/investor review runs on a local/offline host, use the soak wrapper:

```bash
./scripts/run_docker_soak.sh 30
```

This performs:
- full stack startup (`redis`, `scout`, `processor`, `ui`)
- API readiness checks
- Bluetooth API contract validation (`/api/devices/bluetooth`) including
  confidence + behavior + rotation-correlation + recurrence fields consumed by the UI
- fail-fast API gate checks during soak (`/api/stats` and `/api/devices/bluetooth` must stay HTTP 200)
- fail-fast e2e guardrail (aborts after consecutive Playwright failures; configurable via `E2E_FAIL_LIMIT`)
- Playwright e2e loop for both suites:
  - `tests/test_e2e_ui.py`
  - `tests/test_bluetooth_ui.py`

## Health Checks

The container includes automatic health monitoring:

```bash
# Check health status
docker inspect wicap-scout --format='{{.State.Health.Status}}'
docker inspect wicap-processor --format='{{.State.Health.Status}}'
docker inspect wicap-ui --format='{{.State.Health.Status}}'

# View health check logs
docker inspect wicap-scout --format='{{range .State.Health.Log}}{{.Output}}{{end}}'
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs for errors
docker compose logs wicap-scout
docker compose logs wicap-processor
docker compose logs wicap-ui

# Verify image built correctly
docker images | grep wicap
```

### Wireless Interface Not Found

The container needs:
1. **Host networking** (`network_mode: host`)
2. **Privileged mode** (`privileged: true`)
3. **Interface in monitor mode** (set before container start)
4. **Stable interface selection** (use MAC/regex if names change)

```bash
# On host, prepare interface
IFACE=${WICAP_INTERFACE:-wlan1}
sudo ip link set "$IFACE" down
sudo iw "$IFACE" set monitor none
sudo ip link set "$IFACE" up
```

If interface names change across re-plugs, set one of (or set `WICAP_INTERFACE=auto` and provide a MAC/regex):

```bash
# Pin by MAC or name pattern
WICAP_INTERFACE_MAC=aa:bb:cc:dd:ee:ff
WICAP_INTERFACE_REGEX=^wlan[0-9]+$
WICAP_INTERFACE_EXCLUDE_REGEX=^wlan0$
```

### Bluetooth Device Not Found (BLE)

If BLE capture is enabled, ensure the Nordic dongle is present and accessible:

```bash
BT_IFACE=${WICAP_BT_INTERFACE:-auto}
if [ "$BT_IFACE" = "auto" ]; then BT_IFACE=/dev/ttyACM0; fi
ls -l "$BT_IFACE"
```

For stable device naming across re-plugs, prefer `/dev/serial/by-id`:

```bash
WICAP_BT_INTERFACE_GLOB=/dev/serial/by-id/*nRF*
# or
WICAP_BT_SERIAL=5CE98EE77DD8C5C0
```

If the configured `WICAP_BT_INTERFACE` path is missing inside the container,
startup now falls back to auto-detection and then to `/dev/ttyACM*` or
`/dev/ttyUSB*`. This prevents rapid restart loops and keeps scout running.

If permissions fail, add your user to `uucp` (or `dialout`) and re-login.

### SQL Connection Failed

```bash
# Test from inside container
docker compose exec wicap-processor python3 -c "
from nexus.config import NexusConfig
c = NexusConfig()
print(f'SQL Host: {c.sql_host}')
"
```

### Permission Denied on Captures

```bash
# Fix ownership
sudo chown -R $USER:$USER captures/ logs/
```

## Security Notes

> [!CAUTION]
> This container runs in **privileged mode** with **host networking**. This is required for wireless interface access but grants extensive system access. Only run on trusted networks.

### Why Privileged?
- Raw packet capture (tcpdump, airodump-ng)
- Monitor mode interface control
- Direct hardware access for hashcat

### Mitigation
- Run only on dedicated capture hardware
- Don't expose Docker socket
- Use firewall rules on host

## Development

### Hot Reload
Source code is mounted via volumes. For Python changes:

```bash
docker compose restart wicap-scout
docker compose restart wicap-processor
docker compose restart wicap-ui
```

### Interactive Debug
```bash
docker compose exec wicap-processor python3
```

### Run Specific Script
```bash
docker compose exec wicap-processor python3 scripts/check_wicap_status.py
```

## Included Tools

The Docker image includes all essential WICAP tools:

| Tool | Purpose |
|------|---------|
| hashcat | GPU-accelerated password auditing |
| hcxpcapngtool | Handshake extraction from pcapng |
| tcpdump | Packet capture |
| aircrack-ng | WiFi security tools |
| iw/iwconfig | Wireless interface management |
| pipal | Password statistics analyzer |
| statsgen.py | PACK mask extraction |
| pp64 | PRINCE wordlist processor |
| cewl | Custom wordlist generator |

## Image Details

| Property | Value |
|----------|-------|
| Base Image | `python:3.10-slim` |
| Image Size | ~1.2 GB |
| Exposed Ports | None (host network) |
| Health Check | Every 30s |
| Log Rotation | 50MB × 3 files |
