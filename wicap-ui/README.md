# WICAP Dashboard UI

Real-time web dashboard for WICAP WiFi capture monitoring.

Canonical docs live under `docs/` only. Do not add roadmaps or reports here.
Start here for project-wide docs: `docs/INDEX.md`

## Quick Start

```bash
# Build and run
docker compose up -d --build

# View logs
docker compose logs -f

# Access
http://localhost:8080
```

## Features

- **Live Dashboard**: Real-time stats with HTMX auto-refresh
- **Handshakes**: View captured handshakes and crack status
- **Networks**: Discovered WiFi networks and vendors
- **WebSocket**: Live event streaming
- **Replay (Admin)**: Re-run a capture through the pipeline; view playback in the Replay Dashboard (`/replay`)
- **Chart Fallbacks**: If recent WiFi events are missing, charts fall back to telemetry/BLE events so the dashboard still reflects activity.

## UI Assets

The network map renders Font Awesome icons in a canvas (vis-network). A small
CSS alias maps the solid Font Awesome font to a regular-weight family so icons
render consistently in canvas contexts. If you update the Font Awesome version,
adjust the font URLs in `wicap-ui/app/static/css/style.css`.

## Configuration

Configuration is documented centrally in `docs/CONFIGURATION.md`.

## Development

Run locally without Docker:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

## Tech Stack

- **FastAPI**: Modern async Python web framework
- **HTMX**: HTML-first reactivity without JavaScript frameworks
- **Jinja2**: Server-side templates
- **pyodbc**: SQL Server connectivity
