# Offline / Metered Development Guide

This guide explains how to develop WICAP in an environment with metered or restricted internet access.

Start here for project-wide docs: `docs/INDEX.md`

## Strategy
To minimize bandwidth usage, we use a two-tiered build strategy:
1. **Base Image (`wicap-base`):** Contains all heavy system dependencies (APT packages, ODBC drivers, Git tools). This is built *once* and cached locally.
2. **Vendored Python Packages:** All Python dependencies (wheels) are downloaded to `vendor/wheels` and `wicap-ui/vendor/wheels` so they can be installed without PyPI access.

## One-Time Setup (Online)
Run the setup script while you have a good internet connection. This will download ~200MB of data.

```bash
./scripts/setup_offline.sh
```

This script:
1. Downloads Python wheels to `vendor/wheels`.
2. Downloads UI Python wheels to `wicap-ui/vendor/wheels`.
3. Builds the `wicap-base` Docker image.

## Routine Development (Offline/Metered)
Once setup is complete, you can rebuild your containers without using internet bandwidth.

```bash
docker compose build
docker compose up -d
```

The build process will:
- Use the locally cached `wicap-base` image (skipping `apt-get install`).
- Install Python packages from the local `vendor/wheels` directory.

## Handling Updates & Maintenance

### Update Workflow
When you have internet access and want to update your environment (e.g., get new package versions or add libraries):

1. **Connect** to the internet.
2. **Modify Configuration** (if needed):
   - Update `requirements.txt` for Python packages.
   - Update `docker/base.Dockerfile` for system tools.
3. **Run Setup Script**:
   ```bash
   ./scripts/setup_offline.sh
   ```
   *This downloads the latest wheels and rebuilds the base image.*
4. **Go Offline**: You are now ready to develop offline again.
5. **Rebuild App**:
   ```bash
   docker compose build
   ```

### Adding New Dependencies

**Option A: The Easy Way (Recommended)**
Use the helper script to add python packages and auto-sync:

```bash
# Add to Core
python3 scripts/add_package.py requests

# Add to UI
python3 scripts/add_package.py some-library --ui
```

**Option B: Manual Method**
1. **System Package (APT):**
   - Edit `docker/base.Dockerfile`.
   - Run `./scripts/setup_offline.sh`.

2. **Python Package:**
   - Edit `requirements.txt` manually.
   - Run `./scripts/setup_offline.sh`.
