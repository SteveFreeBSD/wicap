#!/bin/bash
set -e

echo "=== WICAP Offline Setup ==="
echo "This script prepares your environment for offline/metered usage."

# 1. Download Python Wheels (using matching container environment)
# We use docker to ensure we get wheels compatible with linux/amd64 + python 3.10
echo "[1/3] Downloading Core Python wheels (using python:3.10-slim)..."
mkdir -p vendor/wheels
docker run --rm -v "$(pwd):/app" -w /app python:3.10-slim \
    pip download --dest vendor/wheels -r requirements.txt

echo "[2/3] Downloading UI Python wheels (using python:3.10-slim)..."
mkdir -p wicap-ui/vendor/wheels
docker run --rm -v "$(pwd):/app" -w /app python:3.10-slim \
    pip download --dest wicap-ui/vendor/wheels -r wicap-ui/requirements.txt

# 2. Build Base Image
echo "[3/3] Building wicap-base Docker image..."
docker build -t wicap-base:latest -f docker/base.Dockerfile .

echo "=== Offline Setup Complete ==="
echo "You can now build wicap-core and wicap-ui without internet access."
