# WICAP Core Dockerfile
# Containerized WiFi capture and password auditing system
#
# Build: docker compose build
# Run:   docker compose up -d

# =============================================================================
# BASE IMAGE
# =============================================================================
FROM wicap-base:latest AS base

# Metadata labels
LABEL maintainer="WICAP Project"
LABEL version="1.0"
LABEL description="WiFi Capture and Password Auditing Platform"

# =============================================================================
# APPLICATION SETUP
# =============================================================================
WORKDIR /app

# Copy offline wheels
COPY vendor/wheels /vendor/wheels

# Copy requirements (Core)
COPY requirements.txt .

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireless-tools \
    iw \
    tcpdump \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies (try offline first, allow fallback if online)

# Install dependencies (try offline first, allow fallback if online)
RUN pip install --no-cache-dir --no-index --find-links=/vendor/wheels -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# UI DEPENDENCIES (Merged into Core Image for unified deployment)
# -----------------------------------------------------------------------------
# Copy offline wheels (UI)
COPY wicap-ui/vendor/wheels /vendor/wheels-ui

# Copy requirements (UI)
COPY wicap-ui/requirements.txt requirements-ui.txt

# Install UI dependencies
RUN pip install --no-cache-dir --no-index --find-links=/vendor/wheels-ui -r requirements-ui.txt || \
    pip install --no-cache-dir -r requirements-ui.txt

# Copy application code
COPY . .

# Create runtime directories
RUN mkdir -p captures logs

# =============================================================================
# HEALTHCHECK
# =============================================================================
# Verify Python and critical imports are available
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; from nexus import NexusConfig; sys.exit(0)" || exit 1

# =============================================================================
# ENTRYPOINT
# =============================================================================
# Default: Launch the WICAP capture suite with SQL integration
CMD ["python3", "start_wicap.py", "--push-to-sql"]
