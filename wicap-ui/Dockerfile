# WICAP Dashboard UI Dockerfile
# Lightweight Python + FastAPI dashboard
#
# Build: docker compose build
# Run:   docker compose up -d

FROM wicap-base:latest

LABEL maintainer="WICAP Project"
LABEL version="1.0"
LABEL description="WICAP Dashboard Web Interface"

WORKDIR /app

# Copy offline wheels
# Note: UI build context is often wicap-ui/, so we copy from local vendor/
COPY vendor/wheels /vendor/wheels

# Copy requirements first for layer caching
COPY requirements.txt .

# Install dependencies (try offline first, allow fallback)
RUN pip install --no-cache-dir --no-index --find-links=/vendor/wheels -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Run uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
