# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build deps + system packages needed by lxml/PySocks/stem
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libxml2-dev libxslt-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-dev.txt pyproject.toml ./
RUN pip install --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY deepwebharvester/ ./deepwebharvester/
RUN pip install --no-cache-dir --prefix=/install --no-deps .

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="DeepWebHarvester" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.description="OSINT dark web intelligence platform" \
      org.opencontainers.image.licenses="MIT"

# Security: non-root user, no unnecessary packages
RUN groupadd -r harvester && useradd -r -g harvester -m -d /app harvester \
 && apt-get update && apt-get install -y --no-install-recommends \
        libxml2 libxslt1.1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* /var/tmp/*

COPY --from=builder /install /usr/local

WORKDIR /app
RUN mkdir -p results logs && chown -R harvester:harvester /app

USER harvester

# Expose API and metrics ports
EXPOSE 8000 9090

# Health check via API
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

# Default: run API server
ENTRYPOINT ["python", "-m", "deepwebharvester.api_server"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
