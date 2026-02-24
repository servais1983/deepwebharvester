# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools
RUN pip install --upgrade pip build

# Copy dependency manifests first for layer caching
COPY pyproject.toml requirements.txt ./
COPY deepwebharvester/ deepwebharvester/
COPY README.md LICENSE ./

# Build wheel
RUN python -m build --wheel --outdir /dist


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="Tech Enthusiast"
LABEL description="DeepWebHarvester — OSINT dark web intelligence gathering tool"

# Install Tor and system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the wheel built in stage 1
COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Create writable directories for output and logs
RUN mkdir -p results logs

# Run as a non-root user for security
RUN useradd --create-home --shell /bin/bash harvester \
    && chown -R harvester:harvester /app
USER harvester

VOLUME ["/app/results", "/app/logs"]

ENTRYPOINT ["deepwebharvester"]
CMD ["--help"]
