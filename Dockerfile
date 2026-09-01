## Multi-stage Dockerfile optimized for smaller final image
## - builder stage: build Python wheels
## - final stage: clean slim base, install from wheels, copy only runtime files

# Use an official Python runtime as a parent image
FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Build wheels (all deps are pure-Python, so no compilers/apt needed)
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip wheel --wheel-dir /wheels -r requirements.txt

# Use an official Python runtime as a parent image
FROM python:3.11-slim

# OCI image metadata (shown in GHCR package page)
LABEL org.opencontainers.image.description="A humble and fast security-oriented HTTP headers analyzer."
LABEL org.opencontainers.image.source="https://github.com/rfc-st/humble"
LABEL org.opencontainers.image.licenses="MIT"

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps from pre-built wheels, bind-mounted so they are never committed to a layer
COPY requirements.txt .
RUN --mount=type=bind,from=builder,source=/wheels,target=/wheels \
    pip install --no-index --find-links /wheels -r requirements.txt

# Copy only required runtime files
COPY humble.py .
COPY additional ./additional
COPY l10n ./l10n

# Run as non-root for safety
RUN useradd --create-home --uid 1000 humble && \
    chown -R humble:humble /app && \
    chmod -R 755 /app
USER humble

# Run humble.py and forward any CLI args (e.g. -u https://google.com)
ENTRYPOINT ["python3", "humble.py"]