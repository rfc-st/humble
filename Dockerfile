# Use an official Python runtime as a parent image
FROM python:3.11-slim

# OCI image metadata (shown in GHCR package page)
LABEL org.opencontainers.image.description="A humble and fast security-oriented HTTP headers analyzer."
LABEL org.opencontainers.image.source="https://github.com/rfc-st/humble"
LABEL org.opencontainers.image.licenses="MIT"

# Set working directory
WORKDIR /app
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Run humble.py and forward any CLI args (e.g. -u https://google.com)
ENTRYPOINT ["python3", "humble.py"]