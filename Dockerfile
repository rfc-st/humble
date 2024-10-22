# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Update
RUN apt-get update && apt-get install -y && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt