# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set working directory
WORKDIR /app
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Run humble.py and forward any CLI args (e.g. -u https://google.com)
ENTRYPOINT ["python3", "humble.py"]