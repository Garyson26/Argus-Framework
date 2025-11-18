# Build stage
FROM python:3.15.0rc1-slim-bookworm as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir build
RUN pip wheel --no-cache-dir --wheel-dir /app/wheels .

# Production stage
FROM python:3.15.0rc1-slim-bookworm

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    git \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

