# Build stage
FROM python:3.11-slim as builder

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
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    git \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache-dir /wheels/*

# Install Checkov for IaC scanning
RUN pip install --no-cache-dir checkov

# Copy application
COPY . .

# Create reports directory
RUN mkdir -p /app/reports

# Set environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default entrypoint
ENTRYPOINT ["argus"]
CMD ["--help"]
