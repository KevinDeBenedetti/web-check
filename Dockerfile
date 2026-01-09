# Dockerfile for Vigil API
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install uv in a separate layer
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv || mv /root/.cargo/bin/uv /usr/local/bin/uv || true

# Copy pyproject.toml and README.md for installation
COPY pyproject.toml README.md ./
RUN uv pip install --system -e .

# Copy application code
COPY api/ ./api/
COPY outputs/ ./outputs/
COPY config/ ./config/

# Create outputs directory
RUN mkdir -p outputs/temp

# Expose API port
EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
