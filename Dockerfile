# Dockerfile for Vigil API
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies and uv
RUN apt-get update && apt-get install -y \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && curl -LsSf https://astral.sh/uv/install.sh | sh

ENV PATH="/root/.cargo/bin:$PATH"

# Copy pyproject.toml and install Python dependencies
COPY pyproject.toml .
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
