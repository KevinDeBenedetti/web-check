# Dockerfile for Vigil API
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Install system dependencies (git for XSStrike)
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY pyproject.toml README.md ./

# Copy lockfile for reproducible builds
COPY uv.lock ./

# Install dependencies using uv sync (best practice)
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Copy application code
COPY api/ ./api/
COPY alembic/ ./alembic/
COPY alembic.ini ./

# Install project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Install XSStrike from GitHub (no official package)
RUN git clone https://github.com/s0md3v/XSStrike.git /opt/xsstrike \
    && cd /opt/xsstrike \
    && uv pip install --python /app/.venv/bin/python -r requirements.txt

# Create outputs directory and copy config
RUN mkdir -p outputs/temp
COPY config/ ./config/

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Reset the entrypoint, don't invoke `uv`
ENTRYPOINT []

# Expose API port
EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
