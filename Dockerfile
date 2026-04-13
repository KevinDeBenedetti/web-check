# Dockerfile for Web-Check API
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Install system dependencies (git for XSStrike, docker-cli for scanner orchestration)
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
       https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY pyproject.toml README.md ./

# Copy lockfile for reproducible builds
COPY uv.lock ./

# Install dependencies using uv sync (best practice)
RUN uv sync --frozen --no-install-project --no-dev

# Copy application code
COPY apps/api/ ./api/
COPY apps/alembic/ ./alembic/
COPY apps/alembic.ini ./

# Install project
RUN uv sync --frozen --no-dev

# Install XSStrike from GitHub (no official package)
RUN git clone https://github.com/s0md3v/XSStrike.git /opt/xsstrike
WORKDIR /opt/xsstrike
RUN uv pip install --python /app/.venv/bin/python -r requirements.txt
WORKDIR /app

# Create outputs directory and copy config
RUN mkdir -p outputs/temp
COPY apps/config/ ./config/

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Reset the entrypoint, don't invoke `uv`
ENTRYPOINT []

# Expose API port
EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
