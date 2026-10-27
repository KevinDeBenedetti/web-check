# Dockerfile for Web-Check API (serves the web UI under /ui)
# Pinned base images — bumped by Dependabot (docker ecosystem).

# ── Web UI build ────────────────────────────────────────────────────────────
FROM node:24-bookworm-slim AS web-build

WORKDIR /web

COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci

COPY apps/web/ ./
RUN npm run build

# ── API ─────────────────────────────────────────────────────────────────────
FROM ghcr.io/astral-sh/uv:0.13.6-python3.12-trixie-slim

# XSStrike has no package release on PyPI: pin the git tag and its commit.
ARG XSSTRIKE_REF=3.1.6
ARG XSSTRIKE_COMMIT=65dd68ae9051ce7cecf3be23fbda6e329d8580af

WORKDIR /app

# The application is imported from /app (api/, alembic/), not installed.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/app/.venv/bin:$PATH"

# System dependencies: git (XSStrike), curl (healthcheck), docker-cli (scanner orchestration)
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
       https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user. Access to the host docker socket is granted at
# runtime via `group_add: ${DOCKER_GID}` in docker-compose.yml.
RUN useradd --system --create-home --uid 10001 --gid users webcheck

# Dependencies only (cached layer). The project itself is not installed: the
# wheel layout (apps/api…) does not match the image layout (/app/api).
COPY pyproject.toml README.md uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# XSStrike at a pinned, verified commit
RUN git clone --depth 1 --branch "${XSSTRIKE_REF}" https://github.com/s0md3v/XSStrike.git /opt/xsstrike \
    && test "$(git -C /opt/xsstrike rev-parse HEAD)" = "${XSSTRIKE_COMMIT}" \
    && uv pip install --python /app/.venv/bin/python -r /opt/xsstrike/requirements.txt \
    && rm -rf /opt/xsstrike/.git \
    && chown -R 10001:users /opt/xsstrike

# Application code
COPY apps/api/ ./api/
COPY apps/alembic/ ./alembic/
COPY apps/alembic.ini ./
COPY apps/config/ ./config/

# Built web UI, served by the API under /ui
COPY --from=web-build /web/dist ./web/dist

RUN mkdir -p outputs/temp data && chown -R webcheck:users outputs data

USER webcheck

# Reset the entrypoint, don't invoke `uv`
ENTRYPOINT []

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

# No --reload in the image: use docker-compose.override.yml for development.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
