# Development

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose v2
- [uv](https://docs.astral.sh/uv/) — Python package manager
- Python 3.12+

## Quick start (Docker)

```bash
# Copy and customise environment (ZAP_API_KEY is required)
cp .env.example .env

# Start API + all scanners (detects APP_UID/APP_GID/DOCKER_GID for you)
make start

# Same, with live code reload of apps/api (uvicorn --reload, DEBUG logs)
make dev

# Start with optional fuzzer (FFUF)
docker compose --profile tools up -d
```

| URL | Service |
|-----|---------|
| http://localhost:8000 | FastAPI (Swagger at `/docs`) |

ZAP is only reachable from the Docker network (`http://zap:8090`), protected by `ZAP_API_KEY`.

### Container user and permissions

The API image runs as an unprivileged user. `docker-compose.yml` runs it as
`${APP_UID}:${APP_GID}` and adds the group owning `/var/run/docker.sock`
(`${DOCKER_GID}`), which it needs to drive the scanner containers. `make start` /
`make dev` set these automatically (host `id -u` / `id -g`, and the socket's group —
`0` on Docker Desktop for macOS). When calling `docker compose` directly on Linux, set
them in `.env`, otherwise `./outputs` and `./data` may not be writable.

## Local API development (without Docker)

```bash
# Install dependencies
uv sync --all-groups

# Start the API (applies database migrations on startup)
uv run uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

> **Note:** Scanner sidecars (ZAP, Nuclei, Nikto) must be running via Docker for scan features to work.

## Running tests

```bash
# All tests
uv run pytest

# With coverage
uv run pytest --cov --cov-report=term-missing

# Single file
uv run pytest apps/api/tests/test_api.py -v
```

## Code quality

```bash
# Lint
uv run ruff check .

# Format check
uv run ruff format --check .

# Auto-fix
uv run ruff check --fix . && uv run ruff format .

# Type check
uv run ty check
```

Pre-commit hooks are configured via `.pre-commit-config.yaml`:

```bash
pre-commit install
```

## Database migrations

The schema is managed by Alembic only: the API runs `alembic upgrade head` on startup
(databases created by older versions with `create_all()` are stamped automatically).
Commands use the same database as the app (`DATABASE_PATH`, default
`data/web-check.db`); add `-x url=sqlite:///path/to.db` to target another file.

```bash
# Create a new migration after changing apps/api/models/db_models.py
uv run alembic -c apps/alembic.ini revision --autogenerate -m "description"

# Apply migrations
uv run alembic -c apps/alembic.ini upgrade head

# Rollback one step
uv run alembic -c apps/alembic.ini downgrade -1

# Verify models and migrations are in sync (also covered by the test suite)
uv run alembic -c apps/alembic.ini check
```
