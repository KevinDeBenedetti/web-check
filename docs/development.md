# Development

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose v2
- [uv](https://docs.astral.sh/uv/) — Python package manager
- Python 3.12+

## Quick start (Docker)

```bash
# Copy and customise environment
cp .env.example .env

# Start API + all scanners
docker compose up -d

# Start with optional fuzzer (FFUF)
docker compose --profile tools up -d
```

| URL | Service |
|-----|---------|
| http://localhost:8001 | FastAPI (Swagger at `/docs`) |
| http://localhost:8090 | ZAP API |

## Local API development (without Docker)

```bash
# Install dependencies
uv sync --all-groups

# Run database migrations
uv run alembic -c apps/alembic.ini upgrade head

# Start the API
uv run uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

> **Note:** Scanner sidecars (ZAP, Nuclei, Nikto) must be running via Docker for scan features to work.

## Running tests

```bash
# All tests
uv run pytest

# With coverage
uv run pytest --cov --cov-report=term-missing

# Single file
uv run pytest apps/api/tests/test_health.py -v
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

```bash
# Create a new migration
uv run alembic -c apps/alembic.ini revision --autogenerate -m "description"

# Apply migrations
uv run alembic -c apps/alembic.ini upgrade head

# Rollback one step
uv run alembic -c apps/alembic.ini downgrade -1
```
