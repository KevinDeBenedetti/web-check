# Development

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose v2
- [uv](https://docs.astral.sh/uv/) — Python package manager
- [Bun](https://bun.sh/) — JavaScript runtime & package manager
- Python 3.12+

## Quick start (Docker)

```bash
# Copy and customise environment
cp .env.example .env

# Start API + all scanners (development mode with hot-reload)
docker compose --profile dev up -d

# Start API + all scanners (production build)
docker compose --profile prod up -d
```

| URL | Service |
|-----|---------|
| http://localhost:3000 | React UI |
| http://localhost:8000 | FastAPI (Swagger at `/docs`) |
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

## Local frontend development

```bash
cd apps/web

# Install dependencies
bun install

# Start dev server (connects to API at VITE_API_URL)
VITE_API_URL=http://localhost:8000 bun run dev
```

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

# Frontend lint + format
cd apps/web && bun run lint && bun run format:check
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
