---
title: Development
---

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
| http://localhost:8000/ui/ | Web UI |
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

## Web UI development

The UI lives in `apps/web` (Node.js 24+). The Vite dev server proxies `/api` to
the API (`WEB_CHECK_CLI_API_URL`, default `http://localhost:8000`):

```bash
make ui-install   # npm ci
make ui-dev       # http://localhost:5173/ui/ with hot reload
make ui-check     # typecheck, unit tests (Vitest) and production build
```

`make ui-build` writes `apps/web/dist`, which a locally started API serves under
`/ui` (override the location with `WEB_DIST_DIR`).

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

Git hooks are run by [prek](https://github.com/j178/prek) (a dev dependency) from
`.pre-commit-config.yaml`: whitespace and config-file checks, then ruff with the
version locked in `uv.lock`, the one CI runs:

```bash
uv run prek install          # run the hooks on every commit
uv run prek run --all-files  # run them once on the whole tree
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

## Dependency updates

Dependabot (`.github/dependabot.yml`) looks for updates every Monday at 06:00
(Europe/Paris) and only proposes releases that are at least 3 days old; security
updates are never delayed. It covers Python (`pyproject.toml` and `uv.lock`), the
web UI (`apps/web`), the base images of the `Dockerfile`, the scanner images of
`docker-compose.yml` and the GitHub Actions of the workflows.

- Minor and patch updates share one pull request per ecosystem, and so do
  security fixes.
- Major versions come one per pull request, except the Vite toolchain (`vite`,
  `vitest`, `@vitejs/*`) and React (`react`, `react-dom` and their types), which
  are upgraded together.
- `uv.lock` moves on its own; `pyproject.toml` only changes when a release falls
  outside a declared range (`sqlalchemy`, `sqlmap`).
- Node.js majors are not proposed: move to the next LTS line by hand, in the
  `web-build` stage of the `Dockerfile` and in `node-version` of
  `.github/workflows/ci-cd.yml`, in the same commit.

A pull request merged on GitHub is recorded with `dependabot[bot]` as the commit
author. To commit it under your own identity instead, apply it locally once its
checks are green:

```bash
git switch main && git pull --ff-only && git fetch origin
git merge --squash origin/<dependabot-branch>
git commit -m "<pull request title>"
git push
```

Dependabot closes the pull request once it sees the update on `main`; if it stays
open, comment `@dependabot recreate` and it closes it when nothing is left to do.
