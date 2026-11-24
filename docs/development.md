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
# Copy and customise environment (set ALLOWED_DOMAINS to your domains)
cp .env.example .env

# Start API + all scanners in the background (detects APP_UID/APP_GID/DOCKER_GID for you)
make start

# Same, with live code reload of apps/api (uvicorn --reload, DEBUG logs), then
# follow the API logs; Ctrl+C stops the containers
make dev

# Start with optional fuzzer (FFUF)
docker compose --profile tools up -d
```

| URL | Service |
|-----|---------|
| http://localhost:8000/ui/ | Web UI |
| http://localhost:8000 | FastAPI (Swagger at `/docs`) |

Both commands print these URLs with the port Docker actually published (`API_PORT`
in `.env`, `8000` by default).

ZAP is only reachable from the API (`http://zap:8090`, on a Docker network of their
own), so it runs without an API key.

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

The UI lives in `apps/web` (Node.js 26+). The Vite dev server proxies `/api` to
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

[Renovate](https://docs.renovatebot.com/) (`renovate.json`, on top of the shared
preset [`KevinDeBenedetti/renovate-config`](https://github.com/KevinDeBenedetti/renovate-config))
runs from `.github/workflows/renovate.yml` and opens its pull requests on Monday
before 06:00 (Europe/Paris). It only proposes releases that are at least 3 days
old; security fixes (GitHub and OSV advisories) are never delayed. It covers Python
(`pyproject.toml` and `uv.lock`), the web UI (`apps/web`), the base images of the
`Dockerfile`, the scanner images of `docker-compose.yml` and the GitHub Actions of
the workflows. The Dependency Dashboard issue lists every pending update.

- Minor and patch updates share one pull request per ecosystem.
- Major versions come one per pull request, except the Vite toolchain (`vite`,
  `vitest`, `@vitejs/*`) and React (`react`, `react-dom` and their types), which
  are upgraded together.
- Actions and images are pinned to their digest, the version in a trailing
  comment; the lock files get a weekly maintenance pull request.
- `uv.lock` moves on its own; `pyproject.toml` only changes when a release falls
  outside a declared range (`sqlalchemy`, `sqlmap`).
- Node.js majors are not proposed: move to the next LTS line by hand, in the
  `web-build` stage of the `Dockerfile` and in `node-version` of
  `.github/workflows/ci-cd.yml`, in the same commit. The Python runtime is moved
  by hand too (`.python-version`, `requires-python`, the CI `python-version` and
  the `uv` image tag).
- Commits are `chore(deps)` (`ci(deps)` for actions), so they cut no release.

Renovate runs with a token of the release GitHub App, which the repository must
hold as the variable `RELEASE_APP_CLIENT_ID` (the App's client ID) and the secret
`RELEASE_APP_PRIVATE_KEY` (its private key), with the App installed on the
repository. Until the variable is set, the scheduled run is skipped.

`renovate.json` is read from `main`: a change to it takes effect once merged.
Check it before pushing:

```bash
npx --yes --package renovate -- renovate-config-validator --strict
```

A pull request merged on GitHub is recorded with the Renovate App as the commit
author. To commit it under your own identity instead, apply it locally once its
checks are green:

```bash
git switch main && git pull --ff-only && git fetch origin
git merge --squash origin/<renovate-branch>
git commit -m "<pull request title>"
git push
```

Renovate closes the pull request on its next run once it sees the update on
`main`.
