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

## Native run (API and UI on the host)

`make native` runs the API and the web UI directly on the machine (macOS or
Linux), with no API container:

```bash
make install   # uv sync --all-groups, once
make native    # http://localhost:8000/ui/ — Ctrl+C stops the API
make stop      # stops the scanner containers afterwards
```

It builds the UI, starts the ZAP, Nuclei and Nikto containers when Docker
answers (`docker-compose.native.yml` publishes ZAP's API on `127.0.0.1:8090`),
then runs uvicorn on `127.0.0.1:${NATIVE_PORT:-8000}`. It reads the same `.env`
and writes to the same `./outputs` and `./data` as the containerized API.
Stop that one first (`make stop`), or pick another port: `make native NATIVE_PORT=8001`.

Without Docker, the modules that run in Python (headers, DNS, SSLyze, Wapiti,
sqlmap…) still work; ZAP, Nuclei, Nikto and FFUF fail. XSStrike only exists in
the Docker image (`/opt/xsstrike`).

For live reload of the API, run uvicorn yourself:

```bash
uv run uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

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

The tests run offline. The root `conftest.py` makes a test fail when it looks up
a host other than this machine, or connects or sends a datagram to one, even when
the code under test swallows the error, and names that host: a scan test that
reached a real site would scan it. Fake what goes out instead: the scanner
function an endpoint calls, the HTTP client (`httpx.MockTransport`), or the target
resolver, which `apps/api/tests/conftest.py` already answers with a public address
for every API test. The guard sees only this Python process: a subprocess (a
scanner binary, `docker`) is out of its reach, so fake the call that starts it.

### Scanner integration test

The tests above fake every scanner, so nothing in them notices a tool release that
renames a flag. `apps/api/tests/test_scanners_integration.py` does: it runs sqlmap,
Wapiti, SSLyze, Nuclei and Nikto once each, with the arguments the API passes,
against a one-page site the test serves on `127.0.0.1`. It carries the
`integration` marker and is deselected by default; run it after upgrading a scanner:

```bash
make start              # Nuclei and Nikto run in their containers
make test-integration   # uv run pytest -m integration
```

Without the containers, the Nuclei and Nikto tests are skipped and the three tools
installed by `make install` still run. The containers reach the test site through
`host.docker.internal`: Docker Desktop provides the name, and `docker-compose.yml`
maps it to the host (`host-gateway`) on Docker Engine for Linux. On Linux the
containers come in through the host's bridge address, so the site they scan listens
on every interface while the test runs, and a host firewall must let the Docker
bridge reach it.

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
