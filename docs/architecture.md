# Architecture

Web Check is a **monorepo** containing a Python/FastAPI backend, a React/Vite frontend, and Docker Compose orchestration for a suite of security scanner sidecars.

## Repository layout

```
web-check/
├── apps/
│   ├── api/          # FastAPI application (Python 3.12, uv)
│   ├── web/          # Web UI (React, Vite, TypeScript), served under /ui
│   ├── cli/          # Typer CLI entry point
│   ├── my_check/     # Core security checks and reporters
│   ├── alembic/      # Database migrations
│   ├── alembic.ini   # Alembic config (SQLite by default)
│   └── config/       # Static config (wordlists, settings)
├── Dockerfile        # API image (multi-stage, uv + Python 3.12)
├── docker-compose.yml
├── pyproject.toml    # Python project config (uv, ruff, pytest, ty)
└── docs/             # This documentation
```

## Services

| Service | Image | Purpose |
|---------|-------|---------|
| `api` | Custom (repo Dockerfile) | FastAPI REST API + scan orchestrator |
| `zap` | `zaproxy/zap-stable` | OWASP ZAP dynamic analysis proxy |
| `nuclei` | `projectdiscovery/nuclei` | Template-based vulnerability scanner |
| `nikto` | `alpine/nikto` | Web server misconfiguration scanner |
| `ffuf` | `secsi/ffuf` | Directory/path fuzzer (`tools` profile) |

## Networking

All containers share the `scanner-net` bridge network. The API communicates with scanners by their container name (e.g. `http://zap:8090`). The `DOCKER_NETWORK` environment variable allows overriding the network name for external integration.

## API design

The FastAPI app exposes scan endpoints under `/api/`:

| Prefix | Description |
|--------|-------------|
| `/api/health` | Liveness / readiness checks |
| `/api/quick` | Fast, low-impact scans |
| `/api/deep` | Thorough scans (longer runtime) |
| `/api/security` | Dedicated security tool integrations |
| `/api/advanced` | Advanced / multi-tool chained scans |
| `/api/scans` | Full scans: start, history, findings, comparison, exports, SSE logs |
| `/api/catalog` | Modules and scan profiles accepted by `/api/scans/start` |
| `/api/scope` | Scope rules (`ALLOWED_DOMAINS`) and target checks |
| `/api/services` | State of the scanner containers (via the Docker socket) |

### Full scans

`POST /api/scans/start` takes a `target`, either a `profile` (`quick`, `standard`,
`full`) or a list of `modules`, and a per-module `timeout`. Targets outside
`ALLOWED_DOMAINS` are rejected with `403`. Modules run one after the other in a
background task; each result is stored as soon as it completes and progress is
streamed over SSE (`GET /api/scans/{id}/logs`, which replays past entries to late
subscribers).

| Endpoint | Description |
|----------|-------------|
| `GET /api/scans/{id}/findings` | Findings deduplicated across modules, with score |
| `GET /api/scans/{base}/compare/{head}` | New, fixed and unchanged findings |
| `GET /api/scans/{id}/export?format=json\|markdown\|sarif` | Report download |

The score starts at 100 and loses 25, 10, 4 and 1 points per critical, high,
medium and low finding (informational findings do not count).

Database: SQLite via SQLAlchemy async + Alembic migrations (auto-run on startup).

## Web UI

`apps/web` is a React + Vite + TypeScript single-page app, in French. The Docker
image builds it and the API serves it under `/ui` (`apps/api/routers/web_ui.py`),
so `docker compose up -d` is enough to use it at `http://localhost:8000/ui/`.

| Screen | Path |
|--------|------|
| Dashboard | `/ui/` |
| New scan | `/ui/scans/new` |
| Live scan | `/ui/scans/{id}/live` |
| Report | `/ui/scans/{id}` |
| History | `/ui/scans` |
| Compare | `/ui/compare` |
| Settings | `/ui/settings` |

The API remains usable directly via the Swagger UI at `http://localhost:8000/docs`,
the `my-check` CLI, or any HTTP client.
