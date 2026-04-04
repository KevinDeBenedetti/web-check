# Architecture

Web Check is a **monorepo** containing a Python/FastAPI backend, a React/Vite frontend, and Docker Compose orchestration for a suite of security scanner sidecars.

## Repository layout

```
web-check/
├── apps/
│   ├── api/          # FastAPI application (Python 3.12, uv)
│   ├── cli/          # Typer CLI (thin wrapper around the API)
│   ├── alembic/      # Database migrations
│   ├── alembic.ini   # Alembic config (SQLite by default)
│   ├── config/       # Static config (wordlists, settings)
│   └── web/          # React + Vite + Bun frontend
├── Dockerfile        # API image (multi-stage, uv + Python 3.12)
├── docker-compose.yml
├── pyproject.toml    # Python project config (uv, ruff, pytest, ty)
└── docs/             # This documentation
```

## Services

| Service | Image | Purpose |
|---------|-------|---------|
| `api` | Custom (repo Dockerfile) | FastAPI REST API + scan orchestrator |
| `web` | Custom (`apps/web/Dockerfile`) | Production Nginx-served React UI |
| `web-dev` | `oven/bun:1.1-alpine` | Hot-reload dev server |
| `zap` | `zaproxy/zap-stable` | OWASP ZAP dynamic analysis proxy |
| `nuclei` | `projectdiscovery/nuclei` | Template-based vulnerability scanner |
| `nikto` | `alpine/nikto` | Web server misconfiguration scanner |
| `ffuf` | `secsi/ffuf` | Directory/path fuzzer (optional profile) |

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
| `/api/scans` | Scan history and results management |

Database: SQLite via SQLAlchemy async + Alembic migrations (auto-run on startup).

## Frontend

React 18 SPA built with Vite, styled with Tailwind CSS and Radix UI primitives. Communicates with the API via `VITE_API_URL` (defaults to `http://localhost:8000`). Production: served by Nginx. Development: Vite dev server with HMR.
