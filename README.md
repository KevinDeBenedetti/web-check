# web-check

[![CI/CD](https://github.com/KevinDeBenedetti/web-check/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/KevinDeBenedetti/web-check/actions/workflows/ci-cd.yml)

> Docker-based security scanning toolkit with a local web UI, a FastAPI REST API and an interactive CLI (`my-check`) for web and Kubernetes infrastructure security checks.

## Features

- Local web UI (`/ui`): dashboard per site, scan profiles, live logs, reports with
  remediation, scan comparison and exports
- REST API orchestrating ZAP, Nuclei, Nikto, SSLyze and more behind a single interface
- Scope enforcement: scans only run against targets listed in `ALLOWED_DOMAINS`
- Findings deduplicated across scanners, scored from 0 to 100, compared between scans
- Interactive CLI wizard (`my-check`) for web and Kubernetes security scans
- Scan history and result management with SQLite
- SARIF 2.1 output for GitHub Code Scanning integration
- Multiple output formats: terminal, JSON, HTML, webhook
- Optional scanner sidecars via Docker Compose profiles (e.g. FFUF)

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose v2
- [uv](https://docs.astral.sh/uv/) — Python package manager

## Installation

```sh
git clone https://github.com/KevinDeBenedetti/web-check.git
cd web-check
cp .env.example .env
# Then edit .env: ZAP_API_KEY is required (generate one with `openssl rand -hex 32`),
# and set API_KEY too if the API is reachable beyond localhost.
```

Scan targets must be listed in `ALLOWED_DOMAINS` (see [configuration](docs/configuration.md#security)).

## Usage

```sh
# Start the API + all scanner sidecars (or `make dev` for live reload)
make start

# Web UI
open http://localhost:8000/ui/

# API Swagger UI
open http://localhost:8000/docs

# Interactive CLI wizard
make cli

# Non-interactive web scan
uv run my-check web https://example.com

# Non-interactive Kubernetes scan
uv run my-check k8s --context my-cluster
```

→ Full usage guide: [docs](https://kevindebenedetti.github.io/web-check/)

## Documentation

Full documentation is available at **https://kevindebenedetti.github.io/web-check/**.
It is generated from the `docs/` directory and published automatically on push.
