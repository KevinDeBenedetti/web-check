# web-check

[![CI/CD](https://github.com/KevinDeBenedetti/web-check/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/KevinDeBenedetti/web-check/actions/workflows/ci-cd.yml)

> Docker-based security scanning toolkit with a FastAPI REST API and an interactive CLI (`my-check`) for web and Kubernetes infrastructure security checks.

## Features

- REST API orchestrating ZAP, Nuclei, Nikto, and FFUF behind a single interface
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
```

## Usage

```sh
# Start the API + all scanner sidecars
docker compose up -d

# API Swagger UI
open http://localhost:8001/docs

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
