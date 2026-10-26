# Configuration

## Environment variables

Copy `.env.example` to `.env` and adjust as needed.

### API

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Enable debug mode (verbose errors, auto-reload) |
| `LOG_LEVEL` | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `DOCKER_NETWORK` | `scanner-net` | Docker network name used to reach scanner sidecars |
| `ALLOWED_DOMAINS` | `example.com` | Comma-separated scope rules; scans of other targets are refused |
| `WEB_DIST_DIR` | `apps/web/dist` | Directory of the built web UI served under `/ui` |

### Scope (`ALLOWED_DOMAINS`)

`POST /api/scans/start` and the web UI only accept targets matching a rule:

| Rule | Allows |
|------|--------|
| `example.com` | `example.com` and every subdomain |
| `*.example.com` | subdomains only, not `example.com` itself |
| `localhost` | `localhost` on any port |

Only scan sites you own or have written permission to test. Restart the API after
changing the rules. The UI's Settings screen lists the active rules and can check
a target against them.

### Ports

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `8001` | Host port for the FastAPI server |

## Docker Compose profiles

| Profile | Services started |
|---------|-----------------|
| *(none)* | `api`, `zap`, `nuclei`, `nikto` |
| `tools` | + `ffuf` (directory fuzzer) |

Example:

```bash
# API + scanners + fuzzer
docker compose --profile tools up -d
```

## Scanner configuration

### ZAP

ZAP runs in daemon mode with the REST API enabled (`api.disablekey=true`). Scan output is written to `./outputs/`. The API connects to ZAP via `http://zap:8090` on the Docker network.

### Nuclei

Nuclei templates are stored in the `nuclei-templates` Docker volume and persist between restarts. The container stays idle until the API dispatches a scan command.

### Nikto

Nikto runs in on-demand mode (idle container). The API calls nikto via `docker exec` or the internal Docker socket when a scan is triggered.

### Wordlists (FFuf)

Custom wordlists go in `apps/config/wordlists/`. They are mounted at `/wordlists` inside the `ffuf` container.

## Release configuration

Release Please is configured in `.github/release/release-please-config.json` (Python release type). The version is tracked in `.github/release/.release-please-manifest.json`.
