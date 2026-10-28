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

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | *(empty)* | Shared secret required in the `X-API-Key` header (never accepted in the URL) on every endpoint except `/api/health`, `/api/ready` and the web UI files. When empty, the API is unauthenticated (a warning is logged at startup) — only acceptable on localhost. The web UI asks for the key in *Réglages* and keeps it in the browser. |
| `WEB_CHECK_CLI_API_KEY` | *(empty)* | Key sent by the `web-check` CLI; must match `API_KEY`. |
| `API_BIND` | `127.0.0.1` | Host interface the API port is published on. Only switch to `0.0.0.0` with `API_KEY` set. |
| `ALLOWED_DOMAINS` | `example.com` | Comma-separated allowlist. Every scan target must be one of these domains or a subdomain of one. |
| `ALLOW_PRIVATE_TARGETS` | `false` | Allow targets that are, or resolve to, private/loopback/link-local IPs, and single-label hostnames. Lab use only. |
| `CORS_ORIGINS` | *(empty)* | Comma-separated allowed origins. Empty disables CORS. |
| `ZAP_API_KEY` | **required** | Key protecting the internal ZAP daemon API. `docker compose` refuses to start without it (`openssl rand -hex 32`). |

#### Scan target validation

Before any scanner runs, the API rejects (HTTP 400) targets that:

- do not use `http://` or `https://` (bare domains are accepted on `/api/quick/dns`, `/api/quick/dns-enum` and `/api/deep/sslyze`; `/api/scans/start` requires the scheme and answers 403 for targets outside the scope);
- are `localhost`, end in `.local`, `.internal`, `.localhost`, `.lan` or `.home.arpa`, or are single-label names such as the `zap` / `nuclei` containers;
- are non-public IP literals (private, loopback, link-local such as `169.254.169.254`, reserved…);
- are not covered by `ALLOWED_DOMAINS`;
- resolve to a non-public IP address.

The last two IP-based rules are lifted by `ALLOW_PRIVATE_TARGETS=true`.

### Ports

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `8000` | Host port for the FastAPI server (the container always listens on 8000) |

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

ZAP runs in daemon mode with its REST API protected by `ZAP_API_KEY`. Scan output is written to `./outputs/`. The API connects to ZAP via `http://zap:8090` on the Docker network (`ZAP_HOST` / `ZAP_PORT`).

### Nuclei

Nuclei templates are stored in the `nuclei-templates` Docker volume and persist between restarts. The container stays idle until the API dispatches a scan command.

### Nikto

Nikto runs in on-demand mode (idle container). The API calls nikto via `docker exec` or the internal Docker socket when a scan is triggered.

### Wordlists (FFuf)

Custom wordlists go in `apps/config/wordlists/`. They are mounted at `/wordlists` inside the `ffuf` container.

## Release configuration

Release Please is configured in `.github/release/release-please-config.json` (Python release type). The version is tracked in `.github/release/.release-please-manifest.json`.
