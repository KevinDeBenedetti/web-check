# my-check — Unified Security Scanner

A CLI tool for web and Kubernetes infrastructure security scanning.

## Quick Start

```bash
# Install
make install

# Launch the interactive wizard (one command to rule them all)
make cli
```

That's it. The wizard guides you through every option step by step.

## Interactive Wizard

`make cli` (or `uv run my-check`) opens a 5-step interactive form:

```
Step 1 — What do you want to scan?   web / k8s / all
Step 2 — Web target URL               (reads default from .env)
Step 3 — Kubernetes cluster           context, kubeconfig, namespace
Step 4 — Select checks                all or toggle individual checks
Step 5 — Output format                terminal / json / html / all
         Confirm & run
```

## Non-interactive (CI / scripting)

```bash
# Web scan
uv run my-check web https://example.com

# K8s scan
uv run my-check k8s --context my-cluster

# Full scan — web + k8s
uv run my-check all https://example.com --context my-cluster --output terminal,json
```

## Configuration

All defaults are loaded from **`.env`** at the project root. Copy `.env.example`:

```bash
cp .env.example .env
# Edit .env with your targets, k8s context, etc.
```

### Key variables

| Variable | Description | Example |
|---|---|---|
| `MY_CHECK_WEB_TARGET` | Default web scan URL | `https://example.com` |
| `MY_CHECK_K8S_CONTEXT` | Kubeconfig context name | `k3s`, `kind-local` |
| `MY_CHECK_K8S_KUBECONFIG` | Path to kubeconfig | `/home/you/.kube/config` |
| `MY_CHECK_K8S_SERVER` | Override K8s API server URL | `https://192.168.1.10:6443` |
| `MY_CHECK_K8S_NAMESPACE` | Scope to one namespace | `default` |
| `MY_CHECK_OUTPUT` | Default reporters | `terminal,json` |
| `MY_CHECK_SARIF` | Emit SARIF 2.1 for GitHub Code Scanning | `true` |
| `MY_CHECK_WEBHOOK_URL` | Slack / custom webhook | `https://hooks.slack.com/…` |
| `API_PORT` | Docker API port (old web-check) | `8001` |

Priority: **CLI flags > my-check.config.json > .env > built-in defaults**

## Available Checks

### Web
| Check | Description |
|-------|-------------|
| `web-tls` | Certificate expiry, chain validation, CT log presence |
| `web-headers` | CSP, HSTS, X-Frame-Options, Permissions-Policy |
| `web-dns` | DNSSEC validation, CAA records, SPF / DMARC |
| `web-ports` | Common exposed ports via TCP connect |
| `web-redirects` | Full redirect chain, HTTP→HTTPS downgrade |
| `web-subdomain-takeover` | CNAME resolution, decommissioned service detection |

### Kubernetes
| Check | Description |
|-------|-------------|
| `k8s-rbac` | Wildcard verbs, automount tokens, anonymous bindings |
| `k8s-workloads` | Root pods, privileged containers, missing limits |
| `k8s-network-policies` | Zero-policy namespaces, exposed admin endpoints |
| `k8s-secrets` | Plain env var secrets, missing sealed secrets |
| `k8s-images` | `latest` tag without SHA digest |
| `k8s-kube-bench` | CIS benchmarks (requires `kube-bench`) |
| `k8s-trivy` | Vulnerability scan (requires `trivy`) |
| `k8s-polaris` | Best practices (requires `polaris`) |
| `k8s-falco` | Runtime security DaemonSet health |

## Output Formats

| Format | Description |
|--------|-------------|
| `terminal` | Colored Rich table with ✓/⚠/✗ icons and global score |
| `json` | `outputs/my-check-results.json` |
| `html` | `outputs/my-check-report.html` — standalone, diff-aware |
| `webhook` | POST to Slack or custom URL |

## CI Integration

See `.github/workflows/security-scan.yml` for a full example.

```yaml
- name: Run security scan
  run: uv run my-check all ${{ vars.SCAN_TARGET_URL }} --output terminal,json

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: outputs/my-check-results.sarif
```


## Commands

### `my-check web <url>`

Run web security checks against a target URL.

| Check | Description |
|-------|-------------|
| `web-tls` | Certificate expiry, chain validation, CT log presence |
| `web-headers` | CSP, HSTS, X-Frame-Options, Permissions-Policy |
| `web-dns` | DNSSEC validation, CAA records, SPF / DMARC |
| `web-ports` | Common exposed ports via TCP connect |
| `web-redirects` | Full redirect chain, HTTP→HTTPS downgrade |
| `web-subdomain-takeover` | CNAME resolution, decommissioned service detection |

### `my-check k8s [options]`

Run Kubernetes security checks.

| Check | Description |
|-------|-------------|
| `k8s-rbac` | Wildcard verbs, automount tokens, anonymous bindings |
| `k8s-workloads` | Root pods, privileged containers, missing limits |
| `k8s-network-policies` | Zero-policy namespaces, exposed admin endpoints |
| `k8s-secrets` | Plain env var secrets, missing sealed secrets |
| `k8s-images` | `latest` tag without SHA digest |
| `k8s-kube-bench` | CIS benchmarks (requires `kube-bench`) |
| `k8s-trivy` | Vulnerability scan (requires `trivy`) |
| `k8s-polaris` | Best practices (requires `polaris`) |
| `k8s-falco` | Runtime security DaemonSet health |

### `my-check all <url> [options]`

Run both web and Kubernetes checks in a single pass.

## Options

| Flag | Description |
|------|-------------|
| `--output, -o` | Comma-separated reporters: `terminal`, `json`, `html`, `webhook` |
| `--config, -c` | Path to `my-check.config.json` |
| `--context` | Kubeconfig context name |
| `--kubeconfig` | Path to kubeconfig file |
| `--namespace, -n` | Kubernetes namespace scope |
| `--verbose, -v` | Enable debug logging |

## Configuration

Create a `my-check.config.json` at the project root:

```json
{
  "web": {
    "targets": ["https://example.com"],
    "enabled_checks": ["web-tls", "web-headers", "web-dns"],
    "timeout": 30
  },
  "k8s": {
    "context": "my-cluster",
    "enabled_checks": ["k8s-rbac", "k8s-workloads"],
    "timeout": 60
  },
  "output": {
    "formats": ["terminal", "json"],
    "output_dir": "outputs",
    "sarif": true
  }
}
```

## Output Formats

### Terminal
Colored table with ✓/⚠/✗ icons, global score, and per-category breakdown.

### JSON
Structured `my-check-results.json` in the output directory. Optionally emit
SARIF 2.1 for GitHub Advanced Security with `"sarif": true`.

### HTML
Self-contained `my-check-report.html` with score gauges and diff support
against a previous report.

### Webhook
POST results to a Slack incoming webhook or custom endpoint:
```json
{ "output": { "formats": ["webhook"], "webhook_url": "https://hooks.slack.com/..." } }
```

## CI Integration

Add to `.github/workflows/security-scan.yml`:

```yaml
- name: Run security scan
  run: my-check all ${{ vars.SCAN_TARGET_URL }} --output terminal,json

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: outputs/my-check-results.sarif
```

See `.github/workflows/security-scan.yml` for a complete example with a `kind` cluster.
