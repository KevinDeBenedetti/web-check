---
title: my-check
---

# my-check

`my-check` is a standalone command-line scanner for web endpoints and Kubernetes
clusters. It runs its checks locally and does not need the web-check API.

## Quick start

```sh
make install   # uv sync --all-groups
make cli       # the interactive wizard (uv run my-check)
```

## Interactive wizard

`uv run my-check` with no command opens a guided form. It asks what to scan (web,
Kubernetes or both), then the web target URL and/or the Kubernetes context,
kubeconfig and namespace, then which checks to run (all of them, or a selection
built from every registered check), the output reporters (`terminal`, `markdown`,
`json`, `html`, `webhook`) and a final confirmation.

## Commands

```sh
uv run my-check web https://example.com
uv run my-check k8s --context my-cluster --namespace app
uv run my-check all https://example.com --context my-cluster --output terminal,json
```

| Command                    | Runs                                     |
| -------------------------- | ---------------------------------------- |
| `my-check web <url>`       | the web checks against `<url>`           |
| `my-check k8s`             | the Kubernetes checks                    |
| `my-check all <url>`       | both, in one run                         |

### Options

| Flag                | Commands         | Description                                                                                                  |
| ------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------ |
| `--output`, `-o`    | all              | Comma-separated reporters: `terminal`, `json`, `html`, `markdown`, `webhook`. Default: `output.formats`.     |
| `--sarif`           | all              | Also write `outputs/my-check-results.sarif`; turns the `json` reporter on and overrides `output.sarif`.      |
| `--strict`          | all              | Exit with code 1 when any check fails (CI).                                                                  |
| `--config`, `-c`    | all              | Path to a configuration file (default: `my-check.config.json` or `.my-check.json`, searched upwards).        |
| `--verbose`, `-v`   | all              | Debug logging.                                                                                               |
| `--context`         | `k8s`, `all`     | Kubeconfig context.                                                                                          |
| `--kubeconfig`      | `k8s`, `all`     | Kubeconfig file.                                                                                             |
| `--namespace`, `-n` | `k8s`, `all`     | Limit the Kubernetes checks to one namespace.                                                                |

## Checks

### Web

| Check                    | What it looks at                                                                                     |
| ------------------------ | ---------------------------------------------------------------------------------------------------- |
| `web-tls`                | Certificate expiry, chain validation and embedded CT timestamps, on the URL's port (443 by default)  |
| `web-headers`            | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy             |
| `web-csp`                | Content-Security-Policy: missing key directives, `'unsafe-inline'` / `'unsafe-eval'`, wildcards      |
| `web-cors`               | Reflected arbitrary or `null` origins, combined with `Access-Control-Allow-Credentials`              |
| `web-cookies`            | `Secure`, `HttpOnly`, `SameSite` and the `__Host-` / `__Secure-` prefixes                            |
| `web-dns`                | DNSSEC validation, CAA records, SPF and DMARC                                                        |
| `web-ports`              | Open TCP ports; database and remote-access ports fail the check                                     |
| `web-redirects`          | The full redirect chain (relative `Location` included), HTTP→HTTPS upgrade, HTTPS→HTTP downgrade     |
| `web-subdomain-takeover` | CNAME records pointing at decommissioned services                                                    |

### Kubernetes

| Check                  | What it looks at                                                                             |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| `k8s-rbac`             | Wildcard verbs, automounted service-account tokens, anonymous bindings                       |
| `k8s-workloads`        | Root and privileged containers, missing resource limits                                      |
| `k8s-network-policies` | Namespaces without a NetworkPolicy, exposed admin endpoints                                  |
| `k8s-secrets`          | Secrets in plain environment variables, missing sealed secrets                               |
| `k8s-images`           | `latest` tags without a digest                                                               |
| `k8s-pss-compliance`   | Pod Security Standards: host namespaces and container security settings                      |
| `k8s-etcd-encryption`  | Encryption at rest of secrets in etcd                                                        |
| `k8s-kube-bench`       | CIS benchmarks (needs `kube-bench`; it audits the node it runs on, not the selected cluster) |
| `k8s-trivy`            | Image vulnerabilities (needs `trivy`)                                                        |
| `k8s-polaris`          | Best practices (needs `polaris`)                                                             |
| `k8s-falco`            | Health of the Falco runtime-security DaemonSet                                               |

`kube-bench`, `trivy` and `polaris` are optional: without them their check
reports *not found* as information and does not lower the score.

## Configuration

Settings come from three places. The configuration file wins over the environment,
and command-line flags win over both.

### Environment

`my-check` reads `.env` from the working directory (variables already set are kept).
See `.env.example`.

| Variable                  | Description                           | Example                        |
| ------------------------- | ------------------------------------- | ------------------------------ |
| `MY_CHECK_WEB_TARGET`     | Default web target                    | `https://example.com`          |
| `MY_CHECK_K8S_CONTEXT`    | Kubeconfig context                    | `kind-local`                   |
| `MY_CHECK_K8S_KUBECONFIG` | Kubeconfig file                       | `/home/you/.kube/config`       |
| `MY_CHECK_K8S_NAMESPACE`  | Limit the Kubernetes checks           | `default`                      |
| `MY_CHECK_OUTPUT`         | Default reporters                     | `terminal,json`                |
| `MY_CHECK_OUTPUT_DIR`     | Where reports are written             | `outputs`                      |
| `MY_CHECK_SARIF`          | Write the SARIF file                  | `true`                         |
| `MY_CHECK_WEBHOOK_URL`    | Slack or custom webhook               | `https://hooks.slack.com/…`    |

### Configuration file

`my-check.config.json` (or `.my-check.json`) in the working directory or a parent,
or the file given with `--config`:

```json
{
  "web": {
    "targets": ["https://example.com"],
    "enabled_checks": ["web-tls", "web-headers", "web-dns"],
    "timeout": 30,
    "ports": [80, 443, 8443]
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

- `enabled_checks` lists the checks to run; an empty list runs none of that category.
- `web.ports` replaces the ports `web-ports` probes. Leave it out to keep the
  check's own list: 80, 443, 8080, 8443, 3000 and 9090, plus 21, 22, 3306, 5432,
  6379 and 27017, which fail the check when open.
- `timeout` is per check, in seconds.

## Reporters

| Reporter   | Output                                                                                               |
| ---------- | ---------------------------------------------------------------------------------------------------- |
| `terminal` | Coloured table with the status of each check and the global score                                    |
| `json`     | `outputs/my-check-results.json`, and `outputs/my-check-results.sarif` (SARIF 2.1) with `--sarif`     |
| `markdown` | `outputs/my-check-report.md`, with text from the target escaped                                      |
| `html`     | `outputs/my-check-report.html`, self-contained, with a diff against `output.previous_report`         |
| `webhook`  | A POST to `output.webhook_url` (Slack incoming webhook or custom endpoint)                           |

## CI integration

`.github/workflows/security-scan.yml` runs the web checks and the Kubernetes checks
(against a `kind` cluster) every week and uploads the SARIF file to GitHub code
scanning. The core of it:

```yaml
- name: Run web checks
  run: uv run my-check web "$SCAN_TARGET_URL" --output terminal,json --sarif
  env:
    SCAN_TARGET_URL: ${{ vars.SCAN_TARGET_URL }}

- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: outputs/my-check-results.sarif
```

Add `--strict` to fail the job when a check fails.
