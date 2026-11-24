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
| `--kube-bench-job`  | `k8s`, `all`     | Run kube-bench as a Job in the selected cluster instead of on this machine (`k8s.kube_bench_job`).          |

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
| `k8s-kube-bench`       | CIS benchmarks (needs `kube-bench`, or `kubectl` with `--kube-bench-job`; see below)        |
| `k8s-trivy`            | Image vulnerabilities (needs `trivy`)                                                        |
| `k8s-polaris`          | Best practices (needs `polaris`)                                                             |
| `k8s-falco`            | Health of the Falco runtime-security DaemonSet                                               |

`kube-bench`, `trivy` and `polaris` are optional: without them their check
reports *not found* as information and does not lower the score.

kube-bench audits the node it runs on. By default that is this machine, not the
selected cluster. With `--kube-bench-job` (or `"kube_bench_job": true` under `k8s`
in the configuration), my-check runs upstream's kube-bench Job in the selected
context and namespace (`default` when none is given) instead, once per node: it
lists the nodes (`kubectl get nodes`), creates for each a Job named
`my-check-kube-bench-<random>` pinned to that node (`nodeName`, tolerating its
taints, so control-plane nodes are audited too) with `hostPID` and read-only host
mounts, waits up to 5 minutes for them to succeed or fail, reads their JSON logs,
then deletes them (a 10-minute TTL removes them if the run is interrupted). The
image is pinned by digest. The counts are summed over the nodes, and
`details.nodes` gives each node's own counts and sections, or why it has no
result (with an excerpt of its log when that is not kube-bench JSON); a node
without a result makes the benchmark partial. In a pod, kube-bench often cannot
reach the API server to detect the Kubernetes version and falls back to the
generic `cis-1.6` benchmark, so on a k3s node (`+k3s` in its kubelet version)
my-check passes the k3s benchmark kube-bench itself would pick (`--benchmark
k3s-cis-1.9` from 1.27 on); other nodes keep kube-bench's own choice. The Jobs need the
rights to create Jobs and read pod logs in that namespace, and are blocked by a
namespace enforcing the `restricted` or `baseline` Pod Security Standard. Without
the right to list nodes, a single Job audits the node the scheduler picks, and
the result says so. In this mode the per-check
timeout is raised to at least 510 s, whatever `k8s.timeout` says. The Job's pod
carries the `app.kubernetes.io/managed-by: my-check` label, and the other checks
skip pods with that label: my-check does not audit its own pod.

A pod cannot see everything the benchmark reads. On k3s, the control plane is
embedded in the k3s binary and logs its flags to the host's systemd journal,
which the kube-bench image has no `journalctl` to read. The result then says
**Partial CIS benchmark** and names the gaps: sections missing from the report
(of `master`, `controlplane`, `node` and `policies`) and the journal-based checks
left out of the counts (`details.unverifiable`), rather than scoring them as
failures. A partial benchmark never reads as a clean pass. For the full benchmark
on k3s, run the kube-bench binary on each node with `--benchmark k3s-cis-*`.

A context set by `MY_CHECK_K8S_CONTEXT` or `k8s.context` also applies to a
kubeconfig given with `--kubeconfig`: pass `--context` with a kubeconfig whose
context names differ, or the checks report the cluster as unreachable.

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
- `timeout` is per check, in seconds. A check that runs past it fails as
  "Timed out" and its commands are killed; a check stuck in blocking code gets
  5 more seconds, then `my-check` stops waiting and exits without it.

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

In code scanning, each alert's location is the scanned target rather than a file:
the host and path for web checks (`example.com`, a `:` becomes `_`, so
`example.com:8443` shows as `example.com_8443`) and the context for Kubernetes
checks.

Add `--strict` to fail the job when a check fails.
