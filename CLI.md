# web-check CLI

`web-check` is the command-line client of the web-check API: it starts scans on a
running API and shows their results. For a standalone scanner that needs no API,
see [my-check](docs/my-check.md).

## Installation

```sh
make install          # uv sync --all-groups
uv run web-check --help
```

## Connecting to the API

The CLI talks to `http://localhost:8000` by default. Start the API first
(`make start`), then check the connection:

```sh
web-check health
web-check config validate
```

When the API has `API_KEY` set, give the CLI the same value. Settings are read from
the environment or from a `.env` file in the working directory:

| Variable                    | Default                 | Description                                           |
| --------------------------- | ----------------------- | ----------------------------------------------------- |
| `WEB_CHECK_CLI_API_URL`     | `http://localhost:8000` | API base URL (must match `API_PORT`)                  |
| `WEB_CHECK_CLI_API_KEY`     | *(empty)*               | Sent as `X-API-Key`; must match the API's `API_KEY`   |
| `WEB_CHECK_CLI_API_TIMEOUT` | `600`                   | Request timeout in seconds; a scan waits at least its own `--timeout` plus 30 s |
| `ALLOWED_DOMAINS`           | *(empty)*               | Shared with the API: the domains `check`, `guide` and `domains list` offer       |

`web-check config show` prints the settings in use.

## Commands

Running `web-check` with no command opens the interactive guide (`web-check guide`).

| Command                         | What it does                                                                |
| ------------------------------- | --------------------------------------------------------------------------- |
| `web-check check [domain]`      | Complete check: DNS, DNS records, headers, SSL/TLS, Nuclei, Nikto, in order |
| `web-check scan quick <url>`    | DNS and reachability                                                        |
| `web-check scan nuclei <url>`   | Nuclei vulnerability and CVE templates                                      |
| `web-check scan nikto <url>`    | Nikto web-server scan                                                       |
| `web-check scan ssl <url>`      | SSL/TLS assessment (SSLyze)                                                 |
| `web-check scan full <url>`     | Multi-module scan run by the API, with live progress                        |
| `web-check results list`        | Recent scans                                                                |
| `web-check results show <id>`   | One scan's results                                                          |
| `web-check results clear`       | Delete all scan results from the local database                            |
| `web-check domains list`        | The domains of `ALLOWED_DOMAINS`                                            |
| `web-check config show`         | The CLI's settings                                                          |
| `web-check config validate`     | Check that the API answers                                                  |
| `web-check health`              | API health                                                                  |

Global options: `--version` / `-v` and `--debug` (JSON log output).

### Options

| Option            | Commands                                     | Description                                                       |
| ----------------- | -------------------------------------------- | ----------------------------------------------------------------- |
| `--output-format` | `check`, `scan *`, `results list/show`, `domains list` | `table` (default) or `json`                                  |
| `--report`        | `check`, `scan *`                            | Also save a Markdown report to `outputs/`                         |
| `--skip`          | `check`                                      | Steps to skip: `dns`, `dns_enum`, `headers`, `ssl`, `nuclei`, `nikto` |
| `--timeout`       | `scan nuclei`, `scan nikto`                  | Seconds, 30–3600 (defaults 300 and 600)                           |
| `--timeout`       | `scan ssl`                                   | Seconds, 60–3600 (default 300)                                    |
| `--timeout`       | `scan full`                                  | Seconds per module, 30–3600 (default 300)                         |
| `--modules`       | `scan full`                                  | Comma-separated module ids from the API catalog (`GET /api/catalog`), e.g. `headers`, `dns`, `nuclei` (default `nuclei,nikto,zap`) |
| `--all`           | `scan full`                                  | Every module of the API catalog (much slower)                     |
| `--limit`         | `results list`                               | Number of scans (default 10)                                      |
| `--status`        | `results list`                               | `success`, `error` or `timeout`                                   |
| `--confirm`       | `results clear`                              | Skip the confirmation prompt                                      |

Options can follow the arguments: `web-check check example.com --report`.

## Examples

```sh
# Complete check of a domain, with a Markdown report
web-check check example.com --report

# Full scan with every module, results as JSON (progress goes to stderr)
web-check scan full https://example.com --all --output-format json > scan.json

# A longer Nikto scan
web-check scan nikto https://example.com --timeout 900

# Review a scan later
web-check results list --status error
web-check results show <scan-id>
```

With `--output-format json`, stdout carries only the JSON document, so it can be
piped or redirected; `--report` still writes the Markdown report.

## Troubleshooting

- **Connection refused:** start the API (`make start`) and check
  `WEB_CHECK_CLI_API_URL` with `web-check config validate`.
- **401 Invalid or missing API key:** set `WEB_CHECK_CLI_API_KEY` to the API's
  `API_KEY`.
- **Target not allowed:** the target must be in the API's `ALLOWED_DOMAINS`.
