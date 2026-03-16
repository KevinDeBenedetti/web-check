# Web-Check CLI

A command-line interface for Web-Check security scanning toolkit. This is a self-hosted, CLI-only tool for performing security assessments on web applications.

## Installation

```bash
# Install with dependencies
uv sync --all-extras --dev

# Or using pip
pip install -e .
```

## Quick Start

### 1. Check CLI Configuration

```bash
web-check config show
```

### 2. Verify API Connection

```bash
web-check config validate
```

This assumes the API is running locally on `http://localhost:8000`. You can customize this with environment variables:

```bash
export WEB_CHECK_CLI_API_URL=http://your-api:8000
web-check config validate
```

### 3. Run a Scan

```bash
# Quick vulnerability scan
web-check scan quick https://example.com

# Nuclei vulnerability scan
web-check scan nuclei https://example.com

# Nikto web server scan
web-check scan nikto https://example.com

# SSL/TLS assessment
web-check scan ssl https://example.com
```

### 4. View Results

```bash
# List recent scans
web-check results list

# View specific scan
web-check results show <scan-id>

# Clear all results
web-check results clear
```

## Commands

### Scan Operations

```bash
web-check scan nuclei <URL>    # Run Nuclei vulnerability scan
web-check scan nikto <URL>     # Run Nikto web server scan
web-check scan quick <URL>     # Run quick security scan
web-check scan ssl <URL>       # Run SSL/TLS assessment
```

**Options:**
- `--timeout` - Timeout in seconds (default: varies by scanner)
- `--output-format` - Output format: `table` or `json` (default: table)

### Results Operations

```bash
web-check results list         # List recent scan results
web-check results show <ID>    # Show specific result
web-check results clear        # Clear all results
```

**Options:**
- `--limit` - Number of results to display (default: 10)
- `--status` - Filter by status: success, error, timeout
- `--output-format` - Output format: `table` or `json`

### Configuration Operations

```bash
web-check config show          # Display current configuration
web-check config validate      # Validate API connection
```

## Configuration

Configure via environment variables:

```bash
export WEB_CHECK_CLI_API_URL=http://localhost:8000
export WEB_CHECK_CLI_API_TIMEOUT=600
export WEB_CHECK_CLI_OUTPUT_FORMAT=json
export WEB_CHECK_CLI_DEBUG=false
export WEB_CHECK_CLI_LOG_LEVEL=INFO
```

Or create a `.env` file in your working directory:

```env
WEB_CHECK_CLI_API_URL=http://localhost:8000
WEB_CHECK_CLI_API_TIMEOUT=600
WEB_CHECK_CLI_OUTPUT_FORMAT=table
```

## Output Formats

### Table Format (Default)

Human-readable table output with color highlighting:

```
✓ Scan Result (nuclei - 1523ms)

Status: success

Found 3 Finding(s)

[red][1] CRITICAL[/red]
  Title: SQL Injection
  Description: Application is vulnerable to SQL injection
  CVE: CVE-2024-1234
  CVSS: 9.8
```

### JSON Format

Complete JSON output for programmatic processing:

```bash
web-check scan nuclei https://example.com --output-format json
```

Returns full scan result including all metadata and findings.

## Self-Hosted Setup

The CLI is designed for self-hosted deployments:

1. **Start the API locally:**
   ```bash
   cd /path/to/web-check
   uv run uvicorn apps.api.main:app --host 0.0.0.0 --port 8000
   ```

2. **Or use Docker:**
   ```bash
   docker compose up -d api
   ```

3. **Run CLI commands:**
   ```bash
   web-check scan nuclei https://example.com
   ```

## Examples

### Basic Vulnerability Scan

```bash
web-check scan quick https://example.com
```

### Output to JSON

```bash
web-check scan nuclei https://example.com --output-format json > results.json
```

### Custom Timeout

```bash
web-check scan nikto https://example.com --timeout 900
```

### List Results with Filtering

```bash
# Show last 20 results
web-check results list --limit 20

# Show only failed scans
web-check results list --status error
```

## Troubleshooting

### API Connection Refused

Ensure the API is running:
```bash
web-check config validate
```

### Change API URL

```bash
export WEB_CHECK_CLI_API_URL=http://your-server:8000
web-check config validate
```

### Enable Debug Mode

```bash
web-check --debug scan quick https://example.com
```

### Check Logs

The CLI uses structured logging. View logs with:
```bash
web-check --debug scan quick https://example.com 2>&1 | grep -i error
```

## Development

### Running Tests

```bash
uv run pytest apps/api/tests/ -v
```

### Code Quality

```bash
# Format code
uv run ruff format apps/

# Lint code
uv run ruff check apps/

# Type check
uv run ty check apps/api
```

## Version

```bash
web-check --version
```
