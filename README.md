# 🔒 Vigil

A comprehensive, Docker-based security scanning toolkit for web applications. Modern REST API built with FastAPI and async Python, orchestrating multiple industry-standard security tools.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)

---

## 🚀 Quick Start

### Web Interface (Recommended)

```bash
# Start all services including web UI
docker-compose up -d

# Access the web interface
open http://localhost:3000

# Access the API
curl http://localhost:8000

# View interactive API docs
open http://localhost:8000/docs
```

### With API Only

```bash
# Start all services
docker-compose up -d

# Run a quick scan
curl "http://localhost:8000/api/quick/nuclei?url=https://example.com"
```

### With CLI (Legacy)

```bash
# Install Docker images
make install

# Run a complete security scan
make scan TARGET=https://your-site.com

# Open the HTML report
make open
```

---

## 📦 Project Structure

```
vigil/
├── web/                     # React Web Interface
│   ├── src/
│   │   ├── components/      # UI components
│   │   ├── services/        # API client
│   │   └── types/           # TypeScript types
│   ├── Dockerfile           # Web container
│   └── package.json         # Node dependencies
├── api/                     # FastAPI application
│   ├── main.py              # Application entry point
│   ├── models/              # Pydantic data models
│   │   ├── findings.py      # Security finding models
│   │   └── results.py       # Scan result models
│   ├── routers/             # API route handlers
│   │   ├── health.py        # Health check endpoints
│   │   ├── quick.py         # Quick scan endpoints
│   │   ├── deep.py          # Deep scan endpoints
│   │   ├── security.py      # Security scan endpoints
│   │   └── scans.py         # Scan management
│   ├── services/            # Business logic
│   │   ├── docker_runner.py # Docker execution utilities
│   │   ├── nuclei.py        # Nuclei scanner service
│   │   ├── nikto.py         # Nikto scanner service
│   │   └── zap.py           # ZAP scanner service
│   └── utils/               # Shared utilities
│       └── config.py        # Configuration management
├── tests/                   # Test suite
├── Dockerfile               # API container image
├── docker-compose.yml       # Multi-container setup
├── pyproject.toml           # Python project config
├── requirements.txt         # Python dependencies
├── Makefile                 # CLI commands (legacy)
├── scripts/                 # Shell scripts (legacy)
├── config/                  # Scanner configuration
└── outputs/                 # Scan results
```

### Output Structure

Each scan creates a timestamped folder with a **uniform structure**:

```
outputs/
└── YYYYMMDD-HHMMSS/         # Unique scan ID
    ├── scans/               # Raw tool outputs
    │   ├── zap.html         # ZAP HTML report
    │   ├── zap.json         # ZAP JSON data
    │   ├── nuclei.json      # Nuclei findings
    │   ├── nikto.html       # Nikto report
    │   ├── testssl.json     # SSL/TLS analysis
    │   └── ffuf.json        # Fuzzing results
    ├── logs/                # Execution logs
    │   ├── zap.log
    │   ├── nuclei.log
    │   ├── nikto.log
    │   ├── testssl.log
    │   └── ffuf.log
    ├── report.html          # Interactive HTML report
    ├── report.json          # Machine-readable JSON data
    ├── report.md            # LLM-optimized Markdown report
    └── metadata.json        # Scan metadata
```

### Report Formats

| Format       | File          | Description                           | Best For                      |
| ------------ | ------------- | ------------------------------------- | ----------------------------- |
| **HTML**     | `report.html` | Interactive dashboard with filters    | Human review, sharing         |
| **JSON**     | `report.json` | Structured data with all findings     | CI/CD integration, automation |
| **Markdown** | `report.md`   | YAML frontmatter + structured content | LLM analysis, AI assistants   |

---

## 🛠️ Security Tools

### [OWASP ZAP](https://www.zaproxy.org/) - Dynamic Application Security Testing

> Zed Attack Proxy (ZAP) is a free and open-source web application that helps automatically find security vulnerabilities in web applications during development and testing.

| Feature       | Description                                              |
| ------------- | -------------------------------------------------------- |
| **Type**      | DAST (Dynamic Application Security Testing)              |
| **Scan Mode** | Baseline scan with passive analysis                      |
| **Output**    | HTML report + JSON data                                  |
| **Best For**  | Catching common vulnerabilities early, CI/CD integration |

**Key Capabilities:**
- Spider and crawl web applications
- Passive vulnerability scanning
- Active attack simulation
- API security testing
- WebSocket scanning

---

### [Nuclei](https://github.com/projectdiscovery/nuclei) - Template-Based Vulnerability Scanner

> Nuclei is a modern, high-performance vulnerability scanner built in Go that leverages YAML-based templates for customizable vulnerability detection. It supports multiple protocols (HTTP, DNS, TCP, SSL, WebSocket) and is designed for zero false positives.

| Feature       | Description                                 |
| ------------- | ------------------------------------------- |
| **Type**      | Template-based scanner                      |
| **Templates** | 5000+ community-curated templates           |
| **Output**    | JSON Lines format                           |
| **Best For**  | CVE detection, misconfigurations, exposures |

**Key Capabilities:**
- Multi-protocol support (HTTP, DNS, TCP, SSL)
- Severity-based filtering (critical, high, medium, low)
- Community-driven templates for latest CVEs
- Fast parallel scanning

---

### [Nikto](https://cirt.net/Nikto2) - Web Server Scanner

> Nikto is an Open Source web server scanner that performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs.

| Feature      | Description                                 |
| ------------ | ------------------------------------------- |
| **Type**     | Web Server Scanner                          |
| **Tests**    | 6700+ dangerous files/CGIs                  |
| **Output**   | HTML report                                 |
| **Best For** | Server misconfigurations, outdated software |

**Key Capabilities:**
- Outdated server software detection
- Default file and program scanning
- Server configuration issues
- SSL certificate analysis

---

### [testssl.sh](https://testssl.sh/) - SSL/TLS Configuration Analyzer

> testssl.sh is a free command-line tool to check a server's TLS/SSL configuration, ciphers, protocols, and cryptographic flaws.

| Feature      | Description                         |
| ------------ | ----------------------------------- |
| **Type**     | SSL/TLS Analyzer                    |
| **Checks**   | Protocols, ciphers, vulnerabilities |
| **Output**   | JSON report                         |
| **Best For** | SSL/TLS hardening, compliance       |

**Key Capabilities:**
- Protocol support analysis (SSLv2, SSLv3, TLS 1.0-1.3)
- Cipher suite enumeration
- Certificate chain verification
- Known vulnerabilities (BEAST, POODLE, Heartbleed, etc.)

---

### [ffuf](https://github.com/ffuf/ffuf) - Fast Web Fuzzer

> ffuf is a fast web fuzzer written in Go, designed for content discovery, virtual host discovery, and parameter fuzzing.

| Feature      | Description                           |
| ------------ | ------------------------------------- |
| **Type**     | Web Fuzzer                            |
| **Speed**    | Very fast (Go-based)                  |
| **Output**   | JSON results                          |
| **Best For** | Hidden directories, files, parameters |

**Key Capabilities:**
- Directory and file brute-forcing
- Virtual host discovery
- Parameter fuzzing
- Custom wordlist support

---

## 📋 Available Commands

### Scanning Commands

| Command                        | Description                  | Duration  |
| ------------------------------ | ---------------------------- | --------- |
| `make scan`                    | Complete scan with all tools | 30-60 min |
| `make quick`                   | Quick scan (Nuclei + Nikto)  | 5-10 min  |
| `make custom TOOLS=zap,nuclei` | Custom tool selection        | Varies    |

### Individual Tool Scans

| Command        | Tool       | Description                |
| -------------- | ---------- | -------------------------- |
| `make zap`     | OWASP ZAP  | DAST baseline scan         |
| `make nuclei`  | Nuclei     | CVE and vulnerability scan |
| `make nikto`   | Nikto      | Web server scanner         |
| `make testssl` | testssl.sh | SSL/TLS analysis           |
| `make ffuf`    | ffuf       | Directory fuzzing          |

### Report Management

| Command       | Description                          |
| ------------- | ------------------------------------ |
| `make report` | Generate HTML report for latest scan |
| `make open`   | Open latest report in browser        |
| `make list`   | List all scans with status           |
| `make tree`   | Show file structure of latest scan   |

### Docker Management

| Command        | Description               |
| -------------- | ------------------------- |
| `make install` | Pull/update Docker images |
| `make start`   | Start scanner containers  |
| `make stop`    | Stop all containers       |
| `make status`  | Show container status     |
| `make restart` | Restart containers        |

### Utilities

| Command        | Description             |
| -------------- | ----------------------- |
| `make check`   | Verify prerequisites    |
| `make logs`    | View Docker logs        |
| `make clean`   | Delete all scan results |
| `make version` | Show version            |

---

## 🎯 Usage Examples

### Basic Scanning

```bash
# Full security audit
make scan TARGET=https://example.com

# Quick vulnerability check
make quick TARGET=https://staging.example.com

# SSL/TLS only
make testssl TARGET=https://api.example.com
```

### Custom Scans

```bash
# ZAP + Nuclei only
make custom TARGET=https://example.com TOOLS=zap,nuclei

# Everything except fuzzing
make custom TARGET=https://example.com TOOLS=zap,nuclei,nikto,testssl
```

### CI/CD Integration

```bash
# Returns non-zero exit code if critical vulnerabilities found
make ci-scan TARGET=https://staging.example.com
```

### View Results

```bash
# List all scans
make list

# Output:
# 📋 Available scans:
#   📁 20231223-143052  |  5 files  |  Report: ✅
#   📁 20231223-120015  |  3 files  |  Report: ✅

# Open specific scan
open outputs/20231223-143052/report.html
```

---

## 🔧 Configuration

### Environment Variables

```bash
# Default target
TARGET=https://example.com

# Scan mode (full, quick, custom)
MODE=full

# Tools to use (comma-separated)
TOOLS=zap,nuclei,nikto,testssl,ffuf
```

### Custom Wordlists

Place custom wordlists in `config/wordlists/`:

```bash
# Download SecLists common.txt (automatic if missing)
curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
  -o config/wordlists/common.txt
```

---

## 🐛 Troubleshooting

### Prerequisites Check

```bash
make check

# ✅ All prerequisites satisfied
```

### Common Issues

| Issue                  | Solution                     |
| ---------------------- | ---------------------------- |
| Docker not running     | `docker info` to verify      |
| Containers won't start | `make restart`               |
| Scan hangs             | Check target accessibility   |
| Empty results          | Verify target URL is correct |

### Debug Commands

```bash
# View container status
make status

# Check container logs
make logs

# Shell into container
make shell-zap
make shell-nuclei
```

---

## 📊 Understanding Reports

### HTML Report (`report.html`)

The interactive HTML report includes:

- **Summary Dashboard** - Critical/High/Medium/Low counts with visual indicators
- **Filterable Findings** - Filter by severity, tool, or search terms
- **Tool Results** - Links to individual scan outputs
- **Execution Logs** - Debug information for each tool

### Markdown Report (`report.md`)

The Markdown report is specifically designed for **LLM/AI analysis**:

```yaml
---
type: security_scan_report
version: "1.0"
generated_at: 2024-12-23T10:30:00Z
scan:
  id: "20241223-103000"
  target: "https://example.com"
  mode: "full"
summary:
  critical: 0
  high: 2
  medium: 5
  low: 3
  info: 10
  total: 20
tools_used:
  - nuclei
  - zap
  - testssl
  - nikto
  - ffuf
---
```

**Features:**
- **YAML Frontmatter** - Structured metadata for easy parsing
- **Executive Summary** - Risk level assessment and severity distribution
- **Grouped Findings** - Organized by severity (Critical → Info)
- **Actionable Recommendations** - Prioritized remediation guidance
- **LLM Instructions** - Context for AI-assisted analysis

**Use with AI assistants:**
```bash
# Copy report content to clipboard (macOS)
cat outputs/YYYYMMDD-HHMMSS/report.md | pbcopy

# Then paste into ChatGPT, Claude, or your preferred AI assistant
```

### JSON Report (`report.json`)

Machine-readable format for automation:

```json
{
  "scan_id": "20241223-103000",
  "target": "https://example.com",
  "summary": { "critical": 0, "high": 2, ... },
  "findings": [...],
  "files": { "scans": [...], "logs": [...] }
}
```

### Severity Levels

| Level      | Color  | Action                 |
| ---------- | ------ | ---------------------- |
| 🔴 Critical | Red    | Immediate fix required |
| 🟠 High     | Orange | Fix before production  |
| 🟡 Medium   | Yellow | Plan remediation       |
| 🟢 Low      | Green  | Consider fixing        |
| 🔵 Info     | Blue   | Informational only     |

---

## 🌐 Web Interface

Vigil includes a modern React web interface for simplified usage.

### Features

- **Intuitive Interface** - Simple form to launch scans
- **Real-Time Results** - Immediate display of detected vulnerabilities
- **Finding Visualization** - Severity badges and complete details
- **Scan History** - Quick access to recent scans
- **Responsive Design** - Works on desktop and mobile

### Access

```bash
# Démarrer avec Docker
docker-compose up -d

# Accéder à l'interface
open http://localhost:3000
```

### Développement

```bash
# Installer les dépendances
cd web && npm install

# Mode développement avec hot-reload
npm run dev

# Build de production
npm run build
```

### Stack Technique

- **React 18** - Framework UI moderne
- **TypeScript** - Typage statique pour la sécurité
- **Vite** - Build ultra-rapide
- **TailwindCSS** - Design system utility-first
- **TanStack Query** - Gestion d'état et cache intelligent
- **Axios** - Client HTTP avec intercepteurs

### Screenshots

**Dashboard Principal**
- Formulaire de scan avec sélection du type (Rapide/Approfondi/Sécurité)
- Configuration du timeout
- Liste des scans récents en sidebar

**Résultats de Scan**
- Badges de statut colorés (Success/Error/Timeout)
- Statistiques (durée, nombre de findings)
- Liste détaillée des vulnérabilités avec :
  - Sévérité (Critical → Info)
  - Description complète
  - CVE et CVSS score
  - Liens vers références externes

Pour plus de détails, voir [web/README.md](web/README.md) et [QUICKSTART.md](QUICKSTART.md).

---

## 🔗 Resources

### Tool Documentation

- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Nuclei Documentation](https://docs.projectdiscovery.io/tools/nuclei/overview)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Nikto Documentation](https://cirt.net/Nikto2)
- [testssl.sh Documentation](https://testssl.sh/doc/)
- [ffuf Documentation](https://github.com/ffuf/ffuf)

### Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)

---

## 📝 License

MIT License - Feel free to use and modify.

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting a PR.

1. Fork the repository
2. Create a feature branch
3. Run `make lint` to check code quality
4. Submit a pull request

See also:
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

---

Made with ❤️ for the security community