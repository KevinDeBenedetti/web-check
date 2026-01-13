# 🔒 Web-Check

A comprehensive, Docker-based security scanning toolkit for web applications. Modern REST API built with FastAPI and async Python, orchestrating multiple industry-standard security tools.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)

---

## 🚀 Quick Start

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)

### 1. Clone and Configure

```bash
git clone https://github.com/KevinDeBenedetti/web-check.git
cd web-check

# Optional: Customize configuration
cp .env.example .env
# Edit .env to adjust ports, timeouts, etc.
```

### 2. Start Web-Check

```bash
# Production mode (optimized builds)
make start

# Development mode (hot-reload enabled)
make dev
```

### 3. Access the Interface

| Service      | URL                        |
| ------------ | -------------------------- |
| **Web UI**   | http://localhost:3000      |
| **API Docs** | http://localhost:8000/docs |
| **API**      | http://localhost:8000      |

### Quick Commands

```bash
make start      # Start production environment
make dev        # Start development environment (hot-reload)
make stop       # Stop all containers
make logs       # View logs
make restart    # Restart containers
make clean      # Clean output files
```

---

## 📖 Usage Examples

### Web Interface (Recommended)

1. Open http://localhost:3000
2. Select scanning tools (Nuclei, Nikto, ZAP, etc.)
3. Enter target URL
4. Click "Start Scan"
5. View results organized by severity with accordions

### API Examples

```bash
# Quick vulnerability scan with Nuclei
curl "http://localhost:8000/api/quick/nuclei?url=https://example.com"

# Web server scan with Nikto
curl "http://localhost:8000/api/quick/nikto?url=https://example.com"

# Deep ZAP scan
curl "http://localhost:8000/api/deep/zap?url=https://example.com"

# SSL/TLS analysis with SSLyze
curl "http://localhost:8000/api/deep/sslyze?url=https://example.com"

# SQL injection scan with SQLMap
curl "http://localhost:8000/api/advanced/sqlmap?url=https://example.com"

# XSS detection with XSStrike
curl "http://localhost:8000/api/advanced/xsstrike?url=https://example.com"

# Get scan history
curl "http://localhost:8000/api/scans"
```

---

## 🏗️ Architecture

### Technology Stack

| Layer             | Technologies                                            |
| ----------------- | ------------------------------------------------------- |
| **Frontend**      | React 18 + TypeScript + Vite + shadcn/ui + Tailwind CSS |
| **Backend**       | FastAPI + Python 3.12 + SQLAlchemy 2.0 + Alembic        |
| **Database**      | SQLite (async with aiosqlite)                           |
| **Scanners**      | Docker containers (ZAP, Nuclei, Nikto, SSLyze, SQLMap)  |
| **Orchestration** | Docker Compose with profiles                            |
| **Tooling**       | Ruff (lint/format), Ty (type-check), Pytest             |

---

## 📦 Project Structure

```
web-check/
├── api/                     # FastAPI Backend
│   ├── main.py              # Application entry point
│   ├── database.py          # SQLAlchemy async setup
│   ├── models/              # Pydantic & SQLAlchemy models
│   │   ├── findings.py      # Security finding models
│   │   ├── results.py       # Scan result models
│   │   └── db_models.py     # Database ORM models
│   ├── routers/             # API route handlers
│   │   ├── health.py        # Health check endpoints
│   │   ├── quick.py         # Quick scans (Nuclei, Nikto, DNS)
│   │   ├── deep.py          # Deep scans (ZAP, SSLyze)
│   │   ├── security.py      # Security scans (FFUF, SQLMap Docker)
│   │   ├── advanced.py      # Advanced security (SQLMap, Wapiti, XSStrike)
│   │   └── scans.py         # Scan management (CRUD)
│   ├── services/            # Business logic & scanners
│   │   ├── docker_runner.py # Docker execution utilities
│   │   ├── nuclei.py        # Nuclei scanner service
│   │   ├── nikto.py         # Nikto scanner service
│   │   ├── zap_native.py    # ZAP Python API service
│   │   ├── sslyze_scanner.py# SSLyze scanner service
│   │   ├── sqlmap_scanner.py# SQLMap scanner service
│   │   ├── wapiti_scanner.py# Wapiti scanner service
│   │   ├── xsstrike_scanner.py # XSStrike scanner
│   │   ├── db_service.py    # Database operations
│   │   └── log_streamer.py  # SSE log streaming
│   ├── tests/               # Test suite
│   └── utils/
│       └── config.py        # Settings with pydantic-settings
├── web/                     # React Frontend
│   ├── src/
│   │   ├── components/      # UI components
│   │   ├── services/        # API client
│   │   └── types/           # TypeScript types
│   └── Dockerfile           # Web container
├── alembic/                 # Database migrations
├── config/                  # Scanner configuration
├── outputs/                 # Scan results
├── docker-compose.yml       # Multi-container setup
├── Dockerfile               # API container
├── Makefile                 # CLI commands
└── pyproject.toml           # Python project config
```

---

## 🛠️ Security Tools

### Quick Scans

| Tool                                                     | Description                                               | Timeout |
| -------------------------------------------------------- | --------------------------------------------------------- | ------- |
| **[Nuclei](https://github.com/projectdiscovery/nuclei)** | Template-based vulnerability scanner with 5000+ templates | 300s    |
| **[Nikto](https://cirt.net/Nikto2)**                     | Web server scanner (6700+ dangerous files/CGIs)           | 600s    |
| **DNS**                                                  | Quick DNS reconnaissance and domain information           | 10s     |

### Deep Scans

| Tool                                               | Description                                 | Timeout |
| -------------------------------------------------- | ------------------------------------------- | ------- |
| **[OWASP ZAP](https://www.zaproxy.org/)**          | Dynamic Application Security Testing (DAST) | 900s    |
| **[SSLyze](https://github.com/nabla-c0d3/sslyze)** | SSL/TLS configuration analyzer              | 300s    |

### Security Scans

| Tool                                    | Description                               | Timeout |
| --------------------------------------- | ----------------------------------------- | ------- |
| **[FFUF](https://github.com/ffuf/ffuf)** | Fast web fuzzer (directory/file discovery) | 600s    |
| **SQLMap (Docker)**                     | SQL injection testing (basic)             | 900s    |

### Advanced Security

| Tool                                               | Description                           | Timeout |
| -------------------------------------------------- | ------------------------------------- | ------- |
| **[SQLMap](https://sqlmap.org/)**                  | Automatic SQL injection detection     | 900s    |
| **[Wapiti](https://wapiti.sourceforge.io/)**       | Web application vulnerability scanner | 600s    |
| **[XSStrike](https://github.com/s0md3v/XSStrike)** | Advanced XSS detection                | 300s    |

---

## 🔧 Configuration

### Environment Variables

Copy `.env.example` to `.env` and customize:

```bash
# Core
DEBUG=false
LOG_LEVEL=INFO

# Ports
WEB_PORT=3000
API_PORT=8000

# Timeouts
DEFAULT_TIMEOUT=300
MAX_TIMEOUT=3600

# Database
DATABASE_URL="sqlite+aiosqlite:///./web-check.db"
```

### Docker Profiles

```bash
# Production (default)
docker compose --profile prod up -d

# Development (hot-reload)
docker compose --profile dev up -d
```

---

## 👨‍💻 Development

### Local Setup

```bash
# Install dependencies
make install

# Run API locally (outside Docker)
make run

# Run tests
make test

# Code quality
make check    # lint + format + type-check
make format   # Format code
make lint     # Lint code
```

### CI Workflow

```bash
# Run all CI steps locally
make ci
```

---

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Check what's using the port
lsof -i :3000  # Web
lsof -i :8000  # API

# Change ports in .env
WEB_PORT=3001
API_PORT=8001
```

### Database Issues

```bash
# Reset database
rm web-check.db
docker compose restart api
```

### Container Issues

```bash
# View logs
make logs

# Restart containers
make restart

# Full cleanup
make clean-all
```

---

## 📊 API Endpoints

### Health

| Method | Endpoint      | Description     |
| ------ | ------------- | --------------- |
| GET    | `/api/health` | Health check    |
| GET    | `/api/ready`  | Readiness check |

### Quick Scans

| Method | Endpoint            | Description               |
| ------ | ------------------- | ------------------------- |
| GET    | `/api/quick/nuclei` | Nuclei vulnerability scan |
| GET    | `/api/quick/nikto`  | Nikto web server scan     |
| GET    | `/api/quick/dns`    | DNS reconnaissance        |

### Deep Scans

| Method | Endpoint           | Description             |
| ------ | ------------------ | ----------------------- |
| GET    | `/api/deep/zap`    | OWASP ZAP baseline scan |
| GET    | `/api/deep/sslyze` | SSL/TLS analysis        |

### Security Scans

| Method | Endpoint               | Description                 |
| ------ | ---------------------- | --------------------------- |
| GET    | `/api/security/ffuf`   | Directory/file fuzzing      |
| GET    | `/api/security/sqlmap` | SQL injection scan (Docker) |

### Advanced Security

| Method | Endpoint                 | Description             |
| ------ | ------------------------ | ----------------------- |
| GET    | `/api/advanced/sqlmap`   | SQL injection detection |
| GET    | `/api/advanced/wapiti`   | Web vulnerability scan  |
| GET    | `/api/advanced/xsstrike` | XSS detection           |

### Scan Management

| Method | Endpoint                    | Description            |
| ------ | --------------------------- | ---------------------- |
| GET    | `/api/scans`                | List all scans         |
| POST   | `/api/scans/start`          | Start multi-tool scan  |
| GET    | `/api/scans/{scan_id}`      | Get scan details       |
| GET    | `/api/scans/{scan_id}/logs` | Stream scan logs (SSE) |

---

## 📝 License

MIT License - Feel free to use and modify.

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Run `make check` to validate code quality
4. Submit a pull request

---

Made with ❤️ for the security community
