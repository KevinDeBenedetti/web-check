# GitHub Copilot Instructions

This repository is **Vigil**, a Docker-based security scanning toolkit.

## Context

- **Language**: Python 3.11+
- **Framework**: FastAPI 0.115+ avec Uvicorn
- **Architecture**: Docker-first avec docker-compose
- **Purpose**: Analyse de sécurité web et scans de vulnérabilités
- **Database**: SQLAlchemy 2.0 + Alembic + SQLite (async)
- **Logging**: structlog pour logs structurés
- **HTTP**: httpx pour requêtes async
- **Tooling**: Ruff (linting/formatting), Pyright (type checking), Pytest (testing)

## Code Style

- Use **type hints** sur toutes les fonctions (obligatoire)
- Use **Pydantic v2** pour validation et settings
- Use **async/await** pour toutes les opérations I/O
- Follow **PEP 8** avec max line length **100**
- Use **Google-style docstrings**
- Use **datetime.now(UTC)** au lieu de `datetime.utcnow()` (deprecated)
- Use **structlog** pour tous les logs, jamais `print()`
- Use **httpx.AsyncClient** au lieu de requests
- Use **type aliases** pour Literal types (ex: `Severity`, `ScanStatus`)

## Patterns to Follow

### API Endpoints
```python
@router.get("/scan", response_model=CheckResult)
async def perform_scan(
    url: str = Query(..., description="Target URL to scan"),
    timeout: int = Query(300, ge=30, le=600, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run security scan on target URL.

    Average duration: 2-5 minutes.
    """
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    return await run_scan(url, timeout)
```

### Service Functions
```python
async def run_scanner(target: str, timeout: int = 300) -> CheckResult:
    """
    Run scanner against a target.

    Args:
        target: URL or domain to scan
        timeout: Timeout in seconds

    Returns:
        CheckResult with findings
    """
    start = time.time()
    findings: list[Finding] = []

    try:
        result = await docker_run(
            image="scanner/image:latest",
            command=["--target", target],
            timeout=timeout,
            container_name="security-scanner-tool",
        )

        if result["timeout"]:
            return CheckResult(
                module="scanner",
                category="quick",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="timeout",
                data=None,
                findings=[],
                error="Scan timed out",
            )

        findings = _parse_output(result["stdout"])

        logger.info(
            "scan_completed",
            target=target,
            findings_count=len(findings),
        )

        return CheckResult(
            module="scanner",
            category="quick",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"findings_count": len(findings)},
            findings=findings,
            error=None,
        )

    except Exception as e:
        logger.error("scan_failed", target=target, error=str(e))
        return CheckResult(
            module="scanner",
            category="quick",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=str(e),
        )
```

### Docker Container Execution
```python
async def docker_run(
    image: str,
    command: list[str],
    volumes: dict[str, str] | None = None,
    timeout: int = 300,
    container_name: str | None = None,
    network: str | None = None,
) -> dict[str, Any]:
    """Run Docker container and return results."""
    if container_name:
        # Use existing container with docker exec
        cmd = ["docker", "exec", container_name] + command
    else:
        # Run new container
        cmd = ["docker", "run", "--rm"]
        if volumes:
            for host_path, container_path in volumes.items():
                cmd.extend(["-v", f"{host_path}:{container_path}"])
        if network:
            cmd.extend(["--network", network])
        cmd.append(image)
        cmd.extend(command)

    logger.info("running_docker_command", command=" ".join(cmd))
    # ... implementation
```

## Key Models

### Finding Model
```python
from typing import Literal
from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]

class Finding(BaseModel):
    """Security finding from a scan."""
    severity: Severity = Field(..., description="Severity level")
    title: str = Field(..., description="Short title")
    description: str = Field(..., description="Detailed description")
    reference: str | None = Field(None, description="URL or reference")
    cve: str | None = Field(None, description="CVE identifier if applicable")
    cvss_score: float | None = Field(None, ge=0.0, le=10.0, description="CVSS score")
```

### CheckResult Model
```python
from datetime import UTC, datetime

ScanStatus = Literal["success", "error", "timeout", "running"]
ScanCategory = Literal["quick", "deep", "security"]

class CheckResult(BaseModel):
    """Result from a security check."""
    module: str = Field(..., description="Name of the scanning module")
    category: ScanCategory = Field(..., description="Category of the scan")
    target: str = Field(..., description="Target URL or domain")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When the scan was performed",
    )
    duration_ms: int = Field(..., ge=0, description="Scan duration in milliseconds")
    status: ScanStatus = Field(..., description="Status of the scan")
    data: dict[str, Any] | None = Field(None, description="Raw scan data and metadata")
    findings: list[Finding] = Field(default_factory=list, description="Security findings")
    error: str | None = Field(None, description="Error message if scan failed")
```

## File Organization

```
api/
├── main.py              # FastAPI app, middleware, lifespan
├── database.py          # SQLAlchemy setup
├── routers/             # FastAPI route handlers
│   ├── health.py        # Health check endpoint
│   ├── quick.py         # Quick scans (nuclei, nikto, dns)
│   ├── deep.py          # Deep analysis
│   ├── security.py      # Security-focused scans
│   └── scans.py         # Scan management (CRUD)
├── services/            # Business logic
│   ├── nikto.py         # Nikto scanner service
│   ├── nuclei.py        # Nuclei scanner service
│   ├── zap.py           # OWASP ZAP service
│   ├── docker_runner.py # Docker execution utilities
│   └── db_service.py    # Database operations
├── models/              # Pydantic models
│   ├── findings.py      # Finding, Severity types
│   ├── results.py       # CheckResult, ScanStatus types
│   └── db_models.py     # SQLAlchemy models
└── utils/
    └── config.py        # Settings avec pydantic-settings

alembic/                 # Database migrations
scripts/                 # Shell scripts for reporting
outputs/                 # Scan outputs (HTML, JSON)
```

## Configuration

Settings via `pydantic-settings`:

```python
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

class Settings(BaseSettings):
    """Application settings."""
    api_title: str = "Vigil Security Scanner"
    api_version: str = "0.1.0"
    debug: bool = False
    docker_network: str = "scanner-net"
    output_base_dir: Path = Path("outputs")
    default_timeout: int = 300
    max_timeout: int = 3600
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

@lru_cache
def get_settings() -> Settings:
    return Settings()
```

## Logging

Use structlog with structured logs:

```python
import structlog

logger = structlog.get_logger()

# Good
logger.info("scan_completed", target=url, findings_count=len(findings))
logger.error("scan_failed", target=url, error=str(e))

# Bad
logger.info(f"Scan completed for {url}")  # ❌ No string formatting
print("Scan completed")                    # ❌ Never use print()
```

## Database

SQLAlchemy 2.0 avec async SQLite:

```python
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase

engine = create_async_engine("sqlite+aiosqlite:///./vigil.db")

class Base(DeclarativeBase):
    pass

# Dans les services
async def create_scan(db: AsyncSession, scan_data: dict):
    scan = Scan(**scan_data)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan
```

## Scanner Modules Actuels

1. **Nuclei** (`api/services/nuclei.py`)
   - Image: `projectdiscovery/nuclei:latest`
   - Scan rapide CVE et vulnérabilités
   - Timeout: 300s par défaut

2. **Nikto** (`api/services/nikto.py`)
   - Image: `alpine/nikto:latest`
   - Scan web server misconfigurations
   - Output HTML dans `/outputs/`
   - Timeout: 600s par défaut

3. **OWASP ZAP** (`api/services/zap.py`)
   - Image: `zaproxy/zap-stable`
   - Scan sécurité complet
   - Timeout: 900s par défaut

## Don'ts

- ❌ Don't use `requests` - use `httpx.AsyncClient`
- ❌ Don't use `datetime.utcnow()` - use `datetime.now(UTC)`
- ❌ Don't block event loop - use async throughout
- ❌ Don't hardcode timeouts/paths - use Settings
- ❌ Don't ignore errors - always return CheckResult with error field
- ❌ Don't use `print()` - use `structlog.get_logger()`
- ❌ Don't use bare Exception - catch specific exceptions
- ❌ Don't forget type hints - they're mandatory
- ❌ Don't use `default_factory=lambda: []` - use `default_factory=list`

## Testing

```python
import pytest
from httpx import AsyncClient
from api.main import app

@pytest.mark.asyncio
async def test_nuclei_scan():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get(
            "/api/quick/nuclei",
            params={"url": "https://example.com", "timeout": 300}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "nuclei"
        assert data["status"] in ["success", "error", "timeout"]
```

## Commit Messages

Use conventional commits:
- `feat:` - Nouvelle fonctionnalité
- `fix:` - Correction de bug
- `docs:` - Documentation
- `refactor:` - Refactoring sans changement de comportement
- `test:` - Ajout/modification de tests
- `chore:` - Tâches de maintenance