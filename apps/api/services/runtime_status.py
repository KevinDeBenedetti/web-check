"""Runtime status of the scanner containers started by Docker Compose."""

import asyncio
from dataclasses import dataclass

import structlog
from api.models.services import ServiceState, ServiceStatus

logger = structlog.get_logger()


@dataclass(frozen=True, slots=True)
class ScannerService:
    """A scanner sidecar declared in docker-compose.yml."""

    id: str
    name: str
    role: str
    container: str
    image: str
    compose_profile: str | None = None


SCANNER_SERVICES: tuple[ScannerService, ...] = (
    ScannerService(
        "zap", "OWASP ZAP", "Dynamic analysis", "security-scanner-zap", "zaproxy/zap-stable"
    ),
    ScannerService(
        "nuclei",
        "Nuclei",
        "Known vulnerabilities",
        "security-scanner-nuclei",
        "projectdiscovery/nuclei",
    ),
    ScannerService(
        "nikto", "Nikto", "Web server configuration", "security-scanner-nikto", "alpine/nikto"
    ),
    ScannerService(
        "ffuf",
        "FFUF",
        "Forgotten files and directories",
        "security-scanner-ffuf",
        "secsi/ffuf",
        compose_profile="tools",
    ),
)


async def get_container_state(container: str, timeout: float = 5.0) -> ServiceState:
    """Return the state of a container, or "unknown" if Docker cannot be queried."""
    try:
        process = await asyncio.create_subprocess_exec(
            "docker",
            "inspect",
            "-f",
            "{{.State.Status}}",
            container,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as e:
        logger.warning("docker_cli_unavailable", container=container, error=str(e))
        return "unknown"

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        return "unknown"

    if process.returncode == 0:
        return "running" if stdout.decode().strip() == "running" else "stopped"
    if b"no such" in stderr.lower():
        return "missing"
    return "unknown"


async def list_service_statuses() -> list[ServiceStatus]:
    """Status of the API and every scanner sidecar."""
    states = await asyncio.gather(
        *(get_container_state(service.container) for service in SCANNER_SERVICES)
    )
    statuses = [
        ServiceStatus(
            id="api",
            name="Web-Check API",
            role="Scan orchestrator",
            container="web-check-api",
            state="running",
        )
    ]
    statuses += [
        ServiceStatus(
            id=service.id,
            name=service.name,
            role=service.role,
            container=service.container,
            image=service.image,
            state=state,
            compose_profile=service.compose_profile,
        )
        for service, state in zip(SCANNER_SERVICES, states, strict=True)
    ]
    return statuses
