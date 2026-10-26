"""Runtime status of the API and its scanner containers."""

from api.models.services import ServiceStatus
from api.services.runtime_status import list_service_statuses
from fastapi import APIRouter

router = APIRouter()


@router.get("", response_model=list[ServiceStatus])
async def read_services() -> list[ServiceStatus]:
    """State of each Docker Compose service (requires access to the Docker socket)."""
    return await list_service_statuses()
