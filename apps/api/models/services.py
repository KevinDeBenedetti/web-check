"""Runtime status models for the API and its scanner containers."""

from typing import Literal

from pydantic import BaseModel, Field

ServiceState = Literal["running", "stopped", "missing", "unknown"]


class ServiceStatus(BaseModel):
    """State of one service of the Docker Compose stack."""

    id: str
    name: str
    role: str
    container: str | None = None
    image: str | None = None
    state: ServiceState = Field(
        ...,
        description="running, stopped, missing (container not created) or unknown (Docker unreachable)",
    )
    compose_profile: str | None = Field(None, description="Compose profile that starts it, if any")
