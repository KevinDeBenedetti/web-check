"""Health check endpoints."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    """Check API health status."""
    return {"status": "healthy", "service": "vigil-scanner"}


@router.get("/ready")
async def readiness_check():
    """Check if API is ready to accept requests."""
    # TODO: Check Docker containers are running
    return {"status": "ready"}
