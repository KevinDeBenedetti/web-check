"""Catalog endpoint: scan modules and profiles."""

from api.models.catalog import Catalog
from api.services.catalog import get_catalog
from fastapi import APIRouter

router = APIRouter()


@router.get("", response_model=Catalog)
async def read_catalog() -> Catalog:
    """List the modules and profiles that /api/scans/start accepts."""
    return get_catalog()
