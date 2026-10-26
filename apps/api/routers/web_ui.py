"""Serve the built web UI (apps/web) under /ui."""

from pathlib import Path

from api.utils.config import get_settings
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, RedirectResponse

router = APIRouter()

# apps/api/routers/web_ui.py -> apps/web/dist (repository) or /app/web/dist (Docker image)
_DEFAULT_DIST = Path(__file__).resolve().parents[2] / "web" / "dist"


def get_web_dist() -> Path | None:
    """Return the directory of the built UI, or None if it has not been built."""
    dist = get_settings().web_dist_dir or _DEFAULT_DIST
    return dist if (dist / "index.html").is_file() else None


@router.get("/ui", include_in_schema=False)
async def ui_root() -> RedirectResponse:
    """Redirect to the UI with a trailing slash so relative assets resolve."""
    return RedirectResponse(url="/ui/")


@router.get("/ui/{path:path}", include_in_schema=False)
async def serve_ui(path: str) -> FileResponse:
    """Serve a static asset, or index.html for client-side routes."""
    dist = get_web_dist()
    if dist is None:
        raise HTTPException(
            status_code=404,
            detail="Web UI is not built. Run `make web-build` or use the Docker image.",
        )

    root = dist.resolve()
    candidate = (root / path).resolve()
    if path and candidate.is_relative_to(root) and candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(root / "index.html", headers={"Cache-Control": "no-cache"})
