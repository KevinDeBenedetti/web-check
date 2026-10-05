"""Main FastAPI application for Web-Check Security Scanner."""

import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from api.database import Base, engine
from api.routers import advanced, deep, health, quick, scans, security
from api.utils.config import get_settings
from api.utils.security import require_api_key
from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logger = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown."""
    logger.info("Starting Web-Check Security Scanner API")
    if not settings.api_key or not settings.api_key.get_secret_value():
        logger.warning(
            "api_key_not_configured",
            message="API_KEY is not set: scan endpoints are unauthenticated. "
            "Do not expose this API beyond localhost.",
        )
    if settings.allow_private_targets:
        logger.warning("private_targets_allowed", message="ALLOW_PRIVATE_TARGETS is enabled")

    # Create database tables if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")

    yield
    logger.info("Shutting down Web-Check Security Scanner API")


app = FastAPI(
    title="Web-Check Security Scanner",
    description="Docker-based security scanning toolkit for web applications",
    version="0.1.0",
    lifespan=lifespan,
    redirect_slashes=False,
)

# CORS middleware — only enabled for explicitly configured origins.
# Auth uses the X-API-Key header (not cookies), so credentials are never allowed.
if cors_origins := settings.get_cors_origins():
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key"],
    )


@app.middleware("http")
async def log_requests(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    start_time = time.time()

    response = await call_next(request)

    duration = (time.time() - start_time) * 1000
    logger.info(
        "http_request",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=int(duration),
    )

    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions."""
    logger.error("unhandled_exception", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if app.debug else "An unexpected error occurred",
        },
    )


# Include routers — everything except health checks requires the API key (if configured)
auth = [Depends(require_api_key)]
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(quick.router, prefix="/api/quick", tags=["Quick Scans"], dependencies=auth)
app.include_router(deep.router, prefix="/api/deep", tags=["Deep Scans"], dependencies=auth)
app.include_router(
    security.router, prefix="/api/security", tags=["Security Scans"], dependencies=auth
)
app.include_router(
    advanced.router, prefix="/api/advanced", tags=["Advanced Security"], dependencies=auth
)
app.include_router(scans.router, prefix="/api/scans", tags=["Scan Management"], dependencies=auth)


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Web-Check Security Scanner",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/api/health",
    }
