"""Main FastAPI application for Web-Check Security Scanner."""

import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routers import advanced, deep, health, quick, scans, security

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown."""
    logger.info("Starting Web-Check Security Scanner API")
    yield
    logger.info("Shutting down Web-Check Security Scanner API")


app = FastAPI(
    title="Web-Check Security Scanner",
    description="Docker-based security scanning toolkit for web applications",
    version="0.1.0",
    lifespan=lifespan,
    redirect_slashes=False,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,  # ty: ignore[invalid-argument-type]
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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


# Include routers
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(quick.router, prefix="/api/quick", tags=["Quick Scans"])
app.include_router(deep.router, prefix="/api/deep", tags=["Deep Scans"])
app.include_router(security.router, prefix="/api/security", tags=["Security Scans"])
app.include_router(advanced.router, prefix="/api/advanced", tags=["Advanced Security"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scan Management"])


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Web-Check Security Scanner",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/api/health",
    }
