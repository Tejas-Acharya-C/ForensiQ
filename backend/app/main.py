"""FastAPI application entrypoint for ForensiQ (Phase 9A Security Hardened)."""

import re
import time
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import api_v1_router
from app.core.config import get_settings
from app.core.errors import (
    ForensiQException,
    forensiq_exception_handler,
    generic_exception_handler,
)
from app.core.logging import get_logger, setup_logging

logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for clean startup and shutdown."""
    settings = get_settings()
    setup_logging(log_level=settings.LOG_LEVEL)
    logger.info(f"Starting {settings.APP_NAME} in [{settings.APP_ENV}] mode...")
    yield
    logger.info(f"Shutting down {settings.APP_NAME}...")


def create_app() -> FastAPI:
    """FastAPI application factory with security headers, CORS, and conditional docs."""
    settings = get_settings()

    # Determine docs URLs based on configuration
    docs_url = "/docs" if settings.ENABLE_API_DOCS else None
    redoc_url = "/redoc" if settings.ENABLE_API_DOCS else None
    openapi_url = "/openapi.json" if settings.ENABLE_API_DOCS else None

    app = FastAPI(
        title=settings.APP_NAME,
        description="AI-Assisted Digital Forensic Triage and Evidence Prioritization Platform",
        version="0.1.0",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )

    # Configuration-driven CORS Middleware (no wildcards)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "Accept"],
    )

    # Request ID and Security Headers Middleware
    @app.middleware("http")
    async def security_and_request_middleware(request: Request, call_next):
        # Validate incoming client request ID or generate high-entropy server UUID
        client_req_id = request.headers.get("X-Request-ID")
        if client_req_id and len(client_req_id) <= 64 and re.match(r"^[a-zA-Z0-9_-]+$", client_req_id):
            request_id = client_req_id
        else:
            request_id = str(uuid.uuid4())

        start_time = time.perf_counter()
        request.state.request_id = request_id

        response: Response = await call_next(request)

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Standard Security & Timing Headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time-MS"] = str(duration_ms)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"

        return response

    # Exception Handlers
    app.add_exception_handler(ForensiQException, forensiq_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)

    # Register API Routers
    app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

    # Conditionally Mount Frontend Static Files (Phase 12 Production Serving)
    if settings.SERVE_FRONTEND and settings.STATIC_DIR.exists():
        from fastapi.staticfiles import StaticFiles
        app.mount(
            "/",
            StaticFiles(directory=str(settings.STATIC_DIR), html=True),
            name="frontend",
        )

    return app


app = create_app()

