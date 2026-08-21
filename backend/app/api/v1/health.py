"""Health check endpoint controller."""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.session import get_db
from app.schemas.health import HealthResponse

router = APIRouter(tags=["Health"])
logger = get_logger("health")


@router.get("/health", response_model=HealthResponse, summary="Application, Database, and Storage Health Check")
def health_check(db: Session = Depends(get_db)) -> HealthResponse:
    """Verify application health, database connectivity, and persistent evidence storage accessibility."""
    settings = get_settings()

    db_status = "connected"
    try:
        # Execute lightweight database ping
        db.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error(f"Database health check failed: {exc}")
        db_status = "unreachable"

    # Verify evidence storage directory accessibility
    storage_status = "healthy"
    try:
        source_dir = settings.UPLOAD_SOURCE_DIR
        source_dir.mkdir(parents=True, exist_ok=True)
        # Test read/write
        test_probe = source_dir / ".health_probe"
        test_probe.write_text("ok", encoding="utf-8")
        test_probe.unlink(missing_ok=True)
    except Exception as exc:
        logger.error(f"Storage health check failed for path {settings.UPLOAD_SOURCE_DIR}: {exc}")
        storage_status = "unreachable"

    if db_status == "connected" and storage_status == "healthy":
        overall_status = "healthy"
    elif db_status == "connected" or storage_status == "healthy":
        overall_status = "degraded"
    else:
        overall_status = "unhealthy"

    return HealthResponse(
        status=overall_status,
        app_name=settings.APP_NAME,
        environment=settings.APP_ENV,
        database_status=db_status,
        storage_status=storage_status,
        version="0.1.0",
    )

