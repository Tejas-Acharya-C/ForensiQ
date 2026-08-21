#!/usr/bin/env python3
"""Database connectivity verification script for ForensiQ."""

import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from sqlalchemy import text
from app.core.config import get_settings
from app.core.logging import get_logger, setup_logging
from app.database.session import engine


def check_db() -> bool:
    settings = get_settings()
    setup_logging(log_level=settings.LOG_LEVEL)
    logger = get_logger("db_check")

    logger.info(f"Testing database connection to: {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL}")

    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1 AS alive")).scalar()
            if result == 1:
                logger.info("[SUCCESS] Database connection established and verified.")
                return True
            else:
                logger.error("[FAILURE] Unexpected query result from database.")
                return False
    except Exception as exc:
        logger.error(f"[ERROR] Database connection failed: {exc}")
        return False


if __name__ == "__main__":
    success = check_db()
    sys.exit(0 if success else 1)
