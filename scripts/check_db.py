#!/usr/bin/env python3
"""Database connectivity verification script for ForensiQ."""

import sys
import os
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from sqlalchemy import text
from sqlalchemy.engine import make_url

from app.core.config import get_settings
from app.core.logging import get_logger, setup_logging


def check_db() -> int:
    try:
        settings = get_settings()
        database_url = make_url(settings.DATABASE_URL)
    except Exception as exc:
        print(f"[ERROR] Invalid database configuration: {exc}", file=sys.stderr)
        return 1

    setup_logging(log_level=settings.LOG_LEVEL)
    logger = get_logger("db_check")

    logger.info(
        "Testing database connection to: %s",
        database_url.render_as_string(hide_password=True),
    )

    if database_url.get_backend_name() == "sqlite":
        database_name = database_url.database
        if not database_name or database_name == ":memory:":
            logger.error(
                "A file-backed SQLite database is required for application startup."
            )
            return 1

        database_path = Path(database_name)
        if not database_path.is_absolute():
            logger.error(
                "SQLite DATABASE_URL must resolve to an absolute path; "
                "relative database paths are not checked or created."
            )
            return 1
        if not database_path.exists():
            if not database_path.parent.is_dir():
                logger.error(
                    "SQLite database directory does not exist: %s. "
                    "No directory or database was created.",
                    database_path.parent,
                )
                return 1
            logger.error(
                "Configured SQLite database does not exist: %s. "
                "No database was created.",
                database_path,
            )
            return 2
        if not database_path.is_file():
            logger.error("Configured SQLite database is not a file: %s", database_path)
            return 1

    try:
        from app.database.session import engine

        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1 AS alive")).scalar()
            if result == 1:
                logger.info("[SUCCESS] Database connection established and verified.")
                return 0
            else:
                logger.error("[FAILURE] Unexpected query result from database.")
                return 1
    except Exception as exc:
        logger.error(f"[ERROR] Database connection failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(check_db())
