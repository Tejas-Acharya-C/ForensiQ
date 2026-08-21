"""Database engine configuration, session factories, and dependency injection."""

import uuid
from typing import Generator
from sqlalchemy import create_engine, Uuid, JSON, event
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import get_settings

# Universal dialect-aware types
GUID_TYPE = Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql")
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Ensure SQLite enforces foreign key constraints on every connection."""
    # Check if connection is from sqlite3 driver
    if dbapi_connection.__class__.__module__.startswith("sqlite3"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def create_db_engine() -> Engine:
    """Create and configure the SQLAlchemy database engine."""
    settings = get_settings()
    is_sqlite = settings.DATABASE_URL.startswith("sqlite")

    connect_args = {"check_same_thread": False} if is_sqlite else {}

    return create_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG and settings.APP_ENV == "development",
        connect_args=connect_args,
        pool_pre_ping=True,
    )


engine: Engine = create_db_engine()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for yielding database session with automatic cleanup."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
