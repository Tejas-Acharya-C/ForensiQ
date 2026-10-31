"""Core configuration module for ForensiQ.

Strictly enforces external, isolated application-data storage outside the
repository root to prevent any accidental collision or mutation of protected
databases or production evidence.
"""

import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import List, Literal
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]


def get_default_app_data_dir() -> Path:
    """Resolve the authoritative user-local application-data directory.

    On Windows: %LOCALAPPDATA%\\ForensiQ
    On Linux/macOS: $XDG_DATA_HOME/forensiq or ~/.local/share/forensiq
    """
    override = os.environ.get("FORENSIQ_APP_DATA_DIR")
    if override:
        return Path(override).resolve()

    if sys.platform == "win32":
        local_app = os.environ.get("LOCALAPPDATA")
        if local_app:
            return (Path(local_app) / "ForensiQ").resolve()
        return (Path.home() / "AppData" / "Local" / "ForensiQ").resolve()

    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        return (Path(xdg_data) / "forensiq").resolve()
    return (Path.home() / ".local" / "share" / "forensiq").resolve()


def get_default_database_url() -> str:
    """Construct an absolute SQLite URL targeting the isolated external database."""
    base_dir = get_default_app_data_dir()
    db_path = (base_dir / "database" / "forensiq.db").resolve()
    posix_path = db_path.as_posix()
    if not posix_path.startswith("/"):
        posix_path = f"/{posix_path}"
    return f"sqlite://{posix_path}"


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    APP_NAME: str = "ForensiQ"
    APP_ENV: Literal["development", "testing", "production"] = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    API_V1_PREFIX: str = "/api/v1"

    # Base application storage directory (external to repository)
    DATA_DIR: Path = get_default_app_data_dir()

    # Database Settings — default is resolved absolute external path
    DATABASE_URL: str = get_default_database_url()

    # Ingestion & Staging Settings — defaulted to isolated external subdirectories
    UPLOAD_STAGING_DIR: Path = get_default_app_data_dir() / "staging"
    UPLOAD_SOURCE_DIR: Path = get_default_app_data_dir() / "sources"
    REPORT_DIR: Path = get_default_app_data_dir() / "reports"
    LOG_DIR: Path = get_default_app_data_dir() / "logs"

    MAX_INGESTION_FILE_SIZE_MB: int = 50
    INGESTION_BATCH_SIZE: int = 10000
    CORRELATION_WINDOW_SECONDS: int = 300

    # Frontend Serving Settings
    SERVE_FRONTEND: bool = True
    STATIC_DIR: Path = REPO_ROOT / "frontend"

    # API and rate-limiting settings
    CORS_ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    ENABLE_API_DOCS: bool = True
    RATE_LIMIT_ANALYSIS_PER_MINUTE: int = 30

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("DATABASE_URL must be a non-empty string.")
        stripped = v.strip()
        # Reject dangerous relative paths like sqlite:///./forensiq.db
        if stripped.startswith("sqlite:///./") or stripped == "sqlite:///forensiq.db":
            raise ValueError(
                f"Unsafe repository-relative database URL '{v}' is prohibited. "
                "Use an explicit absolute path or configure FORENSIQ_APP_DATA_DIR."
            )
        return stripped

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()
