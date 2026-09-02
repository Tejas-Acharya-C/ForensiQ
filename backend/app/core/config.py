"""Core configuration module for ForensiQ."""

from functools import lru_cache
from pathlib import Path
from typing import List, Literal, Optional
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    APP_NAME: str = "ForensiQ"
    APP_ENV: Literal["development", "testing", "production"] = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    API_V1_PREFIX: str = "/api/v1"

    # Database Settings
    DATABASE_URL: str = "sqlite:///./forensiq.db"

    # Ingestion & Staging Settings
    UPLOAD_STAGING_DIR: Path = Path("data/staging")
    UPLOAD_SOURCE_DIR: Path = Path("data/sources")
    MAX_INGESTION_FILE_SIZE_MB: int = 50
    INGESTION_BATCH_SIZE: int = 10000
    CORRELATION_WINDOW_SECONDS: int = 300

    # Frontend Serving Settings (Phase 12)
    SERVE_FRONTEND: bool = True
    STATIC_DIR: Path = Path("frontend")


    # Security & Authentication Settings (Phase 9A)
    JWT_SECRET: Optional[str] = None
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours for development
    CORS_ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    ENABLE_API_DOCS: bool = True
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 10
    RATE_LIMIT_ANALYSIS_PER_MINUTE: int = 30

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Enforce strict security requirements based on environment."""
        if self.APP_ENV != "development":
            if self.DEBUG and self.APP_ENV == "production":
                raise ValueError("DEBUG mode must be FALSE in production environment.")
            if not self.JWT_SECRET or len(self.JWT_SECRET) < 32 or "dev-insecure" in self.JWT_SECRET:
                raise ValueError(
                    "JWT_SECRET must be explicitly set to a strong, high-entropy secret (>=32 chars) in non-development environments."
                )
        else:
            if not self.JWT_SECRET:
                self.JWT_SECRET = "forensiq-dev-insecure-secret-key-change-in-production-12345"
        return self

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

