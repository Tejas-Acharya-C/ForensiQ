"""EvidenceSource Pydantic DTO schemas."""

import uuid
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator


class EvidenceSourceBase(BaseModel):
    filename: str = Field(..., max_length=255)
    file_format: str = Field(..., max_length=32)
    sha256_hash: str = Field(..., min_length=64, max_length=64)
    file_size_bytes: int = Field(0, ge=0)
    total_records: int = Field(0, ge=0)
    ingestion_status: Literal["PENDING", "PROCESSING", "COMPLETED", "FAILED"] = "PENDING"

    @field_validator("sha256_hash")
    @classmethod
    def validate_sha256_hex(cls, v: str) -> str:
        if not all(c in "0123456789abcdefABCDEF" for c in v):
            raise ValueError("sha256_hash must be a valid 64-character hexadecimal string")
        return v.lower()


class EvidenceSourceCreate(EvidenceSourceBase):
    investigation_id: uuid.UUID


class EvidenceSourceRead(EvidenceSourceBase):
    id: uuid.UUID
    investigation_id: uuid.UUID
    ingested_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SourceIntegrityResult(BaseModel):
    """Result of verifying stored evidence source file bytes against recorded ingestion digest."""
    source_id: uuid.UUID
    investigation_id: uuid.UUID
    filename: str
    recorded_sha256: str
    computed_sha256: str | None = None
    status: Literal["VERIFIED", "INTEGRITY_MISMATCH", "VERIFICATION_UNAVAILABLE", "MALFORMED_DIGEST"]
    verified_at: datetime
    message: str
    disclaimer: str = (
        "Cryptographic SHA-256 integrity verification confirms bit-level match against "
        "the digest recorded at ingestion; it does not claim legal chain of custody or evidence authenticity."
    )
