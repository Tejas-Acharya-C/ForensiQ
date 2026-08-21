"""Evidence Pydantic DTO schemas (Common Evidence Schema)."""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class EvidenceBase(BaseModel):
    raw_record_offset: int = Field(0, ge=0)
    timestamp: datetime
    event_type: str = Field(..., max_length=64)
    source_type: str = Field(..., max_length=32)

    user_id: Optional[str] = Field(None, max_length=128)
    device_id: Optional[str] = Field(None, max_length=128)
    session_id: Optional[str] = Field(None, max_length=128)

    process_id: Optional[int] = None
    process_name: Optional[str] = Field(None, max_length=255)
    parent_process_name: Optional[str] = Field(None, max_length=255)

    file_path: Optional[str] = None
    file_hash: Optional[str] = Field(None, max_length=64)

    ip_address: Optional[str] = Field(None, max_length=45)
    port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = Field(None, max_length=16)

    action: Optional[str] = Field(None, max_length=64)
    status: Optional[str] = Field(None, max_length=32)

    attributes: Dict[str, Any] = Field(default_factory=dict)


class EvidenceCreate(EvidenceBase):
    investigation_id: uuid.UUID
    source_id: uuid.UUID


class EvidenceRead(EvidenceBase):
    id: uuid.UUID
    investigation_id: uuid.UUID
    source_id: uuid.UUID
    normalized_at: datetime

    model_config = ConfigDict(from_attributes=True)
