"""Relationship Pydantic DTO schemas."""

import uuid
from typing import Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class RelationshipBase(BaseModel):
    relationship_type: str = Field(..., max_length=64)
    weight: float = Field(1.0, ge=0.0)
    context_attributes: Dict[str, Any] = Field(default_factory=dict)


class RelationshipCreate(RelationshipBase):
    investigation_id: uuid.UUID
    source_evidence_id: uuid.UUID
    target_evidence_id: uuid.UUID


class RelationshipRead(RelationshipBase):
    id: uuid.UUID
    investigation_id: uuid.UUID
    source_evidence_id: uuid.UUID
    target_evidence_id: uuid.UUID

    model_config = ConfigDict(from_attributes=True)
