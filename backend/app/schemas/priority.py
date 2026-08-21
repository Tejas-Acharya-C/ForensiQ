"""PriorityResult Pydantic DTO schemas."""

import uuid
from datetime import datetime
from typing import Dict, Any, Literal
from pydantic import BaseModel, Field, ConfigDict


class PriorityResultBase(BaseModel):
    target_type: Literal["ARTIFACT", "ACTIVITY"]
    target_id: uuid.UUID
    priority_score: float = Field(..., ge=0.0, le=100.0)
    priority_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    factor_breakdown: Dict[str, Any] = Field(default_factory=dict)
    explanation_text: str
    method_type: Literal["BASELINE_INDEPENDENT", "PROPOSED_CONTEXTUAL"]


class PriorityResultCreate(PriorityResultBase):
    investigation_id: uuid.UUID


class PriorityResultRead(PriorityResultBase):
    id: uuid.UUID
    investigation_id: uuid.UUID
    computed_at: datetime

    model_config = ConfigDict(from_attributes=True)
