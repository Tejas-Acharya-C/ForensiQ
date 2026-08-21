"""Activity Pydantic DTO schemas."""

import uuid
from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, ConfigDict, model_validator


class ActivityBase(BaseModel):
    title: str = Field(..., max_length=255)
    activity_type: str = Field(..., max_length=64)
    start_time: datetime
    end_time: datetime
    status: Literal["NEW", "REVIEWING", "REVIEWED", "DISMISSED"] = "NEW"

    @model_validator(mode="after")
    def validate_time_bounds(self) -> "ActivityBase":
        if self.start_time > self.end_time:
            raise ValueError("start_time must be less than or equal to end_time")
        return self


class ActivityCreate(ActivityBase):
    investigation_id: uuid.UUID
    evidence_ids: List[uuid.UUID] = Field(default_factory=list)
    finding_ids: List[uuid.UUID] = Field(default_factory=list)


class ActivityRead(ActivityBase):
    id: uuid.UUID
    investigation_id: uuid.UUID
    description: Optional[str] = None
    evidence_count: int
    finding_count: int
    evidence_ids: List[uuid.UUID] = Field(default_factory=list)
    finding_ids: List[uuid.UUID] = Field(default_factory=list)
    context_attributes: dict = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)
