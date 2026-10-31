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
        t1 = self.start_time
        t2 = self.end_time
        if t1 and t2:
            if t1.tzinfo is None and t2.tzinfo is not None:
                t1 = t1.replace(tzinfo=t2.tzinfo)
            elif t1.tzinfo is not None and t2.tzinfo is None:
                t2 = t2.replace(tzinfo=t1.tzinfo)
            if t1 > t2:
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
