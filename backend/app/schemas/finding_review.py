"""FindingReview Pydantic DTO schemas."""

import uuid
from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, Field, ConfigDict

ReviewStatus = Literal["NEW", "REVIEWED", "FALSE_POSITIVE", "ESCALATED"]


class FindingReviewBase(BaseModel):
    status: ReviewStatus = Field(default="NEW", description="Investigator review triage decision")
    notes: Optional[str] = Field(None, max_length=5000, description="Optional investigative notes or justification")


class FindingReviewUpdate(BaseModel):
    investigation_id: uuid.UUID = Field(..., description="Investigation ID scoping this review decision")
    status: Optional[ReviewStatus] = Field(None, description="Investigator review triage decision")
    notes: Optional[str] = Field(None, max_length=5000, description="Optional investigative notes or justification")


class FindingReviewRead(FindingReviewBase):
    id: uuid.UUID
    investigation_id: uuid.UUID
    finding_id: uuid.UUID
    reviewed_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

