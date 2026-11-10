"""Investigation Pydantic DTO schemas."""

import uuid
from datetime import datetime
from typing import Optional, Literal, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator
from app.schemas.priority import PriorityResultRead


class InvestigationBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255, description="Investigation title")
    description: Optional[str] = Field(None, description="Detailed case notes or context")
    case_number: str = Field(..., min_length=1, max_length=64, description="Unique case reference identifier")
    status: Literal["OPEN", "CLOSED", "ARCHIVED"] = Field("OPEN", description="Investigation status")
    investigator_notes: Optional[str] = Field(None, max_length=20000, description="Investigator commentary and conclusion notes")

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Investigation title cannot be empty or purely whitespace.")
        return s

    @field_validator("case_number")
    @classmethod
    def validate_case_number(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Case number cannot be empty or purely whitespace.")
        return s


class InvestigationCreate(InvestigationBase):
    pass


class InvestigationUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    status: Optional[Literal["OPEN", "CLOSED", "ARCHIVED"]] = None
    investigator_notes: Optional[str] = Field(None, max_length=20000)


class InvestigationNotesUpdate(BaseModel):
    notes: Optional[str] = Field(None, max_length=20000, description="Investigator notes or commentary")


class InvestigationNotesRead(BaseModel):
    investigation_id: uuid.UUID
    notes: Optional[str] = None
    updated_at: datetime


class ChecklistItemRead(BaseModel):
    key: str
    label: str
    category: Literal["REQUIRED_OPERATION", "OPTIONAL_INVESTIGATION", "INFORMATIONAL"]
    status: Literal["COMPLETE", "INCOMPLETE", "ATTENTION"]
    description: str
    action_tab: Optional[str] = None
    action_label: Optional[str] = None


class InvestigationChecklistRead(BaseModel):
    investigation_id: uuid.UUID
    case_number: str
    items: List[ChecklistItemRead]
    completed_required_count: int
    total_required_count: int
    summary_text: str


class InvestigationRead(InvestigationBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SourceHealthSummary(BaseModel):
    id: uuid.UUID
    filename: str
    file_format: str
    sha256_hash: str
    file_size_bytes: int
    total_records: int
    normalized_records: int
    ingestion_status: str
    ingested_at: datetime


class PriorityTierCounts(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFORMATIONAL: int = 0


class FindingTypeCounts(BaseModel):
    RULE_MATCH: int = 0
    IOC_MATCH: int = 0
    ML_ANOMALY: int = 0


class InvestigationSummaryRead(BaseModel):
    """Unified Dashboard Aggregation Schema."""
    investigation: InvestigationRead
    owner_email: Optional[str] = None   # always None without auth; kept for schema compat
    total_sources: int = 0
    total_evidence: int = 0
    total_findings: int = 0
    total_anomalies: int = 0
    total_relationships: int = 0
    total_activities: int = 0
    total_priority_results: int = 0
    finding_counts: FindingTypeCounts = Field(default_factory=FindingTypeCounts)
    priority_tier_counts: PriorityTierCounts = Field(default_factory=PriorityTierCounts)
    top_priority_results: List[PriorityResultRead] = Field(default_factory=list)
    sources: List[SourceHealthSummary] = Field(default_factory=list)
    pipeline_status: Dict[str, Any] = Field(default_factory=dict)
