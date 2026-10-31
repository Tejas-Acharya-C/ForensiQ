"""Finding Pydantic DTO schemas."""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field, ConfigDict


class FindingBase(BaseModel):
    finding_type: str = Field(..., description="RULE_MATCH, IOC_MATCH, or ML_ANOMALY")
    rule_id: Optional[str] = Field(None, max_length=128)
    severity: float = Field(..., ge=0.0, le=1.0)
    description: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def severity_score(self) -> float:
        return self.severity


class FindingCreate(FindingBase):
    investigation_id: uuid.UUID
    evidence_ids: List[uuid.UUID] = Field(default_factory=list, description="Supporting evidence IDs")

    def __init__(self, **data: Any):
        if "severity_score" in data and "severity" not in data:
            data["severity"] = data.pop("severity_score")
        super().__init__(**data)


class FindingResponse(FindingBase):
    id: uuid.UUID
    investigation_id: uuid.UUID
    created_at: datetime
    evidence_ids: List[uuid.UUID] = Field(default_factory=list, description="Supporting evidence IDs")

    model_config = ConfigDict(from_attributes=True)


FindingRead = FindingResponse
