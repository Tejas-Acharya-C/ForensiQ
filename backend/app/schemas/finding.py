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


# ---------------------------------------------------------------------------
# Phase 2: Finding Explanation & Traceability Schemas
# ---------------------------------------------------------------------------

class ConditionMatchDetail(BaseModel):
    """Detailed breakdown of a single rule condition evaluation."""
    field: str
    operator: str
    expected_value: Any
    actual_value: Optional[Any] = None
    matched: bool = True


class SequenceStepDetail(BaseModel):
    """Detailed breakdown of a satisfied step in a sequence detection rule."""
    step_index: int
    event_type: Optional[str] = None
    status: Optional[str] = None
    conditions: List[ConditionMatchDetail] = Field(default_factory=list)
    evidence_id: Optional[uuid.UUID] = None
    timestamp: Optional[datetime] = None
    matched: bool = True


class DetectionExplanation(BaseModel):
    """Complete, transparent explanation of why a finding was detected."""
    category: str = Field(..., description="RULE_BASED, SEQUENCE, IOC, ISOLATION_FOREST, or UNKNOWN")
    summary: str
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    rule_description: Optional[str] = None
    rule_version: Optional[str] = None
    matched_conditions: List[ConditionMatchDetail] = Field(default_factory=list)
    matched_attributes: Dict[str, Any] = Field(default_factory=dict)

    # Sequence detection specifics
    sequence_group_by: Optional[str] = None
    sequence_group_value: Optional[str] = None
    max_span_seconds: Optional[int] = None
    actual_span_seconds: Optional[float] = None
    sequence_steps: List[SequenceStepDetail] = Field(default_factory=list)

    # IOC specifics
    indicator_type: Optional[str] = None
    matched_value: Optional[str] = None
    indicator_source: Optional[str] = None
    context_note: Optional[str] = None

    # ML Isolation Forest specifics
    model_name: Optional[str] = None
    anomaly_score: Optional[float] = None
    threshold: Optional[float] = None
    is_anomaly: Optional[bool] = None
    features_evaluated: List[Dict[str, Any]] = Field(default_factory=list)
    ml_note: Optional[str] = None


class EvidenceTraceItem(BaseModel):
    """Supporting evidence record details with source and integrity metadata."""
    id: uuid.UUID
    source_id: uuid.UUID
    source_name: str
    event_type: str
    source_type: str
    timestamp: datetime
    raw_record_offset: int
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    parent_process_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    sha256_hash: Optional[str] = None
    file_size_bytes: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)


class ActivityTraceItem(BaseModel):
    """Correlated activity details connected to this finding."""
    id: uuid.UUID
    title: str
    activity_type: str
    description: Optional[str] = None
    evidence_count: int = 0
    finding_count: int = 0
    start_time: datetime
    end_time: datetime
    status: str = "NEW"
    shared_entities: Dict[str, List[str]] = Field(default_factory=dict)
    associated_evidence_ids: List[uuid.UUID] = Field(default_factory=list)
    correlation_reasons: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class PriorityFactorDetail(BaseModel):
    """Individual contributing factor to a prioritization score."""
    name: str
    weight: float
    normalized_value: float
    contribution: float
    description: str


class PriorityTraceDetail(BaseModel):
    """Detailed reproduction of prioritization scoring and factor breakdown."""
    has_priority: bool
    priority_tier: str
    priority_score: Optional[float] = None
    priority_source: str = Field(..., description="ACTIVITY, ARTIFACT, or SEVERITY_FALLBACK")
    method_type: Optional[str] = None
    target_id: Optional[uuid.UUID] = None
    target_type: Optional[str] = None
    explanation_text: str = ""
    factors: List[PriorityFactorDetail] = Field(default_factory=list)
    calculated_total: Optional[float] = None
    fallback_reason: Optional[str] = None


class InvestigationChainNode(BaseModel):
    """Single node in the visual investigation traceability chain."""
    node_type: str = Field(..., description="EVIDENCE, FINDING, ACTIVITY, or PRIORITY")
    id: Optional[str] = None
    label: str
    sublabel: Optional[str] = None
    status_or_tier: Optional[str] = None


class FindingExplanation(BaseModel):
    """Composite explanation bundle for forensic finding investigation view."""
    detection: DetectionExplanation
    evidence: List[EvidenceTraceItem] = Field(default_factory=list)
    activities: List[ActivityTraceItem] = Field(default_factory=list)
    priority: PriorityTraceDetail
    secondary_priorities: List[PriorityTraceDetail] = Field(default_factory=list)
    investigation_chain: List[InvestigationChainNode] = Field(default_factory=list)


class FindingResponse(FindingBase):
    id: uuid.UUID
    investigation_id: uuid.UUID
    created_at: datetime
    evidence_ids: List[uuid.UUID] = Field(default_factory=list, description="Supporting evidence IDs")
    title: Optional[str] = None
    rule_name: Optional[str] = None
    detection_method: Optional[str] = None
    evidence_count: int = 0
    activity_ids: List[uuid.UUID] = Field(default_factory=list, description="Related activity IDs")
    activity_id: Optional[uuid.UUID] = None
    priority_score: Optional[float] = None
    priority_tier: Optional[str] = None
    priority_source: Optional[str] = Field(None, description="ACTIVITY, ARTIFACT, or SEVERITY_FALLBACK")
    review_status: str = Field(default="NEW", description="Investigator review triage status: NEW, REVIEWED, FALSE_POSITIVE, ESCALATED")
    reviewed_at: Optional[datetime] = Field(None, description="Timestamp of when finding review decision was made or updated")
    review_notes: Optional[str] = Field(None, description="Investigator notes associated with review decision")
    explanation: Optional[FindingExplanation] = Field(None, description="Detailed explanation and traceability data (Phase 2)")

    model_config = ConfigDict(from_attributes=True)


class FindingDetailResponse(FindingResponse):
    """Extended finding response with guaranteed explanation payload."""
    pass


FindingRead = FindingResponse
