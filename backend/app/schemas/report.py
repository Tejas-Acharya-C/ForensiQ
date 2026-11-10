"""Report preflight, configuration, and audit DTO schemas."""

import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class ReportSectionInfo(BaseModel):
    key: str
    label: str
    available: bool
    item_count: int = 0
    description: str


class ReportFindingsSummary(BaseModel):
    total_findings: int = 0
    included_findings: int = 0
    by_priority_tier: Dict[str, int] = Field(default_factory=dict)
    by_review_status: Dict[str, int] = Field(default_factory=dict)


class ReportEvidenceSummary(BaseModel):
    total_sources: int = 0
    total_evidence_records: int = 0
    referenced_evidence_count: int = 0


class ReportIntegrityStatus(BaseModel):
    has_sha256_hashes: bool = False
    total_sources: int = 0
    sources_with_hash: int = 0
    integrity_wording: str = (
        "SHA-256 digests record raw evidence content integrity at ingestion time. "
        "Verifies file content against stored digest; does not constitute third-party "
        "authenticity or legal chain of custody."
    )


class ReportPreflightRead(BaseModel):
    investigation_id: uuid.UUID
    case_number: str
    title: str
    status: str
    created_at: datetime
    has_investigator_notes: bool = False
    notes_preview: Optional[str] = None
    sections_available: List[ReportSectionInfo] = Field(default_factory=list)
    findings_summary: ReportFindingsSummary
    evidence_summary: ReportEvidenceSummary
    integrity_status: ReportIntegrityStatus
    missing_or_incomplete: List[str] = Field(default_factory=list)
    can_generate_pdf: bool = True

