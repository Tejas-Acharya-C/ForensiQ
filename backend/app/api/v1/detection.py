"""Deterministic rule detection API controller (Hardened for Phase 9C)."""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from app.api.deps import (
    get_current_user,
    check_investigation_access,
    check_source_access,
    rate_limit_analysis,
)
from app.database.session import get_db
from app.detection import DetectionService, DetectionSummary
from app.models.finding import Finding
from app.models.investigation import Investigation
from app.models.user import User
from app.schemas.finding import FindingResponse
from app.schemas.pagination import PaginatedResponse
from app.core.errors import NotFoundError

router = APIRouter(prefix="/detection", tags=["Deterministic Detection"])


class DetectionRunResponse(BaseModel):
    """Response DTO for deterministic detection analysis run."""
    source_id: uuid.UUID
    investigation_id: Optional[uuid.UUID] = None
    evidence_evaluated: int
    rules_evaluated: int
    findings_created: int
    findings_reused: int = 0
    duplicates_skipped: int = 0
    duration_ms: float
    status: str
    errors: List[str] = Field(default_factory=list)


@router.post(
    "/sources/{source_id}/analyze-rules",
    response_model=DetectionRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute deterministic detection rules and IOC matching on normalized evidence",
)
def run_deterministic_detection(
    source_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_analysis),
) -> DetectionRunResponse:
    """Run active deterministic rules and IOCs over all evidence records from the specified source."""
    check_source_access(source_id, db, current_user)

    service = DetectionService()
    summary: DetectionSummary = service.analyze_source_evidence(db=db, source_id=source_id)

    return DetectionRunResponse(
        source_id=summary.source_id,
        investigation_id=summary.investigation_id,
        evidence_evaluated=summary.evidence_evaluated,
        rules_evaluated=summary.rules_evaluated,
        findings_created=summary.findings_created,
        findings_reused=summary.findings_reused,
        duplicates_skipped=summary.duplicates_skipped,
        duration_ms=summary.duration_ms,
        status=summary.status,
        errors=summary.errors,
    )


@router.get(
    "/findings",
    response_model=PaginatedResponse[FindingResponse],
    status_code=status.HTTP_200_OK,
    summary="Query analytical findings with pagination, filtering, and authorization",
)
def list_findings(
    investigation_id: Optional[uuid.UUID] = Query(None, description="Filter by investigation ID"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type (e.g. RULE_MATCH, IOC_MATCH)"),
    min_severity: Optional[float] = Query(None, ge=0.0, le=1.0, description="Filter by minimum severity"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedResponse[FindingResponse]:
    """Retrieve paginated Findings with authorization-first scoping and stable sorting."""
    query = db.query(Finding)

    if investigation_id:
        check_investigation_access(investigation_id, db, current_user)
        query = query.filter(Finding.investigation_id == investigation_id)
    else:
        query = query.join(Investigation, Finding.investigation_id == Investigation.id).filter(
            (Investigation.owner_user_id == current_user.id) | (Investigation.owner_user_id.is_(None))
        )

    if finding_type:
        query = query.filter(Finding.finding_type == finding_type)
    if min_severity is not None:
        query = query.filter(Finding.severity_score >= min_severity)

    total = query.count()
    findings = query.order_by(Finding.created_at.desc(), Finding.id.desc()).offset(offset).limit(limit).all()

    items: List[FindingResponse] = []
    for f in findings:
        mitre_tags = f.optional_mitre_tags or {}
        items.append(
            FindingResponse(
                id=f.id,
                investigation_id=f.investigation_id,
                finding_type=f.finding_type,
                rule_id=f.rule_id,
                severity=f.severity_score,
                description=f.description,
                mitre_tactic=mitre_tags.get("tactic") if isinstance(mitre_tags, dict) else None,
                mitre_technique=mitre_tags.get("technique") if isinstance(mitre_tags, dict) else None,
                created_at=f.created_at,
            )
        )

    return PaginatedResponse[FindingResponse](
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(items) < total),
    )


@router.get(
    "/findings/{finding_id}",
    response_model=FindingResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve full detail for a single analytical finding",
)
def get_finding_detail(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FindingResponse:
    """Retrieve full detail for a single Finding with investigation access verification."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise NotFoundError(f"Finding with ID '{finding_id}' not found.")

    check_investigation_access(finding.investigation_id, db, current_user)
    mitre_tags = finding.optional_mitre_tags or {}
    return FindingResponse(
        id=finding.id,
        investigation_id=finding.investigation_id,
        finding_type=finding.finding_type,
        rule_id=finding.rule_id,
        severity=finding.severity_score,
        description=finding.description,
        mitre_tactic=mitre_tags.get("tactic") if isinstance(mitre_tags, dict) else None,
        mitre_technique=mitre_tags.get("technique") if isinstance(mitre_tags, dict) else None,
        created_at=finding.created_at,
    )
