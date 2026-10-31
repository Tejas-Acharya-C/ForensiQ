"""Investigation management and dashboard aggregation API controller."""

import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.api.deps import check_investigation_access
from app.database.session import get_db
from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.relationship import Relationship
from app.models.activity import Activity
from app.models.priority_result import PriorityResult
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationRead,
    InvestigationUpdate,
    InvestigationSummaryRead,
    SourceHealthSummary,
    PriorityTierCounts,
    FindingTypeCounts,
)
from app.schemas.evidence_source import EvidenceSourceRead
from app.schemas.priority import PriorityResultRead
from app.schemas.pagination import PaginatedResponse
from app.core.errors import ConflictError, NotFoundError

router = APIRouter(prefix="/investigations", tags=["Investigations & Dashboard"])


@router.get(
    "",
    response_model=PaginatedResponse[InvestigationRead],
    status_code=status.HTTP_200_OK,
    summary="List all investigations with pagination",
)
def list_investigations(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
) -> PaginatedResponse[InvestigationRead]:
    """List all investigations."""
    query = db.query(Investigation)

    if status_filter:
        query = query.filter(Investigation.status == status_filter.upper())

    total = query.count()
    records = query.order_by(Investigation.created_at.desc(), Investigation.id.desc()).offset(offset).limit(limit).all()

    items = [InvestigationRead.model_validate(r) for r in records]

    return PaginatedResponse[InvestigationRead](
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(items) < total),
    )


@router.post(
    "",
    response_model=InvestigationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new investigation case",
)
def create_investigation(
    payload: InvestigationCreate,
    db: Session = Depends(get_db),
) -> InvestigationRead:
    """Provision a new investigation container."""
    existing = db.query(Investigation).filter(Investigation.case_number == payload.case_number).first()
    if existing:
        raise ConflictError(f"Investigation with case number '{payload.case_number}' already exists.")

    inv = Investigation(
        title=payload.title,
        description=payload.description,
        case_number=payload.case_number,
        status=payload.status,
        owner_user_id=None,          # no auth — owner field left NULL
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)

    return InvestigationRead.model_validate(inv)


@router.get(
    "/{investigation_id}",
    response_model=InvestigationRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve single investigation details",
)
def get_investigation_detail(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> InvestigationRead:
    """Retrieve detailed investigation metadata."""
    inv = check_investigation_access(investigation_id, db)
    return InvestigationRead.model_validate(inv)


@router.patch(
    "/{investigation_id}",
    response_model=InvestigationRead,
    status_code=status.HTTP_200_OK,
    summary="Update investigation metadata or status",
)
def update_investigation(
    investigation_id: uuid.UUID,
    payload: InvestigationUpdate,
    db: Session = Depends(get_db),
) -> InvestigationRead:
    """Update title, description, or status of an investigation."""
    inv = check_investigation_access(investigation_id, db)

    if payload.title is not None:
        inv.title = payload.title
    if payload.description is not None:
        inv.description = payload.description
    if payload.status is not None:
        inv.status = payload.status

    db.commit()
    db.refresh(inv)
    return InvestigationRead.model_validate(inv)


@router.get(
    "/{investigation_id}/summary",
    response_model=InvestigationSummaryRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve unified dashboard aggregation metrics for an investigation",
)
def get_investigation_summary(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> InvestigationSummaryRead:
    """Compute high-level counts, tier breakdowns, and health status."""
    inv = check_investigation_access(investigation_id, db)

    # Total counts via SQL aggregation
    total_sources = db.query(func.count(EvidenceSource.id)).filter(EvidenceSource.investigation_id == investigation_id).scalar() or 0
    total_evidence = db.query(func.count(Evidence.id)).filter(Evidence.investigation_id == investigation_id).scalar() or 0
    total_findings = db.query(func.count(Finding.id)).filter(Finding.investigation_id == investigation_id).scalar() or 0
    total_relationships = db.query(func.count(Relationship.id)).filter(Relationship.investigation_id == investigation_id).scalar() or 0
    total_activities = db.query(func.count(Activity.id)).filter(Activity.investigation_id == investigation_id).scalar() or 0
    total_priority_results = db.query(func.count(PriorityResult.id)).filter(PriorityResult.investigation_id == investigation_id).scalar() or 0

    # Finding types aggregation
    finding_type_rows = (
        db.query(Finding.finding_type, func.count(Finding.id))
        .filter(Finding.investigation_id == investigation_id)
        .group_by(Finding.finding_type)
        .all()
    )
    finding_counts_dict = {ft: count for ft, count in finding_type_rows}
    finding_counts = FindingTypeCounts(
        RULE_MATCH=finding_counts_dict.get("RULE_MATCH", 0),
        IOC_MATCH=finding_counts_dict.get("IOC_MATCH", 0),
        ML_ANOMALY=finding_counts_dict.get("ML_ANOMALY", 0),
    )

    # Priority Tier breakdown
    tier_rows = (
        db.query(PriorityResult.priority_tier, func.count(PriorityResult.id))
        .filter(PriorityResult.investigation_id == investigation_id)
        .group_by(PriorityResult.priority_tier)
        .all()
    )
    tier_counts_dict = {tier: count for tier, count in tier_rows}
    priority_tier_counts = PriorityTierCounts(
        CRITICAL=tier_counts_dict.get("CRITICAL", 0),
        HIGH=tier_counts_dict.get("HIGH", 0),
        MEDIUM=tier_counts_dict.get("MEDIUM", 0),
        LOW=tier_counts_dict.get("LOW", 0),
        INFORMATIONAL=tier_counts_dict.get("INFORMATIONAL", 0),
    )

    # Top 5 priority results
    top_prio_records = (
        db.query(PriorityResult)
        .filter(PriorityResult.investigation_id == investigation_id)
        .order_by(PriorityResult.priority_score.desc(), PriorityResult.id.desc())
        .limit(5)
        .all()
    )
    top_priority_results = [PriorityResultRead.model_validate(pr) for pr in top_prio_records]

    # Evidence sources health and normalized record counts
    sources_records = (
        db.query(EvidenceSource)
        .filter(EvidenceSource.investigation_id == investigation_id)
        .order_by(EvidenceSource.ingested_at.desc())
        .all()
    )

    source_norm_counts = dict(
        db.query(Evidence.source_id, func.count(Evidence.id))
        .filter(Evidence.investigation_id == investigation_id)
        .group_by(Evidence.source_id)
        .all()
    )

    sources_summary: List[SourceHealthSummary] = []
    for s in sources_records:
        norm_count = source_norm_counts.get(s.id, 0)
        sources_summary.append(
            SourceHealthSummary(
                id=s.id,
                filename=s.filename,
                file_format=s.file_format,
                sha256_hash=s.sha256_hash,
                file_size_bytes=s.file_size_bytes,
                total_records=s.total_records,
                normalized_records=norm_count,
                ingestion_status=s.ingestion_status,
                ingested_at=s.ingested_at,
            )
        )

    # Pipeline readiness / stage status
    pipeline_status = {
        "has_sources": total_sources > 0,
        "has_evidence": total_evidence > 0,
        "has_detections": total_findings > 0,
        "has_correlations": total_relationships > 0,
        "has_activities": total_activities > 0,
        "has_prioritization": total_priority_results > 0,
    }

    return InvestigationSummaryRead(
        investigation=InvestigationRead.model_validate(inv),
        owner_email=None,           # no auth — always None
        total_sources=total_sources,
        total_evidence=total_evidence,
        total_findings=total_findings,
        total_anomalies=finding_counts.ML_ANOMALY,
        total_relationships=total_relationships,
        total_activities=total_activities,
        total_priority_results=total_priority_results,
        finding_counts=finding_counts,
        priority_tier_counts=priority_tier_counts,
        top_priority_results=top_priority_results,
        sources=sources_summary,
        pipeline_status=pipeline_status,
    )


@router.get(
    "/{investigation_id}/sources",
    response_model=List[SourceHealthSummary],
    status_code=status.HTTP_200_OK,
    summary="List evidence sources belonging to an investigation",
)
def list_investigation_sources(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> List[SourceHealthSummary]:
    """Retrieve all evidence sources for an investigation, omitting storage_path."""
    check_investigation_access(investigation_id, db)

    sources_records = (
        db.query(EvidenceSource)
        .filter(EvidenceSource.investigation_id == investigation_id)
        .order_by(EvidenceSource.ingested_at.desc())
        .all()
    )

    source_norm_counts = dict(
        db.query(Evidence.source_id, func.count(Evidence.id))
        .filter(Evidence.investigation_id == investigation_id)
        .group_by(Evidence.source_id)
        .all()
    )

    return [
        SourceHealthSummary(
            id=s.id,
            filename=s.filename,
            file_format=s.file_format,
            sha256_hash=s.sha256_hash,
            file_size_bytes=s.file_size_bytes,
            total_records=s.total_records,
            normalized_records=source_norm_counts.get(s.id, 0),
            ingestion_status=s.ingestion_status,
            ingested_at=s.ingested_at,
        )
        for s in sources_records
    ]
