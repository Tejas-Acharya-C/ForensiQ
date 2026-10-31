"""Contextual Evidence Correlation API controller."""

import uuid
from typing import List, Optional, Dict, Any, Literal
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from app.api.deps import (
    check_investigation_access,
    check_source_access,
    rate_limit_analysis,
)
from app.database.session import get_db
from app.correlation import CorrelationService, CorrelationSummary
from app.models.relationship import Relationship
from app.schemas.relationship import RelationshipRead
from app.schemas.pagination import PaginatedResponse
from app.core.errors import NotFoundError

router = APIRouter(prefix="/correlation", tags=["Contextual Correlation"])


class CorrelationSummaryResponse(BaseModel):
    """Response DTO for evidence correlation run."""
    source_id: Optional[uuid.UUID]
    investigation_id: uuid.UUID
    status: str
    evidence_evaluated: int
    candidate_pairs_evaluated: int
    relationships_created: int
    relationships_reused: int = 0
    duplicates_skipped: int = 0
    strategy_counts: Dict[str, int] = Field(default_factory=dict)
    configuration_version: str
    duration_ms: float
    errors: List[str] = Field(default_factory=list)


@router.post(
    "/sources/{source_id}/analyze",
    response_model=CorrelationSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute contextual evidence correlation over normalized evidence records",
)
def run_evidence_correlation(
    source_id: uuid.UUID,
    db: Session = Depends(get_db),
    _rate_limit: None = Depends(rate_limit_analysis),
) -> CorrelationSummaryResponse:
    """Run contextual correlation discovering multi-dimensional relationships across evidence records."""
    check_source_access(source_id, db)

    service = CorrelationService()
    summary: CorrelationSummary = service.analyze_source_evidence(db=db, source_id=source_id)

    return CorrelationSummaryResponse(
        source_id=summary.source_id,
        investigation_id=summary.investigation_id,
        status=summary.status,
        evidence_evaluated=summary.evidence_evaluated,
        candidate_pairs_evaluated=summary.candidate_pairs_evaluated,
        relationships_created=summary.relationships_created,
        relationships_reused=summary.relationships_reused,
        duplicates_skipped=summary.duplicates_skipped,
        strategy_counts=summary.strategy_counts,
        configuration_version=summary.configuration_version,
        duration_ms=summary.duration_ms,
        errors=summary.errors,
    )


@router.get(
    "/relationships",
    response_model=PaginatedResponse[RelationshipRead],
    status_code=status.HTTP_200_OK,
    summary="Query discovered evidence relationships with pagination and filtering",
)
def list_relationships(
    investigation_id: Optional[uuid.UUID] = Query(None, description="Filter by investigation ID"),
    relationship_type: Optional[str] = Query(None, description="Filter by relationship type"),
    min_weight: Optional[float] = Query(None, ge=0.0, le=1.0, description="Filter by minimum relationship weight"),
    source_evidence_id: Optional[uuid.UUID] = Query(None, description="Filter by source evidence ID"),
    target_evidence_id: Optional[uuid.UUID] = Query(None, description="Filter by target evidence ID"),
    sort_by: Optional[Literal["weight", "id"]] = Query("id", description="Sort field"),
    order: Optional[Literal["asc", "desc"]] = Query("desc", description="Sort order"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> PaginatedResponse[RelationshipRead]:
    """Retrieve paginated contextual evidence relationships scoped to the requested investigation."""
    query = db.query(Relationship)

    if investigation_id:
        check_investigation_access(investigation_id, db)
        query = query.filter(Relationship.investigation_id == investigation_id)

    if relationship_type:
        query = query.filter(Relationship.relationship_type == relationship_type)
    if min_weight is not None:
        query = query.filter(Relationship.weight >= min_weight)
    if source_evidence_id:
        query = query.filter(Relationship.source_evidence_id == source_evidence_id)
    if target_evidence_id:
        query = query.filter(Relationship.target_evidence_id == target_evidence_id)

    total = query.count()

    if sort_by == "weight":
        order_clause = (
            (Relationship.weight.desc(), Relationship.id.desc())
            if order == "desc"
            else (Relationship.weight.asc(), Relationship.id.asc())
        )
    else:
        order_clause = (
            (Relationship.id.desc(),)
            if order == "desc"
            else (Relationship.id.asc(),)
        )

    records = query.order_by(*order_clause).offset(offset).limit(limit).all()

    items = [
        RelationshipRead(
            id=r.id,
            investigation_id=r.investigation_id,
            source_evidence_id=r.source_evidence_id,
            target_evidence_id=r.target_evidence_id,
            relationship_type=r.relationship_type,
            weight=r.weight,
            context_attributes=r.context_attributes,
        )
        for r in records
    ]

    return PaginatedResponse[RelationshipRead](
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(items) < total),
    )


@router.get(
    "/relationships/{relationship_id}",
    response_model=RelationshipRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve full detail for a single relationship",
)
def get_relationship_detail(
    relationship_id: uuid.UUID,
    investigation_id: Optional[uuid.UUID] = Query(None, description="Optional investigation ID to verify investigation containment"),
    db: Session = Depends(get_db),
) -> RelationshipRead:
    """Retrieve full detail for a single relationship with optional investigation containment check."""
    if investigation_id:
        check_investigation_access(investigation_id, db)

    rel = db.get(Relationship, relationship_id)
    if not rel or (investigation_id and rel.investigation_id != investigation_id):
        if investigation_id:
            raise NotFoundError(f"Relationship with ID '{relationship_id}' not found in investigation '{investigation_id}'.")
        raise NotFoundError(f"Relationship with ID '{relationship_id}' not found.")

    return RelationshipRead.model_validate(rel)
