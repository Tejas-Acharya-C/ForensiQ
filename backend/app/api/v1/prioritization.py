"""Prioritization API controller for ForensiQ Phase 9 (Hardened for Phase 9C)."""

import uuid
from typing import List, Optional, Dict, Any, Literal
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.api.deps import (
    get_current_user,
    check_investigation_access,
    rate_limit_analysis,
)
from app.database.session import get_db
from app.models.investigation import Investigation
from app.prioritization import PrioritizationService, PrioritizationSummary
from app.models.priority_result import PriorityResult
from app.models.user import User
from app.schemas.priority import PriorityResultRead
from app.schemas.pagination import PaginatedResponse
from app.core.errors import NotFoundError

router = APIRouter(prefix="/prioritization", tags=["Explainable Prioritization"])





class PrioritizationResponse(BaseModel):
    """Response DTO for prioritization run."""
    investigation_id: uuid.UUID
    method_type: str
    target_type: str
    status: str
    targets_evaluated: int
    results_created: int
    results_reused: int = 0
    tier_counts: Dict[str, int] = Field(default_factory=dict)
    duration_ms: float
    errors: List[str] = Field(default_factory=list)


@router.post(
    "/investigations/{investigation_id}/baseline",
    response_model=PrioritizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Prioritize investigation evidence records independently",
)
def run_baseline_artifact_prioritization(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_analysis),
) -> PrioritizationResponse:
    """Run operational artifact-level prioritization."""
    check_investigation_access(investigation_id, db, current_user)

    service = PrioritizationService()
    summary = service.prioritize_artifacts(db=db, investigation_id=investigation_id)
    return PrioritizationResponse(
        investigation_id=summary.investigation_id,
        method_type=summary.method_type,
        target_type=summary.target_type,
        status=summary.status,
        targets_evaluated=summary.targets_evaluated,
        results_created=summary.results_created,
        results_reused=summary.results_reused,
        tier_counts=summary.tier_counts,
        duration_ms=summary.duration_ms,
        errors=summary.errors,
    )


@router.post(
    "/investigations/{investigation_id}/contextual",
    response_model=PrioritizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Prioritize investigation activities using contextual evidence graphs",
)
def run_contextual_activity_prioritization(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_analysis),
) -> PrioritizationResponse:
    """Run operational activity-level prioritization."""
    check_investigation_access(investigation_id, db, current_user)

    service = PrioritizationService()
    summary = service.prioritize_activities(db=db, investigation_id=investigation_id)
    return PrioritizationResponse(
        investigation_id=summary.investigation_id,
        method_type=summary.method_type,
        target_type=summary.target_type,
        status=summary.status,
        targets_evaluated=summary.targets_evaluated,
        results_created=summary.results_created,
        results_reused=summary.results_reused,
        tier_counts=summary.tier_counts,
        duration_ms=summary.duration_ms,
        errors=summary.errors,
    )


@router.get(
    "/results",
    response_model=PaginatedResponse[PriorityResultRead],
    status_code=status.HTTP_200_OK,
    summary="Query prioritization results with pagination, filtering, and stable sorting",
)
def list_priority_results(
    investigation_id: Optional[uuid.UUID] = Query(None, description="Filter by investigation ID"),
    method_type: Optional[Literal["BASELINE_INDEPENDENT", "PROPOSED_CONTEXTUAL"]] = Query(None, description="Filter by prioritization method"),
    target_type: Optional[Literal["ARTIFACT", "ACTIVITY"]] = Query(None, description="Filter by target type"),
    priority_tier: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]] = Query(None, description="Filter by priority tier"),
    min_score: Optional[float] = Query(None, ge=0.0, le=100.0, description="Filter by minimum priority score"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedResponse[PriorityResultRead]:
    """Retrieve paginated explainable priority results with authorization-first scoping and stable sorting."""
    query = db.query(PriorityResult)

    if investigation_id:
        check_investigation_access(investigation_id, db, current_user)
        query = query.filter(PriorityResult.investigation_id == investigation_id)


    if method_type:
        query = query.filter(PriorityResult.method_type == method_type)
    if target_type:
        query = query.filter(PriorityResult.target_type == target_type)
    if priority_tier:
        query = query.filter(PriorityResult.priority_tier == priority_tier)
    if min_score is not None:
        query = query.filter(PriorityResult.priority_score >= min_score)

    total = query.count()
    records = (
        query.order_by(PriorityResult.priority_score.desc(), PriorityResult.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    items = [
        PriorityResultRead(
            id=r.id,
            investigation_id=r.investigation_id,
            target_type=r.target_type,
            target_id=r.target_id,
            priority_score=r.priority_score,
            priority_tier=r.priority_tier,
            factor_breakdown=r.factor_breakdown,
            explanation_text=r.explanation_text,
            method_type=r.method_type,
            computed_at=r.computed_at,
        )
        for r in records
    ]

    return PaginatedResponse[PriorityResultRead](
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(items) < total),
    )


@router.get(
    "/results/{result_id}",
    response_model=PriorityResultRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve full detail for a single priority result",
)
def get_priority_result_detail(
    result_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PriorityResultRead:
    """Retrieve full detail for a single PriorityResult with investigation access verification."""
    result = db.get(PriorityResult, result_id)
    if not result:
        raise NotFoundError(f"PriorityResult with ID '{result_id}' not found.")

    check_investigation_access(result.investigation_id, db, current_user)
    return PriorityResultRead(
        id=result.id,
        investigation_id=result.investigation_id,
        target_type=result.target_type,
        target_id=result.target_id,
        priority_score=result.priority_score,
        priority_tier=result.priority_tier,
        factor_breakdown=result.factor_breakdown,
        explanation_text=result.explanation_text,
        method_type=result.method_type,
        computed_at=result.computed_at,
    )
