"""Investigation Activity API controller."""

import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session, selectinload
from pydantic import BaseModel, Field
from app.api.deps import (
    check_investigation_access,
    check_source_access,
    rate_limit_analysis,
)
from app.database.session import get_db
from app.activities import ActivityService, ActivityFormationSummary
from app.models.activity import Activity
from app.schemas.activity import ActivityRead
from app.schemas.pagination import PaginatedResponse
from app.core.errors import NotFoundError

router = APIRouter(prefix="/activities", tags=["Investigation Activities"])


class ActivityFormationResponse(BaseModel):
    """Response DTO for activity formation run."""
    source_id: Optional[uuid.UUID]
    investigation_id: uuid.UUID
    status: str
    evidence_evaluated: int
    relationships_evaluated: int
    activities_created: int
    activities_reused: int = 0
    duration_ms: float
    errors: List[str] = Field(default_factory=list)


@router.post(
    "/sources/{source_id}/form",
    response_model=ActivityFormationResponse,
    status_code=status.HTTP_200_OK,
    summary="Form coherent investigation activities from source evidence and relationships",
)
def form_activities(
    source_id: uuid.UUID,
    db: Session = Depends(get_db),
    _rate_limit: None = Depends(rate_limit_analysis),
) -> ActivityFormationResponse:
    """Cluster contextual evidence relationships into investigation activities."""
    check_source_access(source_id, db)

    service = ActivityService()
    summary: ActivityFormationSummary = service.form_activities_for_source(db=db, source_id=source_id)

    return ActivityFormationResponse(
        source_id=summary.source_id,
        investigation_id=summary.investigation_id,
        status=summary.status,
        evidence_evaluated=summary.evidence_evaluated,
        relationships_evaluated=summary.relationships_evaluated,
        activities_created=summary.activities_created,
        activities_reused=summary.activities_reused,
        duration_ms=summary.duration_ms,
        errors=summary.errors,
    )


@router.get(
    "",
    response_model=PaginatedResponse[ActivityRead],
    status_code=status.HTTP_200_OK,
    summary="Query investigation activities with pagination and filtering",
)
def list_activities(
    investigation_id: Optional[uuid.UUID] = Query(None, description="Filter by investigation ID"),
    activity_type: Optional[str] = Query(None, description="Filter by activity type"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by activity status"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> PaginatedResponse[ActivityRead]:
    """Retrieve paginated activities scoped to the requested investigation."""
    query = db.query(Activity)

    if investigation_id:
        check_investigation_access(investigation_id, db)
        query = query.filter(Activity.investigation_id == investigation_id)

    if activity_type:
        query = query.filter(Activity.activity_type == activity_type)
    if status_filter:
        query = query.filter(Activity.status == status_filter)

    total = query.count()

    records = (
        query.options(
            selectinload(Activity.evidence_items),
            selectinload(Activity.findings),
        )
        .order_by(Activity.start_time.asc(), Activity.id.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    items = [
        ActivityRead(
            id=a.id,
            investigation_id=a.investigation_id,
            title=a.title,
            activity_type=a.activity_type,
            description=a.description,
            start_time=a.start_time,
            end_time=a.end_time,
            evidence_count=a.evidence_count,
            finding_count=a.finding_count,
            status=a.status,
            evidence_ids=[e.id for e in a.evidence_items],
            finding_ids=[f.id for f in a.findings],
            context_attributes=a.context_attributes,
        )
        for a in records
    ]

    return PaginatedResponse[ActivityRead](
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(items) < total),
    )


@router.get(
    "/{activity_id}",
    response_model=ActivityRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve full detail for a single investigation activity",
)
def get_activity_detail(
    activity_id: uuid.UUID,
    investigation_id: Optional[uuid.UUID] = Query(None, description="Optional investigation ID to verify investigation containment"),
    db: Session = Depends(get_db),
) -> ActivityRead:
    """Retrieve full activity detail with eager loading and optional investigation containment check."""
    if investigation_id:
        check_investigation_access(investigation_id, db)

    act = (
        db.query(Activity)
        .options(
            selectinload(Activity.evidence_items),
            selectinload(Activity.findings),
        )
        .filter(Activity.id == activity_id)
        .first()
    )
    if not act or (investigation_id and act.investigation_id != investigation_id):
        if investigation_id:
            raise NotFoundError(f"Activity with ID '{activity_id}' not found in investigation '{investigation_id}'.")
        raise NotFoundError(f"Activity with ID '{activity_id}' not found.")

    return ActivityRead(
        id=act.id,
        investigation_id=act.investigation_id,
        title=act.title,
        activity_type=act.activity_type,
        description=act.description,
        start_time=act.start_time,
        end_time=act.end_time,
        evidence_count=act.evidence_count,
        finding_count=act.finding_count,
        status=act.status,
        evidence_ids=[e.id for e in act.evidence_items],
        finding_ids=[f.id for f in act.findings],
        context_attributes=act.context_attributes,
    )
