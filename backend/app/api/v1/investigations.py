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
from app.models.finding_review import FindingReview
from app.models.relationship import Relationship
from app.models.activity import Activity
from app.models.priority_result import PriorityResult
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationRead,
    InvestigationUpdate,
    InvestigationSummaryRead,
    InvestigationNotesUpdate,
    InvestigationNotesRead,
    ChecklistItemRead,
    InvestigationChecklistRead,
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
    if payload.investigator_notes is not None:
        inv.investigator_notes = payload.investigator_notes

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


@router.get(
    "/{investigation_id}/notes",
    response_model=InvestigationNotesRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve investigator commentary notes for an investigation",
)
def get_investigator_notes(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> InvestigationNotesRead:
    """Retrieve the persisted commentary and conclusion notes for this investigation."""
    inv = check_investigation_access(investigation_id, db)
    return InvestigationNotesRead(
        investigation_id=inv.id,
        notes=inv.investigator_notes,
        updated_at=inv.updated_at,
    )


@router.put(
    "/{investigation_id}/notes",
    response_model=InvestigationNotesRead,
    status_code=status.HTTP_200_OK,
    summary="Record or update investigator commentary notes for an investigation",
)
def update_investigator_notes(
    investigation_id: uuid.UUID,
    payload: InvestigationNotesUpdate,
    db: Session = Depends(get_db),
) -> InvestigationNotesRead:
    """Update or clear investigator commentary notes for the specified investigation."""
    inv = check_investigation_access(investigation_id, db)
    inv.investigator_notes = payload.notes
    db.commit()
    db.refresh(inv)
    return InvestigationNotesRead(
        investigation_id=inv.id,
        notes=inv.investigator_notes,
        updated_at=inv.updated_at,
    )


@router.get(
    "/{investigation_id}/checklist",
    response_model=InvestigationChecklistRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve authoritative investigation quality and readiness checklist",
)
def get_investigation_checklist(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> InvestigationChecklistRead:
    """Compute an operational investigation checklist based on verifiable database state.
    Serves as an operational audit aid before report generation (does not block report generation).
    """
    inv = check_investigation_access(investigation_id, db)

    total_sources = db.query(func.count(EvidenceSource.id)).filter(EvidenceSource.investigation_id == investigation_id).scalar() or 0
    total_evidence = db.query(func.count(Evidence.id)).filter(Evidence.investigation_id == investigation_id).scalar() or 0
    total_findings = db.query(func.count(Finding.id)).filter(Finding.investigation_id == investigation_id).scalar() or 0
    total_activities = db.query(func.count(Activity.id)).filter(Activity.investigation_id == investigation_id).scalar() or 0
    total_priority = db.query(func.count(PriorityResult.id)).filter(PriorityResult.investigation_id == investigation_id).scalar() or 0

    sources = db.query(EvidenceSource).filter(EvidenceSource.investigation_id == investigation_id).all()
    hashed_sources = [s for s in sources if s.sha256_hash and len(s.sha256_hash) == 64]

    reviews_count = (
        db.query(func.count(FindingReview.id))
        .filter(FindingReview.investigation_id == investigation_id)
        .scalar()
        or 0
    )

    items: List[ChecklistItemRead] = []

    # 1. Evidence Ingestion
    if total_sources > 0:
        items.append(ChecklistItemRead(
            key="evidence_ingested",
            label="Evidence Ingestion",
            category="REQUIRED_OPERATION",
            status="COMPLETE",
            description=f"{total_sources} evidence source file(s) ingested.",
            action_tab="tab-overview",
            action_label="View Sources",
        ))
    else:
        items.append(ChecklistItemRead(
            key="evidence_ingested",
            label="Evidence Ingestion",
            category="REQUIRED_OPERATION",
            status="INCOMPLETE",
            description="No evidence files have been ingested into this investigation.",
            action_tab="tab-overview",
            action_label="Import Evidence",
        ))

    # 2. Evidence Normalization
    if total_evidence > 0:
        items.append(ChecklistItemRead(
            key="evidence_normalized",
            label="Evidence Normalization",
            category="REQUIRED_OPERATION",
            status="COMPLETE",
            description=f"{total_evidence} raw records normalized into Common Evidence Schema.",
            action_tab="tab-evidence",
            action_label="View Stream",
        ))
    else:
        items.append(ChecklistItemRead(
            key="evidence_normalized",
            label="Evidence Normalization",
            category="REQUIRED_OPERATION",
            status="INCOMPLETE" if total_sources > 0 else "ATTENTION",
            description="Evidence has not been normalized into structured forensic events.",
            action_tab="tab-overview",
            action_label="Run Pipeline",
        ))

    # 3. Threat Detection Evaluation
    if total_findings > 0:
        items.append(ChecklistItemRead(
            key="detection_executed",
            label="Threat Detection Execution",
            category="REQUIRED_OPERATION",
            status="COMPLETE",
            description=f"{total_findings} analytical threat finding(s) detected across rules and ML models.",
            action_tab="tab-analysis",
            action_label="View Findings",
        ))
    elif total_evidence > 0:
        items.append(ChecklistItemRead(
            key="detection_executed",
            label="Threat Detection Execution",
            category="REQUIRED_OPERATION",
            status="ATTENTION",
            description="No threat findings recorded; detection execution cannot be independently confirmed from persisted state.",
            action_tab="tab-overview",
            action_label="Run Pipeline",
        ))
    else:
        items.append(ChecklistItemRead(
            key="detection_executed",
            label="Threat Detection Execution",
            category="REQUIRED_OPERATION",
            status="INCOMPLETE",
            description="No normalized evidence available for threat detection engines to evaluate.",
            action_tab="tab-overview",
            action_label="Import Evidence",
        ))

    # 4. Finding Triage & Review
    if total_findings == 0:
        items.append(ChecklistItemRead(
            key="findings_reviewed",
            label="Finding Triage Decisions",
            category="OPTIONAL_INVESTIGATION",
            status="COMPLETE",
            description="No detected findings requiring investigator triage.",
            action_tab="tab-analysis",
            action_label="View Findings",
        ))
    elif reviews_count >= total_findings:
        items.append(ChecklistItemRead(
            key="findings_reviewed",
            label="Finding Triage Decisions",
            category="OPTIONAL_INVESTIGATION",
            status="COMPLETE",
            description=f"All {total_findings} detected findings have investigator review decisions recorded.",
            action_tab="tab-analysis",
            action_label="View Triage",
        ))
    elif reviews_count > 0:
        items.append(ChecklistItemRead(
            key="findings_reviewed",
            label="Finding Triage Decisions",
            category="OPTIONAL_INVESTIGATION",
            status="ATTENTION",
            description=f"{reviews_count} of {total_findings} findings triaged. {total_findings - reviews_count} pending review.",
            action_tab="tab-analysis",
            action_label="Triage Findings",
        ))
    else:
        items.append(ChecklistItemRead(
            key="findings_reviewed",
            label="Finding Triage Decisions",
            category="OPTIONAL_INVESTIGATION",
            status="INCOMPLETE",
            description=f"{total_findings} finding(s) detected; triage decisions recommended prior to report publication.",
            action_tab="tab-analysis",
            action_label="Triage Findings",
        ))

    # 5. Event Correlation & Narrative
    if total_activities > 0:
        items.append(ChecklistItemRead(
            key="correlation_completed",
            label="Activity Correlation & Narrative",
            category="REQUIRED_OPERATION",
            status="COMPLETE",
            description=f"{total_activities} correlated activity thread(s) formed from linked events.",
            action_tab="tab-analysis",
            action_label="View Activities",
        ))
    else:
        items.append(ChecklistItemRead(
            key="correlation_completed",
            label="Activity Correlation & Narrative",
            category="REQUIRED_OPERATION",
            status="INCOMPLETE" if total_evidence > 0 else "ATTENTION",
            description="Correlation and activity thread formation have not been executed.",
            action_tab="tab-overview",
            action_label="Run Pipeline",
        ))

    # 6. Threat Prioritization
    if total_priority > 0:
        items.append(ChecklistItemRead(
            key="prioritization_available",
            label="Threat Prioritization",
            category="REQUIRED_OPERATION",
            status="COMPLETE",
            description=f"Risk scoring and priority tiers calculated for {total_priority} target(s).",
            action_tab="tab-overview",
            action_label="View Priority",
        ))
    else:
        items.append(ChecklistItemRead(
            key="prioritization_available",
            label="Threat Prioritization",
            category="REQUIRED_OPERATION",
            status="INCOMPLETE" if total_evidence > 0 else "ATTENTION",
            description="Evidence and activity risk prioritization have not been scored.",
            action_tab="tab-overview",
            action_label="Run Pipeline",
        ))

    # 7. Evidence Ingestion Integrity
    if total_sources > 0 and len(hashed_sources) == total_sources:
        items.append(ChecklistItemRead(
            key="evidence_integrity",
            label="Evidence Ingestion Integrity",
            category="REQUIRED_OPERATION",
            status="COMPLETE",
            description=f"Cryptographic SHA-256 ingestion digests recorded for all {total_sources} source file(s) (verifies stored digest availability; active re-hash not performed).",
            action_tab="tab-overview",
            action_label="View Sources",
        ))
    elif total_sources > 0:
        items.append(ChecklistItemRead(
            key="evidence_integrity",
            label="Evidence Ingestion Integrity",
            category="REQUIRED_OPERATION",
            status="ATTENTION",
            description=f"SHA-256 ingestion digests recorded for {len(hashed_sources)} of {total_sources} evidence files.",
            action_tab="tab-overview",
            action_label="Check Sources",
        ))
    else:
        items.append(ChecklistItemRead(
            key="evidence_integrity",
            label="Evidence Ingestion Integrity",
            category="REQUIRED_OPERATION",
            status="INCOMPLETE",
            description="No evidence files available to evaluate ingestion digests.",
            action_tab="tab-overview",
            action_label="Import Evidence",
        ))

    # 8. Investigator Notes & Commentary
    if inv.investigator_notes and inv.investigator_notes.strip():
        items.append(ChecklistItemRead(
            key="investigator_notes",
            label="Investigator Notes & Commentary",
            category="OPTIONAL_INVESTIGATION",
            status="COMPLETE",
            description=f"Investigator commentary documented ({len(inv.investigator_notes.strip())} chars) for report inclusion.",
            action_tab="tab-report",
            action_label="Edit Notes",
        ))
    else:
        items.append(ChecklistItemRead(
            key="investigator_notes",
            label="Investigator Notes & Commentary",
            category="OPTIONAL_INVESTIGATION",
            status="INCOMPLETE",
            description="No investigator commentary recorded yet. Add notes to provide analytical context.",
            action_tab="tab-report",
            action_label="Add Notes",
        ))

    # 9. Report Preflight
    if total_sources > 0:
        items.append(ChecklistItemRead(
            key="report_preflight",
            label="Report Preflight Readiness",
            category="INFORMATIONAL",
            status="COMPLETE",
            description="Investigation contains evidence records and is ready for report generation.",
            action_tab="tab-report",
            action_label="Preview Report",
        ))
    else:
        items.append(ChecklistItemRead(
            key="report_preflight",
            label="Report Preflight Readiness",
            category="INFORMATIONAL",
            status="INCOMPLETE",
            description="Requires at least one evidence source before report compilation can proceed.",
            action_tab="tab-overview",
            action_label="Import Evidence",
        ))

    required_items = [it for it in items if it.category == "REQUIRED_OPERATION"]
    completed_required = [it for it in required_items if it.status == "COMPLETE"]

    return InvestigationChecklistRead(
        investigation_id=inv.id,
        case_number=inv.case_number,
        items=items,
        completed_required_count=len(completed_required),
        total_required_count=len(required_items),
        summary_text=f"{len(completed_required)} of {len(required_items)} required investigation operations complete.",
    )
