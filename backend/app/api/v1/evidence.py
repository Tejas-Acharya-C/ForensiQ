"""Evidence Ingestion, Normalization & Query API controller (Hardened for Phase 9C)."""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.api.deps import get_current_user, check_investigation_access, check_source_access
from app.database.session import get_db
from app.ingestion.service import IngestionService
from app.ingestion.contracts import IngestionResult
from app.models.investigation import Investigation
from app.models.evidence import Evidence
from app.models.user import User
from app.normalization.service import NormalizationService
from app.normalization.contracts import BatchNormalizationSummary
from app.schemas.evidence import EvidenceRead
from app.schemas.pagination import PaginatedResponse
from app.core.errors import NotFoundError

router = APIRouter(prefix="/evidence", tags=["Evidence Processing"])


class EvidenceImportResponse(BaseModel):
    """Response DTO for evidence file upload and ingestion."""
    source_id: uuid.UUID
    investigation_id: uuid.UUID
    filename: str
    file_format: str
    sha256_hash: str
    file_size_bytes: int
    total_records: int
    ingestion_status: str
    warnings: List[str] = Field(default_factory=list)


class NormalizationResponse(BaseModel):
    """Response DTO for source normalization execution."""
    source_id: uuid.UUID
    investigation_id: uuid.UUID
    total_records: int
    normalized_records: int
    rejected_records: int
    warning_count: int
    duration_ms: float
    status: str
    errors: List[str] = Field(default_factory=list)


@router.post(
    "/import",
    response_model=EvidenceImportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Import raw digital evidence file into an investigation",
)
def import_evidence_file(
    investigation_id: uuid.UUID = Form(..., description="Target investigation UUID"),
    file: UploadFile = File(..., description="Evidence file (CSV, JSON, or JSONL)"),
    allow_duplicates: bool = Form(False, description="Allow importing identical SHA-256 files"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EvidenceImportResponse:
    """Import and structurally validate an evidence file, verifying authorization and preserving provenance."""
    # Authorization check
    check_investigation_access(investigation_id, db, current_user)

    service = IngestionService()
    result: IngestionResult = service.ingest_file(
        db=db,
        investigation_id=investigation_id,
        file_obj=file.file,
        original_filename=file.filename or "unnamed_evidence",
        allow_duplicates=allow_duplicates,
    )

    return EvidenceImportResponse(
        source_id=result.source_id,
        investigation_id=result.investigation_id,
        filename=result.filename,
        file_format=result.file_format,
        sha256_hash=result.sha256_hash,
        file_size_bytes=result.file_size_bytes,
        total_records=result.total_records,
        ingestion_status=result.ingestion_status,
        warnings=result.warnings,
    )


@router.post(
    "/sources/{source_id}/normalize",
    response_model=NormalizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Normalize raw evidence records from an ingested source into canonical Evidence records",
)
def normalize_evidence_source(
    source_id: uuid.UUID,
    source_type_override: Optional[str] = Form(None, description="Optional source schema profile override (e.g. WINDOWS_EVTX)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NormalizationResponse:
    """Trigger batch normalization and persistent insertion into the Common Evidence Schema."""
    # Authorization check
    check_source_access(source_id, db, current_user)

    service = NormalizationService()
    summary: BatchNormalizationSummary = service.normalize_source(
        db=db,
        source_id=source_id,
        source_type_override=source_type_override,
    )

    return NormalizationResponse(
        source_id=summary.source_id,
        investigation_id=summary.investigation_id,
        total_records=summary.total_records,
        normalized_records=summary.normalized_records,
        rejected_records=summary.rejected_records,
        warning_count=summary.warning_count,
        duration_ms=summary.duration_ms,
        status=summary.status,
        errors=summary.errors,
    )


@router.get(
    "",
    response_model=PaginatedResponse[EvidenceRead],
    status_code=status.HTTP_200_OK,
    summary="Query normalized evidence records with pagination and filtering",
)
def list_evidence(
    investigation_id: Optional[uuid.UUID] = Query(None, description="Filter by investigation ID"),
    source_id: Optional[uuid.UUID] = Query(None, description="Filter by evidence source ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    user_id: Optional[str] = Query(None, description="Filter by user identifier"),
    device_id: Optional[str] = Query(None, description="Filter by device identifier"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedResponse[EvidenceRead]:
    """Retrieve paginated normalized evidence records."""
    query = db.query(Evidence)

    if investigation_id:
        check_investigation_access(investigation_id, db, current_user)
        query = query.filter(Evidence.investigation_id == investigation_id)


    if source_id:
        query = query.filter(Evidence.source_id == source_id)
    if event_type:
        query = query.filter(Evidence.event_type == event_type)
    if user_id:
        query = query.filter(Evidence.user_id == user_id)
    if device_id:
        query = query.filter(Evidence.device_id == device_id)

    total = query.count()
    records = query.order_by(Evidence.timestamp.desc(), Evidence.id.desc()).offset(offset).limit(limit).all()

    items = [
        EvidenceRead.model_validate(r)
        for r in records
    ]

    return PaginatedResponse[EvidenceRead](
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(items) < total),
    )


@router.get(
    "/{evidence_id}",
    response_model=EvidenceRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve full details for a single normalized evidence record",
)
def get_evidence_detail(
    evidence_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EvidenceRead:
    """Retrieve full normalized evidence detail with anti-IDOR investigation scope check."""
    evd = db.get(Evidence, evidence_id)
    if not evd:
        raise NotFoundError(f"Evidence with ID '{evidence_id}' not found.")

    check_investigation_access(evd.investigation_id, db, current_user)
    return EvidenceRead.model_validate(evd)
