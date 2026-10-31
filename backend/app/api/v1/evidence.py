"""Evidence Ingestion, Normalization & Query API controller."""

import uuid
import re
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, Query, status, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.api.deps import check_investigation_access, check_source_access
from app.database.session import get_db
from app.core.storage import EvidenceStorage
from app.ingestion.service import IngestionService
from app.ingestion.contracts import IngestionResult
from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.normalization.service import NormalizationService
from app.normalization.contracts import BatchNormalizationSummary
from app.schemas.evidence import EvidenceRead
from app.schemas.evidence_source import SourceIntegrityResult
from app.schemas.pagination import PaginatedResponse
from app.core.errors import NotFoundError, BadRequestError
from app.core.logging import get_logger

logger = get_logger("evidence_api")

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
) -> EvidenceImportResponse:
    """Import and structurally validate an evidence file, preserving provenance."""
    check_investigation_access(investigation_id, db)

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
    source_type_override: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> NormalizationResponse:
    """Trigger batch normalization and persistent insertion into the Common Evidence Schema."""
    check_source_access(source_id, db)

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


@router.post(
    "/sources/{source_id}/verify-integrity",
    response_model=SourceIntegrityResult,
    status_code=status.HTTP_200_OK,
    summary="Cryptographically verify stored source file artifact against recorded ingestion SHA-256 digest",
)
def verify_source_integrity(
    source_id: uuid.UUID,
    investigation_id: Optional[uuid.UUID] = Query(None, description="Optional investigation ID to verify investigation containment"),
    db: Session = Depends(get_db),
) -> SourceIntegrityResult:
    """Verifies that the byte content of the stored source file artifact on disk matches
    the cryptographic SHA-256 digest recorded during evidence ingestion.
    """
    if investigation_id:
        check_investigation_access(investigation_id, db)

    source = check_source_access(source_id, db)
    if investigation_id and source.investigation_id != investigation_id:
        raise NotFoundError(f"EvidenceSource with ID '{source_id}' not found in investigation '{investigation_id}'.")

    now = datetime.now(timezone.utc)
    raw_hash = (source.sha256_hash or "").strip()

    # 1. Format check
    if not re.match(r"^[0-9a-fA-F]{64}$", raw_hash):
        return SourceIntegrityResult(
            source_id=source.id,
            investigation_id=source.investigation_id,
            filename=source.filename,
            recorded_sha256=raw_hash,
            computed_sha256=None,
            status="MALFORMED_DIGEST",
            verified_at=now,
            message="Recorded digest is not a valid 64-character hexadecimal SHA-256 string.",
        )

    # 2. File presence check
    storage = EvidenceStorage()
    try:
        path = storage.get_source_path(source)
    except Exception as exc:
        return SourceIntegrityResult(
            source_id=source.id,
            investigation_id=source.investigation_id,
            filename=source.filename,
            recorded_sha256=raw_hash,
            computed_sha256=None,
            status="VERIFICATION_UNAVAILABLE",
            verified_at=now,
            message=f"Stored evidence file artifact is unavailable on disk: {str(exc)}",
        )

    # 3. Compute hash and compare
    try:
        computed = storage.compute_file_sha256(path)
    except Exception as exc:
        return SourceIntegrityResult(
            source_id=source.id,
            investigation_id=source.investigation_id,
            filename=source.filename,
            recorded_sha256=raw_hash,
            computed_sha256=None,
            status="VERIFICATION_UNAVAILABLE",
            verified_at=now,
            message=f"Could not compute hash from stored evidence file artifact: {str(exc)}",
        )

    if computed.lower() == raw_hash.lower():
        return SourceIntegrityResult(
            source_id=source.id,
            investigation_id=source.investigation_id,
            filename=source.filename,
            recorded_sha256=raw_hash,
            computed_sha256=computed,
            status="VERIFIED",
            verified_at=now,
            message="Cryptographic SHA-256 digest verified: stored file content exactly matches recorded ingestion hash.",
        )
    else:
        return SourceIntegrityResult(
            source_id=source.id,
            investigation_id=source.investigation_id,
            filename=source.filename,
            recorded_sha256=raw_hash,
            computed_sha256=computed,
            status="INTEGRITY_MISMATCH",
            verified_at=now,
            message=f"Integrity violation detected: computed SHA-256 digest ({computed}) does not match recorded digest ({raw_hash}).",
        )


def _safe_validate_evidence(record: Evidence) -> EvidenceRead:
    """Deserialize an Evidence model into EvidenceRead without silent truncation.
    
    If standard validation encounters an issue (e.g. unexpected DB representation),
    preserves original stored values and records structured data quality warnings
    in attributes rather than silently truncating or converting invalid data into
    pseudo-valid forensic representations.
    """
    try:
        return EvidenceRead.model_validate(record)
    except Exception as exc:
        rec_id = getattr(record, "id", None)
        logger.warning(
            "Evidence deserialization fallback triggered for record %s: %s",
            rec_id,
            exc,
            extra={
                "evidence_id": str(rec_id),
                "investigation_id": str(getattr(record, "investigation_id", None)),
                "error": str(exc),
            },
        )
        attrs = {c.name: getattr(record, c.name) for c in record.__table__.columns}
        record_attrs = dict(attrs.get("attributes") or {})
        record_attrs["_data_quality_warning"] = {
            "status": "DESERIALIZATION_FALLBACK",
            "error_detail": str(exc),
            "deserialized_without_truncation": True,
        }
        attrs["attributes"] = record_attrs
        return EvidenceRead.model_construct(**attrs)


@router.get(
    "",
    response_model=PaginatedResponse[EvidenceRead],
    status_code=status.HTTP_200_OK,
    summary="Query normalized evidence records with pagination and filtering",
)
def list_evidence(
    investigation_id: Optional[uuid.UUID] = Query(None),
    source_id: Optional[uuid.UUID] = Query(None),
    event_type: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    ids: Optional[str] = Query(None, description="Comma-separated list of Evidence UUIDs to filter"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> PaginatedResponse[EvidenceRead]:
    """Retrieve paginated normalized evidence records."""
    query = db.query(Evidence)

    if investigation_id:
        check_investigation_access(investigation_id, db)
        query = query.filter(Evidence.investigation_id == investigation_id)

    if ids is not None:
        raw_list = [r.strip() for r in ids.split(",") if r.strip()]
        if len(raw_list) > 100:
            raise BadRequestError("The 'ids' filter cannot exceed 100 identifiers per request.")
        parsed_ids: List[uuid.UUID] = []
        for raw_id in raw_list:
            try:
                parsed_ids.append(uuid.UUID(raw_id))
            except ValueError:
                raise BadRequestError(f"Malformed UUID in 'ids' parameter: '{raw_id}'")
        query = query.filter(Evidence.id.in_(parsed_ids))

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

    items = [_safe_validate_evidence(r) for r in records]

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
    investigation_id: Optional[uuid.UUID] = Query(None, description="Optional investigation ID to verify investigation containment"),
    db: Session = Depends(get_db),
) -> EvidenceRead:
    """Retrieve full normalized evidence detail with optional investigation containment check."""
    if investigation_id:
        check_investigation_access(investigation_id, db)

    evd = db.get(Evidence, evidence_id)
    if not evd or (investigation_id and evd.investigation_id != investigation_id):
        if investigation_id:
            raise NotFoundError(f"Evidence with ID '{evidence_id}' not found in investigation '{investigation_id}'.")
        raise NotFoundError(f"Evidence with ID '{evidence_id}' not found.")

    return _safe_validate_evidence(evd)
