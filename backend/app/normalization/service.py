"""Evidence Normalization Service orchestrating record transformation and atomic persistence (Phase 9B)."""

import time
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.errors import NotFoundError
from app.core.rate_limit import analysis_concurrency_guard
from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.ingestion.contracts import RawEvidenceRecord
from app.ingestion.service import IngestionService
from app.normalization.contracts import (
    NormalizedEvidence,
    NormalizationResult,
    BatchNormalizationSummary,
)
from app.normalization.mapper import (
    parse_to_utc,
    normalize_event_type,
    normalize_user_id,
    normalize_device_id,
    normalize_process_name,
    normalize_ip_address,
    normalize_port,
    normalize_protocol,
    normalize_file_hash,
    validate_and_parse_file_hash,
    normalize_status,
    normalize_action,
    sanitize_string,
    get_source_mapping,
    extract_field_value,
    SourceFieldMapping,
)
from app.normalization.validators import validate_normalized_evidence
from app.normalization.exceptions import NormalizationError

logger = get_logger("normalization_service")


class NormalizationService:
    """Service transforming RawEvidenceRecords into canonical Evidence database entities with atomic commit/rollback."""

    def __init__(self, staging_dir: Optional[Any] = None, source_dir: Optional[Any] = None):
        settings = get_settings()
        self.batch_size = settings.INGESTION_BATCH_SIZE
        self.staging_dir = staging_dir
        self.source_dir = source_dir

    def normalize_record(
        self,
        raw_record: RawEvidenceRecord,
        investigation_id: uuid.UUID,
        source_type_override: Optional[str] = None,
    ) -> NormalizationResult:
        """Transform a single RawEvidenceRecord into a NormalizedEvidence contract."""
        errors: List[str] = []
        warnings: List[str] = []
        raw_data = raw_record.raw_data

        source_type = source_type_override or raw_record.source_format
        mapping = get_source_mapping(source_type)

        # 1. Timestamp Normalization (Mandatory)
        raw_ts = extract_field_value(raw_data, mapping.timestamp_fields)
        normalized_ts: Optional[datetime] = None
        if raw_ts is not None:
            try:
                normalized_ts = parse_to_utc(raw_ts)
            except Exception as exc:
                errors.append(f"Timestamp parsing error: {str(exc)}")
        else:
            errors.append("Missing required timestamp field.")

        # 2. Event Type Normalization (Mandatory)
        raw_event = extract_field_value(raw_data, mapping.event_type_fields)
        normalized_event = normalize_event_type(raw_event)
        if normalized_event == "UNKNOWN" and raw_event:
            warnings.append(f"Unmapped raw event type: '{raw_event}' mapped to UNKNOWN.")

        # 3. Entity Normalization
        raw_user = extract_field_value(raw_data, mapping.user_fields)
        user_id = normalize_user_id(raw_user)

        raw_device = extract_field_value(raw_data, mapping.device_fields)
        device_id = normalize_device_id(raw_device)

        raw_session = extract_field_value(raw_data, mapping.session_fields)
        session_id = sanitize_string(raw_session)

        # Process entities
        raw_proc = extract_field_value(raw_data, mapping.process_name_fields)
        process_name, proc_full_path = normalize_process_name(raw_proc)

        raw_parent = extract_field_value(raw_data, mapping.parent_process_fields)
        parent_process_name, _ = normalize_process_name(raw_parent)

        raw_pid = extract_field_value(raw_data, mapping.process_id_fields)
        process_id: Optional[int] = None
        if raw_pid is not None:
            try:
                process_id = int(str(raw_pid).strip())
            except ValueError:
                warnings.append(f"Invalid process_id '{raw_pid}', skipping PID.")

        # File entities
        raw_file_path = extract_field_value(raw_data, mapping.file_path_fields) or proc_full_path
        file_path = sanitize_string(raw_file_path)

        raw_file_hash = extract_field_value(raw_data, mapping.file_hash_fields)
        file_hash, hash_metadata = validate_and_parse_file_hash(raw_file_hash)
        if hash_metadata.get("status") not in ("MISSING", "VALID"):
            warnings.append(f"Invalid record file hash: {hash_metadata.get('error', 'Malformed hash digest')}")

        # Network entities
        raw_ip = extract_field_value(raw_data, mapping.ip_fields)
        ip_address: Optional[str] = None
        if raw_ip is not None:
            try:
                ip_address = normalize_ip_address(raw_ip)
            except ValueError as ve:
                warnings.append(str(ve))

        raw_port = extract_field_value(raw_data, mapping.port_fields)
        port: Optional[int] = None
        if raw_port is not None:
            try:
                port = normalize_port(raw_port)
            except ValueError as ve:
                warnings.append(str(ve))

        raw_proto = extract_field_value(raw_data, mapping.protocol_fields)
        protocol = normalize_protocol(raw_proto)

        # Action & Status
        raw_action = extract_field_value(raw_data, mapping.action_fields)
        action = normalize_action(raw_action)

        raw_status = extract_field_value(raw_data, mapping.status_fields)
        status = normalize_status(raw_status)

        # 4. Construct attributes payload (Preserving original fields and unmapped items)
        attributes: Dict[str, Any] = {
            "source_format": raw_record.source_format,
            "_raw_fields": {k: v for k, v in raw_data.items() if v is not None and str(v).strip() != ""},
        }
        if hash_metadata.get("status") != "MISSING":
            attributes["hash_metadata"] = hash_metadata

        # If timestamp failed, return invalid result
        if errors or normalized_ts is None:
            return NormalizationResult(
                is_valid=False,
                record_offset=raw_record.record_offset,
                errors=errors,
                warnings=warnings,
            )

        norm_evd = NormalizedEvidence(
            investigation_id=investigation_id,
            source_id=raw_record.source_id,
            raw_record_offset=raw_record.record_offset,
            timestamp=normalized_ts,
            event_type=normalized_event,
            source_type=source_type,
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            process_id=process_id,
            process_name=process_name,
            parent_process_name=parent_process_name,
            file_path=file_path,
            file_hash=file_hash,
            ip_address=ip_address,
            port=port,
            protocol=protocol,
            action=action,
            status=status,
            attributes=attributes,
            normalized_at=datetime.now(timezone.utc),
        )

        # Final semantic validation
        val_errors = validate_normalized_evidence(norm_evd)
        if val_errors:
            return NormalizationResult(
                is_valid=False,
                record_offset=raw_record.record_offset,
                errors=val_errors,
                warnings=warnings,
            )

        return NormalizationResult(
            is_valid=True,
            evidence=norm_evd,
            record_offset=raw_record.record_offset,
            warnings=warnings,
        )

    def normalize_source(
        self,
        db: Session,
        source_id: uuid.UUID,
        source_type_override: Optional[str] = None,
    ) -> BatchNormalizationSummary:
        """Batch normalize all raw records from an EvidenceSource with strict atomic transaction semantics."""
        start_time = time.perf_counter()

        source = db.get(EvidenceSource, source_id)
        if not source:
            raise NotFoundError(f"EvidenceSource '{source_id}' not found.")

        # Same-source concurrency guard
        guard_key = f"norm:{source_id}"
        if not analysis_concurrency_guard.acquire(guard_key, max_concurrent=1):
            raise NormalizationError(f"Source '{source_id}' is currently being normalized by another process.")

        try:
            # Check if source is already processing
            if source.ingestion_status == "PROCESSING":
                logger.warning(f"Source {source_id} is in PROCESSING status")

            investigation_id = source.investigation_id
            ingestion_service = IngestionService(
                staging_dir=self.staging_dir,
                source_dir=self.source_dir,
            )
            raw_stream = ingestion_service.get_raw_record_stream(db, source_id)

            # Retry safety: Atomically clean previous normalized evidence and dependent analytical entities for this source
            old_evidence_ids = [r[0] for r in db.query(Evidence.id).filter_by(source_id=source_id).all()]
            if old_evidence_ids:
                from app.models.associations import FindingEvidence, ActivityEvidence
                from app.models.finding import Finding
                from app.models.relationship import Relationship
                from app.models.activity import Activity
                from app.models.priority_result import PriorityResult

                # 1. Find findings that solely rely on these evidence records
                finding_ids_with_old_evd = [
                    r[0] for r in db.query(FindingEvidence.finding_id)
                    .filter(FindingEvidence.evidence_id.in_(old_evidence_ids))
                    .distinct().all()
                ]

                # 2. Find activities that rely on these evidence records
                activity_ids_with_old_evd = [
                    r[0] for r in db.query(ActivityEvidence.activity_id)
                    .filter(ActivityEvidence.evidence_id.in_(old_evidence_ids))
                    .distinct().all()
                ]

                # 3. Delete relationships involving these evidence records
                db.query(Relationship).filter(
                    (Relationship.source_evidence_id.in_(old_evidence_ids)) |
                    (Relationship.target_evidence_id.in_(old_evidence_ids))
                ).delete(synchronize_session=False)

                # 4. Delete PriorityResults for artifact targets
                db.query(PriorityResult).filter(
                    PriorityResult.target_type == "ARTIFACT",
                    PriorityResult.target_id.in_(old_evidence_ids)
                ).delete(synchronize_session=False)

                # 5. Delete PriorityResults for activity targets
                if activity_ids_with_old_evd:
                    db.query(PriorityResult).filter(
                        PriorityResult.target_type == "ACTIVITY",
                        PriorityResult.target_id.in_(activity_ids_with_old_evd)
                    ).delete(synchronize_session=False)

                # 6. Delete FindingEvidence associations
                db.query(FindingEvidence).filter(
                    FindingEvidence.evidence_id.in_(old_evidence_ids)
                ).delete(synchronize_session=False)

                # 7. Delete ActivityEvidence associations (explicitly, though cascade does it)
                db.query(ActivityEvidence).filter(
                    ActivityEvidence.evidence_id.in_(old_evidence_ids)
                ).delete(synchronize_session=False)

                # 8. Delete Findings that have no remaining supporting evidence
                for fid in finding_ids_with_old_evd:
                    remaining = db.query(FindingEvidence).filter_by(finding_id=fid).count()
                    if remaining == 0:
                        db.query(PriorityResult).filter_by(target_id=fid).delete(synchronize_session=False)
                        db.query(Finding).filter_by(id=fid).delete(synchronize_session=False)

                # 9. Delete Activities that have no remaining supporting evidence
                for act_id in activity_ids_with_old_evd:
                    remaining = db.query(ActivityEvidence).filter_by(activity_id=act_id).count()
                    if remaining == 0:
                        db.query(Activity).filter_by(id=act_id).delete(synchronize_session=False)

                # 10. Delete Evidence records
                db.query(Evidence).filter_by(source_id=source_id).delete(synchronize_session=False)
                db.flush()

            total_records = 0
            normalized_count = 0
            rejected_count = 0
            total_warnings = 0
            summary_errors: List[str] = []

            batch_to_insert: List[Evidence] = []

            for raw_record in raw_stream:
                total_records += 1
                result = self.normalize_record(
                    raw_record=raw_record,
                    investigation_id=investigation_id,
                    source_type_override=source_type_override or source.file_format,
                )

                if result.is_valid and result.evidence:
                    norm = result.evidence
                    evd_entity = Evidence(
                        investigation_id=norm.investigation_id,
                        source_id=norm.source_id,
                        raw_record_offset=norm.raw_record_offset,
                        timestamp=norm.timestamp,
                        event_type=norm.event_type,
                        source_type=norm.source_type,
                        user_id=norm.user_id,
                        device_id=norm.device_id,
                        session_id=norm.session_id,
                        process_id=norm.process_id,
                        process_name=norm.process_name,
                        parent_process_name=norm.parent_process_name,
                        file_path=norm.file_path,
                        file_hash=norm.file_hash,
                        ip_address=norm.ip_address,
                        port=norm.port,
                        protocol=norm.protocol,
                        action=norm.action,
                        status=norm.status,
                        attributes=norm.attributes,
                        normalized_at=norm.normalized_at or datetime.now(timezone.utc),
                    )
                    batch_to_insert.append(evd_entity)
                    normalized_count += 1
                else:
                    rejected_count += 1
                    if len(summary_errors) < 10:
                        summary_errors.append(f"Record offset {result.record_offset}: {'; '.join(result.errors)}")

                total_warnings += len(result.warnings)

                if len(batch_to_insert) >= self.batch_size:
                    db.add_all(batch_to_insert)
                    db.flush()
                    batch_to_insert.clear()

            # Flush remaining records
            if batch_to_insert:
                db.add_all(batch_to_insert)
                db.flush()
                batch_to_insert.clear()

            # Atomic commit of all normalized evidence records
            status_str = "COMPLETED" if rejected_count == 0 else "COMPLETED_WITH_WARNINGS"
            source.ingestion_status = "COMPLETED"
            db.commit()

            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.info(
                f"Normalized Source {source_id}: {normalized_count}/{total_records} records persisted, {rejected_count} rejected in {duration_ms}ms"
            )

            return BatchNormalizationSummary(
                source_id=source_id,
                investigation_id=investigation_id,
                total_records=total_records,
                normalized_records=normalized_count,
                rejected_records=rejected_count,
                warning_count=total_warnings,
                duration_ms=duration_ms,
                status=status_str,
                errors=summary_errors,
            )

        except Exception as exc:
            # Policy A: Atomic source normalization rollback
            logger.error(f"Batch normalization failed for Source {source_id}: {exc}")
            try:
                # Remove uncommitted evidence entities from session
                for obj in list(db.new):
                    if isinstance(obj, Evidence):
                        db.expunge(obj)
                # Ensure any flush is cleaned up for this source's evidence
                db.query(Evidence).filter_by(source_id=source_id).delete()
                # Update source status to FAILED
                failed_source = db.get(EvidenceSource, source_id)
                if failed_source:
                    failed_source.ingestion_status = "FAILED"
                db.commit()
            except Exception as inner_exc:
                logger.warning(f"Could not update status to FAILED for Source {source_id}: {inner_exc}")
                db.rollback()

            raise NormalizationError(f"Normalization failed: {str(exc)}")

        finally:
            analysis_concurrency_guard.release(guard_key)
