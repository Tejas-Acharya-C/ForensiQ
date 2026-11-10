"""Evidence ingestion orchestration service (Hardened for Phase 9B)."""

import hashlib
import os
import shutil
import uuid
from pathlib import Path
from typing import BinaryIO, Optional, Tuple, Iterator
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import sanitize_filename, validate_file_path
from app.core.storage import EvidenceStorage
from app.core.errors import NotFoundError
from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.ingestion.contracts import IngestionResult, ValidationResult, RawEvidenceRecord
from app.ingestion.detector import detect_file_format
from app.ingestion.parser import BaseEvidenceParser, CSVParser, JSONParser
from app.ingestion.exceptions import (
    IngestionError,
    UnsupportedFileTypeError,
    InvalidFileError,
    EmptyFileError,
    FileTooLargeError,
    DuplicateSourceError,
)

logger = get_logger("ingestion_service")


class IngestionService:
    """Service orchestrating evidence intake, hashing, validation, staging, and immutable storage."""

    def __init__(
        self,
        staging_dir: Optional[Path] = None,
        source_dir: Optional[Path] = None,
    ):
        settings = get_settings()
        self.storage = EvidenceStorage(staging_dir=staging_dir, source_dir=source_dir)
        self.max_size_bytes = settings.MAX_INGESTION_FILE_SIZE_MB * 1024 * 1024

    def _get_parser(self, format_name: str) -> BaseEvidenceParser:
        """Select appropriate parser based on detected format."""
        if format_name == "CSV":
            return CSVParser()
        elif format_name in ["JSON", "JSONL"]:
            return JSONParser()
        else:
            raise UnsupportedFileTypeError(f"Unsupported evidence file format: {format_name}")

    def compute_sha256_and_stage(
        self,
        file_obj: BinaryIO,
    ) -> Tuple[Path, str, int]:
        """Stream uploaded file to an isolated temporary staging file and compute SHA-256 hash."""
        staged_path = self.storage.create_staging_path()
        hasher = hashlib.sha256()
        bytes_written = 0

        try:
            with open(staged_path, "wb") as out_f:
                while chunk := file_obj.read(64 * 1024):  # 64 KB streaming chunks
                    bytes_written += len(chunk)
                    if bytes_written > self.max_size_bytes:
                        raise FileTooLargeError(
                            f"File exceeds maximum allowed size ({self.max_size_bytes // (1024*1024)} MB)."
                        )
                    hasher.update(chunk)
                    out_f.write(chunk)

            if bytes_written == 0:
                self.storage.cleanup_staging_file(staged_path)
                raise EmptyFileError("Uploaded evidence file contains zero bytes.")

            sha256_hash = hasher.hexdigest()
            return staged_path, sha256_hash, bytes_written

        except Exception as exc:
            self.storage.cleanup_staging_file(staged_path)
            if isinstance(exc, (FileTooLargeError, EmptyFileError)):
                raise exc
            raise InvalidFileError(f"Failed while staging file: {str(exc)}")

    def ingest_file(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        file_obj: BinaryIO,
        original_filename: str,
        allow_duplicates: bool = False,
    ) -> IngestionResult:
        """Orchestrate the complete Phase 9B ingestion and immutable storage lifecycle."""
        # 1. Verify Investigation exists
        investigation = db.get(Investigation, investigation_id)
        if not investigation:
            raise NotFoundError(f"Investigation with ID '{investigation_id}' not found.")

        # 2. Stage file & compute SHA-256
        staged_path, sha256_hash, file_size = self.compute_sha256_and_stage(file_obj)

        try:
            logger.info(
                f"Staged upload '{original_filename}' (SHA-256: {sha256_hash[:12]}..., Size: {file_size} bytes) for Investigation {investigation_id}"
            )

            # 3. Check for Duplicate Source File within same investigation
            existing_source = (
                db.query(EvidenceSource)
                .filter_by(investigation_id=investigation_id, sha256_hash=sha256_hash)
                .first()
            )
            if existing_source and not allow_duplicates:
                raise DuplicateSourceError(
                    f"An identical evidence file (SHA-256: {sha256_hash}) already exists in this investigation.",
                    details={
                        "existing_source_id": str(existing_source.id),
                        "filename": existing_source.filename,
                        "sha256_hash": sha256_hash,
                    },
                )

            # 4. Format Detection
            detected_fmt, _ = detect_file_format(staged_path, original_filename)
            if detected_fmt in ["UNSUPPORTED", "EMPTY"]:
                raise UnsupportedFileTypeError(
                    f"Could not determine a supported format for file '{original_filename}'."
                )

            # 5. Create EvidenceSource entity in PROCESSING status
            source = EvidenceSource(
                investigation_id=investigation_id,
                filename=sanitize_filename(original_filename),
                file_format=detected_fmt,
                sha256_hash=sha256_hash,
                file_size_bytes=file_size,
                total_records=0,
                ingestion_status="PROCESSING",
            )
            db.add(source)
            db.commit()
            db.refresh(source)

            # 6. Structural Validation using selected parser
            parser = self._get_parser(detected_fmt)
            validation: ValidationResult = parser.validate_structure(staged_path)

            if not validation.is_valid:
                source.ingestion_status = "FAILED"
                db.commit()
                raise InvalidFileError(
                    f"Structural validation failed: {'; '.join(validation.errors)}",
                    details={"errors": validation.errors, "warnings": validation.warnings},
                )

            # 7. Move verified staged file to immutable storage data/sources/<source_id>/original
            rel_storage_path = self.storage.store_source(source.id, staged_path)

            # 8. Update EvidenceSource with final completed metadata and storage_path
            source.storage_path = rel_storage_path
            source.total_records = validation.estimated_record_count
            source.ingestion_status = "COMPLETED"
            db.commit()
            db.refresh(source)

            logger.info(
                f"Ingestion completed for source {source.id}: {source.total_records} records stored at {rel_storage_path}."
            )

            return IngestionResult(
                source_id=source.id,
                investigation_id=investigation_id,
                filename=source.filename,
                file_format=source.file_format,
                sha256_hash=source.sha256_hash,
                file_size_bytes=source.file_size_bytes,
                total_records=source.total_records,
                ingestion_status=source.ingestion_status,
                warnings=validation.warnings,
            )

        except Exception as exc:
            # Ensure temporary staging file is cleaned up on any error
            self.storage.cleanup_staging_file(staged_path)
            if "source" in locals() and source.id:
                try:
                    source.ingestion_status = "FAILED"
                    db.commit()
                except Exception:
                    db.rollback()

            if isinstance(exc, IngestionError):
                raise exc
            raise InvalidFileError(f"Ingestion failure: {str(exc)}")

    def get_raw_record_stream(
        self,
        db: Session,
        source_id: uuid.UUID,
    ) -> Iterator[RawEvidenceRecord]:
        """Provide a streaming iterator of raw records strictly from the source's authoritative storage artifact."""
        source = db.get(EvidenceSource, source_id)
        if not source:
            raise NotFoundError(f"EvidenceSource with ID '{source_id}' not found.")

        # 1. Resolve authoritative source path
        source_path = self.storage.get_source_path(source)

        # 2. Re-verify SHA-256 before streaming
        if not self.storage.verify_source_integrity(source):
            raise InvalidFileError(
                f"Forensic integrity check failed for source '{source_id}'. Recorded hash mismatch."
            )

        # 3. Stream records
        parser = self._get_parser(source.file_format)
        return parser.iter_records(source_path, source_id=source_id)
