"""Forensic evidence storage and integrity service for ForensiQ (Phase 9B)."""

import hashlib
import os
import shutil
import uuid
from pathlib import Path
from typing import Optional

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import validate_file_path
from app.models.evidence_source import EvidenceSource

logger = get_logger("evidence_storage")


class EvidenceStorage:
    """Service managing immutable source storage, atomic staging movement, and SHA-256 integrity verification."""

    def __init__(
        self,
        staging_dir: Optional[Path] = None,
        source_dir: Optional[Path] = None,
    ):
        settings = get_settings()
        self.staging_dir = (staging_dir or settings.UPLOAD_STAGING_DIR).resolve()
        self.source_dir = (source_dir or settings.UPLOAD_SOURCE_DIR).resolve()

        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.source_dir.mkdir(parents=True, exist_ok=True)

    def create_staging_path(self) -> Path:
        """Generate a secure, unique temporary staging file path."""
        temp_id = uuid.uuid4()
        return self.staging_dir / f"{temp_id}.tmp"

    def compute_file_sha256(self, file_path: Path) -> str:
        """Calculate SHA-256 hash across the exact bytes of a file in 64KB chunks."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(64 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()

    def store_source(self, source_id: uuid.UUID, staged_path: Path) -> str:
        """Atomically move verified staged file into immutable source storage data/sources/<source_id>/original.
        
        Returns the relative internal storage path string (e.g. "sources/<source_id>/original").
        """
        source_dir = self.source_dir / str(source_id)
        source_dir.mkdir(parents=True, exist_ok=True)
        dest_path = source_dir / "original"

        # Atomic move (or copy + unlink across filesystems)
        shutil.move(str(staged_path), str(dest_path))

        # Return standardized relative storage path
        rel_path = dest_path.relative_to(self.source_dir.parent).as_posix()
        logger.info(f"Source {source_id} stored authoritatively at {dest_path}")
        return rel_path

    def get_source_path(self, source: EvidenceSource) -> Path:
        """Resolve and validate the absolute filesystem path for an authoritative source artifact."""
        if source.storage_path:
            # Resolved relative to root data dir
            candidate = (self.source_dir.parent / source.storage_path).resolve()
        else:
            # Fallback convention data/sources/<source_id>/original
            candidate = (self.source_dir / str(source.id) / "original").resolve()

        # Path validation: ensure the target resides strictly within source_dir or root storage
        if not validate_file_path(self.source_dir, candidate) and not validate_file_path(self.source_dir.parent, candidate):
            raise PermissionError(f"Storage path traversal detected for source {source.id}")

        if not candidate.exists():
            raise FileNotFoundError(f"Authoritative source artifact for source {source.id} is missing.")

        return candidate

    def verify_source_integrity(self, source: EvidenceSource) -> bool:
        """Verify that the stored source artifact's SHA-256 matches the recorded sha256_hash."""
        try:
            path = self.get_source_path(source)
            actual_hash = self.compute_file_sha256(path)
            is_valid = (actual_hash.lower() == source.sha256_hash.lower())
            if not is_valid:
                logger.error(
                    f"Integrity violation on Source {source.id}: "
                    f"expected {source.sha256_hash}, actual {actual_hash}"
                )
            return is_valid
        except Exception as exc:
            logger.error(f"Integrity check error on Source {source.id}: {exc}")
            return False

    def cleanup_staging_file(self, path: Optional[Path]):
        """Safely remove a temporary staging file without throwing exceptions."""
        if path and isinstance(path, Path):
            try:
                # Never delete files outside of staging_dir
                if validate_file_path(self.staging_dir, path.resolve()):
                    path.unlink(missing_ok=True)
            except Exception as exc:
                logger.warning(f"Could not clean up temporary staging file {path}: {exc}")
