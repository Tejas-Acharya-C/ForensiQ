"""Ingestion contracts, models, and data transfer objects."""

import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class RawEvidenceRecord:
    """Lightweight raw record structure handed over to Phase 4 Normalization."""
    source_id: uuid.UUID
    record_offset: int
    raw_data: Dict[str, Any]
    source_format: str


@dataclass
class ValidationResult:
    """Structural validation result for an ingested evidence source file."""
    is_valid: bool
    detected_format: str
    estimated_record_count: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    preview_records: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class IngestionResult:
    """Outcome of an evidence file ingestion operation."""
    source_id: uuid.UUID
    investigation_id: uuid.UUID
    filename: str
    file_format: str
    sha256_hash: str
    file_size_bytes: int
    total_records: int
    ingestion_status: str
    warnings: List[str] = field(default_factory=list)
