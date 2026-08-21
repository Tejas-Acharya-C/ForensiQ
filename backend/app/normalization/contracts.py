"""Normalization contracts and data structures."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional


@dataclass
class NormalizedEvidence:
    """Internal standardized evidence data contract matching the Common Evidence Schema."""
    investigation_id: uuid.UUID
    source_id: uuid.UUID
    raw_record_offset: int
    timestamp: datetime
    event_type: str
    source_type: str

    user_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None

    process_id: Optional[int] = None
    process_name: Optional[str] = None
    parent_process_name: Optional[str] = None

    file_path: Optional[str] = None
    file_hash: Optional[str] = None

    ip_address: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None

    action: Optional[str] = None
    status: Optional[str] = None

    attributes: Dict[str, Any] = field(default_factory=dict)
    normalized_at: Optional[datetime] = None


@dataclass
class NormalizationResult:
    """Outcome of normalizing a single RawEvidenceRecord."""
    is_valid: bool
    evidence: Optional[NormalizedEvidence] = None
    record_offset: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class BatchNormalizationSummary:
    """Summary of batch normalization operation across an entire EvidenceSource."""
    source_id: uuid.UUID
    investigation_id: uuid.UUID
    total_records: int
    normalized_records: int
    rejected_records: int
    warning_count: int
    duration_ms: float
    status: str
    errors: List[str] = field(default_factory=list)
