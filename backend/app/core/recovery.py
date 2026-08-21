"""Operational failure recovery utilities for ForensiQ (Phase 9F)."""

import uuid
from typing import List
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.evidence_source import EvidenceSource

logger = get_logger("failure_recovery")


def reset_stale_processing_sources(db: Session, investigation_id: uuid.UUID) -> int:
    """Reset any EvidenceSource stuck in 'PROCESSING' status back to 'FAILED' or 'PENDING' to allow safe retry."""
    stale_sources = (
        db.query(EvidenceSource)
        .filter_by(investigation_id=investigation_id, ingestion_status="PROCESSING")
        .all()
    )
    if not stale_sources:
        return 0

    count = 0
    for src in stale_sources:
        logger.warning(f"Resetting stale processing status for EvidenceSource {src.id} to FAILED")
        src.ingestion_status = "FAILED"
        count += 1

    db.commit()
    return count
