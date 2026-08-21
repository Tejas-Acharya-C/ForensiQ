"""Semantic validation rules for Common Evidence Schema."""

from typing import List
from app.normalization.contracts import NormalizedEvidence


def validate_normalized_evidence(evd: NormalizedEvidence) -> List[str]:
    """Validate mandatory fields and value domains on a NormalizedEvidence instance.

    Returns:
        List of validation error strings (empty if valid).
    """
    errors: List[str] = []

    # Mandatory constraints
    if not evd.investigation_id:
        errors.append("Missing mandatory investigation_id.")
    if not evd.source_id:
        errors.append("Missing mandatory source_id.")
    if evd.raw_record_offset < 0:
        errors.append("raw_record_offset must be non-negative.")
    if not evd.timestamp:
        errors.append("Missing mandatory timestamp.")
    elif evd.timestamp.tzinfo is None:
        errors.append("Timestamp must be timezone-aware UTC.")
    if not evd.event_type:
        errors.append("Missing mandatory event_type.")
    if not evd.source_type:
        errors.append("Missing mandatory source_type.")

    # Numeric bounds
    if evd.port is not None and not (0 <= evd.port <= 65535):
        errors.append(f"Port {evd.port} out of range (0-65535).")

    return errors
