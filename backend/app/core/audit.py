"""Security audit logger for privileged operations, auth events, and access violations (Phase 9G)."""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from app.core.logging import get_logger

audit_logger = get_logger("security_audit")


def log_security_event(
    event_type: str,
    user_id: Optional[uuid.UUID | str] = None,
    client_ip: Optional[str] = None,
    investigation_id: Optional[uuid.UUID | str] = None,
    details: Optional[Dict[str, Any]] = None,
):
    """Log a security-sensitive event without exposing credentials, tokens, or raw evidence."""
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "user_id": str(user_id) if user_id else None,
        "client_ip": client_ip or "unknown",
        "investigation_id": str(investigation_id) if investigation_id else None,
        "details": details or {},
    }
    audit_logger.info(f"SECURITY_AUDIT: {event_type}", extra=payload)
