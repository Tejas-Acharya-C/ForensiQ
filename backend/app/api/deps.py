"""Investigation-level access helpers and analysis rate-limiting dependency.

Authentication removed (local single-investigator mode).

Retained:
  check_investigation_access — existence check; raises NotFoundError when the
      investigation UUID is not found.  Called by every investigation-scoped
      route to ensure a 404 is returned before any work is attempted.
  check_source_access        — existence check for an EvidenceSource; also
      validates that its parent investigation exists.
  rate_limit_analysis        — IP-based sliding-window rate limiter for
      expensive analytical endpoints.  Prevents accidental or scripted burst
      abuse without requiring user identity.
"""

import uuid
from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import NotFoundError, RateLimitError
from app.core.logging import get_logger
from app.core.rate_limit import analysis_rate_limiter
from app.database.session import get_db
from app.models.evidence_source import EvidenceSource
from app.models.investigation import Investigation

logger = get_logger("deps")


def check_investigation_access(
    investigation_id: uuid.UUID,
    db: Session,
) -> Investigation:
    """Verify that an investigation with the given UUID exists.

    Raises NotFoundError (HTTP 404) when the investigation is not found.
    Returns the Investigation ORM object so callers can use it directly.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise NotFoundError(f"Investigation '{investigation_id}' not found.")
    return inv


def check_source_access(
    source_id: uuid.UUID,
    db: Session,
) -> EvidenceSource:
    """Verify that an EvidenceSource with the given UUID exists.

    Also confirms that the source's parent investigation exists, so that
    source-scoped routes always operate within a valid investigation context.
    Raises NotFoundError (HTTP 404) when either is missing.
    """
    source = db.query(EvidenceSource).filter(EvidenceSource.id == source_id).first()
    if not source:
        raise NotFoundError(f"EvidenceSource '{source_id}' not found.")
    # Confirm parent investigation still exists
    check_investigation_access(source.investigation_id, db)
    return source


def rate_limit_analysis(
    request: Request,
) -> None:
    """IP-based sliding-window rate limiter for expensive analytical endpoints.

    Keyed by client IP address.  Limit is RATE_LIMIT_ANALYSIS_PER_MINUTE
    requests per 60-second window (default 30).  Raises RateLimitError
    (HTTP 429) when the limit is exceeded.
    """
    settings = get_settings()
    client_ip = request.client.host if request.client else "unknown"
    key = f"analysis:{client_ip}"
    allowed, retry_after = analysis_rate_limiter.is_allowed(
        key=key,
        max_requests=settings.RATE_LIMIT_ANALYSIS_PER_MINUTE,
        window_seconds=60,
    )
    if not allowed:
        logger.warning(f"Analysis rate limit exceeded for IP {client_ip}")
        raise RateLimitError(
            f"Analysis rate limit exceeded ({settings.RATE_LIMIT_ANALYSIS_PER_MINUTE} req/min). "
            f"Please retry after {retry_after} seconds."
        )
