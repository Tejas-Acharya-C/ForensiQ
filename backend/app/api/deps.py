"""Authentication and Investigation-level authorization dependencies."""

import uuid
from typing import Callable, List, Optional
from fastapi import Depends, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AuthenticationError, AuthorizationError, NotFoundError, RateLimitError
from app.core.logging import get_logger
from app.core.rate_limit import analysis_rate_limiter, analysis_concurrency_guard
from app.core.security import decode_access_token
from app.database.session import get_db
from app.models.evidence_source import EvidenceSource
from app.models.investigation import Investigation
from app.models.user import User

logger = get_logger("auth_deps")

# Bearer scheme (auto_error=False allows returning custom sanitized JSON error)
security_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Extract and validate JWT Bearer token, returning the authenticated User."""
    if not credentials or not credentials.credentials:
        logger.warning("Unauthenticated request to protected endpoint", extra={"path": request.url.path})
        raise AuthenticationError("Authentication required. Please provide a valid Bearer token.")

    token = credentials.credentials
    payload = decode_access_token(token)
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise AuthenticationError("Malformed token claims.")

    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise AuthenticationError("Invalid user ID in token.")

    user = db.query(User).filter(User.id == user_uuid).first()
    if not user:
        logger.warning(f"User not found for token sub={user_id_str}")
        raise AuthenticationError("User account not found.")

    if not user.is_active:
        logger.warning(f"Inactive user attempt: {user.email}")
        raise AuthenticationError("User account is inactive.")

    # Attach user info to request state for access logging
    request.state.user_id = str(user.id)

    return user


def require_authenticated_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure request is made by an authenticated investigator/user."""
    return current_user





def check_investigation_access(
    investigation_id: uuid.UUID,
    db: Session,
    current_user: User,
) -> Investigation:
    """Verify that investigation exists and is accessible by the authenticated user."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise NotFoundError(f"Investigation '{investigation_id}' not found.")
    return inv


def check_source_access(
    source_id: uuid.UUID,
    db: Session,
    current_user: User,
) -> EvidenceSource:
    """Verify that evidence source exists via its parent investigation."""
    source = db.query(EvidenceSource).filter(EvidenceSource.id == source_id).first()
    if not source:
        raise NotFoundError(f"EvidenceSource '{source_id}' not found.")

    check_investigation_access(source.investigation_id, db, current_user)
    return source


def rate_limit_analysis(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """User-aware rate limiting dependency for expensive analytical endpoints."""
    settings = get_settings()
    key = f"analysis:{current_user.id}"
    allowed, retry_after = analysis_rate_limiter.is_allowed(
        key=key,
        max_requests=settings.RATE_LIMIT_ANALYSIS_PER_MINUTE,
        window_seconds=60,
    )
    if not allowed:
        logger.warning(f"Analysis rate limit exceeded for user {current_user.email}")
        raise RateLimitError(
            f"Analysis rate limit exceeded ({settings.RATE_LIMIT_ANALYSIS_PER_MINUTE} req/min). "
            f"Please retry after {retry_after} seconds."
        )
