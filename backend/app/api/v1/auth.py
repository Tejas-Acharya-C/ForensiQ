"""Authentication API router for ForensiQ Phase 9A."""

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.errors import AuthenticationError, ConflictError, RateLimitError
from app.core.logging import get_logger
from app.core.rate_limit import login_rate_limiter
from app.core.security import create_access_token, hash_password, verify_password
from app.database.session import get_db
from app.models.user import User
from app.schemas.user import TokenResponse, UserCreate, UserLogin, UserRead

logger = get_logger("auth_router")

router = APIRouter(prefix="/auth", tags=["Authentication & Access"])


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and issue JWT access token",
)
def login(
    payload: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Validate credentials with rate limiting and issue a signed JWT access token."""
    settings = get_settings()

    # Rate limiting by client IP and email
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"login:{client_ip}:{payload.email.lower()}"
    allowed, retry_after = login_rate_limiter.is_allowed(
        key=rate_key,
        max_requests=settings.RATE_LIMIT_LOGIN_PER_MINUTE,
        window_seconds=60,
    )
    if not allowed:
        logger.warning(
            f"Login rate limit exceeded for email={payload.email} from ip={client_ip}"
        )
        raise RateLimitError(
            f"Too many failed or repeated login attempts. Please retry after {retry_after} seconds."
        )

    # Lookup user
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user:
        logger.warning(f"Login failed: User not found for email={payload.email}")
        from app.core.audit import log_security_event
        log_security_event("AUTH_FAILURE", client_ip=client_ip, details={"reason": "user_not_found", "email": payload.email.lower()})
        raise AuthenticationError("Invalid email or password.")

    if not user.is_active:
        logger.warning(f"Login failed: Inactive user account for email={payload.email}")
        from app.core.audit import log_security_event
        log_security_event("AUTH_FAILURE", user_id=user.id, client_ip=client_ip, details={"reason": "inactive_account"})
        raise AuthenticationError("User account is inactive.")

    # Verify password hash
    if not verify_password(payload.password, user.password_hash):
        logger.warning(f"Login failed: Password mismatch for email={payload.email}")
        from app.core.audit import log_security_event
        log_security_event("AUTH_FAILURE", user_id=user.id, client_ip=client_ip, details={"reason": "invalid_credentials"})
        raise AuthenticationError("Invalid email or password.")

    # Reset rate limit counter on successful login
    login_rate_limiter.reset(rate_key)

    # Issue JWT token
    token = create_access_token(
        user_id=user.id,
        email=user.email,
    )

    from app.core.audit import log_security_event
    log_security_event("AUTH_SUCCESS", user_id=user.id, client_ip=client_ip, details={})

    logger.info(f"User login successful: {user.email}")

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        user=UserRead.model_validate(user),
    )


@router.get(
    "/me",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    summary="Get current authenticated user profile",
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> UserRead:
    """Return the profile of the currently authenticated user."""
    return UserRead.model_validate(current_user)


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Provision a new user account",
)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserRead:
    """Create a new user account."""
    existing = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing:
        raise ConflictError(f"User with email '{payload.email}' already exists.")

    password_hash = hash_password(payload.password)
    new_user = User(
        email=payload.email.lower(),
        password_hash=password_hash,

        is_active=payload.is_active,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info(f"User {current_user.email} created user {new_user.email}")
    return UserRead.model_validate(new_user)
