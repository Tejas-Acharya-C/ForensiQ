"""Security baseline, password hashing, and JWT token utilities for ForensiQ.

Core Principles:
1. Secrets are loaded strictly from environment variables via Settings.
2. Uploaded evidence files reside in isolated staging directories with UUID naming.
3. Errors must never leak system filesystem paths, credentials, or internal stack traces.
4. Passwords are never stored in plaintext and are hashed using bcrypt.
5. JWTs are signed using HMAC-SHA256 with strict expiration and claim validation.
"""

import os
import posixpath
import re
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

import bcrypt
from jose import jwt, JWTError, ExpiredSignatureError

from app.core.config import get_settings
from app.core.errors import AuthenticationError


def hash_password(password: str) -> str:
    """Securely hash a plaintext password using bcrypt with salt."""
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash in constant time."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def create_access_token(
    user_id: uuid.UUID | str,
    email: Optional[str] = None,

    expires_delta: Optional[timedelta] = None,
) -> str:
    """Generate a signed JWT access token containing standard claims."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))

    to_encode: Dict[str, Any] = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    if email:
        to_encode["email"] = email


    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token signature, expiration, and payload."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": True, "verify_sub": True},
        )
        sub: Optional[str] = payload.get("sub")
        if not sub:
            raise AuthenticationError("Invalid token payload: missing subject identifier.")
        return payload
    except ExpiredSignatureError:
        raise AuthenticationError("Authentication token has expired. Please log in again.")
    except JWTError:
        raise AuthenticationError("Could not validate authentication credentials.")


def sanitize_filename(filename: str) -> str:
    """Sanitize uploaded filenames across all OS platforms to prevent directory traversal and injection attacks."""
    if not filename or not isinstance(filename, str):
        return "unnamed_evidence"

    # Neutralize null bytes and whitespace
    cleaned = filename.replace("\x00", "").strip()
    if not cleaned:
        return "unnamed_evidence"

    # Normalize Windows drive letter if present (e.g., C:\...)
    cleaned = re.sub(r"^[a-zA-Z]:", "", cleaned)

    # Normalize both Windows and POSIX path separators to forward slash
    normalized = cleaned.replace("\\", "/")

    # Extract basename deterministically using POSIX path semantics
    base_name = posixpath.basename(normalized.rstrip("/"))

    # Strip any characters that are not alphanumeric, dots, underscores, or hyphens
    sanitized = re.sub(r"[^a-zA-Z0-9._-]", "_", base_name)

    # Strip leading dots to neutralize hidden files and directory traversal remnants
    sanitized = sanitized.lstrip(".")

    return sanitized or "unnamed_evidence"


def validate_file_path(base_dir: Path, target_path: Path) -> bool:
    """Verify that a target file path remains safely within the designated base directory."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return resolved_target.is_relative_to(resolved_base)
    except (ValueError, RuntimeError):
        return False
