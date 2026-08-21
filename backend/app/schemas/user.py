"""Pydantic schemas for authentication and user management."""

import uuid
from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    """Payload for creating a new user account."""
    email: str = Field(..., pattern=r"^[^@]+@[^@]+\.[^@]+$", description="Unique email address")
    password: str = Field(..., min_length=8, description="Plaintext password (min 8 chars)")
    is_active: bool = Field(True, description="Account active status")


class UserRead(BaseModel):
    """Public representation of a User entity."""
    id: uuid.UUID
    email: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserLogin(BaseModel):
    """Payload for API authentication / login."""
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")


class TokenResponse(BaseModel):
    """JWT bearer token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: UserRead


class TokenPayload(BaseModel):
    """Decoded JWT claims payload."""
    sub: str

    iat: int
    exp: int
    email: Optional[str] = None
