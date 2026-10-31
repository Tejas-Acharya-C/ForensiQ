"""User SQLAlchemy domain model for authentication and access control."""

import uuid
from datetime import datetime, timezone
from typing import List, TYPE_CHECKING
from sqlalchemy import String, Boolean, DateTime, CheckConstraint, Uuid
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.investigation import Investigation


class User(Base):
    """User account entity for authentication."""

    __tablename__ = "users"

    __table_args__ = ()

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        primary_key=True,
        default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    # back_populates removed — the Investigation.owner relationship was
    # removed when authentication was removed.  The users table and the
    # owner_user_id FK remain in the schema; this relationship is simply
    # no longer navigated from the application layer.
    investigations: Mapped[List["Investigation"]] = relationship(
        "Investigation",
        cascade="all",
        lazy="select",
    )
