"""Investigation SQLAlchemy domain model."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Text, DateTime, CheckConstraint, Uuid, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.evidence_source import EvidenceSource
    from app.models.evidence import Evidence
    from app.models.finding import Finding
    from app.models.relationship import Relationship
    from app.models.activity import Activity
    from app.models.priority_result import PriorityResult


class Investigation(Base):
    """Investigation case container entity."""

    __tablename__ = "investigations"

    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN', 'CLOSED', 'ARCHIVED')",
            name="chk_investigation_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        primary_key=True,
        default=uuid.uuid4,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    case_number: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN")
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
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
    owner: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="investigations",
        lazy="select",
    )
    evidence_sources: Mapped[List["EvidenceSource"]] = relationship(
        "EvidenceSource",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="select",
    )
    evidence: Mapped[List["Evidence"]] = relationship(
        "Evidence",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="select",
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="select",
    )
    relationships: Mapped[List["Relationship"]] = relationship(
        "Relationship",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="select",
    )
    activities: Mapped[List["Activity"]] = relationship(
        "Activity",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="select",
    )
    priority_results: Mapped[List["PriorityResult"]] = relationship(
        "PriorityResult",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="select",
    )
