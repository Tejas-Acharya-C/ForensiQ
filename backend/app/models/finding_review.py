"""FindingReview SQLAlchemy domain model for investigator triage."""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import (
    String,
    Text,
    DateTime,
    ForeignKey,
    Index,
    CheckConstraint,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, backref
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.investigation import Investigation
    from app.models.finding import Finding

GUID_TYPE = Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql")


class FindingReview(Base):
    """Investigator review decision and triage notes for a detected finding."""

    __tablename__ = "finding_reviews"

    __table_args__ = (
        CheckConstraint(
            "status IN ('NEW', 'REVIEWED', 'FALSE_POSITIVE', 'ESCALATED')",
            name="chk_finding_review_status",
        ),
        UniqueConstraint("investigation_id", "finding_id", name="uq_finding_review_inv_finding"),
        Index("idx_finding_reviews_investigation", "investigation_id"),
        Index("idx_finding_reviews_status", "investigation_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        GUID_TYPE,
        primary_key=True,
        default=uuid.uuid4,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        GUID_TYPE,
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        GUID_TYPE,
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="NEW",
    )
    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
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
    investigation: Mapped["Investigation"] = relationship("Investigation")
    finding: Mapped["Finding"] = relationship(
        "Finding",
        backref=backref("reviews", cascade="all, delete-orphan", passive_deletes=True),
        passive_deletes=True,
    )

