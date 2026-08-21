"""Activity SQLAlchemy domain model."""

import uuid
from datetime import datetime
from typing import List, TYPE_CHECKING
from sqlalchemy import (
    String,
    Integer,
    DateTime,
    ForeignKey,
    Index,
    CheckConstraint,
    JSON,
    Uuid,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.investigation import Investigation
    from app.models.evidence import Evidence
    from app.models.finding import Finding

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")
GUID_TYPE = Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql")


class Activity(Base):
    """Investigation activity / contextual evidence thread entity."""

    __tablename__ = "activities"

    __table_args__ = (
        CheckConstraint("start_time <= end_time", name="chk_activity_time_bounds"),
        CheckConstraint("evidence_count >= 0", name="chk_activity_evidence_count"),
        CheckConstraint("finding_count >= 0", name="chk_activity_finding_count"),
        CheckConstraint(
            "status IN ('NEW', 'REVIEWING', 'REVIEWED', 'DISMISSED')",
            name="chk_activity_status",
        ),
        Index("idx_activities_investigation_start", "investigation_id", "start_time"),
        Index("idx_activities_investigation_status", "investigation_id", "status"),
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
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    activity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="NEW")
    context_attributes: Mapped[dict] = mapped_column(
        JSON_TYPE,
        nullable=False,
        default=dict,
    )
    activity_fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        unique=True,
        index=True,
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="activities",
    )
    evidence_items: Mapped[List["Evidence"]] = relationship(
        "Evidence",
        secondary="activity_evidence",
        back_populates="activities",
        lazy="select",
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        secondary="activity_findings",
        back_populates="activities",
        lazy="select",
    )
