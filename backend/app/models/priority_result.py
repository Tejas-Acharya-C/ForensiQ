"""PriorityResult SQLAlchemy domain model."""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, TYPE_CHECKING
from sqlalchemy import (
    String,
    Text,
    Float,
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

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")
GUID_TYPE = Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql")


class PriorityResult(Base):
    """Prioritization output for baseline artifacts or proposed activities."""

    __tablename__ = "priority_results"

    __table_args__ = (
        CheckConstraint(
            "priority_score >= 0.0 AND priority_score <= 100.0",
            name="chk_priority_score_range",
        ),
        CheckConstraint(
            "target_type IN ('ARTIFACT', 'ACTIVITY')",
            name="chk_priority_target_type",
        ),
        CheckConstraint(
            "priority_tier IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')",
            name="chk_priority_tier",
        ),
        CheckConstraint(
            "method_type IN ('BASELINE_INDEPENDENT', 'PROPOSED_CONTEXTUAL')",
            name="chk_priority_method_type",
        ),
        Index("idx_priority_target", "investigation_id", "target_type", "target_id"),
        Index("idx_priority_score", "investigation_id", "priority_score"),
        Index("idx_priority_inv_method", "investigation_id", "method_type"),
        Index("idx_priority_inv_tier", "investigation_id", "priority_tier"),
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
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(GUID_TYPE, nullable=False)
    priority_score: Mapped[float] = mapped_column(Float, nullable=False)
    priority_tier: Mapped[str] = mapped_column(String(32), nullable=False)
    factor_breakdown: Mapped[Dict[str, Any]] = mapped_column(
        JSON_TYPE,
        nullable=False,
        default=dict,
    )
    explanation_text: Mapped[str] = mapped_column(Text, nullable=False)
    method_type: Mapped[str] = mapped_column(String(32), nullable=False)
    priority_fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        unique=True,
        index=True,
    )
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="priority_results",
    )
