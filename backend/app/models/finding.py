"""Finding SQLAlchemy domain model."""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, TYPE_CHECKING
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
    from app.models.evidence import Evidence
    from app.models.activity import Activity

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")
GUID_TYPE = Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql")


class Finding(Base):
    """Analytical finding (Deterministic Rule, IOC Match, or ML Anomaly Signal)."""

    __tablename__ = "findings"

    __table_args__ = (
        CheckConstraint("severity_score >= 0.0 AND severity_score <= 1.0", name="chk_finding_severity"),
        CheckConstraint(
            "finding_type IN ('RULE_MATCH', 'IOC_MATCH', 'ML_ANOMALY')",
            name="chk_finding_type",
        ),
        Index("idx_findings_investigation_type", "investigation_id", "finding_type"),
        Index("idx_findings_severity", "investigation_id", "severity_score"),
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
    finding_type: Mapped[str] = mapped_column(String(32), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    severity_score: Mapped[float] = mapped_column(Float, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    optional_mitre_tags: Mapped[List[str] | Dict[str, Any]] = mapped_column(
        JSON_TYPE,
        nullable=False,
        default=list,
    )
    detection_fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        unique=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="findings",
    )
    evidence_items: Mapped[List["Evidence"]] = relationship(
        "Evidence",
        secondary="finding_evidence",
        back_populates="findings",
        lazy="select",
    )
    activities: Mapped[List["Activity"]] = relationship(
        "Activity",
        secondary="activity_findings",
        back_populates="findings",
        lazy="select",
    )
