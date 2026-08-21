"""Evidence SQLAlchemy domain model (Common Evidence Schema)."""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, TYPE_CHECKING
from sqlalchemy import (
    String,
    Text,
    BigInteger,
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
    from app.models.evidence_source import EvidenceSource
    from app.models.finding import Finding
    from app.models.relationship import Relationship
    from app.models.activity import Activity


JSON_TYPE = JSON().with_variant(JSONB, "postgresql")
GUID_TYPE = Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql")


class Evidence(Base):
    """Normalized evidence record conforming to the Common Evidence Schema."""

    __tablename__ = "evidence"

    __table_args__ = (
        CheckConstraint("raw_record_offset >= 0", name="chk_evidence_raw_offset"),
        # Optimized composite indexes for timeline, correlation, and entity lookups
        Index("idx_evidence_investigation_ts", "investigation_id", "timestamp"),
        Index("idx_evidence_user", "investigation_id", "user_id"),
        Index("idx_evidence_device", "investigation_id", "device_id"),
        Index("idx_evidence_ip", "investigation_id", "ip_address"),
        Index("idx_evidence_event_type", "investigation_id", "event_type"),
        Index("idx_evidence_source_offset", "source_id", "raw_record_offset"),
    )

    # Core Identifiers & Provenance
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
    source_id: Mapped[uuid.UUID] = mapped_column(
        GUID_TYPE,
        ForeignKey("evidence_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    raw_record_offset: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)

    # Identity & Host Anchors
    user_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Process Execution Anchors
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    parent_process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # File System Anchors
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Network Anchors
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Operational Context
    action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Polymorphic Extensions & Metadata
    attributes: Mapped[Dict[str, Any]] = mapped_column(
        JSON_TYPE,
        nullable=False,
        default=dict,
    )
    normalized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="evidence",
    )
    source: Mapped["EvidenceSource"] = relationship(
        "EvidenceSource",
        back_populates="evidence",
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        secondary="finding_evidence",
        back_populates="evidence_items",
        lazy="select",
    )
    activities: Mapped[List["Activity"]] = relationship(
        "Activity",
        secondary="activity_evidence",
        back_populates="evidence_items",
        lazy="select",
    )
    outbound_relationships: Mapped[List["Relationship"]] = relationship(
        "Relationship",
        foreign_keys="Relationship.source_evidence_id",
        back_populates="source_evidence",
        cascade="all, delete-orphan",
        lazy="select",
    )
    inbound_relationships: Mapped[List["Relationship"]] = relationship(
        "Relationship",
        foreign_keys="Relationship.target_evidence_id",
        back_populates="target_evidence",
        cascade="all, delete-orphan",
        lazy="select",
    )
