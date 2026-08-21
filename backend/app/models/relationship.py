"""Relationship SQLAlchemy domain model."""

import uuid
from typing import Dict, Any, TYPE_CHECKING
from sqlalchemy import (
    String,
    Float,
    ForeignKey,
    Index,
    JSON,
    Uuid,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.investigation import Investigation
    from app.models.evidence import Evidence

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")
GUID_TYPE = Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql")


class Relationship(Base):
    """Explicit multi-dimensional relationship between two evidence records."""

    __tablename__ = "relationships"

    __table_args__ = (
        Index("idx_relationships_source", "investigation_id", "source_evidence_id"),
        Index("idx_relationships_target", "investigation_id", "target_evidence_id"),
        Index("idx_relationships_inv_weight", "investigation_id", "weight"),
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
    source_evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID_TYPE,
        ForeignKey("evidence.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID_TYPE,
        ForeignKey("evidence.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    context_attributes: Mapped[Dict[str, Any]] = mapped_column(
        JSON_TYPE,
        nullable=False,
        default=dict,
    )
    relationship_fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        unique=True,
        index=True,
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="relationships",
    )
    source_evidence: Mapped["Evidence"] = relationship(
        "Evidence",
        foreign_keys=[source_evidence_id],
        back_populates="outbound_relationships",
    )
    target_evidence: Mapped["Evidence"] = relationship(
        "Evidence",
        foreign_keys=[target_evidence_id],
        back_populates="inbound_relationships",
    )
