"""EvidenceSource SQLAlchemy domain model."""

import uuid
from datetime import datetime, timezone
from typing import List, TYPE_CHECKING
from sqlalchemy import String, BigInteger, Integer, DateTime, ForeignKey, CheckConstraint, Uuid
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.investigation import Investigation
    from app.models.evidence import Evidence


class EvidenceSource(Base):
    """Imported raw evidence file or source provenance record."""

    __tablename__ = "evidence_sources"

    __table_args__ = (
        CheckConstraint("file_size_bytes >= 0", name="chk_evidence_source_file_size"),
        CheckConstraint("total_records >= 0", name="chk_evidence_source_total_records"),
        CheckConstraint(
            "ingestion_status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')",
            name="chk_evidence_source_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        primary_key=True,
        default=uuid.uuid4,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_format: Mapped[str] = mapped_column(String(32), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    total_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ingestion_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    storage_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="evidence_sources",
    )
    evidence: Mapped[List["Evidence"]] = relationship(
        "Evidence",
        back_populates="source",
        cascade="all, delete-orphan",
        lazy="select",
    )
