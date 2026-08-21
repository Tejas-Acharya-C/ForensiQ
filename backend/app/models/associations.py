"""FindingEvidence and Activity association models."""

import uuid
from sqlalchemy import ForeignKey, Uuid
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.database.base import Base


class FindingEvidence(Base):
    """Many-to-Many association between Findings and supporting Evidence records."""

    __tablename__ = "finding_evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("evidence.id", ondelete="CASCADE"),
        primary_key=True,
    )


class ActivityEvidence(Base):
    """Many-to-Many association between Activities and member Evidence records."""

    __tablename__ = "activity_evidence"

    activity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("activities.id", ondelete="CASCADE"),
        primary_key=True,
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("evidence.id", ondelete="CASCADE"),
        primary_key=True,
    )


class ActivityFinding(Base):
    """Many-to-Many association between Activities and member Finding records."""

    __tablename__ = "activity_findings"

    activity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("activities.id", ondelete="CASCADE"),
        primary_key=True,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql"),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    )
