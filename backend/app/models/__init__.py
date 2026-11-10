"""Domain models package export and registry."""

# User is retained here so Alembic autogenerate continues to see the users
# table definition — the table itself remains in the database schema.
from app.database.base import Base
from app.models.user import User
from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.associations import FindingEvidence, ActivityEvidence, ActivityFinding
from app.models.relationship import Relationship
from app.models.activity import Activity
from app.models.priority_result import PriorityResult
from app.models.finding_review import FindingReview

__all__ = [
    "Base",
    "User",
    "Investigation",
    "EvidenceSource",
    "Evidence",
    "Finding",
    "FindingEvidence",
    "Relationship",
    "Activity",
    "ActivityEvidence",
    "ActivityFinding",
    "PriorityResult",
    "FindingReview",
]
