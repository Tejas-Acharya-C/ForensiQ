"""
Investigation Report API endpoint.
GET /api/v1/investigations/{investigation_id}/report
Returns a dynamically generated PDF. No database writes. No persistent storage.
"""

import uuid
import re
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, status
from fastapi.responses import Response
from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from app.api.deps import check_investigation_access, get_current_user
from app.database.session import get_db
from app.models.activity import Activity
from app.models.evidence import Evidence
from app.models.evidence_source import EvidenceSource
from app.models.finding import Finding
from app.models.priority_result import PriorityResult
from app.models.relationship import Relationship
from app.models.user import User
from app.report import ReportData, generate_report_pdf

router = APIRouter(tags=["Investigation Report"])


def _safe_filename(text: str) -> str:
    """Produce a safe ASCII filename component from arbitrary text."""
    cleaned = re.sub(r"[^\w\-]", "_", str(text))
    return cleaned[:60]


@router.get(
    "/investigations/{investigation_id}/report",
    status_code=status.HTTP_200_OK,
    summary="Generate and download a PDF investigation report",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "PDF investigation report",
        }
    },
)
def download_investigation_report(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """
    Assemble current investigation data and produce a professional A4 PDF report.
    The PDF is generated entirely in memory — nothing is written to the database
    or to persistent storage.
    """
    inv = check_investigation_access(investigation_id, db, current_user)

    # ── Assemble ReportData ────────────────────────────────────────────────────
    data = ReportData()
    data.generated_at = datetime.now(timezone.utc)

    # Investigation metadata
    data.investigation = {
        "id":           str(inv.id),
        "title":        inv.title,
        "description":  inv.description,
        "case_number":  inv.case_number,
        "status":       inv.status,
        "created_at":   inv.created_at,
    }

    # Aggregate summary counts (mirrors investigations.py get_investigation_summary)
    total_sources       = db.query(func.count(EvidenceSource.id)).filter(EvidenceSource.investigation_id == investigation_id).scalar() or 0
    total_evidence      = db.query(func.count(Evidence.id)).filter(Evidence.investigation_id == investigation_id).scalar() or 0
    total_findings      = db.query(func.count(Finding.id)).filter(Finding.investigation_id == investigation_id).scalar() or 0
    total_relationships = db.query(func.count(Relationship.id)).filter(Relationship.investigation_id == investigation_id).scalar() or 0
    total_activities    = db.query(func.count(Activity.id)).filter(Activity.investigation_id == investigation_id).scalar() or 0
    total_priority      = db.query(func.count(PriorityResult.id)).filter(PriorityResult.investigation_id == investigation_id).scalar() or 0

    ml_anomaly_count = db.query(func.count(Finding.id)).filter(
        Finding.investigation_id == investigation_id,
        Finding.finding_type == "ML_ANOMALY",
    ).scalar() or 0

    tier_rows = (
        db.query(PriorityResult.priority_tier, func.count(PriorityResult.id))
        .filter(PriorityResult.investigation_id == investigation_id)
        .group_by(PriorityResult.priority_tier)
        .all()
    )
    tier_dict = {t: c for t, c in tier_rows}

    data.summary = {
        "total_sources":       total_sources,
        "total_evidence":      total_evidence,
        "total_findings":      total_findings,
        "total_anomalies":     ml_anomaly_count,
        "total_relationships": total_relationships,
        "total_activities":    total_activities,
        "total_priority":      total_priority,
        "priority_tier_counts": {
            "CRITICAL":      tier_dict.get("CRITICAL", 0),
            "HIGH":          tier_dict.get("HIGH", 0),
            "MEDIUM":        tier_dict.get("MEDIUM", 0),
            "LOW":           tier_dict.get("LOW", 0),
            "INFORMATIONAL": tier_dict.get("INFORMATIONAL", 0),
        },
    }

    # Findings (up to 200 for the report)
    findings_q = (
        db.query(Finding)
        .filter(Finding.investigation_id == investigation_id)
        .order_by(Finding.created_at.desc())
        .limit(200)
        .all()
    )
    data.findings = [
        {
            "id":            str(f.id),
            "finding_type":  f.finding_type,
            "rule_id":       f.rule_id,
            "severity":      f.severity_score,
            "description":   f.description,
            "mitre_tactic":  (f.optional_mitre_tags or {}).get("tactic"),
            "mitre_technique": (f.optional_mitre_tags or {}).get("technique"),
            "created_at":    f.created_at,
        }
        for f in findings_q
    ]

    # Relationships (up to 200)
    rels_q = (
        db.query(Relationship)
        .filter(Relationship.investigation_id == investigation_id)
        .order_by(Relationship.id)
        .limit(200)
        .all()
    )
    data.relationships = [
        {
            "id":                   str(r.id),
            "relationship_type":    r.relationship_type,
            "weight":               r.weight,
            "source_evidence_id":   str(r.source_evidence_id),
            "target_evidence_id":   str(r.target_evidence_id),
            "context_attributes":   r.context_attributes,
        }
        for r in rels_q
    ]

    # Activities (all)
    acts_q = (
        db.query(Activity)
        .options(selectinload(Activity.evidence_items), selectinload(Activity.findings))
        .filter(Activity.investigation_id == investigation_id)
        .order_by(Activity.start_time.asc())
        .all()
    )
    data.activities = [
        {
            "id":             str(a.id),
            "title":          a.title,
            "activity_type":  a.activity_type,
            "status":         a.status,
            "start_time":     a.start_time,
            "end_time":       a.end_time,
            "evidence_count": a.evidence_count,
            "finding_count":  a.finding_count,
            "description":    a.description,
        }
        for a in acts_q
    ]

    # Priority results (top 20 for the report)
    prio_q = (
        db.query(PriorityResult)
        .filter(PriorityResult.investigation_id == investigation_id)
        .order_by(PriorityResult.priority_score.desc())
        .limit(20)
        .all()
    )
    data.priority_results = [
        {
            "id":               str(pr.id),
            "priority_tier":    pr.priority_tier,
            "priority_score":   pr.priority_score,
            "target_type":      pr.target_type,
            "target_id":        str(pr.target_id),
            "explanation_text": pr.explanation_text,
            "method_type":      pr.method_type,
        }
        for pr in prio_q
    ]

    # Evidence sources
    src_norm_counts = dict(
        db.query(Evidence.source_id, func.count(Evidence.id))
        .filter(Evidence.investigation_id == investigation_id)
        .group_by(Evidence.source_id)
        .all()
    )
    sources_q = (
        db.query(EvidenceSource)
        .filter(EvidenceSource.investigation_id == investigation_id)
        .order_by(EvidenceSource.ingested_at)
        .all()
    )
    data.sources = [
        {
            "id":                str(src.id),
            "filename":          src.filename,
            "file_format":       src.file_format,
            "sha256_hash":       src.sha256_hash,
            "file_size_bytes":   src.file_size_bytes,
            "total_records":     src.total_records,
            "normalized_records": src_norm_counts.get(src.id, 0),
            "ingestion_status":  src.ingestion_status,
            "ingested_at":       src.ingested_at,
        }
        for src in sources_q
    ]

    # ── Generate PDF ───────────────────────────────────────────────────────────
    pdf_bytes = generate_report_pdf(data)

    safe_case = _safe_filename(inv.case_number)
    filename = f"ForensiQ_{safe_case}_Report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
            "Cache-Control": "no-store",
        },
    )
