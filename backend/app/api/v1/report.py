"""
Investigation Report API endpoint.
GET /api/v1/investigations/{investigation_id}/report
Returns a dynamically generated PDF. No database writes. No persistent storage.
"""

import uuid
import re
from datetime import datetime, timezone
from typing import List, Optional, Set, Dict

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import Response
from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from app.api.deps import check_investigation_access
from app.database.session import get_db
from app.models.activity import Activity
from app.models.evidence import Evidence
from app.models.evidence_source import EvidenceSource
from app.models.finding import Finding
from app.models.finding_review import FindingReview
from app.models.priority_result import PriorityResult
from app.models.relationship import Relationship
from app.report import ReportData, generate_report_pdf
from app.schemas.report import (
    ReportPreflightRead,
    ReportSectionInfo,
    ReportFindingsSummary,
    ReportEvidenceSummary,
    ReportIntegrityStatus,
)

router = APIRouter(tags=["Investigation Report"])


def _safe_filename(text: str) -> str:
    """Produce a safe ASCII filename component from arbitrary text."""
    cleaned = re.sub(r"[^\w\-]", "_", str(text))
    return cleaned[:60]


def _classify_severity_tier(sev: float) -> str:
    if sev >= 0.8:
        return "CRITICAL"
    if sev >= 0.6:
        return "HIGH"
    if sev >= 0.4:
        return "MEDIUM"
    if sev >= 0.2:
        return "LOW"
    return "INFORMATIONAL"


@router.get(
    "/investigations/{investigation_id}/report/preflight",
    response_model=ReportPreflightRead,
    status_code=status.HTTP_200_OK,
    summary="Preview and audit investigation data readiness prior to PDF report compilation",
)
def get_report_preflight(
    investigation_id: uuid.UUID,
    priority_filter: Optional[str] = Query(None, description="Optional priority tier filter, e.g. 'CRITICAL,HIGH' or 'ALL'"),
    sections: Optional[str] = Query(None, description="Optional comma-separated list of section keys"),
    db: Session = Depends(get_db),
) -> ReportPreflightRead:
    """Evaluate and return an authoritative preflight summary of data available for report compilation.
    Does not modify database records.
    """
    inv = check_investigation_access(investigation_id, db)

    sources = (
        db.query(EvidenceSource)
        .filter(EvidenceSource.investigation_id == investigation_id)
        .all()
    )
    total_sources = len(sources)
    sources_with_hash = sum(1 for s in sources if s.sha256_hash and len(s.sha256_hash) == 64)

    total_evidence = (
        db.query(func.count(Evidence.id))
        .filter(Evidence.investigation_id == investigation_id)
        .scalar()
        or 0
    )

    findings = (
        db.query(Finding)
        .options(
            selectinload(Finding.evidence_items),
            selectinload(Finding.activities),
        )
        .filter(Finding.investigation_id == investigation_id)
        .all()
    )

    existing_prio = (
        db.query(PriorityResult)
        .filter(PriorityResult.investigation_id == investigation_id)
        .all()
    )
    prio_by_target: Dict[Tuple[str, uuid.UUID], PriorityResult] = {
        (pr.target_type, pr.target_id): pr for pr in existing_prio
    }

    def _resolve_finding_tier(f: Finding) -> str:
        for act in (f.activities or []):
            if ("ACTIVITY", act.id) in prio_by_target:
                return prio_by_target[("ACTIVITY", act.id)].priority_tier
        for ev in (f.evidence_items or []):
            if ("ARTIFACT", ev.id) in prio_by_target:
                return prio_by_target[("ARTIFACT", ev.id)].priority_tier
        return _classify_severity_tier(f.severity_score)

    reviews = (
        db.query(FindingReview)
        .filter(FindingReview.investigation_id == investigation_id)
        .all()
    )
    reviews_by_finding = {r.finding_id: r.status for r in reviews}

    tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    status_counts = {"NEW": 0, "REVIEWED": 0, "FALSE_POSITIVE": 0, "ESCALATED": 0}

    for f in findings:
        tier = _resolve_finding_tier(f)
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        st = reviews_by_finding.get(f.id, "NEW")
        status_counts[st] = status_counts.get(st, 0) + 1

    # Filter findings if priority_filter specified
    included_findings = findings
    if priority_filter and priority_filter.upper().strip() != "ALL":
        allowed = {p.strip().upper() for p in priority_filter.split(",") if p.strip()}
        included_findings = [f for f in findings if _resolve_finding_tier(f) in allowed]

    referenced_eids: Set[uuid.UUID] = set()
    for f in included_findings:
        for ev in f.evidence_items:
            referenced_eids.add(ev.id)

    activities_count = (
        db.query(func.count(Activity.id))
        .filter(Activity.investigation_id == investigation_id)
        .scalar()
        or 0
    )

    prio_count = (
        db.query(func.count(PriorityResult.id))
        .filter(PriorityResult.investigation_id == investigation_id)
        .scalar()
        or 0
    )

    has_notes = bool(inv.investigator_notes and inv.investigator_notes.strip())
    notes_preview = None
    if has_notes:
        raw_notes = inv.investigator_notes.strip()
        notes_preview = (raw_notes[:140] + "…") if len(raw_notes) > 140 else raw_notes

    sections_available = [
        ReportSectionInfo(
            key="executive_summary",
            label="Executive Overview",
            available=True,
            item_count=1,
            description="Case overview and aggregate triage metrics",
        ),
        ReportSectionInfo(
            key="metadata",
            label="Investigation Metadata",
            available=True,
            item_count=1,
            description="Case identifier, title, timestamps, and containment state",
        ),
        ReportSectionInfo(
            key="evidence_inventory",
            label="Evidence Inventory",
            available=total_sources > 0,
            item_count=total_sources,
            description="Ingested forensic evidence files and record volumes",
        ),
        ReportSectionInfo(
            key="evidence_integrity",
            label="Evidence Ingestion Integrity",
            available=sources_with_hash > 0,
            item_count=sources_with_hash,
            description="Ingestion-time cryptographic SHA-256 digest records",
        ),
        ReportSectionInfo(
            key="findings",
            label="Analytical Findings & Threats",
            available=len(findings) > 0,
            item_count=len(included_findings),
            description="Evaluated threat detections, sequence matches, and IOC indicators",
        ),
        ReportSectionInfo(
            key="prioritization",
            label="Prioritization Assessment",
            available=prio_count > 0,
            item_count=prio_count,
            description="Algorithmic risk scoring and operational priority tiers",
        ),
        ReportSectionInfo(
            key="activities",
            label="Correlated Activities & Narrative",
            available=activities_count > 0,
            item_count=activities_count,
            description="Synthesized multi-event activity threads and attack narrative",
        ),
        ReportSectionInfo(
            key="investigator_notes",
            label="Investigator Notes & Commentary",
            available=has_notes,
            item_count=1 if has_notes else 0,
            description="Subjective analytical commentary and conclusion notes from the investigator",
        ),
    ]

    missing: List[str] = []
    if total_sources == 0:
        missing.append("No evidence sources ingested.")
    elif total_evidence == 0:
        missing.append("Evidence sources have not been normalized into Common Evidence Schema (0 normalized records).")
    if len(findings) == 0:
        missing.append("No analytical threat detections recorded.")
    if prio_count == 0:
        missing.append("Prioritization scoring has not been computed.")
    if not has_notes:
        missing.append("No investigator notes or commentary recorded.")

    return ReportPreflightRead(
        investigation_id=inv.id,
        case_number=inv.case_number,
        title=inv.title,
        status=inv.status,
        created_at=inv.created_at,
        has_investigator_notes=has_notes,
        notes_preview=notes_preview,
        sections_available=sections_available,
        findings_summary=ReportFindingsSummary(
            total_findings=len(findings),
            included_findings=len(included_findings),
            by_priority_tier=tier_counts,
            by_review_status=status_counts,
        ),
        evidence_summary=ReportEvidenceSummary(
            total_sources=total_sources,
            total_evidence_records=total_evidence,
            referenced_evidence_count=len(referenced_eids),
        ),
        integrity_status=ReportIntegrityStatus(
            has_sha256_hashes=sources_with_hash > 0,
            total_sources=total_sources,
            sources_with_hash=sources_with_hash,
        ),
        missing_or_incomplete=missing,
        can_generate_pdf=total_sources > 0 or len(findings) > 0,
    )


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
    priority_filter: Optional[str] = Query(None, description="Optional priority tier filter, e.g. 'CRITICAL,HIGH' or 'ALL'"),
    sections: Optional[str] = Query(None, description="Optional comma-separated list of section keys"),
    db: Session = Depends(get_db),
) -> Response:
    """
    Assemble current investigation data and produce a professional A4 PDF report.
    The PDF is generated entirely in memory — nothing is written to the database
    or to persistent storage.
    """
    inv = check_investigation_access(investigation_id, db)

    # ── Assemble ReportData ────────────────────────────────────────────────────
    data = ReportData()
    data.generated_at = datetime.now(timezone.utc)
    data.investigator_notes = inv.investigator_notes

    if sections:
        data.sections = [sec.strip() for sec in sections.split(",") if sec.strip()]
    if priority_filter and priority_filter.upper().strip() != "ALL":
        data.findings_priority_filter = [p.strip().upper() for p in priority_filter.split(",") if p.strip()]

    # Investigation metadata
    data.investigation = {
        "id":           str(inv.id),
        "title":        inv.title,
        "description":  inv.description,
        "case_number":  inv.case_number,
        "status":       inv.status,
        "created_at":   inv.created_at,
    }

    # Aggregate summary counts
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

    # Findings (up to 200)
    findings_q = (
        db.query(Finding)
        .options(
            selectinload(Finding.evidence_items),
            selectinload(Finding.activities),
        )
        .filter(Finding.investigation_id == investigation_id)
        .order_by(Finding.created_at.desc())
        .limit(200)
        .all()
    )

    existing_prio_download = (
        db.query(PriorityResult)
        .filter(PriorityResult.investigation_id == investigation_id)
        .all()
    )
    prio_by_target_download: Dict[Tuple[str, uuid.UUID], PriorityResult] = {
        (pr.target_type, pr.target_id): pr for pr in existing_prio_download
    }

    def _resolve_download_tier(f: Finding) -> str:
        for act in (f.activities or []):
            if ("ACTIVITY", act.id) in prio_by_target_download:
                return prio_by_target_download[("ACTIVITY", act.id)].priority_tier
        for ev in (f.evidence_items or []):
            if ("ARTIFACT", ev.id) in prio_by_target_download:
                return prio_by_target_download[("ARTIFACT", ev.id)].priority_tier
        return _classify_severity_tier(f.severity_score)

    data.findings = [
        {
            "id":            str(f.id),
            "finding_type":  f.finding_type,
            "rule_id":       f.rule_id,
            "severity":      f.severity_score,
            "priority_tier": _resolve_download_tier(f),
            "description":   f.description,
            "mitre_tactic":  (f.optional_mitre_tags or {}).get("tactic"),
            "mitre_technique": (f.optional_mitre_tags or {}).get("technique"),
            "created_at":    f.created_at,
            "evidence_count": len(f.evidence_items),
            "evidence_ids":   [str(e.id) for e in f.evidence_items],
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

    # Priority results (top 20)
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
