"""Deterministic rule detection API controller."""

import uuid
from typing import List, Optional, Dict, Tuple, Any
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session, selectinload
from pydantic import BaseModel, Field
from app.api.deps import (
    check_investigation_access,
    check_source_access,
    rate_limit_analysis,
)
from app.database.session import get_db
from sqlalchemy import or_
from app.detection import (
    DetectionService,
    DetectionSummary,
    resolve_finding_metadata,
    get_rules_lookup,
    build_detection_explanation,
)
from datetime import datetime, timezone
from app.models.finding import Finding
from app.models.finding_review import FindingReview
from app.models.evidence import Evidence
from app.models.evidence_source import EvidenceSource
from app.models.activity import Activity
from app.models.relationship import Relationship
from app.models.priority_result import PriorityResult
from app.models.associations import FindingEvidence
from app.schemas.finding_review import (
    FindingReviewRead,
    FindingReviewUpdate,
)
from app.schemas.finding import (
    FindingResponse,
    FindingDetailResponse,
    FindingExplanation,
    EvidenceTraceItem,
    ActivityTraceItem,
    PriorityTraceDetail,
    PriorityFactorDetail,
    InvestigationChainNode,
)
from app.schemas.pagination import PaginatedResponse
from app.core.errors import NotFoundError
from app.prioritization import PrioritizationService

router = APIRouter(prefix="/detection", tags=["Deterministic Detection"])


class DetectionRunResponse(BaseModel):
    """Response DTO for deterministic detection analysis run."""
    source_id: uuid.UUID
    investigation_id: Optional[uuid.UUID] = None
    evidence_evaluated: int
    rules_evaluated: int
    findings_created: int
    findings_reused: int = 0
    duplicates_skipped: int = 0
    duration_ms: float
    status: str
    errors: List[str] = Field(default_factory=list)


@router.post(
    "/sources/{source_id}/analyze-rules",
    response_model=DetectionRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute deterministic detection rules and IOC matching on normalized evidence",
)
def run_deterministic_detection(
    source_id: uuid.UUID,
    db: Session = Depends(get_db),
    _rate_limit: None = Depends(rate_limit_analysis),
) -> DetectionRunResponse:
    """Run active deterministic rules and IOCs over all evidence records from the specified source."""
    check_source_access(source_id, db)

    service = DetectionService()
    summary: DetectionSummary = service.analyze_source_evidence(db=db, source_id=source_id)

    return DetectionRunResponse(
        source_id=summary.source_id,
        investigation_id=summary.investigation_id,
        evidence_evaluated=summary.evidence_evaluated,
        rules_evaluated=summary.rules_evaluated,
        findings_created=summary.findings_created,
        findings_reused=summary.findings_reused,
        duplicates_skipped=summary.duplicates_skipped,
        duration_ms=summary.duration_ms,
        status=summary.status,
        errors=summary.errors,
    )


def _build_finding_explanation(
    finding: Finding,
    db: Session,
    prio_by_target: Dict[Tuple[str, uuid.UUID], PriorityResult],
    prioritization_svc: PrioritizationService,
) -> FindingExplanation:
    """Construct full transparent explanation bundle for Phase 2 Finding View."""
    # 1. Detection Explanation
    det_explanation = build_detection_explanation(finding, finding.evidence_items)

    # 2. Supporting Evidence Details
    evidence_traces: List[EvidenceTraceItem] = []
    finding_ev_ids = set()
    for ev in (finding.evidence_items or []):
        finding_ev_ids.add(ev.id)
        src = ev.source
        src_name = src.filename if src else f"Source-{str(ev.source_id)[:8]}"
        sha256 = src.sha256_hash if src else None
        size_bytes = src.file_size_bytes if src else None
        evidence_traces.append(
            EvidenceTraceItem(
                id=ev.id,
                source_id=ev.source_id,
                source_name=src_name,
                event_type=ev.event_type,
                source_type=ev.source_type,
                timestamp=ev.timestamp,
                raw_record_offset=ev.raw_record_offset,
                user_id=ev.user_id,
                device_id=ev.device_id,
                session_id=ev.session_id,
                process_id=ev.process_id,
                process_name=ev.process_name,
                parent_process_name=ev.parent_process_name,
                file_path=ev.file_path,
                file_hash=ev.file_hash,
                ip_address=ev.ip_address,
                port=ev.port,
                protocol=ev.protocol,
                action=ev.action,
                status=ev.status,
                attributes=ev.attributes or {},
                sha256_hash=sha256,
                file_size_bytes=size_bytes,
            )
        )

    # 3. Correlated Activity Details
    relationships: List[Relationship] = []
    if finding_ev_ids and finding.investigation_id:
        relationships = (
            db.query(Relationship)
            .filter(
                Relationship.investigation_id == finding.investigation_id,
                or_(
                    Relationship.source_evidence_id.in_(finding_ev_ids),
                    Relationship.target_evidence_id.in_(finding_ev_ids),
                ),
            )
            .all()
        )

    activity_traces: List[ActivityTraceItem] = []
    for act in (finding.activities or []):
        act_ev_ids = [e.id for e in (act.evidence_items or [])]
        act_ev_set = set(act_ev_ids)

        # Extract shared entities between finding evidence and activity evidence
        shared_users = set()
        shared_devices = set()
        shared_ips = set()
        for fe in (finding.evidence_items or []):
            if fe.user_id and any(ae.user_id == fe.user_id for ae in (act.evidence_items or [])):
                shared_users.add(fe.user_id)
            if fe.device_id and any(ae.device_id == fe.device_id for ae in (act.evidence_items or [])):
                shared_devices.add(fe.device_id)
            if fe.ip_address and any(ae.ip_address == fe.ip_address for ae in (act.evidence_items or [])):
                shared_ips.add(fe.ip_address)

        shared_entities = {}
        if shared_users:
            shared_entities["users"] = sorted(shared_users)
        if shared_devices:
            shared_entities["devices"] = sorted(shared_devices)
        if shared_ips:
            shared_entities["ip_addresses"] = sorted(shared_ips)

        correlation_reasons = []
        for r in relationships:
            if (r.source_evidence_id in finding_ev_ids and r.target_evidence_id in act_ev_set) or (
                r.target_evidence_id in finding_ev_ids and r.source_evidence_id in act_ev_set
            ):
                sig_desc = []
                ctx = r.context_attributes or {}
                for sig in ctx.get("signals", []):
                    if isinstance(sig, dict) and "description" in sig:
                        sig_desc.append(sig["description"])
                details_str = f" ({', '.join(sig_desc)})" if sig_desc else ""
                correlation_reasons.append(
                    f"Correlated relationship '{r.relationship_type.replace('_', ' ')}' (weight {r.weight:.2f}){details_str}"
                )

        for u in shared_users:
            correlation_reasons.append(f"Shared user account '{u}'")
        for d in shared_devices:
            correlation_reasons.append(f"Shared device anchor '{d}'")
        for ip in shared_ips:
            correlation_reasons.append(f"Shared IP address '{ip}'")

        if not correlation_reasons:
            if act_ev_set.intersection(finding_ev_ids):
                correlation_reasons.append("Supporting evidence record is a direct constituent event of this activity cluster")
            else:
                correlation_reasons.append("Temporal co-occurrence within activity observation window")

        activity_traces.append(
            ActivityTraceItem(
                id=act.id,
                title=act.title,
                activity_type=act.activity_type,
                description=act.description,
                evidence_count=act.evidence_count,
                finding_count=act.finding_count,
                start_time=act.start_time,
                end_time=act.end_time,
                status=act.status,
                shared_entities=shared_entities,
                associated_evidence_ids=act_ev_ids,
                correlation_reasons=list(dict.fromkeys(correlation_reasons)),
            )
        )

    # 4. Priority Explanation & Factor Breakdown
    act_prios = [
        prio_by_target[("ACTIVITY", a.id)]
        for a in (finding.activities or [])
        if ("ACTIVITY", a.id) in prio_by_target
    ]
    evd_prios = [
        prio_by_target[("ARTIFACT", e.id)]
        for e in (finding.evidence_items or [])
        if ("ARTIFACT", e.id) in prio_by_target
    ]

    def _convert_prio(pr: PriorityResult, source_type: str) -> PriorityTraceDetail:
        factors = []
        fb = pr.factor_breakdown or {}
        for f in fb.get("factors", []):
            factors.append(
                PriorityFactorDetail(
                    name=f.get("name", "factor"),
                    weight=float(f.get("weight", 0.0)),
                    normalized_value=float(f.get("normalized_value", 0.0)),
                    contribution=float(f.get("contribution", 0.0)),
                    description=f.get("description", ""),
                )
            )
        return PriorityTraceDetail(
            has_priority=True,
            priority_tier=pr.priority_tier,
            priority_score=pr.priority_score,
            priority_source=source_type,
            method_type=pr.method_type,
            target_id=pr.target_id,
            target_type=pr.target_type,
            explanation_text=pr.explanation_text,
            factors=factors,
            calculated_total=pr.priority_score,
        )

    primary_priority: PriorityTraceDetail
    secondary_priorities: List[PriorityTraceDetail] = []

    if act_prios:
        best_act = max(act_prios, key=lambda p: p.priority_score)
        primary_priority = _convert_prio(best_act, "ACTIVITY")
        if evd_prios:
            best_evd = max(evd_prios, key=lambda p: p.priority_score)
            secondary_priorities.append(_convert_prio(best_evd, "ARTIFACT"))
    elif evd_prios:
        best_evd = max(evd_prios, key=lambda p: p.priority_score)
        primary_priority = _convert_prio(best_evd, "ARTIFACT")
    else:
        tier = prioritization_svc.classify_tier(finding.severity_score * 100.0)
        primary_priority = PriorityTraceDetail(
            has_priority=False,
            priority_tier=tier,
            priority_score=None,
            priority_source="SEVERITY_FALLBACK",
            explanation_text="Prioritization has not been executed yet for this target. Displayed tier is derived from direct detection severity score.",
            fallback_reason="No automated pipeline prioritization score recorded for this finding or its linked artifacts. Raw detection severity score is displayed as an unranked baseline.",
            calculated_total=round(finding.severity_score * 100.0, 2),
        )

    # 5. Visual Investigation Traceability Chain
    chain_nodes: List[InvestigationChainNode] = []
    if evidence_traces:
        for ev in evidence_traces:
            chain_nodes.append(
                InvestigationChainNode(
                    node_type="EVIDENCE",
                    id=str(ev.id),
                    label=f"EVD: {ev.event_type}",
                    sublabel=ev.source_name,
                    status_or_tier=ev.status or "RECORDED",
                )
            )
    else:
        chain_nodes.append(
            InvestigationChainNode(
                node_type="EVIDENCE",
                id=None,
                label="No Supporting Evidence Linked",
                sublabel="Unlinked finding",
                status_or_tier="UNLINKED",
            )
        )

    meta = resolve_finding_metadata(
        rule_id=finding.rule_id,
        finding_type=finding.finding_type,
        description=finding.description,
        optional_mitre_tags=finding.optional_mitre_tags,
    )
    chain_nodes.append(
        InvestigationChainNode(
            node_type="FINDING",
            id=str(finding.id),
            label=meta.get("title") or "Analytical Finding",
            sublabel=meta.get("detection_method") or finding.finding_type,
            status_or_tier=f"Severity {finding.severity_score:.2f}",
        )
    )

    if activity_traces:
        for act in activity_traces:
            chain_nodes.append(
                InvestigationChainNode(
                    node_type="ACTIVITY",
                    id=str(act.id),
                    label=act.title,
                    sublabel=f"{act.evidence_count} events · {act.activity_type}",
                    status_or_tier=act.status,
                )
            )
    else:
        chain_nodes.append(
            InvestigationChainNode(
                node_type="ACTIVITY",
                id=None,
                label="No Correlated Activity",
                sublabel="Uncorrelated finding",
                status_or_tier="NONE",
            )
        )

    chain_nodes.append(
        InvestigationChainNode(
            node_type="PRIORITY",
            id=str(primary_priority.target_id) if primary_priority.target_id else None,
            label=f"Priority: {primary_priority.priority_tier}",
            sublabel=f"Source: {primary_priority.priority_source}",
            status_or_tier=f"{primary_priority.priority_score:.1f}/100"
            if primary_priority.priority_score is not None
            else "Fallback",
        )
    )

    return FindingExplanation(
        detection=det_explanation,
        evidence=evidence_traces,
        activities=activity_traces,
        priority=primary_priority,
        secondary_priorities=secondary_priorities,
        investigation_chain=chain_nodes,
    )


def _build_finding_response(
    finding: Finding,
    prio_by_target: Optional[Dict[Tuple[str, uuid.UUID], PriorityResult]] = None,
    prioritization_svc: Optional[PrioritizationService] = None,
    include_explanation: bool = False,
    db: Optional[Session] = None,
    review: Optional[FindingReview] = None,
) -> FindingResponse:
    """Helper to convert a Finding entity into a comprehensive FindingResponse DTO."""
    mitre_tags = finding.optional_mitre_tags or {}
    meta = resolve_finding_metadata(
        rule_id=finding.rule_id,
        finding_type=finding.finding_type,
        description=finding.description,
        optional_mitre_tags=mitre_tags,
    )

    evidence_ids = [e.id for e in (finding.evidence_items or [])]
    activity_ids = [a.id for a in (finding.activities or [])]
    activity_id = activity_ids[0] if activity_ids else None

    # Derive priority from existing PriorityResults (contextual activity or baseline artifact)
    priority_score = None
    priority_tier = None
    priority_source = None
    if prio_by_target:
        # 1. Check if any associated activity has an existing PriorityResult (contextual priority)
        act_prios = [prio_by_target[("ACTIVITY", aid)] for aid in activity_ids if ("ACTIVITY", aid) in prio_by_target]
        # 2. Check if any supporting evidence record has an existing PriorityResult (artifact priority)
        evd_prios = [prio_by_target[("ARTIFACT", eid)] for eid in evidence_ids if ("ARTIFACT", eid) in prio_by_target]

        if act_prios:
            best_act = max(act_prios, key=lambda p: p.priority_score)
            priority_score = best_act.priority_score
            priority_tier = best_act.priority_tier
            priority_source = "ACTIVITY"
        elif evd_prios:
            best_evd = max(evd_prios, key=lambda p: p.priority_score)
            priority_score = best_evd.priority_score
            priority_tier = best_evd.priority_tier
            priority_source = "ARTIFACT"

    # Safe fallback if prioritization has not been executed yet for this target
    if priority_tier is None and prioritization_svc is not None:
        priority_tier = prioritization_svc.classify_tier(finding.severity_score * 100.0)
        priority_source = "SEVERITY_FALLBACK"

    explanation = None
    if include_explanation and db is not None:
        explanation = _build_finding_explanation(
            finding=finding,
            db=db,
            prio_by_target=prio_by_target or {},
            prioritization_svc=prioritization_svc or PrioritizationService(),
        )

    review_status = review.status if review else "NEW"
    reviewed_at = review.reviewed_at if review else None
    review_notes = review.notes if review else None

    return FindingResponse(
        id=finding.id,
        investigation_id=finding.investigation_id,
        finding_type=finding.finding_type,
        rule_id=finding.rule_id,
        severity=finding.severity_score,
        description=finding.description,
        mitre_tactic=mitre_tags.get("tactic") if isinstance(mitre_tags, dict) else None,
        mitre_technique=mitre_tags.get("technique") if isinstance(mitre_tags, dict) else None,
        created_at=finding.created_at,
        evidence_ids=evidence_ids,
        title=meta.get("title"),
        rule_name=meta.get("rule_name"),
        detection_method=meta.get("detection_method"),
        evidence_count=len(evidence_ids),
        activity_ids=activity_ids,
        activity_id=activity_id,
        priority_score=priority_score,
        priority_tier=priority_tier,
        priority_source=priority_source,
        review_status=review_status,
        reviewed_at=reviewed_at,
        review_notes=review_notes,
        explanation=explanation,
    )



@router.get(
    "/findings",
    response_model=PaginatedResponse[FindingResponse],
    status_code=status.HTTP_200_OK,
    summary="Query analytical findings with pagination, filtering, search, and priority sorting",
)
def list_findings(
    investigation_id: Optional[uuid.UUID] = Query(None, description="Filter by investigation ID"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type (e.g. RULE_MATCH, IOC_MATCH)"),
    min_severity: Optional[float] = Query(None, ge=0.0, le=1.0, description="Filter by minimum severity"),
    search: Optional[str] = Query(None, description="Search query for title, description, finding ID, evidence ID, or rule"),
    priority_tier: Optional[str] = Query(None, description="Filter by priority tier (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)"),
    detection_method: Optional[str] = Query(None, description="Filter by detection method (RULE, ML, IOC, SEQUENCE)"),
    has_activity: Optional[bool] = Query(None, description="Filter by whether finding has linked activity"),
    review_status: Optional[str] = Query(None, description="Filter by review status (NEW, REVIEWED, FALSE_POSITIVE, ESCALATED)"),
    sort_by: Optional[str] = Query("priority", description="Sort order: 'priority' (default) or 'created_at'"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> PaginatedResponse[FindingResponse]:
    """Retrieve paginated Findings scoped to the requested investigation with priority ordering and rich metadata."""
    query = db.query(Finding)

    if investigation_id:
        check_investigation_access(investigation_id, db)
        query = query.filter(Finding.investigation_id == investigation_id)

    if finding_type:
        query = query.filter(Finding.finding_type == finding_type.upper().strip())
    if min_severity is not None:
        query = query.filter(Finding.severity_score >= min_severity)

    if detection_method:
        dm = detection_method.upper().strip()
        if "ML" in dm or "ANOMALY" in dm:
            query = query.filter(Finding.finding_type == "ML_ANOMALY")
        elif "IOC" in dm:
            query = query.filter(Finding.finding_type == "IOC_MATCH")
        elif "RULE" in dm:
            query = query.filter(Finding.finding_type.in_(["RULE_MATCH", "IOC_MATCH"]))

    if has_activity is not None:
        if has_activity:
            query = query.filter(Finding.activities.any())
        else:
            query = query.filter(~Finding.activities.any())

    if search:
        q = search.strip()
        search_clauses = [
            Finding.description.ilike(f"%{q}%"),
            Finding.rule_id.ilike(f"%{q}%"),
        ]
        # Check if search term is a valid UUID
        try:
            q_uuid = uuid.UUID(q)
            search_clauses.append(Finding.id == q_uuid)
            search_clauses.append(Finding.evidence_items.any(Evidence.id == q_uuid))
        except (ValueError, AttributeError):
            pass

        # Check against rule names in catalog
        rules_lookup = get_rules_lookup()
        for r_id, meta in rules_lookup.items():
            if q.lower() in meta["name"].lower():
                search_clauses.append(Finding.rule_id.ilike(f"{r_id}%"))

        query = query.filter(or_(*search_clauses))

    # Efficient batch loading of relationships (no N+1)
    all_matched = (
        query.options(
            selectinload(Finding.evidence_items),
            selectinload(Finding.activities),
        )
        .all()
    )

    # Pre-fetch existing Prioritization and Review results for the investigation once (no N+1)
    prio_by_target: Dict[Tuple[str, uuid.UUID], PriorityResult] = {}
    reviews_by_finding: Dict[uuid.UUID, FindingReview] = {}
    if investigation_id:
        existing_prio = (
            db.query(PriorityResult)
            .filter(PriorityResult.investigation_id == investigation_id)
            .all()
        )
        for pr in existing_prio:
            prio_by_target[(pr.target_type, pr.target_id)] = pr

        existing_reviews = (
            db.query(FindingReview)
            .filter(FindingReview.investigation_id == investigation_id)
            .all()
        )
        for rev in existing_reviews:
            reviews_by_finding[rev.finding_id] = rev

    prioritization_svc = PrioritizationService()

    # Build response DTOs
    dto_items: List[FindingResponse] = []
    for f in all_matched:
        resp = _build_finding_response(
            finding=f,
            prio_by_target=prio_by_target,
            prioritization_svc=prioritization_svc,
            review=reviews_by_finding.get(f.id),
        )

        # Filter by priority tier if requested
        if priority_tier and resp.priority_tier:
            if resp.priority_tier.upper() != priority_tier.upper().strip():
                continue

        # Filter by review status if requested
        if review_status:
            target_status = review_status.upper().strip()
            if resp.review_status != target_status:
                continue

        dto_items.append(resp)

    # Priority Ordering:
    # 1. Existing prioritization score descending (or severity score as safe fallback)
    # 2. Deterministic secondary sorting: created_at desc, then id desc
    if sort_by == "created_at":
        dto_items.sort(
            key=lambda x: (
                x.created_at.timestamp() if x.created_at else 0.0,
                str(x.id),
            ),
            reverse=True,
        )
    else:
        # Default: Priority ordering (canonical tier first, score desc, created_at desc, id desc)
        tier_ranks = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFORMATIONAL": 1,
            "INFO": 1,
        }

        def priority_sort_key(item: FindingResponse):
            tier_val = tier_ranks.get((item.priority_tier or "").upper(), 0)
            has_prio = 1 if item.priority_score is not None else 0
            effective_score = item.priority_score if item.priority_score is not None else (item.severity * 100.0)
            created_ts = item.created_at.timestamp() if item.created_at else 0.0
            return (tier_val, has_prio, effective_score, created_ts, str(item.id))

        dto_items.sort(key=priority_sort_key, reverse=True)

    total = len(dto_items)
    paginated_items = dto_items[offset : offset + limit]

    return PaginatedResponse[FindingResponse](
        items=paginated_items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(paginated_items) < total),
    )


@router.get(
    "/findings/{finding_id}",
    response_model=FindingResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve full detail for a single analytical finding",
)
def get_finding_detail(
    finding_id: uuid.UUID,
    investigation_id: Optional[uuid.UUID] = Query(None, description="Optional investigation ID to verify investigation containment"),
    db: Session = Depends(get_db),
) -> FindingResponse:
    """Retrieve full detail for a single Finding with optional investigation containment check, rich metadata, and Phase 2 explanation."""
    if investigation_id:
        check_investigation_access(investigation_id, db)

    finding = (
        db.query(Finding)
        .options(
            selectinload(Finding.evidence_items).selectinload(Evidence.source),
            selectinload(Finding.activities).selectinload(Activity.evidence_items),
        )
        .filter(Finding.id == finding_id)
        .first()
    )
    if not finding or (investigation_id and finding.investigation_id != investigation_id):
        if investigation_id:
            raise NotFoundError(f"Finding with ID '{finding_id}' not found in investigation '{investigation_id}'.")
        raise NotFoundError(f"Finding with ID '{finding_id}' not found.")

    prio_by_target: Dict[Tuple[str, uuid.UUID], PriorityResult] = {}
    if finding.investigation_id:
        existing_prio = (
            db.query(PriorityResult)
            .filter(PriorityResult.investigation_id == finding.investigation_id)
            .all()
        )
        for pr in existing_prio:
            prio_by_target[(pr.target_type, pr.target_id)] = pr

    prioritization_svc = PrioritizationService()
    review = (
        db.query(FindingReview)
        .filter(
            FindingReview.investigation_id == finding.investigation_id,
            FindingReview.finding_id == finding.id,
        )
        .first()
    )
    return _build_finding_response(
        finding=finding,
        prio_by_target=prio_by_target,
        prioritization_svc=prioritization_svc,
        include_explanation=True,
        db=db,
        review=review,
    )


@router.get(
    "/findings/{finding_id}/explanation",
    response_model=FindingDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve complete forensic explanation and evidence traceability for a finding",
)
def get_finding_explanation(
    finding_id: uuid.UUID,
    investigation_id: Optional[uuid.UUID] = Query(None, description="Optional investigation ID to verify investigation containment"),
    db: Session = Depends(get_db),
) -> FindingDetailResponse:
    """Dedicated endpoint returning complete explainability breakdown for a finding."""
    return get_finding_detail(finding_id=finding_id, investigation_id=investigation_id, db=db)


@router.get(
    "/findings/{finding_id}/review",
    response_model=FindingReviewRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve investigator review triage decision for a finding",
)
def get_finding_review(
    finding_id: uuid.UUID,
    investigation_id: uuid.UUID = Query(..., description="Investigation ID scoping this review"),
    db: Session = Depends(get_db),
) -> FindingReviewRead:
    """Retrieve the current review decision and notes for a finding within the specified investigation."""
    check_investigation_access(investigation_id, db)
    finding = db.get(Finding, finding_id)
    if not finding or finding.investigation_id != investigation_id:
        raise NotFoundError(f"Finding with ID '{finding_id}' not found in investigation '{investigation_id}'.")

    review = (
        db.query(FindingReview)
        .filter(
            FindingReview.investigation_id == investigation_id,
            FindingReview.finding_id == finding_id,
        )
        .first()
    )

    if not review:
        now = datetime.now(timezone.utc)
        return FindingReviewRead(
            id=uuid.uuid4(),
            investigation_id=investigation_id,
            finding_id=finding_id,
            status="NEW",
            notes=None,
            reviewed_at=now,
            created_at=now,
            updated_at=now,
        )

    return FindingReviewRead.model_validate(review)


@router.put(
    "/findings/{finding_id}/review",
    response_model=FindingReviewRead,
    status_code=status.HTTP_200_OK,
    summary="Record or update investigator review triage decision for a finding",
)
def update_finding_review(
    finding_id: uuid.UUID,
    payload: FindingReviewUpdate,
    db: Session = Depends(get_db),
) -> FindingReviewRead:
    """Record an investigator review decision (NEW, REVIEWED, FALSE_POSITIVE, ESCALATED)
    and optional notes. Isolates review decisions by investigation without modifying original findings.
    """
    check_investigation_access(payload.investigation_id, db)
    finding = db.get(Finding, finding_id)
    if not finding or finding.investigation_id != payload.investigation_id:
        raise NotFoundError(f"Finding with ID '{finding_id}' not found in investigation '{payload.investigation_id}'.")

    now = datetime.now(timezone.utc)
    review = (
        db.query(FindingReview)
        .filter(
            FindingReview.investigation_id == payload.investigation_id,
            FindingReview.finding_id == finding_id,
        )
        .first()
    )

    if review:
        if "status" in payload.model_fields_set and payload.status is not None:
            review.status = payload.status
        if "notes" in payload.model_fields_set:
            review.notes = payload.notes
        review.reviewed_at = now
        review.updated_at = now
    else:
        review_status = payload.status if ("status" in payload.model_fields_set and payload.status is not None) else "NEW"
        review_notes = payload.notes if "notes" in payload.model_fields_set else None
        review = FindingReview(
            id=uuid.uuid4(),
            investigation_id=payload.investigation_id,
            finding_id=finding_id,
            status=review_status,
            notes=review_notes,
            reviewed_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(review)

    db.commit()
    db.refresh(review)
    return FindingReviewRead.model_validate(review)
