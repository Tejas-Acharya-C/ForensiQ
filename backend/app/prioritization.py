"""Prioritization service orchestration and scoring."""

import hashlib
import json
import time
import uuid
from typing import List, Dict, Any, Optional, Sequence, Literal
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.logging import get_logger
from app.core.errors import NotFoundError
from app.models.investigation import Investigation
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.associations import FindingEvidence
from app.models.relationship import Relationship
from app.models.activity import Activity
from app.models.priority_result import PriorityResult

logger = get_logger("prioritization_service")


@dataclass
class PriorityFactor:
    name: str
    weight: float
    normalized_value: float
    contribution: float
    description: str


@dataclass
class PrioritizationScore:
    target_id: uuid.UUID
    target_type: Literal["ARTIFACT", "ACTIVITY"]
    method_type: Literal["BASELINE_INDEPENDENT", "PROPOSED_CONTEXTUAL"]
    priority_score: float
    priority_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    factors: List[PriorityFactor] = field(default_factory=list)
    explanation_text: str = ""
    configuration_version: str = "1.0.0"


@dataclass
class PrioritizationSummary:
    investigation_id: uuid.UUID
    method_type: Literal["BASELINE_INDEPENDENT", "PROPOSED_CONTEXTUAL"]
    target_type: Literal["ARTIFACT", "ACTIVITY"]
    status: str
    targets_evaluated: int
    results_created: int
    results_reused: int = 0
    tier_counts: Dict[str, int] = field(default_factory=dict)
    duration_ms: float = 0.0
    errors: List[str] = field(default_factory=list)


def compute_priority_fingerprint(
    investigation_id: uuid.UUID,
    target_type: str,
    target_id: uuid.UUID,
    method_type: str,
) -> str:
    canonical_dict = {
        "investigation_id": str(investigation_id),
        "method_type": method_type,
        "target_id": str(target_id),
        "target_type": target_type,
    }
    canonical_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


class PrioritizationService:
    def __init__(self):
        self.version = "1.0.0"
        self.artifact_rule_w = 0.60
        self.artifact_ml_w = 0.40
        
        self.activity_det_w = 0.40
        self.activity_ml_w = 0.25
        self.activity_ctx_w = 0.20
        self.activity_corrob_w = 0.15

    def classify_tier(self, score: float) -> Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        if score >= 80.0: return "CRITICAL"
        if score >= 60.0: return "HIGH"
        if score >= 40.0: return "MEDIUM"
        if score >= 20.0: return "LOW"
        return "INFORMATIONAL"

    def score_artifact(self, evidence: Evidence, findings: Sequence[Finding]) -> PrioritizationScore:
        rule_f = [f for f in findings if f.finding_type in ["RULE_MATCH", "IOC_MATCH"]]
        rule_sig = max((f.severity_score for f in rule_f), default=0.0)

        ml_f = [f for f in findings if f.finding_type == "ML_ANOMALY"]
        ml_sig = max((float(f.optional_mitre_tags.get("anomaly_score", f.severity_score)) if isinstance(f.optional_mitre_tags, dict) else f.severity_score for f in ml_f), default=0.0)

        rule_contrib = round(self.artifact_rule_w * rule_sig * 100.0, 2)
        ml_contrib = round(self.artifact_ml_w * ml_sig * 100.0, 2)
        total = round(min(100.0, max(0.0, rule_contrib + ml_contrib)), 2)
        tier = self.classify_tier(total)

        factors = [
            PriorityFactor("deterministic_signal", self.artifact_rule_w, round(rule_sig, 4), rule_contrib, "Direct rule matches."),
            PriorityFactor("ml_anomaly", self.artifact_ml_w, round(ml_sig, 4), ml_contrib, "Behavioral ML anomaly."),
        ]

        exp = f"Artifact priority based on direct forensic observations." if total >= 20.0 else "Low informational artifact priority."

        return PrioritizationScore(evidence.id, "ARTIFACT", "BASELINE_INDEPENDENT", total, tier, factors, exp, self.version)

    def score_activity(self, activity: Activity, findings: Sequence[Finding], relationships: Sequence[Relationship]) -> PrioritizationScore:
        rule_f = [f for f in findings if f.finding_type in ["RULE_MATCH", "IOC_MATCH"]]
        det_sig = max((f.severity_score for f in rule_f), default=0.0)

        ml_f = [f for f in findings if f.finding_type == "ML_ANOMALY"]
        ml_sig = max((float(f.optional_mitre_tags.get("anomaly_score", f.severity_score)) if isinstance(f.optional_mitre_tags, dict) else f.severity_score for f in ml_f), default=0.0)

        ctx_sig = float(sum(r.weight for r in relationships) / len(relationships)) if relationships else 0.0

        rel_types = {r.relationship_type for r in relationships}
        f_types = {f.finding_type for f in findings}
        corrob_sig = min(1.0, (len(rel_types) + len(f_types)) / 4.0)

        det_contrib = round(self.activity_det_w * det_sig * 100.0, 2)
        ml_contrib = round(self.activity_ml_w * ml_sig * 100.0, 2)
        ctx_contrib = round(self.activity_ctx_w * ctx_sig * 100.0, 2)
        corrob_contrib = round(self.activity_corrob_w * corrob_sig * 100.0, 2)

        total = round(min(100.0, max(0.0, det_contrib + ml_contrib + ctx_contrib + corrob_contrib)), 2)
        tier = self.classify_tier(total)

        factors = [
            PriorityFactor("deterministic_signal", self.activity_det_w, round(det_sig, 4), det_contrib, "Strongest detection rule."),
            PriorityFactor("ml_anomaly", self.activity_ml_w, round(ml_sig, 4), ml_contrib, "ML anomaly signal."),
            PriorityFactor("contextual_cohesion", self.activity_ctx_w, round(ctx_sig, 4), ctx_contrib, "Contextual strength."),
            PriorityFactor("contextual_corroboration", self.activity_corrob_w, round(corrob_sig, 4), corrob_contrib, "Multi-signal corroboration."),
        ]

        exp = f"Activity priority based on detection and context." if total >= 20.0 else "Low informational activity priority."

        return PrioritizationScore(activity.id, "ACTIVITY", "PROPOSED_CONTEXTUAL", total, tier, factors, exp, self.version)

    def prioritize_artifacts(self, db: Session, investigation_id: uuid.UUID) -> PrioritizationSummary:
        start_time = time.perf_counter()
        if not db.get(Investigation, investigation_id):
            raise NotFoundError(f"Investigation '{investigation_id}' not found.")

        evidence_list = db.query(Evidence).filter_by(investigation_id=investigation_id).all()
        if not evidence_list:
            return PrioritizationSummary(investigation_id, "BASELINE_INDEPENDENT", "ARTIFACT", "INSUFFICIENT_DATA", 0, 0, errors=["No evidence records found."], duration_ms=round((time.perf_counter() - start_time) * 1000, 2))

        evidence_ids = [e.id for e in evidence_list]
        finding_rows = db.query(FindingEvidence.evidence_id, Finding).join(Finding).filter(Finding.investigation_id == investigation_id, FindingEvidence.evidence_id.in_(evidence_ids)).all()
        findings_by_evd = defaultdict(list)
        for eid, fnd in finding_rows: findings_by_evd[eid].append(fnd)

        scores = []
        tier_counts = defaultdict(int)
        for evd in evidence_list:
            sc = self.score_artifact(evd, findings_by_evd.get(evd.id, []))
            scores.append(sc)
            tier_counts[sc.priority_tier] += 1

        created = 0
        reused = 0
        for sc in scores:
            fp = compute_priority_fingerprint(investigation_id, "ARTIFACT", sc.target_id, "BASELINE_INDEPENDENT")
            fd = {"factors": [{"name": f.name, "weight": f.weight, "normalized_value": f.normalized_value, "contribution": f.contribution, "description": f.description} for f in sc.factors], "configuration_version": self.version}
            pe = PriorityResult(id=uuid.uuid4(), investigation_id=investigation_id, target_type="ARTIFACT", target_id=sc.target_id, priority_score=sc.priority_score, priority_tier=sc.priority_tier, factor_breakdown=fd, explanation_text=sc.explanation_text, method_type="BASELINE_INDEPENDENT", priority_fingerprint=fp)
            try:
                with db.begin_nested():
                    db.add(pe)
                    db.flush()
                created += 1
            except IntegrityError:
                reused += 1

        if created > 0: db.commit()
        return PrioritizationSummary(investigation_id, "BASELINE_INDEPENDENT", "ARTIFACT", "COMPLETED", len(evidence_list), created, reused, dict(tier_counts), round((time.perf_counter() - start_time) * 1000, 2))

    def prioritize_activities(self, db: Session, investigation_id: uuid.UUID) -> PrioritizationSummary:
        start_time = time.perf_counter()
        if not db.get(Investigation, investigation_id):
            raise NotFoundError(f"Investigation '{investigation_id}' not found.")

        activities = db.query(Activity).filter_by(investigation_id=investigation_id).all()
        if not activities:
            return PrioritizationSummary(investigation_id, "PROPOSED_CONTEXTUAL", "ACTIVITY", "INSUFFICIENT_DATA", 0, 0, errors=["No activities found."], duration_ms=round((time.perf_counter() - start_time) * 1000, 2))

        all_rels = db.query(Relationship).filter_by(investigation_id=investigation_id).all()

        scores = []
        tier_counts = defaultdict(int)
        for act in activities:
            evd_ids = {e.id for e in act.evidence_items}
            int_rels = [r for r in all_rels if r.source_evidence_id in evd_ids and r.target_evidence_id in evd_ids]
            sc = self.score_activity(act, act.findings, int_rels)
            scores.append(sc)
            tier_counts[sc.priority_tier] += 1

        created = 0
        reused = 0
        for sc in scores:
            fp = compute_priority_fingerprint(investigation_id, "ACTIVITY", sc.target_id, "PROPOSED_CONTEXTUAL")
            fd = {"factors": [{"name": f.name, "weight": f.weight, "normalized_value": f.normalized_value, "contribution": f.contribution, "description": f.description} for f in sc.factors], "configuration_version": self.version}
            pe = PriorityResult(id=uuid.uuid4(), investigation_id=investigation_id, target_type="ACTIVITY", target_id=sc.target_id, priority_score=sc.priority_score, priority_tier=sc.priority_tier, factor_breakdown=fd, explanation_text=sc.explanation_text, method_type="PROPOSED_CONTEXTUAL", priority_fingerprint=fp)
            try:
                with db.begin_nested():
                    db.add(pe)
                    db.flush()
                created += 1
            except IntegrityError:
                reused += 1

        if created > 0: db.commit()
        return PrioritizationSummary(investigation_id, "PROPOSED_CONTEXTUAL", "ACTIVITY", "COMPLETED", len(activities), created, reused, dict(tier_counts), round((time.perf_counter() - start_time) * 1000, 2))
