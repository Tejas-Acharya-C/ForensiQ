"""Deterministic Detection and ML Anomaly Detection Service."""

import hashlib
import json
import math
import re
import time
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Sequence, Set, Tuple
from collections import defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest
import yaml

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.logging import get_logger
from app.core.errors import NotFoundError
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.associations import FindingEvidence
from app.models.investigation import Investigation

logger = get_logger("detection_service")


# ---------------------------------------------------------
# DTOs
# ---------------------------------------------------------

class DetectionSummary:
    def __init__(self, **kwargs):
        self.investigation_id = None
        self.evidence_evaluated = 0
        self.rules_evaluated = 0
        self.findings_created = 0
        self.findings_reused = 0
        self.duplicates_skipped = 0
        self.duration_ms = 0.0
        self.status = "COMPLETED"
        self.errors = []
        for k, v in kwargs.items():
            setattr(self, k, v)


# ---------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------

def compute_detection_fingerprint(
    investigation_id: uuid.UUID,
    rule_id: str,
    rule_version: str,
    supporting_evidence_ids: Sequence[uuid.UUID],
) -> str:
    canonical_dict = {
        "evidence_ids": sorted(str(eid) for eid in supporting_evidence_ids),
        "investigation_id": str(investigation_id),
        "rule_id": str(rule_id),
        "rule_version": str(rule_version),
    }
    canonical_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


# ---------------------------------------------------------
# Rules Engine
# ---------------------------------------------------------

def get_evidence_field_value(evidence: Evidence, field_path: str) -> Optional[Any]:
    if field_path.startswith("attributes."):
        attr_key = field_path.split(".", 1)[1]
        attrs = evidence.attributes or {}
        if attr_key in attrs: return attrs[attr_key]
        return attrs.get("_raw_fields", {}).get(attr_key)
    return getattr(evidence, field_path, None)


def evaluate_step(evidence: Evidence, step: Any) -> bool:
    """Evaluate a sequence step against an evidence record.

    Supported step forms (backward compatible):
    - Single condition dict: {"field": ..., "operator": ..., "value": ...}
    - Multi-condition dict:  {"conditions": [{...}, {...}]}  — all must match (AND)
    - List of condition dicts: [{...}, {...}]               — all must match (AND)
    """
    if isinstance(step, list):
        return all(evaluate_condition(evidence, cond) for cond in step)
    if isinstance(step, dict) and "conditions" in step:
        return all(evaluate_condition(evidence, cond) for cond in step["conditions"])
    return evaluate_condition(evidence, step)


def evaluate_condition(evidence: Evidence, condition: Dict[str, Any]) -> bool:
    val = get_evidence_field_value(evidence, condition.get("field", ""))
    if val is None: return False

    op = condition.get("operator", "")
    target = condition.get("value", "")

    if op == "equals": return str(val).strip().lower() == str(target).strip().lower()
    if op == "contains": return str(target).strip().lower() in str(val).strip().lower()
    if op == "in":
        if isinstance(target, (list, set, tuple)):
            return str(val).strip().lower() in [str(t).strip().lower() for t in target]
        return False
    if op == "regex":
        return bool(re.search(str(target), str(val), re.IGNORECASE))
    if op == "greater_than":
        try: return float(val) > float(target)
        except: return False
    if op == "less_than":
        try: return float(val) < float(target)
        except: return False

    return False


class DetectionService:
    def __init__(self, rules_dir: str = "data/rules"):
        from pathlib import Path
        p = Path(rules_dir)
        if not p.exists():
            for parent in Path(__file__).resolve().parents:
                candidate = parent / "data" / "rules"
                if candidate.exists():
                    p = candidate
                    break
        self.rules_dir = p
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        if not self.rules_dir.exists(): return []
        rules = []
        files = list(self.rules_dir.glob("*.yaml")) + list(self.rules_dir.glob("*.yml")) + list(self.rules_dir.glob("*.json"))
        for rf in sorted(files):
            try:
                with open(rf, "r", encoding="utf-8") as f:
                    content = yaml.safe_load(f) if rf.suffix in [".yaml", ".yml"] else json.load(f)
                if not content: continue
                items = content if isinstance(content, list) else (content.get("rules", []) if isinstance(content, dict) and "rules" in content else [content])
                for item in items:
                    if item.get("enabled", True): rules.append(item)
            except Exception as e:
                logger.error(f"Error loading rule file {rf}: {e}")
        return rules

    def _evaluate_rules(self, evidence_list: List[Evidence]) -> List[Dict[str, Any]]:
        matches = []
        single_rules = [r for r in self.rules if r.get("type") != "SEQUENCE" and r.get("conditions")]
        seq_rules = [r for r in self.rules if r.get("type") == "SEQUENCE" and r.get("sequence")]

        # Single Rules
        for evd in evidence_list:
            for rule in single_rules:
                if evaluate_condition(evd, rule["conditions"]):
                    matches.append({
                        "rule_id": rule["id"],
                        "rule_version": str(rule.get("version", "1.0.0")),
                        "rule_type": rule.get("type", "FIELD_MATCH"),
                        "severity": float(rule.get("severity", 0.5)),
                        "description": rule.get("description", f"Rule '{rule['name']}' matched."),
                        "evidence_ids": [evd.id],
                        "mitre_tactic": rule.get("mitre_tactic"),
                        "mitre_technique": rule.get("mitre_technique"),
                    })

        # Sequence Rules
        if seq_rules:
            sorted_evidence = sorted(evidence_list, key=lambda e: (e.timestamp.timestamp() if e.timestamp else 0.0, e.raw_record_offset or 0))
            for rule in seq_rules:
                seq = rule["sequence"]
                group_by = seq.get("group_by", "user_id")
                steps = seq.get("sequence_steps", [])
                max_span = seq.get("max_span_seconds", 300)
                
                if len(steps) < 2: continue

                grouped = defaultdict(list)
                for e in sorted_evidence:
                    val = getattr(e, group_by, None)
                    if val is not None and str(val).strip():
                        grouped[str(val)].append(e)

                for group_val, evds in grouped.items():
                    n = len(evds)
                    if n < len(steps): continue
                    
                    for i in range(n):
                        if not evaluate_step(evds[i], steps[0]): continue
                        
                        chain = [evds[i]]
                        start_ts = evds[i].timestamp.timestamp() if evds[i].timestamp else 0.0
                        curr_idx = i + 1
                        
                        for step_idx in range(1, len(steps)):
                            found = False
                            while curr_idx < n:
                                cand = evds[curr_idx]
                                curr_ts = cand.timestamp.timestamp() if cand.timestamp else 0.0
                                if curr_ts - start_ts > max_span: break
                                if evaluate_step(cand, steps[step_idx]):
                                    chain.append(cand)
                                    curr_idx += 1
                                    found = True
                                    break
                                curr_idx += 1
                            if not found: break
                        
                        if len(chain) == len(steps):
                            matches.append({
                                "rule_id": rule["id"],
                                "rule_version": str(rule.get("version", "1.0.0")),
                                "rule_type": rule.get("type", "SEQUENCE"),
                                "severity": float(rule.get("severity", 0.8)),
                                "description": rule.get("description", f"Sequence '{rule['name']}' matched."),
                                "evidence_ids": [e.id for e in chain],
                                "mitre_tactic": rule.get("mitre_tactic"),
                                "mitre_technique": rule.get("mitre_technique"),
                            })
                            
        return matches

    def analyze_source_evidence(self, db: Session, source_id: uuid.UUID) -> DetectionSummary:
        start_time = time.perf_counter()
        evidence_list = db.query(Evidence).filter_by(source_id=source_id).order_by(Evidence.raw_record_offset).all()
        if not evidence_list:
            return DetectionSummary(source_id=source_id, evidence_evaluated=0, rules_evaluated=0, findings_created=0, status="COMPLETED")

        matches = self._evaluate_rules(evidence_list)
        investigation_id = evidence_list[0].investigation_id
        
        created, reused = 0, 0
        for m in matches:
            fp = compute_detection_fingerprint(investigation_id, m["rule_id"], m["rule_version"], m["evidence_ids"])
            
            mitre_tags = {}
            if m["mitre_tactic"]: mitre_tags["tactic"] = m["mitre_tactic"]
            if m["mitre_technique"]: mitre_tags["technique"] = m["mitre_technique"]

            finding = Finding(
                id=uuid.uuid4(),
                investigation_id=investigation_id,
                finding_type="IOC_MATCH" if m["rule_type"] == "IOC_MATCH" else "RULE_MATCH",
                rule_id=f"{m['rule_id']}:v{m['rule_version']}",
                severity_score=m["severity"],
                description=m["description"],
                optional_mitre_tags=mitre_tags,
                detection_fingerprint=fp
            )
            
            try:
                with db.begin_nested():
                    db.add(finding)
                    db.flush()
                    for eid in m["evidence_ids"]:
                        db.add(FindingEvidence(finding_id=finding.id, evidence_id=eid))
                    db.flush()
                created += 1
            except IntegrityError:
                reused += 1

        if created > 0: db.commit()
        return DetectionSummary(source_id=source_id, evidence_evaluated=len(evidence_list), rules_evaluated=len(self.rules), findings_created=created, findings_reused=reused, status="COMPLETED")

# ---------------------------------------------------------
# ML Anomaly Engine
# ---------------------------------------------------------

class MLAnomalyService:
    def analyze_source(self, db: Session, source_id: uuid.UUID) -> DetectionSummary:
        start_time = time.perf_counter()
        evidence_list = db.query(Evidence).filter_by(source_id=source_id).order_by(Evidence.timestamp.asc()).all()
        if len(evidence_list) < 10:
            return DetectionSummary(source_id=source_id, status="INSUFFICIENT_DATA", findings_created=0)

        investigation_id = evidence_list[0].investigation_id
        
        # Simple Feature Extraction
        features = []
        user_counts = defaultdict(int)
        for e in evidence_list:
            if e.user_id: user_counts[e.user_id] += 1
            
        last_ts = {}
        for e in evidence_list:
            ts = e.timestamp.timestamp() if e.timestamp else 0
            key = f"{e.user_id}@{e.device_id}"
            delta = max(0.0, ts - last_ts.get(key, ts))
            last_ts[key] = ts
            
            hour = e.timestamp.hour if e.timestamp else 0
            features.append([
                float(user_counts[e.user_id] / len(evidence_list)) if e.user_id else 0.0,
                float(math.log10(delta + 1)),
                1.0 if ("FAIL" in str(e.status).upper() or "ERROR" in str(e.status).upper()) else 0.0,
                float(math.sin(2 * math.pi * (hour / 24.0))),
            ])

        X = np.array(features, dtype=float)

        # Simple ML Anomaly Detection using Isolation Forest
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        model.fit(X)
        scores = -model.score_samples(X)
        
        min_score, max_score = float(np.percentile(scores, 1)), float(np.percentile(scores, 99))
        if max_score <= min_score: max_score = min_score + 0.1
        
        norm_scores = np.clip((scores - min_score) / (max_score - min_score), 0.0, 1.0)
        threshold = float(np.percentile(norm_scores, 95))
        
        created, reused = 0, 0
        for i, e in enumerate(evidence_list):
            s = float(norm_scores[i])
            if s >= threshold:
                fp = compute_detection_fingerprint(investigation_id, "isolation_forest", "1.0", [e.id])
                finding = Finding(
                    id=uuid.uuid4(),
                    investigation_id=investigation_id,
                    finding_type="ML_ANOMALY",
                    rule_id="ML-isolation_forest:v1.0",
                    severity_score=round(s, 2),
                    description=f"Behavioral anomaly detected (score {s:.2f})",
                    optional_mitre_tags={"anomaly_score": round(s, 2)},
                    detection_fingerprint=fp
                )
                try:
                    with db.begin_nested():
                        db.add(finding)
                        db.flush()
                        db.add(FindingEvidence(finding_id=finding.id, evidence_id=e.id))
                        db.flush()
                    created += 1
                except IntegrityError:
                    reused += 1

        if created > 0: db.commit()
        return DetectionSummary(source_id=source_id, status="COMPLETED", evidence_evaluated=len(evidence_list), findings_created=created, findings_reused=reused)
