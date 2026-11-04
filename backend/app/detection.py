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


# ---------------------------------------------------------
# Finding Metadata Resolution Helper (Phase 1 Threat Discovery)
# ---------------------------------------------------------

_RULE_METADATA_CACHE: Optional[Dict[str, Dict[str, Any]]] = None

def get_rules_lookup() -> Dict[str, Dict[str, Any]]:
    """Build and cache a lookup dictionary of known detection rules by rule ID."""
    global _RULE_METADATA_CACHE
    if _RULE_METADATA_CACHE is not None:
        return _RULE_METADATA_CACHE

    catalog: Dict[str, Dict[str, Any]] = {
        "IOC-IP-001": {
            "name": "Known Malicious IP Match",
            "type": "IOC_MATCH",
            "method": "Rule-based (IOC Match)",
        },
        "IOC-HASH-001": {
            "name": "Known Malicious File Hash Match",
            "type": "IOC_MATCH",
            "method": "Rule-based (IOC Match)",
        },
        "RULE-PROC-001": {
            "name": "Suspicious PowerShell Execution",
            "type": "FIELD_MATCH",
            "method": "Rule-based (Deterministic)",
        },
        "RULE-AUTH-SEQ-001": {
            "name": "Repeated Failed Logins Followed by Success",
            "type": "SEQUENCE",
            "method": "Rule-based (Sequence Detection)",
        },
        "RULE-PROC-002": {
            "name": "Mimikatz Execution",
            "type": "FIELD_MATCH",
            "method": "Rule-based (Deterministic)",
        },
    }

    try:
        service = DetectionService()
        for r in service.rules:
            rid = r.get("id")
            if rid:
                rtype = r.get("type", "FIELD_MATCH")
                if rtype == "SEQUENCE":
                    method = "Rule-based (Sequence Detection)"
                elif rtype == "IOC_MATCH":
                    method = "Rule-based (IOC Match)"
                else:
                    method = "Rule-based (Deterministic)"
                catalog[rid] = {
                    "name": r.get("name", rid),
                    "type": rtype,
                    "method": method,
                }
    except Exception as exc:
        logger.warning(f"Could not dynamically populate rules catalog: {exc}")

    _RULE_METADATA_CACHE = catalog
    return _RULE_METADATA_CACHE


def resolve_finding_metadata(
    rule_id: Optional[str],
    finding_type: str,
    description: Optional[str] = None,
    optional_mitre_tags: Any = None,
) -> Dict[str, Optional[str]]:
    """Derive human-readable title, rule name, and detection method without modifying original data."""
    clean_type = (finding_type or "").upper()
    lookup = get_rules_lookup()

    # 1. ML Anomaly signal
    if clean_type == "ML_ANOMALY" or (rule_id and "isolation_forest" in rule_id.lower()):
        return {
            "title": "Behavioral Anomaly (Isolation Forest)",
            "rule_name": "Isolation Forest Anomaly Detection",
            "detection_method": "Machine Learning (Isolation Forest)",
        }

    # 2. Rule-based or IOC match with rule_id
    base_rule_id = None
    if rule_id:
        base_rule_id = rule_id.split(":")[0].strip()

    if base_rule_id and base_rule_id in lookup:
        entry = lookup[base_rule_id]
        return {
            "title": entry["name"],
            "rule_name": entry["name"],
            "detection_method": entry["method"],
        }

    # 3. Fallback title derivation
    detection_method = "Rule-based (Deterministic)"
    if clean_type == "IOC_MATCH":
        detection_method = "Rule-based (IOC Match)"
    elif clean_type == "ML_ANOMALY":
        detection_method = "Machine Learning (Isolation Forest)"

    rule_name = base_rule_id or rule_id

    # Try extracting human title from description if available
    title = None
    if description:
        m = re.match(r"^Rule\s+['\"]([^'\"]+)['\"]\s+matched", description)
        if m:
            title = m.group(1)
        elif description.startswith("Sequence '") and "' matched" in description:
            m_seq = re.search(r"Sequence\s+['\"]([^'\"]+)['\"]\s+matched", description)
            if m_seq:
                title = m_seq.group(1)

    if not title:
        if base_rule_id:
            # Clean up identifier (e.g. RULE-PROC-001 -> Rule Proc 001)
            title = base_rule_id.replace("_", " ").replace("-", " ").title()
        elif description:
            # First clause/sentence
            first_sentence = description.split(".")[0].strip()
            title = (first_sentence[:60] + "...") if len(first_sentence) > 60 else first_sentence
        else:
            title = f"{clean_type.replace('_', ' ').title()} Finding"

    return {
        "title": title,
        "rule_name": rule_name or title,
        "detection_method": detection_method,
    }


# ---------------------------------------------------------------------------
# Phase 2: Finding Explanation Builders
# ---------------------------------------------------------------------------

_LOADED_RULES_DICT: Optional[Dict[str, Dict[str, Any]]] = None

def get_loaded_rules_dict() -> Dict[str, Dict[str, Any]]:
    """Cache and return full rule dictionary definitions keyed by rule ID."""
    global _LOADED_RULES_DICT
    if _LOADED_RULES_DICT is not None:
        return _LOADED_RULES_DICT

    rules_by_id: Dict[str, Dict[str, Any]] = {}
    try:
        service = DetectionService()
        for r in service.rules:
            rid = r.get("id")
            if rid:
                rules_by_id[rid] = r
    except Exception as exc:
        logger.warning(f"Could not load rules dictionary: {exc}")

    _LOADED_RULES_DICT = rules_by_id
    return _LOADED_RULES_DICT


def get_raw_rule_definition(rule_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Retrieve original configured rule definition by full or base rule ID."""
    if not rule_id:
        return None
    base_id = rule_id.split(":")[0].strip()
    return get_loaded_rules_dict().get(base_id)


def build_detection_explanation(
    finding: Finding,
    evidence_items: Optional[Sequence[Evidence]] = None,
) -> Any:
    """Build transparent, evidence-backed DetectionExplanation DTO for a Finding."""
    from app.schemas.finding import (
        DetectionExplanation,
        ConditionMatchDetail,
        SequenceStepDetail,
    )

    clean_type = (finding.finding_type or "").upper()
    evidence_list = list(evidence_items or [])
    mitre_tags = finding.optional_mitre_tags if isinstance(finding.optional_mitre_tags, dict) else {}

    # 1. MACHINE LEARNING (Isolation Forest)
    if clean_type == "ML_ANOMALY" or (finding.rule_id and "isolation_forest" in finding.rule_id.lower()):
        anomaly_score = mitre_tags.get("anomaly_score", round(finding.severity_score, 2))
        try:
            anomaly_score = float(anomaly_score)
        except (ValueError, TypeError):
            anomaly_score = round(finding.severity_score, 2)

        # Retrieve threshold if persisted in metadata; otherwise None (batch 95th percentile cut-off is unpersisted)
        raw_threshold = mitre_tags.get("threshold") or mitre_tags.get("anomaly_threshold")
        threshold = None
        if raw_threshold is not None:
            try:
                threshold = float(raw_threshold)
            except (ValueError, TypeError):
                threshold = None

        is_anomaly = (anomaly_score >= threshold) if threshold is not None else True

        features_evaluated = [
            {
                "feature_name": "user_activity_frequency",
                "description": "Normalized event frequency for the principal user across the observation window",
            },
            {
                "feature_name": "inter_arrival_time_delta",
                "description": "Log10 temporal interval between successive events from identical user and host",
            },
            {
                "feature_name": "error_status_indicator",
                "description": "Binary flag indicating authentication failure or error status code",
            },
            {
                "feature_name": "diurnal_cycle_sin",
                "description": "Harmonic cyclical transformation of timestamp hour into diurnal coordinates",
            },
        ]

        # Extract actual observed feature values from the first linked evidence item if available
        matched_attributes = {}
        if evidence_list:
            ev = evidence_list[0]
            matched_attributes = {
                "user_id": ev.user_id,
                "device_id": ev.device_id,
                "event_type": ev.event_type,
                "status": ev.status,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            }

        thresh_str = f"(threshold: {threshold:.2f})" if threshold is not None else "(classified above 95th percentile batch cut-off)"
        return DetectionExplanation(
            category="ISOLATION_FOREST",
            summary=f"Event was flagged as an outlier by Isolation Forest with an anomaly score of {anomaly_score:.2f} {thresh_str}.",
            model_name="Isolation Forest Anomaly Detection",
            rule_id=finding.rule_id,
            rule_name="Isolation Forest Anomaly Detection",
            rule_description="Unsupervised isolation forest model detecting statistical outliers across multidimensional behavioral event features.",
            rule_version="1.0.0",
            anomaly_score=anomaly_score,
            threshold=threshold,
            is_anomaly=is_anomaly,
            features_evaluated=features_evaluated,
            matched_attributes=matched_attributes,
            ml_note="Isolation Forest detects unusual statistical observations across high-dimensional feature distributions. An outlier score signifies statistical divergence from baseline patterns; it does not independently establish malicious intent or confirm a cyberattack.",
        )

    # 2. RULE-BASED & IOC DETECTION
    raw_rule = get_raw_rule_definition(finding.rule_id)
    rule_type = raw_rule.get("type", "FIELD_MATCH") if raw_rule else ("IOC_MATCH" if clean_type == "IOC_MATCH" else "FIELD_MATCH")
    rule_id_str = raw_rule.get("id", finding.rule_id) if raw_rule else finding.rule_id
    rule_name = raw_rule.get("name") if raw_rule else (finding.rule_id or "Configured Rule")
    rule_desc = raw_rule.get("description") if raw_rule else finding.description
    rule_ver = str(raw_rule.get("version", "1.0.0")) if raw_rule else "1.0.0"

    # 2A. SEQUENCE DETECTION
    if rule_type == "SEQUENCE" or (raw_rule and "sequence" in raw_rule):
        seq_cfg = raw_rule.get("sequence", {}) if raw_rule else {}
        group_by = seq_cfg.get("group_by", "user_id")
        max_span = seq_cfg.get("max_span_seconds", 300)
        steps_cfg = seq_cfg.get("sequence_steps", [])

        # Sort evidence chronologically
        sorted_ev = sorted(
            evidence_list,
            key=lambda e: (e.timestamp.timestamp() if e.timestamp else 0.0, e.raw_record_offset or 0),
        )

        group_val = None
        actual_span = 0.0
        if sorted_ev:
            group_val = str(getattr(sorted_ev[0], group_by, None) or "")
            if len(sorted_ev) >= 2 and sorted_ev[0].timestamp and sorted_ev[-1].timestamp:
                actual_span = round(abs((sorted_ev[-1].timestamp - sorted_ev[0].timestamp).total_seconds()), 2)

        sequence_step_details = []
        for idx, step_item in enumerate(steps_cfg):
            ev_for_step = sorted_ev[idx] if idx < len(sorted_ev) else None
            cond_list = []
            if isinstance(step_item, dict) and "conditions" in step_item:
                raw_conds = step_item["conditions"]
            elif isinstance(step_item, list):
                raw_conds = step_item
            elif isinstance(step_item, dict):
                raw_conds = [step_item]
            else:
                raw_conds = []

            for c in raw_conds:
                f_name = c.get("field", "")
                op = c.get("operator", "")
                exp_v = c.get("value")
                act_v = get_evidence_field_value(ev_for_step, f_name) if ev_for_step else None
                cond_list.append(
                    ConditionMatchDetail(
                        field=f_name,
                        operator=op,
                        expected_value=exp_v,
                        actual_value=str(act_v) if act_v is not None else None,
                        matched=evaluate_condition(ev_for_step, c) if ev_for_step else False,
                    )
                )

            sequence_step_details.append(
                SequenceStepDetail(
                    step_index=idx + 1,
                    event_type=ev_for_step.event_type if ev_for_step else None,
                    status=ev_for_step.status if ev_for_step else None,
                    conditions=cond_list,
                    evidence_id=ev_for_step.id if ev_for_step else None,
                    timestamp=ev_for_step.timestamp if ev_for_step else None,
                    matched=True if ev_for_step else False,
                )
            )

        summary = (
            f"Sequence rule '{rule_name}' matched across {len(sorted_ev)} ordered event(s) "
            f"grouped by {group_by}='{group_val}' spanning {actual_span:.1f}s (window limit: {max_span}s)."
        )

        return DetectionExplanation(
            category="SEQUENCE",
            summary=summary,
            rule_id=rule_id_str,
            rule_name=rule_name,
            rule_description=rule_desc,
            rule_version=rule_ver,
            sequence_group_by=group_by,
            sequence_group_value=group_val,
            max_span_seconds=max_span,
            actual_span_seconds=actual_span,
            sequence_steps=sequence_step_details,
        )

    # 2B. IOC MATCH
    if rule_type == "IOC_MATCH" or clean_type == "IOC_MATCH":
        cond = raw_rule.get("conditions", {}) if raw_rule else {}
        field = cond.get("field", "indicator") if isinstance(cond, dict) else "indicator"
        op = cond.get("operator", "equals") if isinstance(cond, dict) else "equals"
        target_val = cond.get("value") if isinstance(cond, dict) else None

        # Determine IOC type
        ioc_type = "UNKNOWN"
        if "ip" in field.lower():
            ioc_type = "IP_ADDRESS"
        elif "hash" in field.lower():
            ioc_type = "FILE_HASH"
        elif "domain" in field.lower():
            ioc_type = "DOMAIN"
        elif "url" in field.lower():
            ioc_type = "URL"

        # Check against first evidence
        actual_val = None
        matched_attrs = {}
        if evidence_list:
            ev = evidence_list[0]
            actual_val = get_evidence_field_value(ev, field)
            matched_attrs = {
                "ip_address": ev.ip_address,
                "file_hash": ev.file_hash,
                "file_path": ev.file_path,
                "event_type": ev.event_type,
            }

        cond_match = [
            ConditionMatchDetail(
                field=field,
                operator=op,
                expected_value=target_val,
                actual_value=str(actual_val) if actual_val is not None else None,
                matched=True,
            )
        ] if target_val is not None else []

        val_display = str(actual_val or target_val or "indicator")
        summary = f"Event matches known threat indicator ({ioc_type}: {val_display}) defined in rule {rule_id_str}."

        return DetectionExplanation(
            category="IOC",
            summary=summary,
            rule_id=rule_id_str,
            rule_name=rule_name,
            rule_description=rule_desc,
            rule_version=rule_ver,
            indicator_type=ioc_type,
            matched_value=val_display,
            indicator_source=rule_name,
            matched_conditions=cond_match,
            matched_attributes=matched_attrs,
            context_note="An IOC match confirms an exact pattern match against a documented indicator of compromise from configured threat intelligence. It indicates that the observed artifact matches threat criteria, but does not independently establish breach impact without contextual corroboration.",
        )

    # 2C. STANDARD DETERMINISTIC FIELD MATCH
    cond = raw_rule.get("conditions", {}) if raw_rule else {}
    cond_matches = []
    matched_attrs = {}

    if isinstance(cond, dict) and cond:
        field = cond.get("field", "")
        op = cond.get("operator", "equals")
        val = cond.get("value")
        actual_val = None
        if evidence_list:
            actual_val = get_evidence_field_value(evidence_list[0], field)
            matched_attrs[field] = actual_val
        cond_matches.append(
            ConditionMatchDetail(
                field=field,
                operator=op,
                expected_value=val,
                actual_value=str(actual_val) if actual_val is not None else None,
                matched=True,
            )
        )
    elif isinstance(cond, list):
        for c in cond:
            f_name = c.get("field", "")
            actual_val = get_evidence_field_value(evidence_list[0], f_name) if evidence_list else None
            if actual_val is not None:
                matched_attrs[f_name] = actual_val
            cond_matches.append(
                ConditionMatchDetail(
                    field=f_name,
                    operator=c.get("operator", "equals"),
                    expected_value=c.get("value"),
                    actual_value=str(actual_val) if actual_val is not None else None,
                    matched=True,
                )
            )

    cond_details_str = ""
    if cond_matches:
        parts = [f"{c.field} {c.operator} '{c.actual_value or c.expected_value}'" for c in cond_matches if c.matched]
        if parts:
            cond_details_str = f" ({', '.join(parts)})"

    summary = (
        f"Deterministic detection rule '{rule_name}' was triggered because "
        f"configured attribute condition(s) were satisfied{cond_details_str}."
    )

    return DetectionExplanation(
        category="RULE_BASED",
        summary=summary,
        rule_id=rule_id_str,
        rule_name=rule_name,
        rule_description=rule_desc,
        rule_version=rule_ver,
        matched_conditions=cond_matches,
        matched_attributes=matched_attrs,
    )
