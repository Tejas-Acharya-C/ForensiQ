"""Contextual Evidence Correlation Engine and Persistence Service."""

import hashlib
import json
import time
import uuid
from typing import List, Dict, Any, Optional, Tuple, Sequence, Set
from collections import defaultdict
from datetime import datetime, timezone
from dataclasses import dataclass, field

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.logging import get_logger
from app.core.errors import NotFoundError
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.associations import FindingEvidence
from app.models.relationship import Relationship


logger = get_logger("correlation_service")


@dataclass
class CorrelationSignal:
    signal_type: str
    strength: float
    description: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def weight(self) -> float:
        return self.strength


@dataclass
class DiscoveredRelationship:
    investigation_id: uuid.UUID
    source_evidence_id: uuid.UUID
    target_evidence_id: uuid.UUID
    relationship_type: str
    weight: float
    signals: List[CorrelationSignal] = field(default_factory=list)
    context_attributes: Dict[str, Any] = field(default_factory=dict)
    is_directed: bool = False


@dataclass
class CorrelationSummary:
    source_id: Optional[uuid.UUID]
    investigation_id: uuid.UUID
    status: str
    evidence_evaluated: int
    candidate_pairs_evaluated: int
    relationships_created: int
    relationships_reused: int = 0
    duplicates_skipped: int = 0
    strategy_counts: Dict[str, int] = field(default_factory=dict)
    configuration_version: str = "1.0.0"
    duration_ms: float = 0.0
    errors: List[str] = field(default_factory=list)


def compute_relationship_fingerprint(
    investigation_id: uuid.UUID,
    source_evidence_id: uuid.UUID,
    target_evidence_id: uuid.UUID,
    relationship_type: str,
    configuration_version: str,
) -> str:
    e1_str = str(source_evidence_id)
    e2_str = str(target_evidence_id)
    first_id = min(e1_str, e2_str)
    second_id = max(e1_str, e2_str)

    canonical_dict = {
        "configuration_version": configuration_version,
        "first_evidence_id": first_id,
        "investigation_id": str(investigation_id),
        "relationship_type": relationship_type,
        "second_evidence_id": second_id,
    }
    canonical_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


class CorrelationService:
    def __init__(self):
        self.version = "1.0.0"
        self.temporal_window = 300
        self.max_temporal_distance = 1800
        self.min_weight = 0.20

    def evaluate_pair(self, e1: Evidence, e2: Evidence, finding_map: Dict[uuid.UUID, List[str]]) -> List[CorrelationSignal]:
        signals: List[CorrelationSignal] = []

        # 1. Temporal Proximity
        t1 = e1.timestamp.astimezone(timezone.utc) if e1.timestamp.tzinfo else e1.timestamp.replace(tzinfo=timezone.utc)
        t2 = e2.timestamp.astimezone(timezone.utc) if e2.timestamp.tzinfo else e2.timestamp.replace(tzinfo=timezone.utc)
        delta_secs = abs((t2 - t1).total_seconds())
        if delta_secs <= self.temporal_window:
            strength = max(0.0, 1.0 - (delta_secs / float(self.temporal_window)))
            if strength > 0.0:
                signals.append(CorrelationSignal("TEMPORAL_PROXIMITY", round(strength, 3), f"Occurred within {delta_secs:.1f}s", {"delta_seconds": round(delta_secs, 2)}))

        # 2. Entity Correlation
        if e1.session_id and e2.session_id and e1.session_id == e2.session_id:
            signals.append(CorrelationSignal("SAME_SESSION", 0.85, f"Shared session '{e1.session_id}'", {"session_id": e1.session_id}))
        if e1.user_id and e2.user_id and e1.user_id == e2.user_id:
            signals.append(CorrelationSignal("SAME_USER", 0.60, f"Same user '{e1.user_id}'", {"user_id": e1.user_id}))
        if e1.device_id and e2.device_id and e1.device_id == e2.device_id:
            signals.append(CorrelationSignal("SAME_DEVICE", 0.55, f"Same device '{e1.device_id}'", {"device_id": e1.device_id}))

        # 3. Process, File, Network Correlation
        if e1.process_name and e2.process_name and e1.process_name == e2.process_name and e1.device_id and e2.device_id and e1.device_id == e2.device_id:
            signals.append(CorrelationSignal("SAME_PROCESS", 0.40, f"Same process '{e1.process_name}' on '{e1.device_id}'", {"process_name": e1.process_name}))
        
        if e1.file_path and e2.file_path and e1.file_path == e2.file_path:
            signals.append(CorrelationSignal("SAME_FILE", 0.75, f"Identical file path '{e1.file_path}'", {"file_path": e1.file_path}))
        elif e1.file_hash and e2.file_hash and e1.file_hash == e2.file_hash:
            signals.append(CorrelationSignal("SAME_FILE_HASH", 0.80, f"Identical file hash '{e1.file_hash}'", {"file_hash": e1.file_hash}))

        if e1.ip_address and e2.ip_address and e1.ip_address == e2.ip_address:
            signals.append(CorrelationSignal("SAME_IP", 0.70, f"Identical IP '{e1.ip_address}'", {"ip_address": e1.ip_address}))

        # 4. Finding Co-occurrence
        f1_types = finding_map.get(e1.id, [])
        f2_types = finding_map.get(e2.id, [])
        if f1_types and f2_types:
            signals.append(CorrelationSignal("FINDING_CO_OCCURRENCE", 0.35, f"Triggered findings ({', '.join(f1_types)} & {', '.join(f2_types)})", {"f1_types": f1_types, "f2_types": f2_types}))

        return signals

    def score_pair(self, investigation_id: uuid.UUID, e1: Evidence, e2: Evidence, signals: List[CorrelationSignal]) -> DiscoveredRelationship | None:
        if not signals:
            return None
        valid_signals = [s for s in signals if s.strength > 0.0]
        if not valid_signals:
            return None

        signal_types = {s.signal_type for s in valid_signals}
        signal_importance = {
            "SAME_SESSION": 1.5,
            "SAME_FILE_HASH": 1.4,
            "SAME_FILE": 1.3,
            "SAME_IP": 1.2,
            "SAME_USER": 1.0,
            "SAME_DEVICE": 1.0,
            "SAME_PROCESS": 0.8,
            "TEMPORAL_PROXIMITY": 1.0,
            "FINDING_CO_OCCURRENCE": 0.5,
        }

        is_directed = False
        if "SAME_SESSION" in signal_types:
            primary_type = "SAME_SESSION"
        elif "SAME_FILE" in signal_types or "SAME_FILE_HASH" in signal_types:
            primary_type = "PROCESS_FILE" if (e1.process_name or e2.process_name) else "SAME_FILE"
            if (e1.process_name and (e2.file_path or e2.file_hash)) or (e2.process_name and (e1.file_path or e1.file_hash)):
                is_directed = True
        elif "SAME_IP" in signal_types:
            primary_type = "PROCESS_NETWORK" if (e1.process_name or e2.process_name) else "SAME_IP"
            if (e1.process_name and e2.ip_address) or (e2.process_name and e1.ip_address):
                is_directed = True
        elif len(valid_signals) >= 2:
            primary_type = "SHARED_CONTEXT"
        elif "SAME_USER" in signal_types:
            primary_type = "SAME_USER"
        elif "SAME_DEVICE" in signal_types:
            primary_type = "SAME_DEVICE"
        elif "SAME_PROCESS" in signal_types:
            primary_type = "SAME_PROCESS"
        elif "TEMPORAL_PROXIMITY" in signal_types:
            primary_type = "TEMPORALLY_PROXIMATE"
        else:
            primary_type = "SHARED_CONTEXT"

        total_weighted_strength = sum(s.strength * signal_importance.get(s.signal_type, 1.0) for s in valid_signals)
        total_importance = sum(signal_importance.get(s.signal_type, 1.0) for s in valid_signals)
        base_strength = total_weighted_strength / max(1e-6, total_importance)
        
        multi_signal_boost = min(0.15, max(0.0, 0.05 * (len(valid_signals) - 1)))
        aggregate_strength = min(1.0, max(0.0, base_strength + multi_signal_boost))

        if aggregate_strength < self.min_weight:
            return None

        if is_directed:
            if e1.process_name and not e2.process_name:
                src_id, tgt_id = e1.id, e2.id
            elif e2.process_name and not e1.process_name:
                src_id, tgt_id = e2.id, e1.id
            else:
                src_id, tgt_id = (e1.id, e2.id) if e1.timestamp <= e2.timestamp else (e2.id, e1.id)
        else:
            src_id, tgt_id = min(e1.id, e2.id), max(e1.id, e2.id)

        context_attributes = {
            "signals": [{"type": s.signal_type, "strength": round(s.strength, 3), "description": s.description, "attributes": s.attributes} for s in valid_signals],
            "aggregate_strength": round(aggregate_strength, 4),
            "primary_type": primary_type,
            "configuration_version": self.version,
        }

        return DiscoveredRelationship(
            investigation_id=investigation_id,
            source_evidence_id=src_id,
            target_evidence_id=tgt_id,
            relationship_type=primary_type,
            weight=round(aggregate_strength, 4),
            signals=valid_signals,
            context_attributes=context_attributes,
            is_directed=is_directed,
        )

    def analyze_source_evidence(self, db: Session, source_id: uuid.UUID) -> CorrelationSummary:
        start_time = time.perf_counter()

        source = db.get(EvidenceSource, source_id)
        if not source:
            raise NotFoundError(f"EvidenceSource '{source_id}' not found.")

        investigation_id = source.investigation_id

        evidence_list: List[Evidence] = (
            db.query(Evidence)
            .filter_by(source_id=source_id)
            .order_by(Evidence.timestamp.asc(), Evidence.raw_record_offset.asc())
            .all()
        )

        n_records = len(evidence_list)
        if n_records < 2:
            return CorrelationSummary(
                source_id=source_id, investigation_id=investigation_id, status="INSUFFICIENT_DATA",
                evidence_evaluated=n_records, candidate_pairs_evaluated=0, relationships_created=0,
                configuration_version=self.version, errors=["At least 2 normalized evidence records required."],
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2)
            )

        try:
            finding_evidence_rows = (
                db.query(FindingEvidence.evidence_id, Finding.finding_type)
                .join(Finding, FindingEvidence.finding_id == Finding.id)
                .filter(Finding.investigation_id == investigation_id)
                .all()
            )
            finding_map: Dict[uuid.UUID, List[str]] = defaultdict(list)
            for evd_id, f_type in finding_evidence_rows:
                finding_map[evd_id].append(f_type)

            # Generate candidate pairs efficiently
            candidates = set()
            
            # Simple Bucketing
            buckets = defaultdict(list)
            for e in evidence_list:
                if e.session_id: buckets[f"session:{e.session_id}"].append(e)
                if e.user_id: buckets[f"user:{e.user_id}"].append(e)
                if e.device_id: buckets[f"device:{e.device_id}"].append(e)
                if e.process_name: buckets[f"process:{e.process_name}"].append(e)
                if e.ip_address: buckets[f"ip:{e.ip_address}"].append(e)
                if e.file_hash: buckets[f"hash:{e.file_hash}"].append(e)

            def add_pair(e1, e2):
                if e1.id != e2.id:
                    k = (min(e1.id, e2.id), max(e1.id, e2.id))
                    if k not in candidates:
                        candidates.add(k)
                        return (e1, e2)
                return None

            candidate_pairs = []
            
            # Temporal Window
            sorted_evidence = sorted(evidence_list, key=lambda x: x.timestamp)
            for i in range(len(sorted_evidence)):
                e1 = sorted_evidence[i]
                for j in range(i + 1, len(sorted_evidence)):
                    e2 = sorted_evidence[j]
                    if abs((e2.timestamp - e1.timestamp).total_seconds()) <= self.temporal_window:
                        p = add_pair(e1, e2)
                        if p: candidate_pairs.append(p)
                    else:
                        break

            # Bucket Window
            for items in buckets.values():
                if len(items) > 1:
                    b_len = len(items)
                    for i in range(b_len):
                        for j in range(i + 1, b_len):
                            if abs((items[j].timestamp - items[i].timestamp).total_seconds()) <= self.max_temporal_distance:
                                p = add_pair(items[i], items[j])
                                if p: candidate_pairs.append(p)

            discovered_relationships = []
            strategy_counts = defaultdict(int)

            for e1, e2 in candidate_pairs:
                signals = self.evaluate_pair(e1, e2, finding_map)
                rel = self.score_pair(investigation_id, e1, e2, signals)
                if rel:
                    discovered_relationships.append(rel)
                    strategy_counts[rel.relationship_type] += 1

            relationships_created = 0
            relationships_reused = 0

            for rel in discovered_relationships:
                fp = compute_relationship_fingerprint(investigation_id, rel.source_evidence_id, rel.target_evidence_id, rel.relationship_type, self.version)
                rel_entity = Relationship(
                    id=uuid.uuid4(),
                    investigation_id=investigation_id,
                    source_evidence_id=rel.source_evidence_id,
                    target_evidence_id=rel.target_evidence_id,
                    relationship_type=rel.relationship_type,
                    weight=rel.weight,
                    context_attributes=rel.context_attributes,
                    relationship_fingerprint=fp,
                )
                try:
                    with db.begin_nested():
                        db.add(rel_entity)
                        db.flush()
                    relationships_created += 1
                except IntegrityError:
                    relationships_reused += 1

            if relationships_created > 0:
                db.commit()

            return CorrelationSummary(
                source_id=source_id, investigation_id=investigation_id, status="COMPLETED",
                evidence_evaluated=n_records, candidate_pairs_evaluated=len(candidate_pairs),
                relationships_created=relationships_created, relationships_reused=relationships_reused,
                strategy_counts=dict(strategy_counts), configuration_version=self.version,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2)
            )

        except Exception as exc:
            db.rollback()
            return CorrelationSummary(
                source_id=source_id, investigation_id=investigation_id, status="FAILED",
                evidence_evaluated=n_records, candidate_pairs_evaluated=0, relationships_created=0,
                configuration_version=self.version, errors=[str(exc)],
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2)
            )
