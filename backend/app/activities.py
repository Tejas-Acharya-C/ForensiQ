"""Investigation Activity Formation Service, Clustering, and Persistence."""

import hashlib
import json
import time
import uuid
from typing import List, Dict, Any, Optional, Set, Sequence, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import Counter

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.logging import get_logger
from app.core.errors import NotFoundError
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.associations import FindingEvidence, ActivityEvidence, ActivityFinding
from app.models.relationship import Relationship
from app.models.activity import Activity

logger = get_logger("activity_service")


@dataclass
class ActivityFormationSummary:
    source_id: Optional[uuid.UUID]
    investigation_id: uuid.UUID
    status: str
    evidence_evaluated: int
    relationships_evaluated: int
    activities_created: int
    activities_reused: int = 0
    duration_ms: float = 0.0
    errors: List[str] = field(default_factory=list)


def compute_activity_fingerprint(
    investigation_id: uuid.UUID,
    member_evidence_ids: Sequence[uuid.UUID],
) -> str:
    sorted_evd_strings = sorted([str(eid) for eid in member_evidence_ids])
    canonical_dict = {
        "investigation_id": str(investigation_id),
        "member_evidence_ids": sorted_evd_strings,
    }
    canonical_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


class ActivityService:
    def __init__(self):
        self.min_relationship_strength = 0.35
        self.max_temporal_span = 7200

    def form_activities_for_source(self, db: Session, source_id: uuid.UUID) -> ActivityFormationSummary:
        start_time = time.perf_counter()

        source = db.get(EvidenceSource, source_id)
        if not source:
            raise NotFoundError(f"EvidenceSource '{source_id}' not found.")

        investigation_id = source.investigation_id

        # 1. Load Evidence
        evidence_list: List[Evidence] = (
            db.query(Evidence)
            .filter_by(source_id=source_id)
            .order_by(Evidence.timestamp.asc(), Evidence.raw_record_offset.asc())
            .all()
        )
        if not evidence_list:
            return ActivityFormationSummary(
                source_id=source_id, investigation_id=investigation_id, status="INSUFFICIENT_DATA",
                evidence_evaluated=0, relationships_evaluated=0, activities_created=0,
                errors=["No evidence records found."],
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2)
            )

        evidence_by_id = {e.id: e for e in evidence_list}
        evidence_id_set = set(evidence_by_id.keys())

        # 2. Load Relationships
        relationships: List[Relationship] = (
            db.query(Relationship)
            .filter(
                Relationship.investigation_id == investigation_id,
                Relationship.source_evidence_id.in_(evidence_id_set),
                Relationship.target_evidence_id.in_(evidence_id_set),
                Relationship.weight >= self.min_relationship_strength
            )
            .all()
        )

        # 3. Load Findings
        finding_rows = (
            db.query(FindingEvidence.evidence_id, Finding)
            .join(Finding, FindingEvidence.finding_id == Finding.id)
            .filter(Finding.investigation_id == investigation_id, FindingEvidence.evidence_id.in_(evidence_id_set))
            .all()
        )
        findings_by_evidence = defaultdict(list)
        for evd_id, fnd in finding_rows:
            findings_by_evidence[evd_id].append(fnd)

        try:
            # 4. Build Adjacency List
            adj = defaultdict(set)
            for r in relationships:
                if r.source_evidence_id != r.target_evidence_id:
                    adj[r.source_evidence_id].add(r.target_evidence_id)
                    adj[r.target_evidence_id].add(r.source_evidence_id)

            # 5. Extract Connected Components (BFS) — sorted seed order for determinism
            visited = set()
            components = []
            for seed in sorted(evidence_id_set):
                if seed in visited: continue
                
                if seed not in adj or not adj[seed]:
                    visited.add(seed)
                    components.append([seed])
                    continue
                
                comp = []
                queue = deque([seed])
                visited.add(seed)
                while queue:
                    curr = queue.popleft()
                    comp.append(curr)
                    for nxt in sorted(adj[curr]):   # sorted for deterministic BFS expansion
                        if nxt not in visited:
                            visited.add(nxt)
                            queue.append(nxt)
                components.append(comp)

            # 6. Refine by Temporal Boundaries
            final_groups = []
            for comp in components:
                mem = sorted(
                    [evidence_by_id[eid] for eid in comp],
                    key=lambda e: (e.timestamp.replace(tzinfo=timezone.utc) if e.timestamp and e.timestamp.tzinfo is None else (e.timestamp or datetime.min.replace(tzinfo=timezone.utc)), e.id)
                )
                if not mem: continue
                
                cur_sub = [mem[0].id]
                start_ts = mem[0].timestamp.replace(tzinfo=timezone.utc) if mem[0].timestamp and mem[0].timestamp.tzinfo is None else mem[0].timestamp
                for i in range(1, len(mem)):
                    cur_ts = mem[i].timestamp.replace(tzinfo=timezone.utc) if mem[i].timestamp and mem[i].timestamp.tzinfo is None else mem[i].timestamp
                    if cur_ts and start_ts and abs((cur_ts - start_ts).total_seconds()) > self.max_temporal_span:
                        final_groups.append(cur_sub)
                        cur_sub = [mem[i].id]
                        start_ts = cur_ts
                    else:
                        cur_sub.append(mem[i].id)
                if cur_sub:
                    final_groups.append(cur_sub)

            # 7. Filter and Form Activities
            activities_created = 0
            activities_reused = 0

            for group_ids in final_groups:
                if len(group_ids) < 2 and not findings_by_evidence.get(group_ids[0]):
                    continue # Ignore singletons without findings

                group_evd = [evidence_by_id[eid] for eid in group_ids]
                group_id_set = set(group_ids)

                internal_rels = [r for r in relationships if r.source_evidence_id in group_id_set and r.target_evidence_id in group_id_set]
                
                group_findings_map = {}
                for eid in group_ids:
                    for f in findings_by_evidence.get(eid, []):
                        group_findings_map[f.id] = f
                
                t_start = min(e.timestamp for e in group_evd)
                t_end = max(e.timestamp for e in group_evd)

                # Naming and typing
                event_types = [e.event_type for e in group_evd if e.event_type]
                act_type = "MIXED_ACTIVITY"
                if event_types:
                    dominant_event = Counter(event_types).most_common(1)[0][0]
                    if "AUTH" in dominant_event or "LOGIN" in dominant_event: act_type = "AUTHENTICATION"
                    elif "PROCESS" in dominant_event: act_type = "PROCESS_ACTIVITY"
                    elif "NETWORK" in dominant_event or "CONN" in dominant_event: act_type = "NETWORK_ACTIVITY"
                    elif "FILE" in dominant_event: act_type = "FILE_ACTIVITY"
                    else: act_type = dominant_event

                devices = {e.device_id for e in group_evd if e.device_id}
                target_host = sorted(devices)[0] if devices else "Host"
                title = f"{act_type.replace('_', ' ').title()} — {target_host}"

                desc = f"Activity consisting of {len(group_evd)} evidence records on {target_host}."
                
                fp = compute_activity_fingerprint(investigation_id, group_ids)

                act_entity = Activity(
                    id=uuid.uuid4(),
                    investigation_id=investigation_id,
                    title=title,
                    activity_type=act_type,
                    description=desc,
                    start_time=t_start,
                    end_time=t_end,
                    evidence_count=len(group_ids),
                    finding_count=len(group_findings_map),
                    status="NEW",
                    activity_fingerprint=fp,
                )

                try:
                    with db.begin_nested():
                        db.add(act_entity)
                        db.flush()
                        for eid in group_ids:
                            db.add(ActivityEvidence(activity_id=act_entity.id, evidence_id=eid))
                        for fid in group_findings_map:
                            db.add(ActivityFinding(activity_id=act_entity.id, finding_id=fid))
                        db.flush()
                    activities_created += 1
                except IntegrityError:
                    activities_reused += 1

            if activities_created > 0:
                db.commit()

            return ActivityFormationSummary(
                source_id=source_id, investigation_id=investigation_id, status="COMPLETED",
                evidence_evaluated=len(evidence_list), relationships_evaluated=len(relationships),
                activities_created=activities_created, activities_reused=activities_reused,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2)
            )
        except Exception as exc:
            db.rollback()
            return ActivityFormationSummary(
                source_id=source_id, investigation_id=investigation_id, status="FAILED",
                evidence_evaluated=len(evidence_list), relationships_evaluated=len(relationships),
                activities_created=0, errors=[str(exc)],
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2)
            )