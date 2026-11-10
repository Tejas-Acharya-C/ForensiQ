"""Focused regression tests for Findings Priority Sorting Contract (DEF-02).

Validates:
1. Prioritized vs unranked findings in the same tier (prioritized always precedes unranked fallback).
2. Priority tier hierarchy (CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL).
3. Same-tier prioritized findings ordered by priority_score descending.
4. Same-tier unranked findings ordered by raw severity descending.
5. Deterministic secondary tie-breakers: created_at descending, then finding id descending.
6. Endpoint API contract conformance for sort_by=priority and sort_by=created_at.
"""

import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.activity import Activity
from app.models.priority_result import PriorityResult
from app.models.associations import FindingEvidence, ActivityFinding


@pytest.fixture
def sorting_test_env(db_session):
    """Creates a controlled synthetic forensic case to test all priority sorting edge cases."""
    inv = Investigation(
        id=uuid.uuid4(),
        title="Priority Sorting Validation Case",
        case_number=f"CASE-SORT-{uuid.uuid4().hex[:6]}",
        status="OPEN",
    )
    db_session.add(inv)

    src = EvidenceSource(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        filename="telemetry.csv",
        file_format="CSV",
        storage_path="/var/forensics/telemetry.csv",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=1024,
        total_records=10,
        ingestion_status="COMPLETED",
    )
    db_session.add(src)

    base_time = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Evidence records
    ev1 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        source_id=src.id,
        raw_record_offset=1,
        timestamp=base_time,
        event_type="PROCESS_START",
        source_type="ENDPOINT",
        status="SUCCESS",
        attributes={},
    )
    ev2 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        source_id=src.id,
        raw_record_offset=2,
        timestamp=base_time + timedelta(seconds=10),
        event_type="NETWORK_CONNECT",
        source_type="NETWORK",
        status="SUCCESS",
        attributes={},
    )
    db_session.add_all([ev1, ev2])
    db_session.flush()

    # Activity
    act = Activity(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        title="Suspicious Activity Thread",
        activity_type="PROCESS_ACTIVITY",
        start_time=base_time,
        end_time=base_time + timedelta(seconds=10),
        evidence_count=2,
        finding_count=1,
        status="NEW",
    )
    db_session.add(act)
    db_session.flush()

    # Findings
    # F1: Prioritized CRITICAL (Activity-based score 85.5)
    f1 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-001",
        severity_score=0.70,
        description="Prioritized Critical Finding 1",
        created_at=base_time + timedelta(minutes=1),
    )
    # F2: Prioritized CRITICAL (Artifact-based score 92.0)
    f2 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-002",
        severity_score=0.75,
        description="Prioritized Critical Finding 2",
        created_at=base_time + timedelta(minutes=2),
    )
    # F3: Unranked CRITICAL fallback (severity 0.95 -> CRITICAL fallback, score None)
    f3 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-003",
        severity_score=0.95,
        description="Unranked Critical Finding 3 (High Severity Fallback)",
        created_at=base_time + timedelta(minutes=3),
    )
    # F4: Unranked CRITICAL fallback (severity 0.85 -> CRITICAL fallback, score None)
    f4 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-004",
        severity_score=0.85,
        description="Unranked Critical Finding 4 (Lower Severity Fallback)",
        created_at=base_time + timedelta(minutes=4),
    )
    # F5: Prioritized HIGH (score 65.0, tier HIGH)
    f5 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-005",
        severity_score=0.60,
        description="Prioritized High Finding 5",
        created_at=base_time + timedelta(minutes=5),
    )
    # F6: Unranked HIGH fallback (severity 0.70 -> HIGH fallback, score None)
    f6 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-006",
        severity_score=0.70,
        description="Unranked High Finding 6",
        created_at=base_time + timedelta(minutes=6),
    )
    # F7: Unranked MEDIUM fallback (severity 0.50 -> MEDIUM fallback, score None)
    f7 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-007",
        severity_score=0.50,
        description="Unranked Medium Finding 7",
        created_at=base_time + timedelta(minutes=7),
    )
    # F8: Unranked LOW fallback (severity 0.25 -> LOW fallback, score None)
    f8 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-008",
        severity_score=0.25,
        description="Unranked Low Finding 8",
        created_at=base_time + timedelta(minutes=8),
    )
    # F9: Unranked INFORMATIONAL fallback (severity 0.10 -> INFORMATIONAL fallback, score None)
    f9 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-009",
        severity_score=0.10,
        description="Unranked Informational Finding 9",
        created_at=base_time + timedelta(minutes=9),
    )

    db_session.add_all([f1, f2, f3, f4, f5, f6, f7, f8, f9])
    db_session.flush()

    # Link f1 to act
    db_session.add(ActivityFinding(activity_id=act.id, finding_id=f1.id))
    # Link f2 to ev1
    db_session.add(FindingEvidence(finding_id=f2.id, evidence_id=ev1.id))
    # Link f5 to ev2
    db_session.add(FindingEvidence(finding_id=f5.id, evidence_id=ev2.id))

    # Priority results
    # Prio 1 for act (f1)
    p1 = PriorityResult(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        target_type="ACTIVITY",
        target_id=act.id,
        priority_score=85.5,
        priority_tier="CRITICAL",
        factor_breakdown={"factors": []},
        explanation_text="Activity priority explanation text",
        method_type="PROPOSED_CONTEXTUAL",
    )
    # Prio 2 for ev1 (f2)
    p2 = PriorityResult(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        target_type="ARTIFACT",
        target_id=ev1.id,
        priority_score=92.0,
        priority_tier="CRITICAL",
        factor_breakdown={"factors": []},
        explanation_text="Artifact priority explanation text 2",
        method_type="BASELINE_INDEPENDENT",
    )
    # Prio 5 for ev2 (f5)
    p5 = PriorityResult(
        id=uuid.uuid4(),
        investigation_id=inv.id,
        target_type="ARTIFACT",
        target_id=ev2.id,
        priority_score=65.0,
        priority_tier="HIGH",
        factor_breakdown={"factors": []},
        explanation_text="Artifact priority explanation text 5",
        method_type="BASELINE_INDEPENDENT",
    )
    db_session.add_all([p1, p2, p5])
    db_session.commit()

    return {
        "inv_id": str(inv.id),
        "f1_id": str(f1.id),
        "f2_id": str(f2.id),
        "f3_id": str(f3.id),
        "f4_id": str(f4.id),
        "f5_id": str(f5.id),
        "f6_id": str(f6.id),
        "f7_id": str(f7.id),
        "f8_id": str(f8.id),
        "f9_id": str(f9.id),
    }


def test_prioritized_ahead_of_unranked_within_same_tier(app_client: TestClient, sorting_test_env):
    """Test 1: Within the CRITICAL tier, prioritized findings (has_prio=1) must precede unranked findings (has_prio=0)."""
    inv_id = sorting_test_env["inv_id"]
    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&priority_tier=CRITICAL&sort_by=priority")
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 4

    # First two must have priority_score not None
    assert items[0]["priority_score"] == 92.0
    assert items[0]["id"] == sorting_test_env["f2_id"]
    assert items[1]["priority_score"] == 85.5
    assert items[1]["id"] == sorting_test_env["f1_id"]

    # Next two are unranked fallbacks, sorted by effective_score (severity * 100)
    assert items[2]["priority_score"] is None
    assert items[2]["id"] == sorting_test_env["f3_id"]  # 0.95 -> 95.0
    assert items[3]["priority_score"] is None
    assert items[3]["id"] == sorting_test_env["f4_id"]  # 0.85 -> 85.0


def test_priority_tier_hierarchy(app_client: TestClient, sorting_test_env):
    """Test 2: Tier hierarchy must strictly respect CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL."""
    inv_id = sorting_test_env["inv_id"]
    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&sort_by=priority&limit=20")
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 9

    tiers = [item["priority_tier"] for item in items]
    expected_order = [
        "CRITICAL", "CRITICAL", "CRITICAL", "CRITICAL",  # F2, F1, F3, F4
        "HIGH", "HIGH",                                  # F5, F6
        "MEDIUM",                                        # F7
        "LOW",                                           # F8
        "INFORMATIONAL",                                 # F9
    ]
    assert tiers == expected_order


def test_same_tier_prioritized_ordered_by_score(app_client: TestClient, sorting_test_env):
    """Test 3: Prioritized findings within the same tier must order by priority_score descending."""
    inv_id = sorting_test_env["inv_id"]
    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&sort_by=priority")
    assert res.status_code == 200
    items = res.json()["items"]

    critical_prioritized = [it for it in items if it["priority_tier"] == "CRITICAL" and it["priority_score"] is not None]
    assert len(critical_prioritized) == 2
    assert critical_prioritized[0]["priority_score"] > critical_prioritized[1]["priority_score"]
    assert critical_prioritized[0]["priority_score"] == 92.0
    assert critical_prioritized[1]["priority_score"] == 85.5


def test_same_tier_unranked_ordered_by_severity(app_client: TestClient, sorting_test_env):
    """Test 4: Unranked findings within the same tier must order by raw severity score descending."""
    inv_id = sorting_test_env["inv_id"]
    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&sort_by=priority")
    assert res.status_code == 200
    items = res.json()["items"]

    critical_unranked = [it for it in items if it["priority_tier"] == "CRITICAL" and it["priority_score"] is None]
    assert len(critical_unranked) == 2
    assert critical_unranked[0]["severity"] > critical_unranked[1]["severity"]
    assert critical_unranked[0]["severity"] == 0.95
    assert critical_unranked[1]["severity"] == 0.85


def test_deterministic_secondary_tiebreakers(app_client: TestClient, db_session):
    """Test 5: Findings with identical tier, prio status, and score tie-break on created_at desc, then ID desc."""
    inv = Investigation(
        id=uuid.uuid4(),
        title="Tie Breaker Case",
        case_number=f"CASE-TIE-{uuid.uuid4().hex[:6]}",
        status="OPEN",
    )
    db_session.add(inv)

    t1 = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 3, 1, 11, 0, 0, tzinfo=timezone.utc)

    # Newer finding (t2) vs older finding (t1) with identical severity
    fa = Finding(
        id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-TIE-A",
        severity_score=0.50,
        description="Older finding",
        created_at=t1,
    )
    fb = Finding(
        id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-TIE-B",
        severity_score=0.50,
        description="Newer finding",
        created_at=t2,
    )
    # Identical timestamp findings: ID comparison
    fc = Finding(
        id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-TIE-C",
        severity_score=0.30,
        description="Same timestamp lower UUID",
        created_at=t1,
    )
    fd = Finding(
        id=uuid.UUID("44444444-4444-4444-4444-444444444444"),
        investigation_id=inv.id,
        finding_type="RULE_MATCH",
        rule_id="RULE-TIE-D",
        severity_score=0.30,
        description="Same timestamp higher UUID",
        created_at=t1,
    )
    db_session.add_all([fa, fb, fc, fd])
    db_session.commit()

    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv.id}&sort_by=priority")
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 4

    # fb (newer) must precede fa (older)
    assert items[0]["id"] == str(fb.id)
    assert items[1]["id"] == str(fa.id)

    # fd (higher UUID) must precede fc (lower UUID)
    assert items[2]["id"] == str(fd.id)
    assert items[3]["id"] == str(fc.id)
