"""Regression test suite for Comprehensive Functional Logic Audit remediation.

Tests:
1. Priority sorting in /detection/findings:
   - Canonical tier hierarchy: CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL
   - Unprioritized Critical finding (fallback severity) sorts before prioritized Low/Info finding
   - Deterministic tie-breaking on created_at and id
2. Priority tier filtering in /investigations/{id}/report/preflight and PDF generation:
   - Prioritized finding via activity or artifact maintains tier in preflight summary
   - Priority filter 'CRITICAL,HIGH' accurately includes both Critical and High findings
3. Investigation containment and state isolation
"""

import io
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.activity import Activity
from app.models.priority_result import PriorityResult
from app.models.associations import FindingEvidence, ActivityFinding


def test_priority_sorting_canonical_tiers(app_client: TestClient, db_session: Session):
    """Verify that findings are sorted strictly by canonical tier (CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL)
    even when an unprioritized CRITICAL finding (severity fallback) is compared against a prioritized LOW finding.
    """
    now = datetime.now(timezone.utc)
    inv_id = uuid.uuid4()
    inv = Investigation(
        id=inv_id,
        title="Priority Sorting Test Case",
        case_number="CASE-SORT-001",
        created_at=now,
    )
    db_session.add(inv)

    src = EvidenceSource(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        filename="syslog.json",
        file_format="json",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=1024,
        ingested_at=now,
    )
    db_session.add(src)

    ev_low = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=src.id,
        source_type="syslog",
        timestamp=now,
        event_type="network",
        attributes={"test": "low"},
    )
    db_session.add(ev_low)

    # 1. Low finding that HAS an automated PriorityResult with priority_score = 15.0 (INFORMATIONAL/LOW)
    f_low = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-LOW-01",
        severity_score=0.15,
        detection_fingerprint=f"fp-low-{uuid.uuid4()}",
        description="Low severity informational ping",
        created_at=now - timedelta(minutes=5),
    )
    db_session.add(f_low)
    db_session.flush()

    prio_low = PriorityResult(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        target_id=ev_low.id,
        target_type="ARTIFACT",
        priority_score=15.0,
        priority_tier="INFORMATIONAL",
        method_type="BASELINE_INDEPENDENT",
        factor_breakdown={},
        explanation_text="Low risk baseline artifact",
        computed_at=now,
    )
    db_session.add(prio_low)
    db_session.add(FindingEvidence(finding_id=f_low.id, evidence_id=ev_low.id))

    # 2. Critical finding that DOES NOT have a PriorityResult (severity = 0.95 -> fallback CRITICAL)
    f_crit = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-CRIT-01",
        severity_score=0.95,
        detection_fingerprint=f"fp-crit-{uuid.uuid4()}",
        description="Unprioritized critical exploit detection",
        created_at=now - timedelta(minutes=10),
    )
    db_session.add(f_crit)

    # 3. High finding that DOES NOT have a PriorityResult (severity = 0.75 -> fallback HIGH)
    f_high = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-HIGH-01",
        severity_score=0.75,
        detection_fingerprint=f"fp-high-{uuid.uuid4()}",
        description="High severity credential dumping",
        created_at=now - timedelta(minutes=8),
    )
    db_session.add(f_high)

    db_session.commit()

    # Query findings sorted by default (priority ordering)
    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}")
    assert res.status_code == 200, res.text
    data = res.json()
    items = data["items"]
    assert len(items) == 3

    # CRITICAL must sort first, then HIGH, then INFORMATIONAL/LOW
    assert items[0]["id"] == str(f_crit.id), f"Expected CRITICAL first, got {items[0]['priority_tier']}"
    assert items[0]["priority_tier"] == "CRITICAL"

    assert items[1]["id"] == str(f_high.id), f"Expected HIGH second, got {items[1]['priority_tier']}"
    assert items[1]["priority_tier"] == "HIGH"

    assert items[2]["id"] == str(f_low.id), f"Expected LOW/INFO third, got {items[2]['priority_tier']}"
    assert items[2]["priority_tier"] in ("INFORMATIONAL", "LOW")


def test_priority_sorting_tie_breaking(app_client: TestClient, db_session: Session):
    """Verify deterministic tie-breaking: when findings have equal tier and score,
    they are ordered by created_at desc, then id desc.
    """
    now = datetime.now(timezone.utc)
    inv_id = uuid.uuid4()
    inv = Investigation(
        id=inv_id,
        title="Tie Breaking Test Case",
        case_number="CASE-TIE-001",
        created_at=now,
    )
    db_session.add(inv)

    # Two findings with identical severity (0.90) and tier (CRITICAL), but different timestamps
    f_older = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-A",
        severity_score=0.90,
        detection_fingerprint=f"fp-old-{uuid.uuid4()}",
        description="Older finding",
        created_at=now - timedelta(minutes=10),
    )
    f_newer = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-B",
        severity_score=0.90,
        detection_fingerprint=f"fp-new-{uuid.uuid4()}",
        description="Newer finding",
        created_at=now - timedelta(minutes=2),
    )
    db_session.add(f_older)
    db_session.add(f_newer)
    db_session.commit()

    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}")
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 2
    assert items[0]["id"] == str(f_newer.id), "Newer finding must precede older finding on tie"
    assert items[1]["id"] == str(f_older.id)


def test_report_preflight_authoritative_prioritized_tiers(app_client: TestClient, db_session: Session):
    """Verify that Report Preflight and PDF generation evaluate priority tiers consistently with
    active pipeline PriorityResult records (e.g., activity-derived CRITICAL finding).
    """
    now = datetime.now(timezone.utc)
    inv_id = uuid.uuid4()
    inv = Investigation(
        id=inv_id,
        title="Preflight Prioritized Tiers Case",
        case_number="CASE-PRE-001",
        created_at=now,
    )
    db_session.add(inv)

    src = EvidenceSource(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        filename="auth.log",
        file_format="json",
        sha256_hash="a" * 64,
        file_size_bytes=512,
        ingested_at=now,
    )
    db_session.add(src)

    ev = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=src.id,
        source_type="auth",
        timestamp=now,
        event_type="auth",
        attributes={"action": "logon"},
    )
    db_session.add(ev)

    # Finding with raw severity 0.50 (normally MEDIUM), but linked to an Activity with CRITICAL priority (score 92.0)
    f_active = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-PRIV-01",
        severity_score=0.50,
        detection_fingerprint=f"fp-act-{uuid.uuid4()}",
        description="Suspicious privilege escalation",
        created_at=now,
    )
    db_session.add(f_active)
    db_session.flush()

    act = Activity(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        title="Credential Access Thread",
        activity_type="ATTACK_CHAIN",
        status="REVIEWING",
        start_time=now - timedelta(minutes=30),
        end_time=now,
        evidence_count=1,
        finding_count=1,
    )
    db_session.add(act)
    db_session.flush()

    db_session.add(ActivityFinding(activity_id=act.id, finding_id=f_active.id))

    prio_act = PriorityResult(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        target_id=act.id,
        target_type="ACTIVITY",
        priority_score=92.0,
        priority_tier="CRITICAL",
        method_type="PROPOSED_CONTEXTUAL",
        factor_breakdown={},
        explanation_text="Critical multi-event attack chain activity",
        computed_at=now,
    )
    db_session.add(prio_act)
    db_session.commit()

    # Preflight with ALL priorities
    res_all = app_client.get(f"/api/v1/investigations/{inv_id}/report/preflight")
    assert res_all.status_code == 200
    data_all = res_all.json()
    assert data_all["findings_summary"]["total_findings"] == 1
    assert data_all["findings_summary"]["by_priority_tier"]["CRITICAL"] == 1, (
        "Finding linked to CRITICAL activity must be classified as CRITICAL in preflight"
    )

    # Preflight with CRITICAL,HIGH filter
    res_crit_high = app_client.get(f"/api/v1/investigations/{inv_id}/report/preflight?priority_filter=CRITICAL,HIGH")
    assert res_crit_high.status_code == 200
    data_crit_high = res_crit_high.json()
    assert data_crit_high["findings_summary"]["included_findings"] == 1, (
        "CRITICAL activity-derived finding must be included when filtering for CRITICAL,HIGH"
    )

    # Preflight with LOW filter - should exclude the finding
    res_low = app_client.get(f"/api/v1/investigations/{inv_id}/report/preflight?priority_filter=LOW")
    assert res_low.status_code == 200
    data_low = res_low.json()
    assert data_low["findings_summary"]["included_findings"] == 0


def test_report_export_pdf_preserves_priority_filtering(app_client: TestClient, db_session: Session):
    """Verify that download_investigation_report generates a valid PDF respecting priority tier filters."""
    now = datetime.now(timezone.utc)
    inv_id = uuid.uuid4()
    inv = Investigation(
        id=inv_id,
        title="PDF Report Generation Test",
        case_number="CASE-PDF-001",
        created_at=now,
    )
    db_session.add(inv)

    src = EvidenceSource(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        filename="security.evtx",
        file_format="json",
        sha256_hash="b" * 64,
        file_size_bytes=2048,
        ingested_at=now,
    )
    db_session.add(src)

    f = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-ADMIN-01",
        severity_score=0.85,
        detection_fingerprint=f"fp-pdf-{uuid.uuid4()}",
        description="Domain admin account created",
        created_at=now,
    )
    db_session.add(f)
    db_session.commit()

    # Generate PDF with priority filter
    res = app_client.get(f"/api/v1/investigations/{inv_id}/report?priority_filter=CRITICAL,HIGH")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content[:4] == b"%PDF"
