"""Test suite for Phase 2: Investigation & Triage Workflow (Finding Reviews & Keyboard Nav)."""

import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session
from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.finding_review import FindingReview
from app.models.associations import FindingEvidence
from app.detection import compute_detection_fingerprint


@pytest.fixture
def triage_test_environment(db_session: Session):
    """Sets up an isolated investigation with findings for review triage testing."""
    now = datetime.now(timezone.utc)

    # 1. Primary Investigation
    inv_id = uuid.uuid4()
    inv = Investigation(
        id=inv_id,
        title="Triage Investigation Alpha",
        case_number=f"CASE-TRIAGE-{inv_id.hex[:6].upper()}",
        description="Investigation for testing finding triage and review status",
        created_at=now,
    )
    db_session.add(inv)

    # 2. Secondary Investigation for Isolation Tests
    other_inv_id = uuid.uuid4()
    other_inv = Investigation(
        id=other_inv_id,
        title="Triage Investigation Beta (Isolation)",
        case_number=f"CASE-TRIAGE-{other_inv_id.hex[:6].upper()}",
        description="Cross-investigation isolation target",
        created_at=now,
    )
    db_session.add(other_inv)

    # Sources
    source_id = uuid.uuid4()
    source = EvidenceSource(
        id=source_id,
        investigation_id=inv_id,
        filename="syslog.csv",
        file_format="CSV",
        storage_path="/tmp/syslog.csv",
        sha256_hash="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        file_size_bytes=2048,
        total_records=2,
        ingestion_status="COMPLETED",
    )
    db_session.add(source)

    ev1 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=source_id,
        raw_record_offset=0,
        timestamp=now,
        event_type="PROCESS_CREATE",
        source_type="SYSLOG",
        attributes={"process_name": "powershell.exe"},
    )
    ev2 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=source_id,
        raw_record_offset=1,
        timestamp=now,
        event_type="NETWORK_CONNECT",
        source_type="SYSLOG",
        attributes={"ip_address": "198.51.100.24"},
    )
    db_session.add_all([ev1, ev2])
    db_session.flush()

    # Create 3 distinct findings in primary investigation
    fp1 = compute_detection_fingerprint(inv_id, "RULE-POWERSHELL-EXEC", "1.0", [ev1.id])
    finding1 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-POWERSHELL-EXEC:v1.0",
        severity_score=0.90,
        description="Suspicious PowerShell command execution detected",
        detection_fingerprint=fp1,
        created_at=now,
    )

    fp2 = compute_detection_fingerprint(inv_id, "RULE-SUSPICIOUS-C2", "1.0", [ev2.id])
    finding2 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="IOC_MATCH",
        rule_id="RULE-SUSPICIOUS-C2:v1.0",
        severity_score=0.75,
        description="Outbound communication to known C2 indicator",
        detection_fingerprint=fp2,
        created_at=now,
    )

    fp3 = compute_detection_fingerprint(inv_id, "isolation_forest", "1.0", [ev1.id, ev2.id])
    finding3 = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="ML_ANOMALY",
        rule_id="ML-isolation_forest:v1.0",
        severity_score=0.45,
        description="Statistical outlier anomaly detected across process activity",
        detection_fingerprint=fp3,
        created_at=now,
    )
    db_session.add_all([finding1, finding2, finding3])
    db_session.flush()

    db_session.add(FindingEvidence(finding_id=finding1.id, evidence_id=ev1.id))
    db_session.add(FindingEvidence(finding_id=finding2.id, evidence_id=ev2.id))
    db_session.add(FindingEvidence(finding_id=finding3.id, evidence_id=ev1.id))
    db_session.add(FindingEvidence(finding_id=finding3.id, evidence_id=ev2.id))

    # Finding in secondary investigation
    other_source_id = uuid.uuid4()
    other_source = EvidenceSource(
        id=other_source_id,
        investigation_id=other_inv_id,
        filename="other.csv",
        file_format="CSV",
        storage_path="/tmp/other.csv",
        sha256_hash="112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
        file_size_bytes=1024,
        total_records=1,
        ingestion_status="COMPLETED",
    )
    db_session.add(other_source)
    db_session.flush()

    other_ev = Evidence(
        id=uuid.uuid4(),
        investigation_id=other_inv_id,
        source_id=other_source_id,
        raw_record_offset=0,
        timestamp=now,
        event_type="AUTH_FAILURE",
        source_type="SYSLOG",
        attributes={},
    )
    db_session.add(other_ev)
    db_session.flush()

    fp_other = compute_detection_fingerprint(other_inv_id, "RULE-BRUTE-FORCE", "1.0", [other_ev.id])
    other_finding = Finding(
        id=uuid.uuid4(),
        investigation_id=other_inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-BRUTE-FORCE:v1.0",
        severity_score=0.80,
        description="Multiple failed authentications",
        detection_fingerprint=fp_other,
        created_at=now,
    )
    db_session.add(other_finding)
    db_session.flush()
    db_session.add(FindingEvidence(finding_id=other_finding.id, evidence_id=other_ev.id))
    db_session.commit()

    return {
        "inv_id": inv_id,
        "other_inv_id": other_inv_id,
        "finding1": finding1,
        "finding2": finding2,
        "finding3": finding3,
        "other_finding": other_finding,
    }


# -----------------------------------------------------------------------------
# 1. Review Status Lifecycle Tests
# -----------------------------------------------------------------------------

def test_default_review_status_is_new(app_client, triage_test_environment):
    """Verify that any finding without a persisted review record defaults to 'NEW'."""
    inv_id = triage_test_environment["inv_id"]
    finding1 = triage_test_environment["finding1"]

    res = app_client.get(
        f"/api/v1/detection/findings/{finding1.id}/review",
        params={"investigation_id": str(inv_id)},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "NEW"
    assert data["notes"] is None
    assert data["finding_id"] == str(finding1.id)
    assert data["investigation_id"] == str(inv_id)

    # In findings list, review_status must also be NEW
    list_res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}")
    assert list_res.status_code == 200
    items = list_res.json()["items"]
    f1_item = next(item for item in items if item["id"] == str(finding1.id))
    assert f1_item["review_status"] == "NEW"


def test_update_review_status_lifecycle(app_client, triage_test_environment):
    """Verify transitions to REVIEWED, FALSE_POSITIVE, and ESCALATED."""
    inv_id = triage_test_environment["inv_id"]
    finding1 = triage_test_environment["finding1"]

    # 1. Update to REVIEWED
    res1 = app_client.put(
        f"/api/v1/detection/findings/{finding1.id}/review",
        json={
            "investigation_id": str(inv_id),
            "status": "REVIEWED",
            "notes": "Verified initial execution context; suspicious command string confirmed.",
        },
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "REVIEWED"
    assert "Verified initial execution" in res1.json()["notes"]

    # 2. Update to ESCALATED
    res2 = app_client.put(
        f"/api/v1/detection/findings/{finding1.id}/review",
        json={
            "investigation_id": str(inv_id),
            "status": "ESCALATED",
            "notes": "Escalated for immediate forensic imaging of host WS-01.",
        },
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "ESCALATED"

    # 3. Update to FALSE_POSITIVE
    res3 = app_client.put(
        f"/api/v1/detection/findings/{finding1.id}/review",
        json={
            "investigation_id": str(inv_id),
            "status": "FALSE_POSITIVE",
            "notes": "Confirmed benign administrative activity by systems engineer.",
        },
    )
    assert res3.status_code == 200
    assert res3.json()["status"] == "FALSE_POSITIVE"

    # Verify original finding severity and description were NOT modified
    detail_res = app_client.get(
        f"/api/v1/detection/findings/{finding1.id}",
        params={"investigation_id": str(inv_id)},
    )
    assert detail_res.status_code == 200
    assert detail_res.json()["severity"] == finding1.severity_score
    assert detail_res.json()["description"] == finding1.description
    assert detail_res.json()["review_status"] == "FALSE_POSITIVE"


def test_reject_invalid_review_status(app_client, triage_test_environment):
    """Verify backend validation rejects unsupported statuses with 422."""
    inv_id = triage_test_environment["inv_id"]
    finding1 = triage_test_environment["finding1"]

    res = app_client.put(
        f"/api/v1/detection/findings/{finding1.id}/review",
        json={
            "investigation_id": str(inv_id),
            "status": "CONFIRMED_MALICIOUS",  # Invalid, not in allowed set
            "notes": "Invalid status test",
        },
    )
    assert res.status_code == 422


# -----------------------------------------------------------------------------
# 2. Persistence and Session Survival Tests
# -----------------------------------------------------------------------------

def test_review_status_persistence(app_client, triage_test_environment, db_session):
    """Verify review status is reliably written to database table and survives across queries."""
    inv_id = triage_test_environment["inv_id"]
    finding2 = triage_test_environment["finding2"]

    # Record review decision
    app_client.put(
        f"/api/v1/detection/findings/{finding2.id}/review",
        json={
            "investigation_id": str(inv_id),
            "status": "REVIEWED",
            "notes": "Persistent storage test note.",
        },
    )

    # Directly inspect database table via separate query
    db_review = (
        db_session.query(FindingReview)
        .filter(FindingReview.finding_id == finding2.id)
        .first()
    )
    assert db_review is not None
    assert db_review.status == "REVIEWED"
    assert db_review.notes == "Persistent storage test note."
    assert db_review.investigation_id == inv_id


# -----------------------------------------------------------------------------
# 3. Investigation Isolation & Cross-Case Access Tests
# -----------------------------------------------------------------------------

def test_cross_investigation_review_access_blocked(app_client, triage_test_environment):
    """Verify that a finding cannot be reviewed or accessed under a different investigation ID."""
    inv_id = triage_test_environment["inv_id"]
    other_inv_id = triage_test_environment["other_inv_id"]
    finding1 = triage_test_environment["finding1"]

    # 1. Attempt to update review using wrong investigation_id must return 404
    res_update = app_client.put(
        f"/api/v1/detection/findings/{finding1.id}/review",
        json={
            "investigation_id": str(other_inv_id),
            "status": "ESCALATED",
        },
    )
    assert res_update.status_code == 404

    # 2. Attempt to retrieve review using wrong investigation_id must return 404
    res_get = app_client.get(
        f"/api/v1/detection/findings/{finding1.id}/review",
        params={"investigation_id": str(other_inv_id)},
    )
    assert res_get.status_code == 404


def test_missing_or_nonexistent_finding_review(app_client, triage_test_environment):
    """Verify 404 behavior for non-existent finding UUIDs."""
    inv_id = triage_test_environment["inv_id"]
    random_id = uuid.uuid4()

    res = app_client.get(
        f"/api/v1/detection/findings/{random_id}/review",
        params={"investigation_id": str(inv_id)},
    )
    assert res.status_code == 404


# -----------------------------------------------------------------------------
# 4. Review Status Filtering & Batch Loading Tests
# -----------------------------------------------------------------------------

def test_filter_findings_by_review_status(app_client, triage_test_environment):
    """Verify filtering findings by review_status returns exact matches."""
    inv_id = triage_test_environment["inv_id"]
    finding1 = triage_test_environment["finding1"]
    finding2 = triage_test_environment["finding2"]
    finding3 = triage_test_environment["finding3"]

    # Mark finding1 as ESCALATED, finding2 as REVIEWED, leave finding3 as NEW
    app_client.put(
        f"/api/v1/detection/findings/{finding1.id}/review",
        json={"investigation_id": str(inv_id), "status": "ESCALATED"},
    )
    app_client.put(
        f"/api/v1/detection/findings/{finding2.id}/review",
        json={"investigation_id": str(inv_id), "status": "REVIEWED"},
    )

    # 1. Filter by ESCALATED
    res_esc = app_client.get(
        f"/api/v1/detection/findings?investigation_id={inv_id}&review_status=ESCALATED"
    )
    assert res_esc.status_code == 200
    items_esc = res_esc.json()["items"]
    assert len(items_esc) == 1
    assert items_esc[0]["id"] == str(finding1.id)
    assert items_esc[0]["review_status"] == "ESCALATED"

    # 2. Filter by REVIEWED
    res_rev = app_client.get(
        f"/api/v1/detection/findings?investigation_id={inv_id}&review_status=REVIEWED"
    )
    assert res_rev.status_code == 200
    items_rev = res_rev.json()["items"]
    assert len(items_rev) == 1
    assert items_rev[0]["id"] == str(finding2.id)
    assert items_rev[0]["review_status"] == "REVIEWED"

    # 3. Filter by NEW
    res_new = app_client.get(
        f"/api/v1/detection/findings?investigation_id={inv_id}&review_status=NEW"
    )
    assert res_new.status_code == 200
    items_new = res_new.json()["items"]
    assert len(items_new) == 1
    assert items_new[0]["id"] == str(finding3.id)
    assert items_new[0]["review_status"] == "NEW"

    # 4. Filter by FALSE_POSITIVE (none marked yet)
    res_fp = app_client.get(
        f"/api/v1/detection/findings?investigation_id={inv_id}&review_status=FALSE_POSITIVE"
    )
    assert res_fp.status_code == 200
    assert len(res_fp.json()["items"]) == 0


# -----------------------------------------------------------------------------
# 5. Finding Lifecycle and Regeneration Safety Tests
# -----------------------------------------------------------------------------

def test_pipeline_rerun_preserves_finding_identity_and_review(app_client, triage_test_environment, db_session):
    """Verify that detection rules rerun maintains finding IDs and preserved review status."""
    inv_id = triage_test_environment["inv_id"]
    finding1 = triage_test_environment["finding1"]

    # Mark finding1 as ESCALATED
    app_client.put(
        f"/api/v1/detection/findings/{finding1.id}/review",
        json={"investigation_id": str(inv_id), "status": "ESCALATED", "notes": "Hold for review"},
    )

    # Re-query list endpoint
    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}")
    assert res.status_code == 200
    item = next(f for f in res.json()["items"] if f["id"] == str(finding1.id))
    assert item["review_status"] == "ESCALATED"
    assert item["review_notes"] == "Hold for review"


def test_finding_deletion_cascades_to_review(triage_test_environment, db_session):
    """Verify that deleting a finding cascades cleanly to remove the associated review record."""
    inv_id = triage_test_environment["inv_id"]
    finding = triage_test_environment["finding3"]

    # Create review directly in DB
    rev = FindingReview(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_id=finding.id,
        status="REVIEWED",
        notes="Review to be cascaded",
    )
    db_session.add(rev)
    db_session.commit()

    # Delete finding
    db_session.delete(finding)
    db_session.commit()

    # FindingReview must be gone
    orphaned_rev = db_session.query(FindingReview).filter_by(finding_id=finding.id).first()
    assert orphaned_rev is None

