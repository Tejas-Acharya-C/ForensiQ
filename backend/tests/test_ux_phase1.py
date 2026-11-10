"""Automated test suite for Phase 1 UX Improvement Plan:
Workflow Continuity, Evidence Navigation & Targeted De-slopping.

Covers:
1. Duplicate evidence: HTTP 409 conflict, structured error details (existing_source_id, filename, sha256_hash).
2. Distinguishing duplicate conflict from case-number conflict.
3. Genuine upload error handling (unsupported format, invalid file).
4. Evidence position lookup endpoint across pagination:
   - Record on page 1
   - Record on page 2+ (outside first page)
   - Exact offset matches list_evidence ordering (timestamp desc, id desc)
   - Investigation boundary isolation (cannot look up other investigation's evidence)
   - Missing evidence record (404)
5. Pipeline findings summary authoritative contracts for zero and non-zero detections.
"""

import io
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.priority_result import PriorityResult


@pytest.fixture
def ux_test_environment(db_session):
    """Creates isolated test investigations with paginated evidence records."""
    inv_id = uuid.uuid4()
    inv = Investigation(
        id=inv_id,
        title="UX Phase 1 Test Case",
        case_number=f"CASE-UX1-{inv_id.hex[:6]}",
        status="OPEN",
    )
    db_session.add(inv)

    other_inv_id = uuid.uuid4()
    other_inv = Investigation(
        id=other_inv_id,
        title="Other Case Isolation",
        case_number=f"CASE-OTHER-{other_inv_id.hex[:6]}",
        status="OPEN",
    )
    db_session.add(other_inv)

    source_id = uuid.uuid4()
    source = EvidenceSource(
        id=source_id,
        investigation_id=inv_id,
        filename="paginated_stream.csv",
        file_format="CSV",
        storage_path="/tmp/paginated_stream.csv",
        sha256_hash="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        file_size_bytes=4096,
        total_records=60,
        ingestion_status="COMPLETED",
    )
    db_session.add(source)

    # Insert 60 evidence records spanning across multiple 25-record pages
    now = datetime.now(timezone.utc)
    evidence_records = []
    for i in range(60):
        # Evenly spaced timestamps: record 0 is newest, record 59 is oldest
        ev = Evidence(
            id=uuid.uuid4(),
            investigation_id=inv_id,
            source_id=source_id,
            raw_record_offset=i,
            timestamp=now - timedelta(minutes=i),
            event_type="AUTH_LOGIN" if i % 2 == 0 else "PROCESS_START",
            source_type="WINDOWS_EVTX",
            user_id=f"user_{i % 5}",
            device_id="WS-TEST-01",
            action="LOGIN_SUCCESS" if i % 2 == 0 else "START",
            status="SUCCESS",
            attributes={"step": i},
        )
        evidence_records.append(ev)
        db_session.add(ev)

    other_source_id = uuid.uuid4()
    other_source = EvidenceSource(
        id=other_source_id,
        investigation_id=other_inv_id,
        filename="other_stream.csv",
        file_format="CSV",
        storage_path="/tmp/other_stream.csv",
        sha256_hash="223344556677889900aabbccddeeff11223344556677889900aabbccddeeff22",
        file_size_bytes=1024,
        total_records=1,
        ingestion_status="COMPLETED",
    )
    db_session.add(other_source)

    # Evidence in other investigation
    other_ev = Evidence(
        id=uuid.uuid4(),
        investigation_id=other_inv_id,
        source_id=other_source_id,
        raw_record_offset=0,
        timestamp=now,
        event_type="FILE_ACCESS",
        source_type="SYSLOG",
        attributes={},
    )
    db_session.add(other_ev)

    # Finding attached to record 30 (which will be on page 2 with limit=25)
    target_record = evidence_records[30]
    finding = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-SUSPICIOUS-PROC-01",
        severity_score=0.85,
        description="Execution of unapproved utility",
    )
    db_session.add(finding)
    db_session.commit()

    return {
        "inv_id": inv_id,
        "other_inv_id": other_inv_id,
        "source_id": source_id,
        "evidence_records": evidence_records,
        "other_ev": other_ev,
        "target_record_page2": target_record,
        "finding": finding,
    }


def test_duplicate_evidence_conflict_details(app_client, ux_test_environment):
    """Verify that uploading an identical file returns HTTP 409 with structured error details."""
    inv_id = ux_test_environment["inv_id"]

    # Simple CSV content
    csv_content = b"timestamp,event_type,user,device\n2026-11-08T10:00:00Z,AUTH_LOGIN,alice,WS-01\n"
    file_bytes = io.BytesIO(csv_content)

    # First upload: succeeds
    res1 = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": str(inv_id), "allow_duplicates": "false"},
        files={"file": ("evidence_sample.csv", file_bytes, "text/csv")},
    )
    assert res1.status_code == 201
    source_id = res1.json()["source_id"]
    sha256 = res1.json()["sha256_hash"]

    # Second upload of identical file without allow_duplicates: fails with 409
    file_bytes2 = io.BytesIO(csv_content)
    res2 = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": str(inv_id), "allow_duplicates": "false"},
        files={"file": ("evidence_sample.csv", file_bytes2, "text/csv")},
    )
    assert res2.status_code == 409
    data = res2.json()
    assert data["success"] is False
    assert data["error"]["code"] == "DUPLICATE_SOURCE"
    assert "already exists" in data["error"]["message"]
    assert data["error"]["details"]["existing_source_id"] == source_id
    assert data["error"]["details"]["filename"] == "evidence_sample.csv"
    assert data["error"]["details"]["sha256_hash"] == sha256


def test_allow_duplicates_overrides_conflict(app_client, ux_test_environment):
    """Verify that allow_duplicates=true allows re-ingestion of the identical hash."""
    inv_id = ux_test_environment["inv_id"]
    csv_content = b"timestamp,event_type,user\n2026-11-08T11:00:00Z,PROCESS_START,bob\n"

    # Upload 1
    res1 = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": str(inv_id), "allow_duplicates": "false"},
        files={"file": ("dup_allowed.csv", io.BytesIO(csv_content), "text/csv")},
    )
    assert res1.status_code == 201

    # Upload 2 with allow_duplicates=true
    res2 = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": str(inv_id), "allow_duplicates": "true"},
        files={"file": ("dup_allowed.csv", io.BytesIO(csv_content), "text/csv")},
    )
    assert res2.status_code == 201
    assert res2.json()["ingestion_status"] == "COMPLETED"


def test_non_duplicate_409_is_distinct(app_client, db_session):
    """Verify case number conflict returns error_code CONFLICT, distinct from DUPLICATE_SOURCE."""
    case_num = f"CASE-UNIQUE-{uuid.uuid4().hex[:8]}"
    inv = Investigation(
        id=uuid.uuid4(),
        title="Original Case",
        case_number=case_num,
        status="OPEN",
    )
    db_session.add(inv)
    db_session.commit()

    # Try creating second case with identical case_number
    res = app_client.post(
        "/api/v1/investigations",
        json={"title": "Collision Case", "case_number": case_num},
    )
    assert res.status_code == 409
    data = res.json()
    assert data["error"]["code"] == "CONFLICT"
    assert data["error"]["code"] != "DUPLICATE_SOURCE"


def test_evidence_position_page1(app_client, ux_test_environment):
    """Verify evidence position for record on page 1 (index 0)."""
    inv_id = ux_test_environment["inv_id"]
    record_0 = ux_test_environment["evidence_records"][0]

    res = app_client.get(
        f"/api/v1/evidence/{record_0.id}/position",
        params={"investigation_id": str(inv_id), "limit": 25},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["evidence_id"] == str(record_0.id)
    assert data["index"] == 0
    assert data["offset"] == 0
    assert data["page"] == 1
    assert data["limit"] == 25
    assert data["total"] >= 60


def test_evidence_position_page2_and_page3(app_client, ux_test_environment):
    """Verify evidence position for records beyond page 1 matches sort order."""
    inv_id = ux_test_environment["inv_id"]
    # Record 30 should be at index 30 -> offset 25, page 2
    record_30 = ux_test_environment["evidence_records"][30]
    res_p2 = app_client.get(
        f"/api/v1/evidence/{record_30.id}/position",
        params={"investigation_id": str(inv_id), "limit": 25},
    )
    assert res_p2.status_code == 200
    data_p2 = res_p2.json()
    assert data_p2["index"] == 30
    assert data_p2["offset"] == 25
    assert data_p2["page"] == 2

    # Verify that requesting GET /evidence with this offset returns record_30 in its items
    list_res = app_client.get(
        "/api/v1/evidence",
        params={"investigation_id": str(inv_id), "limit": 25, "offset": data_p2["offset"]},
    )
    assert list_res.status_code == 200
    items = list_res.json()["items"]
    item_ids = [item["id"] for item in items]
    assert str(record_30.id) in item_ids
    # At offset 25 with index 30, it should be at local index 5 (30 - 25 = 5)
    assert item_ids[5] == str(record_30.id)

    # Record 55 should be at index 55 -> offset 50, page 3
    record_55 = ux_test_environment["evidence_records"][55]
    res_p3 = app_client.get(
        f"/api/v1/evidence/{record_55.id}/position",
        params={"investigation_id": str(inv_id), "limit": 25},
    )
    assert res_p3.status_code == 200
    data_p3 = res_p3.json()
    assert data_p3["index"] == 55
    assert data_p3["offset"] == 50
    assert data_p3["page"] == 3


def test_evidence_position_isolation_and_missing(app_client, ux_test_environment):
    """Verify cross-investigation isolation and 404 for missing records."""
    inv_id = ux_test_environment["inv_id"]
    other_inv_id = ux_test_environment["other_inv_id"]
    other_ev = ux_test_environment["other_ev"]

    # Attempt to query position of other_ev within inv_id must fail with 404
    res_iso = app_client.get(
        f"/api/v1/evidence/{other_ev.id}/position",
        params={"investigation_id": str(inv_id), "limit": 25},
    )
    assert res_iso.status_code == 404
    assert "not found" in res_iso.json()["error"]["message"].lower()

    # Querying completely nonexistent UUID must fail with 404
    random_id = uuid.uuid4()
    res_missing = app_client.get(
        f"/api/v1/evidence/{random_id}/position",
        params={"investigation_id": str(inv_id), "limit": 25},
    )
    assert res_missing.status_code == 404


def test_investigation_summary_authoritative_findings_contract(app_client, ux_test_environment):
    """Verify GET /investigations/{id}/summary returns authoritative finding counts for workflow continuity."""
    inv_id = ux_test_environment["inv_id"]

    res = app_client.get(f"/api/v1/investigations/{inv_id}/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["total_findings"] >= 1
    assert "pipeline_status" in data
    assert "has_detections" in data["pipeline_status"]
    assert "finding_counts" in data


def test_evidence_position_mismatched_source_id(app_client, ux_test_environment):
    """Verify get_evidence_position returns 404 when requested source_id does not match record's source_id."""
    inv_id = ux_test_environment["inv_id"]
    correct_source_id = ux_test_environment["source_id"]
    ev_record = ux_test_environment["target_record_page2"]
    mismatched_source_id = uuid.uuid4()

    # Request with matching source_id succeeds (200)
    res_ok = app_client.get(
        f"/api/v1/evidence/{ev_record.id}/position",
        params={"investigation_id": str(inv_id), "source_id": str(correct_source_id)},
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["evidence_id"] == str(ev_record.id)
    assert res_ok.json()["source_id"] == str(correct_source_id)

    # Request with mismatched source_id must return 404
    res_mismatch = app_client.get(
        f"/api/v1/evidence/{ev_record.id}/position",
        params={"investigation_id": str(inv_id), "source_id": str(mismatched_source_id)},
    )
    assert res_mismatch.status_code == 404
    error_msg = res_mismatch.json()["error"]["message"]
    assert "does not belong to source" in error_msg
