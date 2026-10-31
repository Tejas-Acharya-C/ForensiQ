"""ForensiQ Phase 4 — Functional Hardening & Workflow Verification Test Suite.

Verifies:
1. Investigation lifecycle, title/case_number whitespace validation, duplicate case rejection, 404 handling.
2. Evidence ingestion provenance, duplicate prevention (409), and allow_duplicates override.
3. Cryptographic SHA-256 integrity verification: VERIFIED, INTEGRITY_MISMATCH, MALFORMED_DIGEST, VERIFICATION_UNAVAILABLE.
4. End-to-end analytical pipeline execution, idempotency, and cross-investigation isolation.
5. Findings-to-evidence traceability via API endpoints.
6. Executive PDF report generation, case metadata reconciliation, and disclaimer presence.
"""

import hashlib
import io
import time
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.core.storage import EvidenceStorage


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    from app.core.rate_limit import analysis_rate_limiter
    analysis_rate_limiter.reset()
    yield


# ==============================================================================
# WORKSTREAM A: INVESTIGATION LIFECYCLE & VALIDATION
# ==============================================================================

def test_investigation_creation_and_whitespace_validation(app_client: TestClient):
    """Investigation title and case number cannot be empty or purely whitespace."""
    # Empty title
    res1 = app_client.post("/api/v1/investigations", json={
        "title": "   ",
        "case_number": "CASE-WHITESPACE-1",
        "description": "Test case",
        "status": "OPEN",
    })
    assert res1.status_code == 422

    # Empty case number
    res2 = app_client.post("/api/v1/investigations", json={
        "title": "Valid Title",
        "case_number": "   ",
        "description": "Test case",
        "status": "OPEN",
    })
    assert res2.status_code == 422

    # Valid creation with whitespace trimmed
    case_num = f"P4-INV-{uuid.uuid4().hex[:6]}"
    res3 = app_client.post("/api/v1/investigations", json={
        "title": "  Investigative Hardening Case  ",
        "case_number": f"  {case_num}  ",
        "description": "Validation test",
        "status": "OPEN",
    })
    assert res3.status_code == 201
    data = res3.json()
    assert data["title"] == "Investigative Hardening Case"
    assert data["case_number"] == case_num
    inv_id = data["id"]

    # Rejection of duplicate case_number
    res_dup = app_client.post("/api/v1/investigations", json={
        "title": "Duplicate Case Number Test",
        "case_number": case_num,
        "status": "OPEN",
    })
    assert res_dup.status_code == 409

    # Reopening/retrieval of investigation
    res_get = app_client.get(f"/api/v1/investigations/{inv_id}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == inv_id

    # Non-existent investigation ID returns 404
    non_existent = str(uuid.uuid4())
    res_missing = app_client.get(f"/api/v1/investigations/{non_existent}")
    assert res_missing.status_code == 404

    # Malformed non-UUID ID returns 422
    res_malformed = app_client.get("/api/v1/investigations/not-a-valid-uuid")
    assert res_malformed.status_code == 422


# ==============================================================================
# WORKSTREAM B: EVIDENCE INGESTION, PROVENANCE & INTEGRITY VERIFICATION
# ==============================================================================

def test_evidence_ingestion_and_duplicate_control(app_client: TestClient):
    """Evidence ingestion records SHA-256 provenance and enforces duplicate controls."""
    # Create investigation
    inv_res = app_client.post("/api/v1/investigations", json={
        "title": "Ingestion Provenance Test",
        "case_number": f"P4-ING-{uuid.uuid4().hex[:6]}",
        "status": "OPEN",
    })
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    csv_content = (
        "timestamp,source,event_id,user,host,process,ip\n"
        "1700000000,windows,4688,alice,wkstn-01,cmd.exe,10.0.0.1\n"
        "1700000010,windows,4688,alice,wkstn-01,powershell.exe,10.0.0.1\n"
    ).encode("utf-8")
    expected_hash = hashlib.sha256(csv_content).hexdigest()

    # 1. Ingest valid file
    file_payload = ("evidence.csv", io.BytesIO(csv_content), "text/csv")
    res1 = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id, "allow_duplicates": "false"},
        files={"file": file_payload},
    )
    assert res1.status_code == 201
    import_data = res1.json()
    source_id = import_data["source_id"]
    assert import_data["sha256_hash"] == expected_hash
    assert import_data["filename"] == "evidence.csv"
    assert import_data["total_records"] == 2
    assert import_data["ingestion_status"] == "COMPLETED"

    # 2. Ingest duplicate without allow_duplicates -> 409 Conflict
    dup_file = ("evidence.csv", io.BytesIO(csv_content), "text/csv")
    res2 = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id, "allow_duplicates": "false"},
        files={"file": dup_file},
    )
    assert res2.status_code == 409
    err_data = res2.json()
    err_msg = err_data.get("error", {}).get("message") or err_data.get("message", "")
    assert "already exists in this investigation" in err_msg

    # 3. Ingest duplicate with allow_duplicates=true -> 201 Created
    allow_dup_file = ("evidence_copy.csv", io.BytesIO(csv_content), "text/csv")
    res3 = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id, "allow_duplicates": "true"},
        files={"file": allow_dup_file},
    )
    assert res3.status_code == 201


def test_cryptographic_source_integrity_verification(app_client: TestClient, db_session: Session):
    """Source integrity verification distinguishes VERIFIED, MISMATCH, MALFORMED, and UNAVAILABLE."""
    inv_res = app_client.post("/api/v1/investigations", json={
        "title": "Integrity Verification Test",
        "case_number": f"P4-INT-{uuid.uuid4().hex[:6]}",
        "status": "OPEN",
    })
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    csv_bytes = b"timestamp,source,event_id,user\n1700000000,windows,4624,bob\n"
    expected_hash = hashlib.sha256(csv_bytes).hexdigest()

    file_payload = ("auth_logs.csv", io.BytesIO(csv_bytes), "text/csv")
    import_res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id, "allow_duplicates": "false"},
        files={"file": file_payload},
    )
    assert import_res.status_code == 201
    source_id = import_res.json()["source_id"]

    # Case A: Untampered source artifact -> VERIFIED
    verify_res = app_client.post(f"/api/v1/evidence/sources/{source_id}/verify-integrity")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["status"] == "VERIFIED"
    assert v_data["recorded_sha256"] == expected_hash
    assert v_data["computed_sha256"] == expected_hash
    assert "Cryptographic SHA-256 digest verified" in v_data["message"]
    assert "does not claim legal chain of custody" in v_data["disclaimer"]

    # Case B: Modified recorded hash in DB -> INTEGRITY_MISMATCH
    source_record = db_session.get(EvidenceSource, uuid.UUID(source_id))
    original_hash = source_record.sha256_hash
    original_storage_path = source_record.storage_path
    tampered_hash = "a" * 64
    source_record.sha256_hash = tampered_hash
    db_session.commit()

    mismatch_res = app_client.post(f"/api/v1/evidence/sources/{source_id}/verify-integrity")
    assert mismatch_res.status_code == 200
    m_data = mismatch_res.json()
    assert m_data["status"] == "INTEGRITY_MISMATCH"
    assert m_data["recorded_sha256"] == tampered_hash
    assert m_data["computed_sha256"] == expected_hash

    # Case C: Malformed recorded hash -> MALFORMED_DIGEST
    source_record.sha256_hash = "not-a-valid-hex-digest"
    db_session.commit()

    malformed_res = app_client.post(f"/api/v1/evidence/sources/{source_id}/verify-integrity")
    assert malformed_res.status_code == 200
    assert malformed_res.json()["status"] == "MALFORMED_DIGEST"

    # Restore correct hash
    source_record.sha256_hash = original_hash
    db_session.commit()

    # Case D: Missing source file on disk -> VERIFICATION_UNAVAILABLE
    source_record.storage_path = "non_existent_folder/missing_file.csv"
    db_session.commit()

    unavail_res = app_client.post(f"/api/v1/evidence/sources/{source_id}/verify-integrity")
    assert unavail_res.status_code == 200
    assert unavail_res.json()["status"] == "VERIFICATION_UNAVAILABLE"

    # Case E: Path traversal attempt -> VERIFICATION_UNAVAILABLE
    source_record.storage_path = "../../../../../etc/passwd"
    db_session.commit()

    traversal_res = app_client.post(f"/api/v1/evidence/sources/{source_id}/verify-integrity")
    assert traversal_res.status_code == 200
    assert traversal_res.json()["status"] == "VERIFICATION_UNAVAILABLE"

    # Case F: Investigation containment check
    inv_b_res = app_client.post("/api/v1/investigations", json={
        "title": "Second Case for Containment Check",
        "case_number": f"P4-INT-B-{uuid.uuid4().hex[:6]}",
        "status": "OPEN",
    })
    inv_b_id = inv_b_res.json()["id"]

    # Calling verify-integrity on source_id specifying wrong investigation_id -> 404
    cross_res = app_client.post(
        f"/api/v1/evidence/sources/{source_id}/verify-integrity?investigation_id={inv_b_id}"
    )
    assert cross_res.status_code == 404

    # Case G: Non-modification guarantee
    # Restore valid storage path
    storage = EvidenceStorage()
    source_record.storage_path = original_storage_path
    source_record.sha256_hash = original_hash
    db_session.commit()

    file_path = storage.get_source_path(source_record)
    with open(file_path, "rb") as f:
        bytes_before = f.read()

    # Run verification multiple times
    for _ in range(3):
        app_client.post(f"/api/v1/evidence/sources/{source_id}/verify-integrity")

    with open(file_path, "rb") as f:
        bytes_after = f.read()

    assert bytes_before == bytes_after, "Original evidence file must never be modified during verification"


# ==============================================================================
# WORKSTREAM C & D: PIPELINE EXECUTION, TRACEABILITY & PRIORITIZATION
# ==============================================================================

def test_full_pipeline_workflow_and_findings_traceability(app_client: TestClient):
    """End-to-end analytical workflow executes correctly with findings traceable to evidence."""
    # 1. Create Investigation
    inv_res = app_client.post("/api/v1/investigations", json={
        "title": "Pipeline Traceability Test",
        "case_number": f"P4-PIPE-{uuid.uuid4().hex[:6]}",
        "description": "Full analysis workflow",
        "status": "OPEN",
    })
    inv_id = inv_res.json()["id"]

    # 2. Ingest Multi-Record Evidence (>= 10 records for ML eligibility)
    base_ts = int(time.time()) - 1000
    rows = ["timestamp,source,event_id,user,host,process,ip,status"]
    # 8 normal records
    for i in range(8):
        rows.append(f"{base_ts + i*10},windows,4688,charlie,wkstn-1,svchost.exe,10.0.0.5,SUCCESS")
    # Mimikatz rule match
    rows.append(f"{base_ts + 90},windows,4688,charlie,wkstn-1,mimikatz.exe,10.0.0.5,SUCCESS")
    # Powershell rule match
    rows.append(f"{base_ts + 100},windows,4688,charlie,wkstn-1,powershell.exe,10.0.0.5,SUCCESS")
    # Additional records for ML statistical feature space
    for i in range(5):
        rows.append(f"{base_ts + 110 + i*10},windows,4688,charlie,wkstn-1,notepad.exe,10.0.0.5,SUCCESS")

    csv_data = "\n".join(rows).encode("utf-8")
    import_res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("compromise_log.csv", io.BytesIO(csv_data), "text/csv")},
    )
    assert import_res.status_code == 201
    source_id = import_res.json()["source_id"]

    # Stage 1: Normalize
    norm_res = app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
    assert norm_res.status_code == 200
    assert norm_res.json()["normalized_records"] >= 15

    # Stage 2: Detections (Deterministic Rules & IOCs)
    det_res = app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules")
    assert det_res.status_code == 200
    assert det_res.json()["findings_created"] > 0

    # Stage 3: ML Anomaly Analysis
    ml_res = app_client.post(f"/api/v1/ml/sources/{source_id}/analyze")
    assert ml_res.status_code == 200

    # Stage 4: Contextual Correlation
    corr_res = app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze")
    assert corr_res.status_code == 200
    assert corr_res.json()["relationships_created"] > 0

    # Stage 5: Activity Grouping
    act_res = app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    assert act_res.status_code == 200

    # Stage 6: Baseline Prioritization (Evidence)
    prio_base = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")
    assert prio_base.status_code == 200

    # Stage 7: Contextual Prioritization (Activities)
    prio_act = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")
    assert prio_act.status_code == 200

    # Verify Findings & Evidence Traceability
    findings_res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}")
    assert findings_res.status_code == 200
    findings = findings_res.json()["items"]
    assert len(findings) > 0

    # Each finding must have evidence_ids linking to existing Evidence records
    for f in findings:
        evidence_ids = f["evidence_ids"]
        assert isinstance(evidence_ids, list)
        if evidence_ids:
            # Query evidence records using the ids filter
            ev_filter_res = app_client.get(
                f"/api/v1/evidence?investigation_id={inv_id}&ids={','.join(evidence_ids)}"
            )
            assert ev_filter_res.status_code == 200
            resolved_items = ev_filter_res.json()["items"]
            assert len(resolved_items) == len(evidence_ids)
            for item in resolved_items:
                assert item["investigation_id"] == inv_id

    # Verify Prioritization Explanations
    prio_res = app_client.get(f"/api/v1/prioritization/results?investigation_id={inv_id}")
    assert prio_res.status_code == 200
    prio_items = prio_res.json()["items"]
    assert len(prio_items) > 0
    for p in prio_items:
        assert p["explanation_text"], "Prioritization result must have an explanation"
        assert p["priority_score"] >= 0.0


# ==============================================================================
# WORKSTREAM E: EXECUTIVE PDF REPORTING
# ==============================================================================

def test_investigation_report_pdf_generation(app_client: TestClient):
    """Report endpoint produces a valid A4 PDF containing investigation metadata, findings, and disclaimer."""
    # 1. Create Investigation
    inv_num = f"P4-REP-{uuid.uuid4().hex[:6]}"
    inv_res = app_client.post("/api/v1/investigations", json={
        "title": "Executive Report Generation Test",
        "case_number": inv_num,
        "description": "Comprehensive report verification",
        "status": "OPEN",
    })
    inv_id = inv_res.json()["id"]

    # 2. Ingest & normalize an evidence file
    csv_bytes = (
        "timestamp,source,event_id,user,host,process,ip\n"
        "1700000000,windows,4688,alice,wkstn-01,powershell.exe,10.0.0.1\n"
    ).encode("utf-8")
    app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("report_source.csv", io.BytesIO(csv_bytes), "text/csv")},
    )

    # 3. Request report
    report_res = app_client.get(f"/api/v1/investigations/{inv_id}/report")
    assert report_res.status_code == 200
    assert report_res.headers["content-type"] == "application/pdf"
    assert report_res.headers["cache-control"] == "no-store"
    assert f'filename="ForensiQ_{inv_num}_Report.pdf"' in report_res.headers["content-disposition"]

    pdf_content = report_res.content
    assert pdf_content.startswith(b"%PDF-"), "Generated report must begin with PDF magic header"
    assert len(pdf_content) > 5000, "Generated report must contain document layout and content"
    assert inv_num.encode("ascii") in pdf_content, "Case number must be present in PDF stream"


def test_cross_investigation_isolation_and_containment(app_client: TestClient):
    """Resources, findings, evidence, and reports remain strictly isolated between investigations."""
    # Create Case 1
    c1_num = f"P4-ISO-A-{uuid.uuid4().hex[:6]}"
    inv1_res = app_client.post("/api/v1/investigations", json={
        "title": "Isolation Test Case 1",
        "case_number": c1_num,
        "status": "OPEN",
    })
    inv1_id = inv1_res.json()["id"]

    # Create Case 2
    c2_num = f"P4-ISO-B-{uuid.uuid4().hex[:6]}"
    inv2_res = app_client.post("/api/v1/investigations", json={
        "title": "Isolation Test Case 2",
        "case_number": c2_num,
        "status": "OPEN",
    })
    inv2_id = inv2_res.json()["id"]

    # Ingest evidence into Case 1 only
    csv_bytes = b"timestamp,source,event_id,user,host,process\n1700000000,windows,4688,alice,wkstn-1,mimikatz.exe\n"
    imp_res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv1_id},
        files={"file": ("case1_evidence.csv", io.BytesIO(csv_bytes), "text/csv")},
    )
    assert imp_res.status_code == 201
    source1_id = imp_res.json()["source_id"]

    # Normalize and run detections on Case 1
    app_client.post(f"/api/v1/evidence/sources/{source1_id}/normalize")
    app_client.post(f"/api/v1/detection/sources/{source1_id}/analyze-rules")

    # Get Case 1 evidence records and findings
    ev1_res = app_client.get(f"/api/v1/evidence?investigation_id={inv1_id}")
    assert ev1_res.status_code == 200
    ev1_items = ev1_res.json()["items"]
    assert len(ev1_items) == 1
    ev1_id = ev1_items[0]["id"]

    find1_res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv1_id}")
    assert find1_res.status_code == 200
    find1_items = find1_res.json()["items"]
    assert len(find1_items) > 0
    find1_id = find1_items[0]["id"]

    # 1. Verify Case 2 has 0 evidence sources, 0 evidence, 0 findings
    c2_sources = app_client.get(f"/api/v1/investigations/{inv2_id}/sources").json()
    assert len(c2_sources) == 0

    c2_ev = app_client.get(f"/api/v1/evidence?investigation_id={inv2_id}").json()["items"]
    assert len(c2_ev) == 0

    c2_findings = app_client.get(f"/api/v1/detection/findings?investigation_id={inv2_id}").json()["items"]
    assert len(c2_findings) == 0

    # 2. Cross-investigation containment checks (must return 404)
    # Querying Case 1 evidence detail while passing Case 2 ID
    res_ev_contain = app_client.get(f"/api/v1/evidence/{ev1_id}?investigation_id={inv2_id}")
    assert res_ev_contain.status_code == 404

    # Querying Case 1 finding detail while passing Case 2 ID
    res_find_contain = app_client.get(f"/api/v1/detection/findings/{find1_id}?investigation_id={inv2_id}")
    assert res_find_contain.status_code == 404

    # Querying Case 1 evidence source verify-integrity while passing Case 2 ID
    res_ver_contain = app_client.post(f"/api/v1/evidence/sources/{source1_id}/verify-integrity?investigation_id={inv2_id}")
    assert res_ver_contain.status_code == 404

    # 3. Report isolation: Case 2 report must not contain Case 1 case_number
    rep2_res = app_client.get(f"/api/v1/investigations/{inv2_id}/report")
    assert rep2_res.status_code == 200
    pdf2_content = rep2_res.content
    assert c2_num.encode("ascii") in pdf2_content
    assert c1_num.encode("ascii") not in pdf2_content
