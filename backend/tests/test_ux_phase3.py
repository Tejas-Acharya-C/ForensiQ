"""Tests for ForensiQ Phase 3: Reporting Workflow, Investigation Quality Checklist & Investigator Notes."""

import io
import uuid
import pypdf
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.finding_review import FindingReview
from app.models.activity import Activity
from app.models.priority_result import PriorityResult


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    from app.core.rate_limit import analysis_rate_limiter
    analysis_rate_limiter.reset()
    yield


CSV_DATA = (
    b"timestamp,user_id,device_id,process_name,ip_address,status,action,event_type\n"
    b"2026-02-01T08:00:00Z,alice,PC-01,explorer.exe,10.0.0.1,SUCCESS,LOGIN,auth_login\n"
    b"2026-02-01T08:01:00Z,alice,PC-01,chrome.exe,10.0.0.1,SUCCESS,LAUNCH,process_create\n"
    b"2026-02-01T08:02:00Z,alice,PC-01,powershell.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-02-01T08:03:00Z,alice,PC-01,mimikatz.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-02-01T08:04:00Z,alice,PC-01,svchost.exe,198.51.100.10,SUCCESS,NETWORK,network_connect\n"
    b"2026-02-01T08:05:00Z,alice,PC-01,notepad.exe,10.0.0.1,SUCCESS,LAUNCH,process_create\n"
    b"2026-02-01T08:06:00Z,alice,PC-01,cmd.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-02-01T08:07:00Z,alice,PC-01,cmd.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-02-01T08:08:00Z,alice,PC-01,outlook.exe,10.0.0.1,SUCCESS,LAUNCH,process_create\n"
    b"2026-02-01T08:09:00Z,alice,PC-01,explorer.exe,10.0.0.1,SUCCESS,LOGOUT,auth_logout\n"
    b"2026-02-01T08:10:00Z,alice,PC-01,cmd.exe,10.0.0.1,FAILURE,EXEC,process_create\n"
    b"2026-02-01T08:11:00Z,alice,PC-01,svchost.exe,10.0.0.1,SUCCESS,NETWORK,network_connect\n"
)


def _create_case(client: TestClient, suffix: str = "") -> str:
    res = client.post(
        "/api/v1/investigations",
        json={
            "title": f"Phase 3 Case {suffix}",
            "case_number": f"CASE-P3-{uuid.uuid4().hex[:8]}",
            "description": "Initial triage case for Phase 3 testing.",
        },
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def _populate_pipeline(client: TestClient, inv_id: str) -> str:
    res = client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("workstation_events.csv", io.BytesIO(CSV_DATA), "text/csv")},
    )
    assert res.status_code in (200, 201), res.text
    sid = res.json()["source_id"]

    client.post(f"/api/v1/evidence/sources/{sid}/normalize")
    client.post(f"/api/v1/detection/sources/{sid}/analyze-rules")
    client.post(f"/api/v1/ml/sources/{sid}/analyze")
    client.post(f"/api/v1/correlation/sources/{sid}/analyze")
    client.post(f"/api/v1/activities/sources/{sid}/form")
    client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")
    client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")
    return sid


def _pdf_latin1(content: bytes) -> str:
    raw = content.decode("latin-1", errors="replace")
    try:
        reader = pypdf.PdfReader(io.BytesIO(content))
        extracted = [page.extract_text() or "" for page in reader.pages]
        return raw + "\n" + "\n".join(extracted)
    except Exception:
        return raw


# ── 1. Report Preflight with Complete Pipeline Data ──────────────────────────
def test_report_preflight_complete(app_client: TestClient):
    inv_id = _create_case(app_client, "Complete")
    _populate_pipeline(app_client, inv_id)

    # Add notes
    app_client.put(
        f"/api/v1/investigations/{inv_id}/notes",
        json={"notes": "Analysis indicates suspicious credential access via mimikatz."},
    )

    res = app_client.get(f"/api/v1/investigations/{inv_id}/report/preflight")
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["investigation_id"] == inv_id
    assert data["has_investigator_notes"] is True
    assert "mimikatz" in data["notes_preview"]
    assert data["evidence_summary"]["total_sources"] >= 1
    assert data["evidence_summary"]["total_evidence_records"] == 12
    assert data["findings_summary"]["total_findings"] > 0
    assert data["findings_summary"]["included_findings"] == data["findings_summary"]["total_findings"]
    assert data["integrity_status"]["has_sha256_hashes"] is True
    assert data["integrity_status"]["sources_with_hash"] >= 1
    assert data["can_generate_pdf"] is True

    # Check sections availability
    secs = {s["key"]: s for s in data["sections_available"]}
    assert secs["executive_summary"]["available"] is True
    assert secs["evidence_inventory"]["available"] is True
    assert secs["findings"]["available"] is True
    assert secs["investigator_notes"]["available"] is True


# ── 2. Report Preflight with Empty/Incomplete Investigation ───────────────────
def test_report_preflight_empty(app_client: TestClient):
    inv_id = _create_case(app_client, "Empty")

    res = app_client.get(f"/api/v1/investigations/{inv_id}/report/preflight")
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["has_investigator_notes"] is False
    assert data["notes_preview"] is None
    assert data["evidence_summary"]["total_sources"] == 0
    assert data["findings_summary"]["total_findings"] == 0
    assert len(data["missing_or_incomplete"]) > 0
    assert any("evidence" in m.lower() for m in data["missing_or_incomplete"])
    assert any("notes" in m.lower() for m in data["missing_or_incomplete"])


# ── 3. Report Configuration Defaults ─────────────────────────────────────────
def test_report_configuration_defaults(app_client: TestClient):
    inv_id = _create_case(app_client, "Defaults")
    _populate_pipeline(app_client, inv_id)

    # Calling report with no params should generate complete PDF by default
    res = app_client.get(f"/api/v1/investigations/{inv_id}/report")
    assert res.status_code == 200
    assert res.content[:4] == b"%PDF"
    text = _pdf_latin1(res.content)
    assert "Executive Overview" in text
    assert "Key Findings" in text


# ── 4. Report Section Selection (Exclusion and Inclusion) ──────────────────────
def test_report_section_selection(app_client: TestClient):
    inv_id = _create_case(app_client, "Sections")
    _populate_pipeline(app_client, inv_id)

    app_client.put(
        f"/api/v1/investigations/{inv_id}/notes",
        json={"notes": "Special forensic note ZXQ999."},
    )

    # Request ONLY investigator notes and executive summary
    res = app_client.get(
        f"/api/v1/investigations/{inv_id}/report?sections=executive_summary,investigator_notes"
    )
    assert res.status_code == 200
    text = _pdf_latin1(res.content)
    assert "Executive Overview" in text
    assert "Investigator Notes & Commentary" in text
    assert "Special forensic note ZXQ999." in text
    # Excluded sections should NOT appear in story
    assert "Investigation Activities" not in text
    assert "Correlations" not in text


# ── 5. Finding Priority Filtering in Preflight and PDF ────────────────────────
def test_report_finding_priority_filtering(app_client: TestClient):
    inv_id = _create_case(app_client, "FilterPrio")
    _populate_pipeline(app_client, inv_id)

    # Preflight with ALL priorities
    res_all = app_client.get(f"/api/v1/investigations/{inv_id}/report/preflight?priority_filter=ALL")
    assert res_all.status_code == 200
    total = res_all.json()["findings_summary"]["total_findings"]

    # Preflight with CRITICAL,HIGH only
    res_high = app_client.get(f"/api/v1/investigations/{inv_id}/report/preflight?priority_filter=CRITICAL,HIGH")
    assert res_high.status_code == 200
    included = res_high.json()["findings_summary"]["included_findings"]
    assert included <= total

    # Generate PDF with priority filter
    pdf_res = app_client.get(f"/api/v1/investigations/{inv_id}/report?priority_filter=CRITICAL,HIGH")
    assert pdf_res.status_code == 200
    assert pdf_res.content[:4] == b"%PDF"


# ── 6. Report Filtering Does Not Mutate Stored Findings ───────────────────────
def test_report_filters_do_not_mutate_stored_findings(app_client: TestClient):
    inv_id = _create_case(app_client, "NoMutation")
    _populate_pipeline(app_client, inv_id)

    # Initial findings count
    findings_before = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}").json()["total"]
    assert findings_before > 0

    # Execute report preflight and report generation with aggressive filter
    app_client.get(f"/api/v1/investigations/{inv_id}/report/preflight?priority_filter=CRITICAL")
    app_client.get(f"/api/v1/investigations/{inv_id}/report?priority_filter=CRITICAL")

    # Stored findings must remain identical
    findings_after = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}").json()["total"]
    assert findings_after == findings_before


# ── 7. Investigation-Level Notes Lifecycle (Create, Read, Update, Clear) ──────
def test_investigation_notes_lifecycle(app_client: TestClient):
    inv_id = _create_case(app_client, "Notes")

    # Initially None/empty
    res = app_client.get(f"/api/v1/investigations/{inv_id}/notes")
    assert res.status_code == 200
    assert res.json()["notes"] is None

    # Set notes
    res = app_client.put(
        f"/api/v1/investigations/{inv_id}/notes",
        json={"notes": "Line 1: Initial observation\nLine 2: Verified persistence."},
    )
    assert res.status_code == 200
    assert "Line 1" in res.json()["notes"]
    assert "Line 2" in res.json()["notes"]

    # Read back in new session
    res = app_client.get(f"/api/v1/investigations/{inv_id}/notes")
    assert res.status_code == 200
    assert "Line 2: Verified persistence." in res.json()["notes"]

    # Clear notes
    res = app_client.put(f"/api/v1/investigations/{inv_id}/notes", json={"notes": None})
    assert res.status_code == 200
    assert res.json()["notes"] is None


# ── 8. Notes Validation and Maximum Length Enforcement ────────────────────────
def test_investigation_notes_max_length(app_client: TestClient):
    inv_id = _create_case(app_client, "NotesLen")

    # Allowed: 20,000 characters
    res = app_client.put(f"/api/v1/investigations/{inv_id}/notes", json={"notes": "A" * 20000})
    assert res.status_code == 200

    # Rejected: 20,001 characters -> 422
    res = app_client.put(f"/api/v1/investigations/{inv_id}/notes", json={"notes": "A" * 20001})
    assert res.status_code == 422


# ── 9. Investigation Isolation for Notes ──────────────────────────────────────
def test_investigation_notes_isolation(app_client: TestClient):
    inv1 = _create_case(app_client, "Iso1")
    inv2 = _create_case(app_client, "Iso2")

    app_client.put(f"/api/v1/investigations/{inv1}/notes", json={"notes": "Confidential Case 1 Notes"})

    # Case 2 notes must remain untouched
    res2 = app_client.get(f"/api/v1/investigations/{inv2}/notes")
    assert res2.status_code == 200
    assert res2.json()["notes"] is None

    # Invalid investigation ID -> 404
    bad_id = uuid.uuid4()
    assert app_client.get(f"/api/v1/investigations/{bad_id}/notes").status_code == 404
    assert app_client.put(f"/api/v1/investigations/{bad_id}/notes", json={"notes": "X"}).status_code == 404


# ── 10. Investigation Quality Checklist State Accuracy ────────────────────────
def test_investigation_checklist_accuracy(app_client: TestClient):
    inv_id = _create_case(app_client, "Checklist")
    _populate_pipeline(app_client, inv_id)

    res = app_client.get(f"/api/v1/investigations/{inv_id}/checklist")
    assert res.status_code == 200, res.text
    chk = res.json()

    assert chk["investigation_id"] == inv_id
    assert chk["total_required_count"] > 0
    items_by_key = {it["key"]: it for it in chk["items"]}

    # Required items must be COMPLETE after full pipeline
    assert items_by_key["evidence_ingested"]["status"] == "COMPLETE"
    assert items_by_key["evidence_normalized"]["status"] == "COMPLETE"
    assert items_by_key["detection_executed"]["status"] == "COMPLETE"
    assert items_by_key["correlation_completed"]["status"] == "COMPLETE"
    assert items_by_key["prioritization_available"]["status"] == "COMPLETE"
    assert items_by_key["evidence_integrity"]["status"] == "COMPLETE"

    # Notes item is INCOMPLETE until added
    assert items_by_key["investigator_notes"]["status"] == "INCOMPLETE"

    # Add notes and verify it updates to COMPLETE
    app_client.put(f"/api/v1/investigations/{inv_id}/notes", json={"notes": "Final case report conclusions."})
    chk2 = app_client.get(f"/api/v1/investigations/{inv_id}/checklist").json()
    items2_by_key = {it["key"]: it for it in chk2["items"]}
    assert items2_by_key["investigator_notes"]["status"] == "COMPLETE"


# ── 11. Checklist Behavior on Empty Investigation ────────────────────────────
def test_investigation_checklist_empty(app_client: TestClient):
    inv_id = _create_case(app_client, "ChecklistEmpty")

    res = app_client.get(f"/api/v1/investigations/{inv_id}/checklist")
    assert res.status_code == 200
    chk = res.json()

    assert chk["completed_required_count"] == 0
    items = {it["key"]: it for it in chk["items"]}
    assert items["evidence_ingested"]["status"] == "INCOMPLETE"
    assert items["investigator_notes"]["status"] == "INCOMPLETE"


# ── 12. PDF Notes Rendering and Line-Break Preservation ───────────────────────
def test_pdf_notes_line_break_preservation(app_client: TestClient):
    inv_id = _create_case(app_client, "PdfNotes")
    _populate_pipeline(app_client, inv_id)

    notes_text = "Phase 3 Primary Finding:\n- Mimikatz detected\n- C2 connection confirmed\nConclusion: Immediate containment."
    app_client.put(f"/api/v1/investigations/{inv_id}/notes", json={"notes": notes_text})

    res = app_client.get(f"/api/v1/investigations/{inv_id}/report?sections=investigator_notes")
    assert res.status_code == 200
    text = _pdf_latin1(res.content)
    assert "Investigator Notes & Commentary" in text
    assert "Mimikatz detected" in text
    assert "C2 connection confirmed" in text


# ── 13. PDF Long Filename and Value Handling Without Crash ────────────────────
def test_pdf_long_filename_handling(app_client: TestClient):
    inv_id = _create_case(app_client, "LongFilename")

    long_filename = "suspicious_workstation_security_audit_log_dump_backup_archive_forensic_extract_2026.csv"
    res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": (long_filename, io.BytesIO(CSV_DATA), "text/csv")},
    )
    assert res.status_code in (200, 201)

    pdf_res = app_client.get(f"/api/v1/investigations/{inv_id}/report")
    assert pdf_res.status_code == 200
    assert pdf_res.content[:4] == b"%PDF"


# ── 14. Evidence Integrity Wording Accuracy in PDF ───────────────────────────
def test_evidence_integrity_wording_accuracy(app_client: TestClient):
    inv_id = _create_case(app_client, "IntegrityWording")
    _populate_pipeline(app_client, inv_id)

    res = app_client.get(f"/api/v1/investigations/{inv_id}/report?sections=evidence_inventory")
    assert res.status_code == 200
    text = _pdf_latin1(res.content)

    # Must accurately distinguish hash verification from legal custody
    assert "Evidence Integrity Notice" in text
    assert "SHA-256" in text
    assert "chain of custody" in text.lower()


# ── 15. Finding-Level Review Note Updates (UI/API Support) ─────────────────────
def test_finding_review_notes_update(app_client: TestClient):
    inv_id = _create_case(app_client, "FindingNotes")
    _populate_pipeline(app_client, inv_id)

    findings = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}").json()["items"]
    assert len(findings) > 0
    f_id = findings[0]["id"]

    # Update finding-level review note
    res = app_client.put(
        f"/api/v1/detection/findings/{f_id}/review",
        json={
            "investigation_id": inv_id,
            "status": "REVIEWED",
            "notes": "Verified legitimate admin utility execution; mitigated risk.",
        },
    )
    assert res.status_code == 200
    assert res.json()["notes"] == "Verified legitimate admin utility execution; mitigated risk."

    # Verify note in finding explanation / detail
    detail = app_client.get(f"/api/v1/detection/findings/{f_id}/explanation?investigation_id={inv_id}").json()
    assert detail["review_notes"] == "Verified legitimate admin utility execution; mitigated risk."


# ── 16. Finding Review Notes Preserved Across Review Status Changes ───────────
def test_finding_review_notes_preserved_on_status_change(app_client: TestClient):
    inv_id = _create_case(app_client, "ReviewNotesPreserve")
    _populate_pipeline(app_client, inv_id)

    findings = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}").json()["items"]
    assert len(findings) > 0
    f_id = findings[0]["id"]

    # 1. Create finding review with notes
    res = app_client.put(
        f"/api/v1/detection/findings/{f_id}/review",
        json={
            "investigation_id": inv_id,
            "status": "REVIEWED",
            "notes": "Critical investigator forensic triage notes.",
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "REVIEWED"
    assert res.json()["notes"] == "Critical investigator forensic triage notes."

    # 2. Change status WITHOUT supplying notes field -> notes must be preserved
    res_status_change = app_client.put(
        f"/api/v1/detection/findings/{f_id}/review",
        json={
            "investigation_id": inv_id,
            "status": "FALSE_POSITIVE",
        },
    )
    assert res_status_change.status_code == 200
    assert res_status_change.json()["status"] == "FALSE_POSITIVE"
    assert res_status_change.json()["notes"] == "Critical investigator forensic triage notes."

    # Verify persistence on subsequent GET
    rev = app_client.get(f"/api/v1/detection/findings/{f_id}/review?investigation_id={inv_id}").json()
    assert rev["status"] == "FALSE_POSITIVE"
    assert rev["notes"] == "Critical investigator forensic triage notes."

    # 3. Update notes while preserving status (status omitted)
    res_notes_update = app_client.put(
        f"/api/v1/detection/findings/{f_id}/review",
        json={
            "investigation_id": inv_id,
            "notes": "Updated justification: confirmed test harness execution.",
        },
    )
    assert res_notes_update.status_code == 200
    assert res_notes_update.json()["status"] == "FALSE_POSITIVE"
    assert res_notes_update.json()["notes"] == "Updated justification: confirmed test harness execution."

    # 4. Explicitly clear notes (sending notes: null)
    res_clear = app_client.put(
        f"/api/v1/detection/findings/{f_id}/review",
        json={
            "investigation_id": inv_id,
            "notes": None,
        },
    )
    assert res_clear.status_code == 200
    assert res_clear.json()["status"] == "FALSE_POSITIVE"
    assert res_clear.json()["notes"] is None

    # 5. Reject notes exceeding maximum length (5000 characters)
    res_overflow = app_client.put(
        f"/api/v1/detection/findings/{f_id}/review",
        json={
            "investigation_id": inv_id,
            "notes": "A" * 5001,
        },
    )
    assert res_overflow.status_code == 422


# ── 17. Checklist Detection Execution Inference When Zero Findings ───────────
def test_checklist_detection_inference_when_zero_findings(app_client: TestClient):
    inv_id = _create_case(app_client, "ZeroFindingsChecklist")
    # Ingest and normalize evidence, but do NOT run detection engines
    res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("events.csv", io.BytesIO(CSV_DATA), "text/csv")},
    )
    sid = res.json()["source_id"]
    app_client.post(f"/api/v1/evidence/sources/{sid}/normalize")

    chk = app_client.get(f"/api/v1/investigations/{inv_id}/checklist").json()
    items_by_key = {it["key"]: it for it in chk["items"]}

    # Evidence is normalized
    assert items_by_key["evidence_normalized"]["status"] == "COMPLETE"
    # But because 0 findings exist and execution state cannot be verified, status must be ATTENTION (not COMPLETE)
    assert items_by_key["detection_executed"]["status"] == "ATTENTION"
    assert "No threat findings recorded" in items_by_key["detection_executed"]["description"]


# ── 18. Checklist Evidence Integrity Label and Ingestion Wording ──────────────
def test_checklist_evidence_integrity_wording_clarified(app_client: TestClient):
    inv_id = _create_case(app_client, "IntegrityClarified")
    res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("events.csv", io.BytesIO(CSV_DATA), "text/csv")},
    )
    assert res.status_code in (200, 201)

    chk = app_client.get(f"/api/v1/investigations/{inv_id}/checklist").json()
    items_by_key = {it["key"]: it for it in chk["items"]}

    assert items_by_key["evidence_integrity"]["label"] == "Evidence Ingestion Integrity"
    assert "ingestion digests recorded" in items_by_key["evidence_integrity"]["description"].lower()


# ── 19. Report Preflight Unnormalized Evidence Warning ────────────────────────
def test_report_preflight_unnormalized_warning(app_client: TestClient):
    inv_id = _create_case(app_client, "UnnormalizedPreflight")
    # Ingest source file but do not normalize
    res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("raw_log.csv", io.BytesIO(CSV_DATA), "text/csv")},
    )
    assert res.status_code in (200, 201)

    preflight = app_client.get(f"/api/v1/investigations/{inv_id}/report/preflight").json()
    assert preflight["evidence_summary"]["total_sources"] == 1
    assert preflight["evidence_summary"]["total_evidence_records"] == 0
    # Must report unnormalized observation
    assert any("not been normalized" in obs for obs in preflight["missing_or_incomplete"])
    # Partial intake report generation remains possible (not blocked)
    assert preflight["can_generate_pdf"] is True


# ── 20. Report Preview Button Contract and Registration ───────────────────────
def test_report_preview_button_and_handler_contract():
    """Verify that Report Preview button exists in frontend/index.html and
    its event handler/interaction contract is properly registered in frontend/app.js.
    """
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent.parent
    html_path = root / "frontend" / "index.html"
    js_path = root / "frontend" / "app.js"

    html_content = html_path.read_text(encoding="utf-8")
    js_content = js_path.read_text(encoding="utf-8")

    # 1. Preview button element and spinner exist in HTML
    assert 'id="btn-preview-report"' in html_content
    assert 'id="btn-preview-report-spinner"' in html_content
    assert "Preview Report" in html_content

    # 2. Event listener for btn-preview-report is registered in app.js
    assert "document.getElementById('btn-preview-report')" in js_content
    assert "triggerReportPreview" in js_content

    # 3. Checklist Item 9 action button triggers preview
    assert "triggerReportPreview()" in js_content

    # 4. Concurrency lock and loading indicators exist
    assert "isPreviewLoading" in js_content
    assert "setPreviewButtonLoading" in js_content

    # 5. Stale case / race condition protection exists
    assert "state.activeInvestigationId !== currentInvId" in js_content


# ── 21. Report Preview Filter & Investigation ID Propagation ──────────────────
def test_report_preview_filter_and_investigation_propagation(app_client: TestClient):
    """Verify investigation ID propagation and configuration filters (priority and sections)
    in the report preview/preflight endpoint.
    """
    inv_id = _create_case(app_client, "PreviewFilterProp")
    _populate_pipeline(app_client, inv_id)

    # Fetch preview with ALL priorities
    prev_all = app_client.get(
        f"/api/v1/investigations/{inv_id}/report/preflight",
        params={"priority_filter": "ALL", "sections": "executive_summary,findings"},
    ).json()
    assert prev_all["investigation_id"] == inv_id
    total_findings = prev_all["findings_summary"]["total_findings"]
    assert total_findings > 0
    assert prev_all["findings_summary"]["included_findings"] == total_findings

    # Fetch preview with specific priority filter (CRITICAL,HIGH)
    prev_crit = app_client.get(
        f"/api/v1/investigations/{inv_id}/report/preflight",
        params={"priority_filter": "CRITICAL,HIGH"},
    ).json()
    assert prev_crit["investigation_id"] == inv_id
    # Included findings must be <= total findings
    assert prev_crit["findings_summary"]["included_findings"] <= total_findings


# ── 22. Report Preview Error Handling on Invalid Case ID ──────────────────────
def test_report_preview_error_handling(app_client: TestClient):
    """Verify preview request fails cleanly with 404 on non-existent case."""
    fake_id = str(uuid.uuid4())
    res = app_client.get(f"/api/v1/investigations/{fake_id}/report/preflight")
    assert res.status_code == 404
    assert "not found" in res.text.lower()


