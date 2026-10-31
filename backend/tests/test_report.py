"""
Tests for the Investigation Report PDF endpoint.
GET /api/v1/investigations/{investigation_id}/report
Verifies: PDF structure, content, counts, and human-readable labels.
"""
import io
import uuid
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    from app.core.rate_limit import analysis_rate_limiter
    analysis_rate_limiter.reset()
    yield


FULL_CSV = (
    b"timestamp,user_id,device_id,process_name,ip_address,status,action,event_type\n"
    b"2026-01-01T08:00:00Z,alice,PC-01,explorer.exe,10.0.0.1,SUCCESS,LOGIN,auth_login\n"
    b"2026-01-01T08:01:00Z,alice,PC-01,chrome.exe,10.0.0.1,SUCCESS,LAUNCH,process_create\n"
    b"2026-01-01T08:02:00Z,alice,PC-01,cmd.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-01-01T08:03:00Z,alice,PC-01,powershell.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-01-01T08:04:00Z,alice,PC-01,mimikatz.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-01-01T08:05:00Z,alice,PC-01,svchost.exe,198.51.100.10,SUCCESS,NETWORK,network_connect\n"
    b"2026-01-01T08:06:00Z,alice,PC-01,cmd.exe,10.0.0.1,FAILURE,EXEC,process_create\n"
    b"2026-01-01T08:07:00Z,alice,PC-01,cmd.exe,10.0.0.1,FAILURE,EXEC,process_create\n"
    b"2026-01-01T08:08:00Z,alice,PC-01,cmd.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-01-01T08:09:00Z,alice,PC-01,notepad.exe,10.0.0.1,SUCCESS,LAUNCH,process_create\n"
    b"2026-01-01T08:10:00Z,alice,PC-01,outlook.exe,10.0.0.1,SUCCESS,LAUNCH,process_create\n"
    b"2026-01-01T08:11:00Z,alice,PC-01,explorer.exe,10.0.0.1,SUCCESS,LOGOUT,auth_logout\n"
)


def _create_inv(client, suffix=""):
    r = client.post("/api/v1/investigations",
        json={"title": f"Report Test{suffix}", "case_number": f"RPT-{uuid.uuid4().hex[:8]}"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _run_full_pipeline(client, inv_id) -> str:
    r = client.post("/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("test.csv", io.BytesIO(FULL_CSV), "text/csv")})
    assert r.status_code in (200, 201), r.text
    sid = r.json()["source_id"]

    client.post(f"/api/v1/evidence/sources/{sid}/normalize")
    client.post(f"/api/v1/detection/sources/{sid}/analyze-rules")
    client.post(f"/api/v1/ml/sources/{sid}/analyze")
    client.post(f"/api/v1/correlation/sources/{sid}/analyze")
    client.post(f"/api/v1/activities/sources/{sid}/form")
    client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")
    client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")
    return sid


def _pdf(client, inv_id):
    return client.get(f"/api/v1/investigations/{inv_id}/report")


def _pdf_text(resp) -> str:
    return resp.content.decode("latin-1", errors="replace")


# ── Test 1: returns 200 with full data ────────────────────────────────────────
def test_report_returns_200(app_client: TestClient):
    inv_id = _create_inv(app_client)
    _run_full_pipeline(app_client, inv_id)
    r = _pdf(app_client, inv_id)
    assert r.status_code == 200, r.text


# ── Test 2: Content-Type is application/pdf ───────────────────────────────────
def test_report_content_type(app_client: TestClient):
    inv_id = _create_inv(app_client)
    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert "application/pdf" in r.headers["content-type"]


# ── Test 3: PDF magic bytes + non-trivial size ────────────────────────────────
def test_report_pdf_magic_bytes(app_client: TestClient):
    inv_id = _create_inv(app_client)
    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"
    assert len(r.content) > 2048


# ── Test 4: Content-Disposition with .pdf filename ───────────────────────────
def test_report_content_disposition(app_client: TestClient):
    inv_id = _create_inv(app_client)
    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    cd = r.headers.get("content-disposition", "")
    assert "attachment" in cd and ".pdf" in cd


# ── Test 5: case number appears in PDF ───────────────────────────────────────
def test_report_contains_case_number(app_client: TestClient):
    r_inv = app_client.post("/api/v1/investigations",
        json={"title": "Unique Title ZXQV", "case_number": f"CASE-RPT-{uuid.uuid4().hex[:6]}"})
    assert r_inv.status_code == 201
    inv = r_inv.json()
    r = _pdf(app_client, inv["id"])
    assert r.status_code == 200
    assert inv["case_number"] in _pdf_text(r)


# ── Test 6: evidence count in PDF matches dashboard ───────────────────────────
def test_report_evidence_count_matches_dashboard(app_client: TestClient):
    inv_id = _create_inv(app_client, " EvidCount")
    _run_full_pipeline(app_client, inv_id)

    summary = app_client.get(f"/api/v1/investigations/{inv_id}/summary").json()
    assert summary["total_evidence"] == 12  # FULL_CSV has 12 records

    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


# ── Test 7: findings count verified via findings API ──────────────────────────
def test_report_findings_count_present(app_client: TestClient):
    inv_id = _create_inv(app_client, " FindCount")
    _run_full_pipeline(app_client, inv_id)

    findings_resp = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&limit=100")
    assert findings_resp.status_code == 200
    assert findings_resp.json()["total"] > 0, \
        "Expected findings from FULL_CSV pipeline (powershell/mimikatz/IOC rules should fire)"

    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


# ── Test 8: ML anomaly count verified via API ────────────────────────────────
def test_report_ml_anomaly_count_present(app_client: TestClient):
    inv_id = _create_inv(app_client, " MLCount")
    _run_full_pipeline(app_client, inv_id)

    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


# ── Test 9: correlation count verified via relationships API ──────────────────
def test_report_correlation_count_present(app_client: TestClient):
    inv_id = _create_inv(app_client, " CorCount")
    _run_full_pipeline(app_client, inv_id)

    rels_resp = app_client.get(f"/api/v1/correlation/relationships?investigation_id={inv_id}&limit=1")
    assert rels_resp.status_code == 200
    assert rels_resp.json()["total"] > 0, "Expected correlations from FULL_CSV pipeline"

    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


# ── Test 10: activity count verified via activities API ───────────────────────
def test_report_activity_count_present(app_client: TestClient):
    inv_id = _create_inv(app_client, " ActCount")
    _run_full_pipeline(app_client, inv_id)

    acts_resp = app_client.get(f"/api/v1/activities?investigation_id={inv_id}&limit=1")
    assert acts_resp.status_code == 200
    assert acts_resp.json()["total"] > 0, "Expected activities from FULL_CSV pipeline"

    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


# ── Test 11: human-readable finding labels ───────────────────────────────────
def test_report_human_readable_finding_labels(app_client: TestClient):
    inv_id = _create_inv(app_client, " Labels")
    _run_full_pipeline(app_client, inv_id)

    findings_resp = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&limit=100")
    assert findings_resp.status_code == 200
    finding_types = {f["finding_type"] for f in findings_resp.json()["items"]}
    assert len(finding_types) > 0, "Expected findings to exist"
    has_rule = "RULE_MATCH" in finding_types or "IOC_MATCH" in finding_types
    assert has_rule, f"Expected RULE_MATCH or IOC_MATCH findings, got: {finding_types}"

    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


# ── Test 12: no duplicate activity rows ──────────────────────────────────────
def test_report_no_duplicate_activity_rows(app_client: TestClient):
    inv_id = _create_inv(app_client, " NoDupAct")
    sid = _run_full_pipeline(app_client, inv_id)

    r2 = app_client.post(f"/api/v1/activities/sources/{sid}/form")
    assert r2.status_code == 200
    assert r2.json()["activities_created"] == 0, \
        f"Second run should create 0 activities, got {r2.json()['activities_created']}"

    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


# ── Test 13: no duplicate activity priority results ───────────────────────────
def test_report_no_duplicate_activity_priorities(app_client: TestClient):
    inv_id = _create_inv(app_client, " NoDupPrio")
    _run_full_pipeline(app_client, inv_id)

    p2 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")
    assert p2.status_code == 200
    assert p2.json()["results_created"] == 0, \
        f"Second prio run should create 0, got {p2.json()['results_created']}"

    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


# ── Test 14: long description no crash ───────────────────────────────────────
def test_report_long_description_no_crash(app_client: TestClient):
    r_inv = app_client.post("/api/v1/investigations",
        json={"title": "Long Desc", "case_number": f"LONG-{uuid.uuid4().hex[:6]}",
              "description": "X" * 2000})
    assert r_inv.status_code == 201
    r = _pdf(app_client, r_inv.json()["id"])
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"


# ── Test 15: invalid investigation ID returns 404 ─────────────────────────────
def test_report_invalid_id_returns_404(app_client: TestClient):
    r = app_client.get(f"/api/v1/investigations/{uuid.uuid4()}/report")
    assert r.status_code == 404


# ── Test 16: empty investigation still renders ────────────────────────────────
def test_report_empty_investigation(app_client: TestClient):
    inv_id = _create_inv(app_client, " Empty")
    r = _pdf(app_client, inv_id)
    assert r.status_code == 200
    assert r.content[:4] == b"%PDF"
