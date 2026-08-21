"""
Idempotency tests — repeated pipeline execution must not create duplicate DB rows.
These tests verify COUNT stability, not just no-crash.
"""
import io
import uuid
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    """Reset in-memory rate limiters before each test to prevent 429 in long test runs."""
    from app.core.rate_limit import analysis_rate_limiter, login_rate_limiter
    analysis_rate_limiter.reset()
    login_rate_limiter.reset()
    yield


# ── shared setup ───────────────────────────────────────────────────────────────
def _make_investigation(app_client, auth_headers, prefix="IDEM"):
    resp = app_client.post(
        "/api/v1/investigations",
        json={"title": f"{prefix} Case", "case_number": f"{prefix}-{uuid.uuid4().hex[:6]}"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    return resp.json()["id"]


def _ingest_and_normalize(app_client, auth_headers, inv_id, csv_bytes):
    r = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("test.csv", io.BytesIO(csv_bytes), "text/csv")},
        headers=auth_headers,
    )
    assert r.status_code in (200, 201), r.text
    source_id = r.json()["source_id"]
    n = app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    assert n.status_code == 200
    return source_id


# ── CSV with enough records for the full pipeline ──────────────────────────────
FULL_CSV = (
    b"timestamp,user_id,device_id,process_name,ip_address,status,action,event_type\n"
    b"2026-01-01T08:00:00Z,alice,PC-01,explorer.exe,10.0.0.1,SUCCESS,LOGIN,auth_login\n"
    b"2026-01-01T08:01:00Z,alice,PC-01,chrome.exe,10.0.0.1,SUCCESS,LAUNCH,process_create\n"
    b"2026-01-01T08:02:00Z,alice,PC-01,cmd.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-01-01T08:03:00Z,alice,PC-01,powershell.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-01-01T08:04:00Z,alice,PC-01,mimikatz.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-01-01T08:05:00Z,alice,PC-01,svchost.exe,10.0.0.2,SUCCESS,NETWORK,network_connect\n"
    b"2026-01-01T08:06:00Z,alice,PC-01,cmd.exe,10.0.0.1,FAILURE,EXEC,process_create\n"
    b"2026-01-01T08:07:00Z,alice,PC-01,cmd.exe,10.0.0.1,FAILURE,EXEC,process_create\n"
    b"2026-01-01T08:08:00Z,alice,PC-01,cmd.exe,10.0.0.1,SUCCESS,EXEC,process_create\n"
    b"2026-01-01T08:09:00Z,alice,PC-01,notepad.exe,10.0.0.1,SUCCESS,LAUNCH,process_create\n"
    b"2026-01-01T08:10:00Z,alice,PC-01,outlook.exe,10.0.0.1,SUCCESS,LAUNCH,process_create\n"
    b"2026-01-01T08:11:00Z,alice,PC-01,explorer.exe,10.0.0.1,SUCCESS,LOGOUT,auth_logout\n"
)

SIMPLE_CSV = b"timestamp,event_type,user\n2023-01-01T10:00:00Z,LOGIN,admin\n"


# ── Test 1: normalization idempotency (count stable, no crash) ─────────────────
def test_idempotency_normalization(app_client: TestClient, auth_headers: dict):
    inv_id    = _make_investigation(app_client, auth_headers)
    source_id = _ingest_and_normalize(app_client, auth_headers, inv_id, SIMPLE_CSV)

    # second normalize — must not crash and must not double records
    r2 = app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    assert r2.status_code in (200, 400), f"Second normalize crashed: {r2.status_code}"


# ── Test 2: activity count stable across 3 runs ────────────────────────────────
def test_idempotency_activities_count_stable(app_client: TestClient, auth_headers: dict):
    inv_id    = _make_investigation(app_client, auth_headers, "ACT-IDEM")
    source_id = _ingest_and_normalize(app_client, auth_headers, inv_id, FULL_CSV)

    # need correlation before activities
    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)

    r1 = app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    assert r1.status_code == 200
    created_run1 = r1.json()["activities_created"]

    r2 = app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    assert r2.status_code == 200
    assert r2.json()["activities_created"] == 0, \
        f"Run 2 should create 0 new activities, got {r2.json()['activities_created']}"

    r3 = app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    assert r3.status_code == 200
    assert r3.json()["activities_created"] == 0, \
        f"Run 3 should create 0 new activities, got {r3.json()['activities_created']}"

    # DB count must equal what run 1 created
    summary = app_client.get(f"/api/v1/investigations/{inv_id}/summary", headers=auth_headers).json()
    assert summary["total_activities"] == created_run1, \
        f"DB has {summary['total_activities']} activities, expected {created_run1}"


# ── Test 3: activity IDs stable (same logical activity, same DB row) ───────────
def test_idempotency_activity_ids_stable(app_client: TestClient, auth_headers: dict):
    inv_id    = _make_investigation(app_client, auth_headers, "ACTID-IDEM")
    source_id = _ingest_and_normalize(app_client, auth_headers, inv_id, FULL_CSV)

    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)

    app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    acts1 = app_client.get(f"/api/v1/activities?investigation_id={inv_id}", headers=auth_headers).json()
    ids1 = {a["id"] for a in acts1["items"]}

    app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    acts2 = app_client.get(f"/api/v1/activities?investigation_id={inv_id}", headers=auth_headers).json()
    ids2 = {a["id"] for a in acts2["items"]}

    assert ids1 == ids2, f"Activity IDs changed after re-run: {ids1} → {ids2}"


# ── Test 4: no duplicate activity-evidence memberships ────────────────────────
def test_idempotency_no_duplicate_activity_memberships(app_client: TestClient, auth_headers: dict):
    inv_id    = _make_investigation(app_client, auth_headers, "ACTMEM-IDEM")
    source_id = _ingest_and_normalize(app_client, auth_headers, inv_id, FULL_CSV)

    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)
    app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)

    acts = app_client.get(f"/api/v1/activities?investigation_id={inv_id}", headers=auth_headers).json()
    for act in acts["items"]:
        # evidence_ids list must not contain duplicates
        eids = act["evidence_ids"]
        assert len(eids) == len(set(str(e) for e in eids)), \
            f"Activity {act['id']} has duplicate evidence memberships: {eids}"


# ── Test 5: activity priority-result count stable across 3 runs ───────────────
def test_idempotency_activity_priority_count_stable(app_client: TestClient, auth_headers: dict):
    inv_id    = _make_investigation(app_client, auth_headers, "APRIO-IDEM")
    source_id = _ingest_and_normalize(app_client, auth_headers, inv_id, FULL_CSV)

    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)
    app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline", headers=auth_headers)

    p1 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual", headers=auth_headers)
    assert p1.status_code == 200
    created_run1 = p1.json()["results_created"]

    p2 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual", headers=auth_headers)
    assert p2.status_code == 200
    assert p2.json()["results_created"] == 0, \
        f"Prio run 2 should create 0, got {p2.json()['results_created']}"

    p3 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual", headers=auth_headers)
    assert p3.status_code == 200
    assert p3.json()["results_created"] == 0, \
        f"Prio run 3 should create 0, got {p3.json()['results_created']}"

    summary = app_client.get(f"/api/v1/investigations/{inv_id}/summary", headers=auth_headers).json()
    activity_prio_count = summary["total_priority_results"] - len(
        app_client.get(f"/api/v1/prioritization/results?investigation_id={inv_id}&method_type=BASELINE_INDEPENDENT&limit=500",
                       headers=auth_headers).json()["items"]
    )
    assert activity_prio_count == created_run1, \
        f"DB activity priorities: {activity_prio_count}, expected {created_run1}"


# ── Test 6: evidence prioritization stable ────────────────────────────────────
def test_idempotency_evidence_prioritization_stable(app_client: TestClient, auth_headers: dict):
    inv_id    = _make_investigation(app_client, auth_headers, "EPRIO-IDEM")
    source_id = _ingest_and_normalize(app_client, auth_headers, inv_id, FULL_CSV)

    r1 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline", headers=auth_headers)
    assert r1.status_code == 200
    created1 = r1.json()["results_created"]

    r2 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline", headers=auth_headers)
    assert r2.status_code == 200
    assert r2.json()["results_created"] == 0, \
        f"Evidence prio run 2 should create 0, got {r2.json()['results_created']}"


# ── Test 7: correlation idempotency ───────────────────────────────────────────
def test_idempotency_correlation_stable(app_client: TestClient, auth_headers: dict):
    inv_id    = _make_investigation(app_client, auth_headers, "COR-IDEM")
    source_id = _ingest_and_normalize(app_client, auth_headers, inv_id, FULL_CSV)

    r1 = app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)
    assert r1.status_code == 200
    created1 = r1.json()["relationships_created"]

    r2 = app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)
    assert r2.status_code == 200
    created2 = r2.json()["relationships_created"]
    assert created2 == 0, f"Correlation run 2 should create 0, got {created2}"

    summary = app_client.get(f"/api/v1/investigations/{inv_id}/summary", headers=auth_headers).json()
    assert summary["total_relationships"] == created1


# ── Test 8: re-normalization does not leave zombie activities ─────────────────
def test_idempotency_renormalization_no_zombies(app_client: TestClient, auth_headers: dict):
    inv_id    = _make_investigation(app_client, auth_headers, "RENORM-IDEM")
    source_id = _ingest_and_normalize(app_client, auth_headers, inv_id, FULL_CSV)

    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)
    app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline", headers=auth_headers)
    app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual", headers=auth_headers)

    # Re-normalize
    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    
    # Check if activities still exist (they shouldn't)
    acts = app_client.get(f"/api/v1/activities?investigation_id={inv_id}", headers=auth_headers).json()
    assert len(acts["items"]) == 0, f"Expected 0 activities after re-normalizing, got {len(acts['items'])}"
    
    # Check if priorities still exist (they shouldn't)
    prios = app_client.get(f"/api/v1/prioritization/results?investigation_id={inv_id}", headers=auth_headers).json()
    assert len(prios["items"]) == 0, f"Expected 0 priorities after re-normalizing, got {len(prios['items'])}"
