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
    from app.core.rate_limit import analysis_rate_limiter
    analysis_rate_limiter.reset()
    yield


# ── shared setup ───────────────────────────────────────────────────────────────
def _make_investigation(app_client, prefix="IDEM"):
    resp = app_client.post(
        "/api/v1/investigations",
        json={"title": f"{prefix} Case", "case_number": f"{prefix}-{uuid.uuid4().hex[:6]}"},
    )
    assert resp.status_code == 201
    return resp.json()["id"]


def _ingest_and_normalize(app_client, inv_id, csv_bytes):
    r = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("test.csv", io.BytesIO(csv_bytes), "text/csv")},
    )
    assert r.status_code in (200, 201), r.text
    source_id = r.json()["source_id"]
    n = app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
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


def test_idempotency_normalization(app_client: TestClient):
    inv_id    = _make_investigation(app_client)
    source_id = _ingest_and_normalize(app_client, inv_id, SIMPLE_CSV)

    r2 = app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
    assert r2.status_code in (200, 400), f"Second normalize crashed: {r2.status_code}"


def test_idempotency_activities_count_stable(app_client: TestClient):
    inv_id    = _make_investigation(app_client, "ACT-IDEM")
    source_id = _ingest_and_normalize(app_client, inv_id, FULL_CSV)

    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze")

    r1 = app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    assert r1.status_code == 200
    created_run1 = r1.json()["activities_created"]

    r2 = app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    assert r2.status_code == 200
    assert r2.json()["activities_created"] == 0, \
        f"Run 2 should create 0 new activities, got {r2.json()['activities_created']}"

    r3 = app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    assert r3.status_code == 200
    assert r3.json()["activities_created"] == 0, \
        f"Run 3 should create 0 new activities, got {r3.json()['activities_created']}"

    summary = app_client.get(f"/api/v1/investigations/{inv_id}/summary").json()
    assert summary["total_activities"] == created_run1, \
        f"DB has {summary['total_activities']} activities, expected {created_run1}"


def test_idempotency_activity_ids_stable(app_client: TestClient):
    inv_id    = _make_investigation(app_client, "ACTID-IDEM")
    source_id = _ingest_and_normalize(app_client, inv_id, FULL_CSV)

    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze")

    app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    acts1 = app_client.get(f"/api/v1/activities?investigation_id={inv_id}").json()
    ids1 = {a["id"] for a in acts1["items"]}

    app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    acts2 = app_client.get(f"/api/v1/activities?investigation_id={inv_id}").json()
    ids2 = {a["id"] for a in acts2["items"]}

    assert ids1 == ids2, f"Activity IDs changed after re-run: {ids1} \u2192 {ids2}"


def test_idempotency_no_duplicate_activity_memberships(app_client: TestClient):
    inv_id    = _make_investigation(app_client, "ACTMEM-IDEM")
    source_id = _ingest_and_normalize(app_client, inv_id, FULL_CSV)

    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze")
    app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    app_client.post(f"/api/v1/activities/sources/{source_id}/form")

    acts = app_client.get(f"/api/v1/activities?investigation_id={inv_id}").json()
    for act in acts["items"]:
        eids = act["evidence_ids"]
        assert len(eids) == len(set(str(e) for e in eids)), \
            f"Activity {act['id']} has duplicate evidence memberships: {eids}"


def test_idempotency_activity_priority_count_stable(app_client: TestClient):
    inv_id    = _make_investigation(app_client, "APRIO-IDEM")
    source_id = _ingest_and_normalize(app_client, inv_id, FULL_CSV)

    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze")
    app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")

    p1 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")
    assert p1.status_code == 200
    created_run1 = p1.json()["results_created"]

    p2 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")
    assert p2.status_code == 200
    assert p2.json()["results_created"] == 0, \
        f"Prio run 2 should create 0, got {p2.json()['results_created']}"

    p3 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")
    assert p3.status_code == 200
    assert p3.json()["results_created"] == 0, \
        f"Prio run 3 should create 0, got {p3.json()['results_created']}"

    summary = app_client.get(f"/api/v1/investigations/{inv_id}/summary").json()
    activity_prio_count = summary["total_priority_results"] - len(
        app_client.get(
            f"/api/v1/prioritization/results?investigation_id={inv_id}&method_type=BASELINE_INDEPENDENT&limit=500"
        ).json()["items"]
    )
    assert activity_prio_count == created_run1, \
        f"DB activity priorities: {activity_prio_count}, expected {created_run1}"


def test_idempotency_evidence_prioritization_stable(app_client: TestClient):
    inv_id    = _make_investigation(app_client, "EPRIO-IDEM")
    source_id = _ingest_and_normalize(app_client, inv_id, FULL_CSV)

    r1 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")
    assert r1.status_code == 200
    created1 = r1.json()["results_created"]

    r2 = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")
    assert r2.status_code == 200
    assert r2.json()["results_created"] == 0, \
        f"Evidence prio run 2 should create 0, got {r2.json()['results_created']}"


def test_idempotency_correlation_stable(app_client: TestClient):
    inv_id    = _make_investigation(app_client, "COR-IDEM")
    source_id = _ingest_and_normalize(app_client, inv_id, FULL_CSV)

    r1 = app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze")
    assert r1.status_code == 200
    created1 = r1.json()["relationships_created"]

    r2 = app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze")
    assert r2.status_code == 200
    assert r2.json()["relationships_created"] == 0, \
        f"Correlation run 2 should create 0, got {r2.json()['relationships_created']}"

    summary = app_client.get(f"/api/v1/investigations/{inv_id}/summary").json()
    assert summary["total_relationships"] == created1


def test_idempotency_renormalization_no_zombies(app_client: TestClient):
    inv_id    = _make_investigation(app_client, "RENORM-IDEM")
    source_id = _ingest_and_normalize(app_client, inv_id, FULL_CSV)

    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze")
    app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")
    app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")

    # Re-normalize — should clear all derived data for this source
    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize")

    acts = app_client.get(f"/api/v1/activities?investigation_id={inv_id}").json()
    assert len(acts["items"]) == 0, \
        f"Expected 0 activities after re-normalizing, got {len(acts['items'])}"

    prios = app_client.get(f"/api/v1/prioritization/results?investigation_id={inv_id}").json()
    assert len(prios["items"]) == 0, \
        f"Expected 0 priorities after re-normalizing, got {len(prios['items'])}"
