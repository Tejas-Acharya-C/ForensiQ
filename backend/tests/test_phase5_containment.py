"""Tests for Phase 5.1 Investigation Containment on detail endpoints."""

import uuid
import pytest
from fastapi.testclient import TestClient


def test_detail_endpoints_containment(app_client: TestClient):
    # Setup two distinct investigations
    inv_a = app_client.post(
        "/api/v1/investigations",
        json={"title": "Containment Case A", "case_number": f"CASE-A-{uuid.uuid4().hex[:6]}"},
    ).json()["id"]

    inv_b = app_client.post(
        "/api/v1/investigations",
        json={"title": "Containment Case B", "case_number": f"CASE-B-{uuid.uuid4().hex[:6]}"},
    ).json()["id"]

    # Ingest evidence into Case A
    csv_data = (
        "timestamp,event_type,user,process,ip_address\n"
        "2026-03-01T10:00:00Z,PROCESS_LAUNCH,admin,powershell.exe,192.168.1.50\n"
        "2026-03-01T10:05:00Z,PROCESS_LAUNCH,admin,cmd.exe,192.168.1.50\n"
    )
    import_res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_a},
        files={"file": ("case_a.csv", csv_data, "text/csv")},
    )
    src_id = import_res.json()["source_id"]

    # Run analysis stages to produce Evidence, Findings, Activities, and Priority Results
    app_client.post(f"/api/v1/evidence/sources/{src_id}/normalize")
    app_client.post(f"/api/v1/detection/sources/{src_id}/analyze-rules")
    app_client.post(f"/api/v1/correlation/sources/{src_id}/analyze")
    app_client.post(f"/api/v1/activities/sources/{src_id}/form")
    app_client.post(f"/api/v1/prioritization/investigations/{inv_a}/baseline")

    # Fetch IDs created in Case A
    ev_items = app_client.get(f"/api/v1/evidence?investigation_id={inv_a}").json()["items"]
    assert len(ev_items) > 0
    ev_id = ev_items[0]["id"]

    finding_items = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_a}").json()["items"]
    assert len(finding_items) > 0
    finding_id = finding_items[0]["id"]

    activity_items = app_client.get(f"/api/v1/activities?investigation_id={inv_a}").json()["items"]
    assert len(activity_items) > 0
    activity_id = activity_items[0]["id"]

    prio_items = app_client.get(f"/api/v1/prioritization/results?investigation_id={inv_a}").json()["items"]
    assert len(prio_items) > 0
    prio_id = prio_items[0]["id"]

    random_uuid = str(uuid.uuid4())
    nonexistent_inv_id = str(uuid.uuid4())

    # =========================================================================
    # 1. Evidence Detail Containment
    # =========================================================================
    # Case A evidence + inv_a -> 200
    res = app_client.get(f"/api/v1/evidence/{ev_id}?investigation_id={inv_a}")
    assert res.status_code == 200
    assert res.json()["id"] == ev_id

    # Case A evidence + omitted investigation_id -> 200 (backward compatibility)
    res = app_client.get(f"/api/v1/evidence/{ev_id}")
    assert res.status_code == 200
    assert res.json()["id"] == ev_id

    # Case A evidence + mismatched inv_b -> 404
    res = app_client.get(f"/api/v1/evidence/{ev_id}?investigation_id={inv_b}")
    assert res.status_code == 404
    assert f"not found in investigation '{inv_b}'" in (res.json().get("error", {}).get("message") or "")

    # Nonexistent evidence + valid inv_a -> 404 without leaking cross-existence
    res = app_client.get(f"/api/v1/evidence/{random_uuid}?investigation_id={inv_a}")
    assert res.status_code == 404
    assert f"not found in investigation '{inv_a}'" in (res.json().get("error", {}).get("message") or "")

    # Nonexistent investigation_id -> 404
    res = app_client.get(f"/api/v1/evidence/{ev_id}?investigation_id={nonexistent_inv_id}")
    assert res.status_code == 404
    assert f"Investigation '{nonexistent_inv_id}' not found" in (res.json().get("error", {}).get("message") or "")

    # =========================================================================
    # 2. Finding Detail Containment
    # =========================================================================
    # Matching investigation -> 200
    res = app_client.get(f"/api/v1/detection/findings/{finding_id}?investigation_id={inv_a}")
    assert res.status_code == 200
    assert res.json()["id"] == finding_id

    # Omitted investigation -> 200 (backward compatible)
    res = app_client.get(f"/api/v1/detection/findings/{finding_id}")
    assert res.status_code == 200
    assert res.json()["id"] == finding_id

    # Mismatched investigation -> 404
    res = app_client.get(f"/api/v1/detection/findings/{finding_id}?investigation_id={inv_b}")
    assert res.status_code == 404
    assert f"not found in investigation '{inv_b}'" in (res.json().get("error", {}).get("message") or "")

    # Nonexistent finding with investigation_id -> 404
    res = app_client.get(f"/api/v1/detection/findings/{random_uuid}?investigation_id={inv_a}")
    assert res.status_code == 404
    assert f"not found in investigation '{inv_a}'" in (res.json().get("error", {}).get("message") or "")

    # Nonexistent finding without investigation_id -> 404
    res = app_client.get(f"/api/v1/detection/findings/{random_uuid}")
    assert res.status_code == 404
    assert "not found" in (res.json().get("error", {}).get("message") or "")

    # Nonexistent investigation_id -> 404
    res = app_client.get(f"/api/v1/detection/findings/{finding_id}?investigation_id={nonexistent_inv_id}")
    assert res.status_code == 404
    assert f"Investigation '{nonexistent_inv_id}' not found" in (res.json().get("error", {}).get("message") or "")

    # =========================================================================
    # 3. Activity Detail Containment
    # =========================================================================
    # Matching investigation -> 200
    res = app_client.get(f"/api/v1/activities/{activity_id}?investigation_id={inv_a}")
    assert res.status_code == 200
    assert res.json()["id"] == activity_id

    # Omitted investigation -> 200
    res = app_client.get(f"/api/v1/activities/{activity_id}")
    assert res.status_code == 200
    assert res.json()["id"] == activity_id

    # Mismatched investigation -> 404
    res = app_client.get(f"/api/v1/activities/{activity_id}?investigation_id={inv_b}")
    assert res.status_code == 404
    assert f"not found in investigation '{inv_b}'" in (res.json().get("error", {}).get("message") or "")

    # Nonexistent activity with investigation_id -> 404
    res = app_client.get(f"/api/v1/activities/{random_uuid}?investigation_id={inv_a}")
    assert res.status_code == 404
    assert f"not found in investigation '{inv_a}'" in (res.json().get("error", {}).get("message") or "")

    # Nonexistent investigation_id -> 404
    res = app_client.get(f"/api/v1/activities/{activity_id}?investigation_id={nonexistent_inv_id}")
    assert res.status_code == 404
    assert f"Investigation '{nonexistent_inv_id}' not found" in (res.json().get("error", {}).get("message") or "")

    # =========================================================================
    # 4. Priority Result Detail Containment
    # =========================================================================
    # Matching investigation -> 200
    res = app_client.get(f"/api/v1/prioritization/results/{prio_id}?investigation_id={inv_a}")
    assert res.status_code == 200
    assert res.json()["id"] == prio_id

    # Omitted investigation -> 200
    res = app_client.get(f"/api/v1/prioritization/results/{prio_id}")
    assert res.status_code == 200
    assert res.json()["id"] == prio_id

    # Mismatched investigation -> 404
    res = app_client.get(f"/api/v1/prioritization/results/{prio_id}?investigation_id={inv_b}")
    assert res.status_code == 404
    assert f"not found in investigation '{inv_b}'" in (res.json().get("error", {}).get("message") or "")

    # Nonexistent priority result with investigation_id -> 404
    res = app_client.get(f"/api/v1/prioritization/results/{random_uuid}?investigation_id={inv_a}")
    assert res.status_code == 404
    assert f"not found in investigation '{inv_a}'" in (res.json().get("error", {}).get("message") or "")

    # Nonexistent investigation_id -> 404
    res = app_client.get(f"/api/v1/prioritization/results/{prio_id}?investigation_id={nonexistent_inv_id}")
    assert res.status_code == 404
    assert f"Investigation '{nonexistent_inv_id}' not found" in (res.json().get("error", {}).get("message") or "")

