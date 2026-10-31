"""Tests for Phase 3 Evidence Explorer & Traceability endpoints."""

import uuid
import pytest
from fastapi.testclient import TestClient


def test_evidence_list_ids_filter(app_client: TestClient):
    # Create investigation
    inv_res = app_client.post(
        "/api/v1/investigations",
        json={"title": "Traceability Test", "case_number": f"CASE-P3-{uuid.uuid4().hex[:6]}"},
    )
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    # Ingest evidence
    csv_data = "timestamp,event_type,user,process\n2026-03-01T10:00:00Z,PROCESS_LAUNCH,alice,cmd.exe\n2026-03-01T10:01:00Z,PROCESS_LAUNCH,bob,powershell.exe\n"
    import_res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("test.csv", csv_data, "text/csv")},
    )
    assert import_res.status_code == 201
    source_id = import_res.json()["source_id"]

    # Normalize
    norm_res = app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
    assert norm_res.status_code == 200
    assert norm_res.json()["normalized_records"] == 2

    # Query all evidence for this investigation
    list_res = app_client.get(f"/api/v1/evidence?investigation_id={inv_id}&limit=10")
    assert list_res.status_code == 200
    items = list_res.json()["items"]
    assert len(items) == 2

    target_id_1 = items[0]["id"]
    target_id_2 = items[1]["id"]

    # Query using single id in ids filter
    filtered_1 = app_client.get(f"/api/v1/evidence?investigation_id={inv_id}&ids={target_id_1}")
    assert filtered_1.status_code == 200
    assert len(filtered_1.json()["items"]) == 1
    assert filtered_1.json()["items"][0]["id"] == target_id_1

    # Query using comma-separated ids in ids filter
    filtered_both = app_client.get(f"/api/v1/evidence?investigation_id={inv_id}&ids={target_id_1},{target_id_2}")
    assert filtered_both.status_code == 200
    assert len(filtered_both.json()["items"]) == 2

    # Query with nonexistent UUID in ids
    nonexistent = str(uuid.uuid4())
    filtered_none = app_client.get(f"/api/v1/evidence?investigation_id={inv_id}&ids={nonexistent}")
    assert filtered_none.status_code == 200
    assert len(filtered_none.json()["items"]) == 0


def test_evidence_list_ids_validation_and_containment(app_client: TestClient):
    # 1. Malformed UUID rejection
    res_malformed = app_client.get("/api/v1/evidence?ids=invalid-uuid-format")
    assert res_malformed.status_code == 400
    err_body = res_malformed.json()
    msg = err_body.get("error", {}).get("message") or err_body.get("detail", "")
    assert "Malformed UUID" in msg

    # 2. Maximum bound of 100 IDs
    too_many_ids = ",".join([str(uuid.uuid4()) for _ in range(101)])
    res_too_many = app_client.get(f"/api/v1/evidence?ids={too_many_ids}")
    assert res_too_many.status_code == 400
    err_body_2 = res_too_many.json()
    msg_2 = err_body_2.get("error", {}).get("message") or err_body_2.get("detail", "")
    assert "cannot exceed 100" in msg_2

    # 3. Investigation cross-containment on list_evidence with ids
    inv_a = app_client.post("/api/v1/investigations", json={"title": "Inv A", "case_number": f"CASE-A-{uuid.uuid4().hex[:6]}"}).json()["id"]
    inv_b = app_client.post("/api/v1/investigations", json={"title": "Inv B", "case_number": f"CASE-B-{uuid.uuid4().hex[:6]}"}).json()["id"]

    import_res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_a},
        files={"file": ("a.csv", "timestamp,event_type\n2026-03-01T10:00:00Z,LOGIN\n", "text/csv")},
    )
    src_id = import_res.json()["source_id"]
    app_client.post(f"/api/v1/evidence/sources/{src_id}/normalize")

    ev_items = app_client.get(f"/api/v1/evidence?investigation_id={inv_a}").json()["items"]
    ev_a_id = ev_items[0]["id"]

    # Query with inv_b and ev_a_id -> should return 0 items
    cross_res = app_client.get(f"/api/v1/evidence?investigation_id={inv_b}&ids={ev_a_id}")
    assert cross_res.status_code == 200
    assert len(cross_res.json()["items"]) == 0

    # 4. Investigation containment on get_evidence_detail
    # Detail with correct investigation_id -> 200
    detail_ok = app_client.get(f"/api/v1/evidence/{ev_a_id}?investigation_id={inv_a}")
    assert detail_ok.status_code == 200
    assert detail_ok.json()["id"] == ev_a_id

    # Detail with wrong investigation_id -> 404
    detail_leak = app_client.get(f"/api/v1/evidence/{ev_a_id}?investigation_id={inv_b}")
    assert detail_leak.status_code == 404
    err_body_leak = detail_leak.json()
    msg_leak = err_body_leak.get("error", {}).get("message") or err_body_leak.get("detail", "")
    assert f"not found in investigation '{inv_b}'" in msg_leak


def test_prioritization_target_id_filter(app_client: TestClient):
    inv_res = app_client.post(
        "/api/v1/investigations",
        json={"title": "Prio Target Test", "case_number": f"CASE-PRIO-{uuid.uuid4().hex[:6]}"},
    )
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    csv_data = "timestamp,event_type,user,process\n2026-03-01T10:00:00Z,PROCESS_LAUNCH,admin,powershell.exe\n"
    import_res = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("prio.csv", csv_data, "text/csv")},
    )
    source_id = import_res.json()["source_id"]
    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
    app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules")
    app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")

    evd_res = app_client.get(f"/api/v1/evidence?investigation_id={inv_id}&limit=1")
    target_evd_id = evd_res.json()["items"][0]["id"]

    # Filter prioritization by target_id
    prio_res = app_client.get(f"/api/v1/prioritization/results?investigation_id={inv_id}&target_id={target_evd_id}")
    assert prio_res.status_code == 200
    prio_items = prio_res.json()["items"]
    assert len(prio_items) == 1
    assert prio_items[0]["target_id"] == target_evd_id
