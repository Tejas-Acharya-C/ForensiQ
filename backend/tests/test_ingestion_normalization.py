import io
import uuid
import pytest
from fastapi.testclient import TestClient

def test_ingest_valid_evidence(app_client: TestClient, auth_headers: dict):
    resp = app_client.post("/api/v1/investigations", json={"title": "Ingest", "case_number": f"ING-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]

    csv_content = b"timestamp,event_type,user,src_ip,dest_port,process,action,status\n2023-01-01T10:00:00Z,LOGIN,admin,192.168.1.100,22,,ALLOW,SUCCESS\n"
    resp = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("valid.csv", io.BytesIO(csv_content), "text/csv")},
        headers=auth_headers
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["total_records"] == 1
    assert data["filename"] == "valid.csv"
    assert data["source_id"] is not None

def test_ingest_empty_evidence(app_client: TestClient, auth_headers: dict):
    resp = app_client.post("/api/v1/investigations", json={"title": "Empty Ingest", "case_number": f"EMP-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]

    csv_content = b""
    resp = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("empty.csv", io.BytesIO(csv_content), "text/csv")},
        headers=auth_headers
    )
    # Backend should reject empty or invalid CSV files
    assert resp.status_code in [400, 422, 500] # Adjust according to actual error handling

def test_normalize_valid_evidence(app_client: TestClient, auth_headers: dict):
    resp = app_client.post("/api/v1/investigations", json={"title": "Norm", "case_number": f"NRM-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]

    csv_content = b"timestamp,event_type,user,src_ip,dest_port,process,action,status\n2023-01-01T10:00:00Z,LOGIN,admin,192.168.1.100,22,,ALLOW,SUCCESS\n"
    resp = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("norm.csv", io.BytesIO(csv_content), "text/csv")},
        headers=auth_headers
    )
    source_id = resp.json()["source_id"]

    resp = app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["normalized_records"] == 1
    assert data["status"] == "COMPLETED"
