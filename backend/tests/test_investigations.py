import uuid
import pytest
from fastapi.testclient import TestClient

def test_create_valid_investigation(app_client: TestClient, auth_headers: dict):
    payload = {
        "title": "Valid Case",
        "description": "Test Case",
        "case_number": f"CASE-{uuid.uuid4().hex[:6]}",
        "status": "OPEN"
    }
    resp = app_client.post("/api/v1/investigations", json=payload, headers=auth_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Valid Case"
    assert data["status"] == "OPEN"
    assert "id" in data

def test_create_invalid_investigation(app_client: TestClient, auth_headers: dict):
    payload = {
        "title": "", # Invalid empty title
        "case_number": "" # Invalid empty case number
    }
    resp = app_client.post("/api/v1/investigations", json=payload, headers=auth_headers)
    assert resp.status_code == 422

def test_get_nonexistent_investigation(app_client: TestClient, auth_headers: dict):
    fake_id = str(uuid.uuid4())
    resp = app_client.get(f"/api/v1/investigations/{fake_id}", headers=auth_headers)
    assert resp.status_code == 404

def test_duplicate_case_number(app_client: TestClient, auth_headers: dict):
    case_no = f"DUP-{uuid.uuid4().hex[:6]}"
    payload = {"title": "Test 1", "case_number": case_no, "status": "OPEN"}
    resp1 = app_client.post("/api/v1/investigations", json=payload, headers=auth_headers)
    assert resp1.status_code == 201
    
    payload2 = {"title": "Test 2", "case_number": case_no, "status": "OPEN"}
    resp2 = app_client.post("/api/v1/investigations", json=payload2, headers=auth_headers)
    assert resp2.status_code == 409
