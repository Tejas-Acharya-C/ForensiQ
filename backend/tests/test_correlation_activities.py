import io
import uuid
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    from app.core.rate_limit import analysis_rate_limiter, login_rate_limiter
    analysis_rate_limiter.reset()
    login_rate_limiter.reset()
    yield

def setup_evidence(app_client, auth_headers, csv_content):
    resp = app_client.post("/api/v1/investigations", json={"title": "CorAct", "case_number": f"COR-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]
    resp = app_client.post("/api/v1/evidence/import", data={"investigation_id": inv_id}, files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}, headers=auth_headers)
    source_id = resp.json()["source_id"]
    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    return inv_id, source_id

def test_correlation_creates_relationship(app_client: TestClient, auth_headers: dict):
    # Two events with same user and close in time
    csv_content = b"timestamp,event_type,user,process_name,action,status\n2023-01-01T10:00:00Z,LOGIN,admin,,ALLOW,SUCCESS\n2023-01-01T10:00:01Z,PROCESS,admin,cmd.exe,EXECUTE,SUCCESS\n"
    inv_id, source_id = setup_evidence(app_client, auth_headers, csv_content)

    resp = app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["relationships_created"] > 0

def test_activity_formation(app_client: TestClient, auth_headers: dict):
    csv_content = b"timestamp,event_type,user,process_name,action,status\n2023-01-01T10:00:00Z,LOGIN,admin,,ALLOW,SUCCESS\n2023-01-01T10:00:01Z,PROCESS,admin,cmd.exe,EXECUTE,SUCCESS\n"
    inv_id, source_id = setup_evidence(app_client, auth_headers, csv_content)
    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)

    resp = app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["activities_created"] > 0
