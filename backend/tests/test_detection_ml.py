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
    resp = app_client.post("/api/v1/investigations", json={"title": "Det", "case_number": f"DET-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]
    resp = app_client.post("/api/v1/evidence/import", data={"investigation_id": inv_id}, files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}, headers=auth_headers)
    source_id = resp.json()["source_id"]
    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    return inv_id, source_id

def test_deterministic_detection_matches(app_client: TestClient, auth_headers: dict):
    csv_content = b"timestamp,event_type,process_name,action,status\n2023-01-01T10:00:00Z,PROCESS,mimikatz.exe,EXECUTE,SUCCESS\n"
    inv_id, source_id = setup_evidence(app_client, auth_headers, csv_content)
    
    resp = app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings_created"] == 1

def test_deterministic_detection_no_match(app_client: TestClient, auth_headers: dict):
    csv_content = b"timestamp,event_type,process_name,action,status\n2023-01-01T10:00:00Z,PROCESS,notepad.exe,EXECUTE,SUCCESS\n"
    inv_id, source_id = setup_evidence(app_client, auth_headers, csv_content)
    
    resp = app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings_created"] == 0

def test_ml_anomaly_detection_sufficient_data(app_client: TestClient, auth_headers: dict):
    lines = ["timestamp,event_type,user,status"]
    for i in range(15):
        lines.append(f"2023-01-01T10:00:{i:02}Z,LOGIN,admin,SUCCESS")
    lines.append("2023-01-01T03:00:00Z,LOGIN,admin,FAILED")
    csv_content = "\n".join(lines).encode('utf-8')
    inv_id, source_id = setup_evidence(app_client, auth_headers, csv_content)

    resp = app_client.post(f"/api/v1/ml/sources/{source_id}/analyze", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["evidence_evaluated"] == 16
