import io
import uuid
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    from app.core.rate_limit import analysis_rate_limiter
    analysis_rate_limiter.reset()
    yield


def setup_full_pipeline(app_client, csv_content):
    resp = app_client.post("/api/v1/investigations", json={"title": "Pri", "case_number": f"PRI-{uuid.uuid4().hex[:6]}"})
    inv_id = resp.json()["id"]
    resp = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")},
    )
    source_id = resp.json()["source_id"]
    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
    app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules")
    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze")
    app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    return inv_id, source_id


def test_evidence_prioritization(app_client: TestClient):
    csv_content = b"timestamp,event_type,user,process_name,action,status\n2023-01-01T10:00:00Z,PROCESS,admin,mimikatz.exe,EXECUTE,SUCCESS\n"
    inv_id, source_id = setup_full_pipeline(app_client, csv_content)

    resp = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")
    assert resp.status_code == 200
    data = resp.json()
    assert data["results_created"] > 0
    assert data["method_type"] == "BASELINE_INDEPENDENT"


def test_activity_prioritization(app_client: TestClient):
    csv_content = (
        b"timestamp,event_type,user,process_name,action,status\n"
        b"2023-01-01T10:00:00Z,LOGIN,admin,,ALLOW,SUCCESS\n"
        b"2023-01-01T10:00:01Z,PROCESS,admin,cmd.exe,EXECUTE,SUCCESS\n"
        b"2023-01-01T10:00:02Z,PROCESS,admin,powershell.exe,EXECUTE,SUCCESS\n"
        b"2023-01-01T10:00:03Z,PROCESS,admin,mimikatz.exe,EXECUTE,SUCCESS\n"
    )
    inv_id, source_id = setup_full_pipeline(app_client, csv_content)

    resp = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")
    assert resp.status_code == 200
    data = resp.json()
    assert data["results_created"] > 0, \
        f"Expected activity priority results; status={data.get('status')} created={data.get('results_created')}"
    assert data["method_type"] == "PROPOSED_CONTEXTUAL"
