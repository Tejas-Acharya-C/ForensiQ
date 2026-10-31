import uuid
import io
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    from app.core.rate_limit import analysis_rate_limiter
    analysis_rate_limiter.reset()
    yield


def test_detection_before_normalization_fails_gracefully(app_client: TestClient):
    resp = app_client.post("/api/v1/investigations", json={"title": "Err", "case_number": f"ERR-{uuid.uuid4().hex[:6]}"})
    inv_id = resp.json()["id"]

    csv_content = b"timestamp,event_type,user\n2023-01-01T10:00:00Z,LOGIN,admin\n"
    resp = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")},
    )
    source_id = resp.json()["source_id"]

    # Run detection BEFORE normalization — should not 500, should return 0 findings
    resp = app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules")
    assert resp.status_code in [200, 400, 422]
    if resp.status_code == 200:
        assert resp.json()["findings_created"] == 0


def test_activity_formation_without_relationships_fails_gracefully(app_client: TestClient):
    resp = app_client.post("/api/v1/investigations", json={"title": "Err", "case_number": f"ERR-{uuid.uuid4().hex[:6]}"})
    inv_id = resp.json()["id"]

    csv_content = b"timestamp,event_type,user\n2023-01-01T10:00:00Z,LOGIN,admin\n"
    resp = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")},
    )
    source_id = resp.json()["source_id"]

    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize")

    # Run activity formation without correlation — should gracefully return 0
    resp = app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    assert resp.status_code in [200, 400]
    if resp.status_code == 200:
        assert resp.json()["activities_created"] == 0
