import io
import math
import uuid
from collections import defaultdict
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    from app.core.rate_limit import analysis_rate_limiter
    analysis_rate_limiter.reset()
    yield


def setup_evidence(app_client, csv_content):
    resp = app_client.post("/api/v1/investigations", json={"title": "Det", "case_number": f"DET-{uuid.uuid4().hex[:6]}"})
    inv_id = resp.json()["id"]
    resp = app_client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")},
    )
    source_id = resp.json()["source_id"]
    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
    return inv_id, source_id


def test_deterministic_detection_matches(app_client: TestClient):
    csv_content = b"timestamp,event_type,process_name,action,status\n2023-01-01T10:00:00Z,PROCESS,mimikatz.exe,EXECUTE,SUCCESS\n"
    inv_id, source_id = setup_evidence(app_client, csv_content)

    resp = app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules")
    assert resp.status_code == 200
    assert resp.json()["findings_created"] == 1


def test_deterministic_detection_no_match(app_client: TestClient):
    csv_content = b"timestamp,event_type,process_name,action,status\n2023-01-01T10:00:00Z,PROCESS,notepad.exe,EXECUTE,SUCCESS\n"
    inv_id, source_id = setup_evidence(app_client, csv_content)

    resp = app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules")
    assert resp.status_code == 200
    assert resp.json()["findings_created"] == 0


def test_ml_anomaly_detection_sufficient_data(app_client: TestClient):
    lines = ["timestamp,event_type,user,status"]
    for i in range(15):
        lines.append(f"2023-01-01T10:00:{i:02}Z,LOGIN,admin,SUCCESS")
    lines.append("2023-01-01T03:00:00Z,LOGIN,admin,FAILED")
    csv_content = "\n".join(lines).encode("utf-8")
    inv_id, source_id = setup_evidence(app_client, csv_content)

    resp = app_client.post(f"/api/v1/ml/sources/{source_id}/analyze")
    assert resp.status_code == 200
    assert resp.json()["evidence_evaluated"] == 16


def test_ml_numpy_feature_extraction_and_deterministic_isolation_forest():
    """Permanent regression test for NumPy feature matrix preparation and deterministic Isolation Forest."""
    num_records = 30
    records = []
    for i in range(num_records):
        records.append({
            "user_id": "alice" if i < 25 else "unknown_actor",
            "device_id": "HOST-01",
            "timestamp_epoch": 1700000000 + i * 60,
            "hour": (10 + (i // 6)) % 24,
            "status": "SUCCESS" if i < 28 else "AUTH_FAILED",
        })

    user_counts = defaultdict(int)
    for r in records:
        if r["user_id"]:
            user_counts[r["user_id"]] += 1

    last_ts = {}
    features = []
    for r in records:
        ts = r["timestamp_epoch"]
        key = f"{r['user_id']}@{r['device_id']}"
        delta = max(0.0, ts - last_ts.get(key, ts))
        last_ts[key] = ts
        hour = r["hour"]
        features.append([
            float(user_counts[r["user_id"]] / len(records)) if r["user_id"] else 0.0,
            float(math.log10(delta + 1)),
            1.0 if ("FAIL" in str(r["status"]).upper() or "ERROR" in str(r["status"]).upper()) else 0.0,
            float(math.sin(2 * math.pi * (hour / 24.0))),
        ])

    X = np.array(features, dtype=float)

    # 1. Verify array geometry and numeric constraints
    assert isinstance(X, np.ndarray)
    assert X.shape == (num_records, 4)
    assert X.dtype == np.float64
    assert np.all(np.isfinite(X)), "All feature values must be finite (no NaN or Inf)"
    assert np.all(X[:, 0] >= 0.0) and np.all(X[:, 0] <= 1.0), "User frequency must be in [0, 1]"
    assert np.all(X[:, 2] >= 0.0) and np.all(X[:, 2] <= 1.0), "Status failure flag must be in [0, 1]"
    assert np.all(X[:, 3] >= -1.0) and np.all(X[:, 3] <= 1.0), "Sine hour feature must be in [-1, 1]"

    # 2. Verify deterministic Isolation Forest execution across repeated fits
    model_a = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model_a.fit(X)
    scores_a = -model_a.score_samples(X)

    model_b = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model_b.fit(X)
    scores_b = -model_b.score_samples(X)

    np.testing.assert_array_almost_equal(scores_a, scores_b, decimal=8)

    # 3. Verify normalization clipping behavior
    min_score, max_score = float(np.percentile(scores_a, 1)), float(np.percentile(scores_a, 99))
    if max_score <= min_score:
        max_score = min_score + 0.1
    norm_scores = np.clip((scores_a - min_score) / (max_score - min_score), 0.0, 1.0)
    assert np.all(norm_scores >= 0.0) and np.all(norm_scores <= 1.0)


def test_ml_anomaly_detection_insufficient_data(app_client: TestClient):
    """Verify that fewer than 10 events return INSUFFICIENT_DATA and create 0 findings."""
    lines = ["timestamp,event_type,user,status"]
    for i in range(5):
        lines.append(f"2023-01-01T10:00:{i:02}Z,LOGIN,admin,SUCCESS")
    csv_content = "\n".join(lines).encode("utf-8")
    inv_id, source_id = setup_evidence(app_client, csv_content)

    resp = app_client.post(f"/api/v1/ml/sources/{source_id}/analyze")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "INSUFFICIENT_DATA"
    assert data["findings_created"] == 0


def test_ml_anomaly_detection_custom_parameters(app_client: TestClient):
    """Verify that custom contamination and threshold parameters in MLAnalysisRequest are respected."""
    lines = ["timestamp,event_type,user,status"]
    for i in range(25):
        lines.append(f"2023-01-01T10:00:{i:02}Z,LOGIN,user{i%3},SUCCESS")
    lines.append("2023-01-01T03:00:00Z,LOGIN,intruder,FAILED")
    csv_content = "\n".join(lines).encode("utf-8")
    inv_id, source_id = setup_evidence(app_client, csv_content)

    payload = {
        "contamination": 0.1,
        "random_seed": 123,
        "threshold": 0.5,
        "model_override": "isolation_forest",
    }
    resp = app_client.post(f"/api/v1/ml/sources/{source_id}/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "COMPLETED"
    assert data["evidence_evaluated"] == 26
    assert isinstance(data["findings_created"], int)

    # Test that invalid model_override returns 400 Bad Request
    invalid_payload = {"model_override": "unsupported_dnn"}
    bad_resp = app_client.post(f"/api/v1/ml/sources/{source_id}/analyze", json=invalid_payload)
    assert bad_resp.status_code == 400
    assert "Unsupported model override" in bad_resp.json()["detail"]
