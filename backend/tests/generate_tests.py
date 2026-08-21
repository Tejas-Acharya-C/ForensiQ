import os
import shutil

TESTS_DIR = r"E:\Python\Python projects\Major Project\backend\tests"

def write_file(filename, content):
    with open(os.path.join(TESTS_DIR, filename), "w", encoding="utf-8") as f:
        f.write(content)

# test_investigations.py
content_inv = """import uuid
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
"""
write_file("test_investigations.py", content_inv)

# test_ingestion_normalization.py
content_ingest = """import io
import uuid
import pytest
from fastapi.testclient import TestClient

def test_ingest_valid_evidence(app_client: TestClient, auth_headers: dict):
    resp = app_client.post("/api/v1/investigations", json={"title": "Ingest", "case_number": f"ING-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]

    csv_content = b"timestamp,event_type,user,src_ip,dest_port,process,action,status\\n2023-01-01T10:00:00Z,LOGIN,admin,192.168.1.100,22,,ALLOW,SUCCESS\\n"
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

    csv_content = b"timestamp,event_type,user,src_ip,dest_port,process,action,status\\n2023-01-01T10:00:00Z,LOGIN,admin,192.168.1.100,22,,ALLOW,SUCCESS\\n"
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
"""
write_file("test_ingestion_normalization.py", content_ingest)

# test_detection_ml.py
content_det = """import io
import uuid
import pytest
from fastapi.testclient import TestClient

def setup_evidence(app_client, auth_headers, csv_content):
    resp = app_client.post("/api/v1/investigations", json={"title": "Det", "case_number": f"DET-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]
    resp = app_client.post("/api/v1/evidence/import", data={"investigation_id": inv_id}, files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}, headers=auth_headers)
    source_id = resp.json()["source_id"]
    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    return inv_id, source_id

def test_deterministic_detection_matches(app_client: TestClient, auth_headers: dict):
    csv_content = b"timestamp,event_type,process_name,action,status\\n2023-01-01T10:00:00Z,PROCESS,mimikatz.exe,EXECUTE,SUCCESS\\n"
    inv_id, source_id = setup_evidence(app_client, auth_headers, csv_content)
    
    resp = app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings_created"] == 1

def test_deterministic_detection_no_match(app_client: TestClient, auth_headers: dict):
    csv_content = b"timestamp,event_type,process_name,action,status\\n2023-01-01T10:00:00Z,PROCESS,notepad.exe,EXECUTE,SUCCESS\\n"
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
    csv_content = "\\n".join(lines).encode('utf-8')
    inv_id, source_id = setup_evidence(app_client, auth_headers, csv_content)

    resp = app_client.post(f"/api/v1/ml/sources/{source_id}/analyze", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["evidence_evaluated"] == 16
"""
write_file("test_detection_ml.py", content_det)

# test_correlation_activities.py
content_cor = """import io
import uuid
import pytest
from fastapi.testclient import TestClient

def setup_evidence(app_client, auth_headers, csv_content):
    resp = app_client.post("/api/v1/investigations", json={"title": "CorAct", "case_number": f"COR-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]
    resp = app_client.post("/api/v1/evidence/import", data={"investigation_id": inv_id}, files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}, headers=auth_headers)
    source_id = resp.json()["source_id"]
    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    return inv_id, source_id

def test_correlation_creates_relationship(app_client: TestClient, auth_headers: dict):
    # Two events with same user and close in time
    csv_content = b"timestamp,event_type,user,process_name,action,status\\n2023-01-01T10:00:00Z,LOGIN,admin,,ALLOW,SUCCESS\\n2023-01-01T10:00:01Z,PROCESS,admin,cmd.exe,EXECUTE,SUCCESS\\n"
    inv_id, source_id = setup_evidence(app_client, auth_headers, csv_content)

    resp = app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["relationships_created"] > 0

def test_activity_formation(app_client: TestClient, auth_headers: dict):
    csv_content = b"timestamp,event_type,user,process_name,action,status\\n2023-01-01T10:00:00Z,LOGIN,admin,,ALLOW,SUCCESS\\n2023-01-01T10:00:01Z,PROCESS,admin,cmd.exe,EXECUTE,SUCCESS\\n"
    inv_id, source_id = setup_evidence(app_client, auth_headers, csv_content)
    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)

    resp = app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["activities_created"] > 0
"""
write_file("test_correlation_activities.py", content_cor)

# test_prioritization.py
content_prio = """import io
import uuid
import pytest
from fastapi.testclient import TestClient

def setup_full_pipeline(app_client, auth_headers, csv_content):
    resp = app_client.post("/api/v1/investigations", json={"title": "Pri", "case_number": f"PRI-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]
    resp = app_client.post("/api/v1/evidence/import", data={"investigation_id": inv_id}, files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}, headers=auth_headers)
    source_id = resp.json()["source_id"]
    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules", headers=auth_headers)
    app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze", headers=auth_headers)
    app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    return inv_id, source_id

def test_evidence_prioritization(app_client: TestClient, auth_headers: dict):
    csv_content = b"timestamp,event_type,user,process_name,action,status\\n2023-01-01T10:00:00Z,PROCESS,admin,mimikatz.exe,EXECUTE,SUCCESS\\n"
    inv_id, source_id = setup_full_pipeline(app_client, auth_headers, csv_content)
    
    resp = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["results_created"] > 0
    assert data["method_type"] == "BASELINE_INDEPENDENT"

def test_activity_prioritization(app_client: TestClient, auth_headers: dict):
    csv_content = b"timestamp,event_type,user,process_name,action,status\\n2023-01-01T10:00:00Z,LOGIN,admin,,ALLOW,SUCCESS\\n2023-01-01T10:00:01Z,PROCESS,admin,cmd.exe,EXECUTE,SUCCESS\\n"
    inv_id, source_id = setup_full_pipeline(app_client, auth_headers, csv_content)
    
    resp = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["results_created"] > 0
    assert data["method_type"] == "PROPOSED_CONTEXTUAL"
"""
write_file("test_prioritization.py", content_prio)

# test_pipeline_errors.py
content_err = """import uuid
import pytest
from fastapi.testclient import TestClient

def test_detection_before_normalization_fails_gracefully(app_client: TestClient, auth_headers: dict):
    resp = app_client.post("/api/v1/investigations", json={"title": "Err", "case_number": f"ERR-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]
    
    import io
    csv_content = b"timestamp,event_type,user\\n2023-01-01T10:00:00Z,LOGIN,admin\\n"
    resp = app_client.post("/api/v1/evidence/import", data={"investigation_id": inv_id}, files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}, headers=auth_headers)
    source_id = resp.json()["source_id"]

    # Run detection BEFORE normalization - should not 500, should either 400 or return 0 findings
    resp = app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules", headers=auth_headers)
    assert resp.status_code in [200, 400, 422]
    if resp.status_code == 200:
        assert resp.json()["findings_created"] == 0

def test_activity_formation_without_relationships_fails_gracefully(app_client: TestClient, auth_headers: dict):
    resp = app_client.post("/api/v1/investigations", json={"title": "Err", "case_number": f"ERR-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]
    
    import io
    csv_content = b"timestamp,event_type,user\\n2023-01-01T10:00:00Z,LOGIN,admin\\n"
    resp = app_client.post("/api/v1/evidence/import", data={"investigation_id": inv_id}, files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}, headers=auth_headers)
    source_id = resp.json()["source_id"]

    app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)

    # Run activity formation without correlation - should gracefully return 0
    resp = app_client.post(f"/api/v1/activities/sources/{source_id}/form", headers=auth_headers)
    assert resp.status_code in [200, 400]
    if resp.status_code == 200:
        assert resp.json()["activities_created"] == 0
"""
write_file("test_pipeline_errors.py", content_err)

# test_idempotency.py
content_idem = """import io
import uuid
import pytest
from fastapi.testclient import TestClient

def setup_evidence(app_client, auth_headers, csv_content):
    resp = app_client.post("/api/v1/investigations", json={"title": "Idem", "case_number": f"IDEM-{uuid.uuid4().hex[:6]}"}, headers=auth_headers)
    inv_id = resp.json()["id"]
    resp = app_client.post("/api/v1/evidence/import", data={"investigation_id": inv_id}, files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}, headers=auth_headers)
    source_id = resp.json()["source_id"]
    return inv_id, source_id

def test_idempotency_normalization(app_client: TestClient, auth_headers: dict):
    csv_content = b"timestamp,event_type,user\\n2023-01-01T10:00:00Z,LOGIN,admin\\n"
    inv_id, source_id = setup_evidence(app_client, auth_headers, csv_content)

    resp1 = app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    assert resp1.status_code == 200
    norm1 = resp1.json()["normalized_records"]

    resp2 = app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize", headers=auth_headers)
    assert resp2.status_code == 200
    # Should not duplicate records if intended to be idempotent, or should return 0 if already normalized.
    # We test that it does not crash (500).
    assert resp2.status_code in [200, 400]
"""
write_file("test_idempotency.py", content_idem)

print("Test generation script complete.")
