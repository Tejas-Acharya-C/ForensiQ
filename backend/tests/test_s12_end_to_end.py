import pytest
import time
import uuid
import json
import io
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    from app.core.rate_limit import analysis_rate_limiter
    analysis_rate_limiter.reset()
    yield


def test_s12_full_analytical_verification(app_client: TestClient, tmp_path):
    # 1. Create Investigation
    inv_res = app_client.post("/api/v1/investigations", json={
        "title": "S12 Verification Case",
        "case_number": "S12-001",
        "description": "Purpose-built test case for final verification",
        "status": "OPEN"
    })
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    # 2. Prepare synthetic evidence (>= 10 records for ML)
    base_time = int(time.time()) - 3600

    evidence_data = [
        {"timestamp": base_time,      "source": "windows", "event_id": 4688, "user": "alice", "host": "wkstn-1", "process": "svchost.exe",    "ip": "10.0.0.5"},
        {"timestamp": base_time + 10, "source": "windows", "event_id": 4688, "user": "alice", "host": "wkstn-1", "process": "explorer.exe",   "ip": "10.0.0.5"},
        {"timestamp": base_time + 20, "source": "windows", "event_id": 4688, "user": "alice", "host": "wkstn-1", "process": "chrome.exe",     "ip": "10.0.0.5"},
        {"timestamp": base_time + 30, "source": "windows", "event_id": 4688, "user": "bob",   "host": "wkstn-2", "process": "svchost.exe",    "ip": "10.0.0.6"},
        {"timestamp": base_time + 40, "source": "windows", "event_id": 4688, "user": "bob",   "host": "wkstn-2", "process": "winword.exe",    "ip": "10.0.0.6"},
        # Mimikatz IOC
        {"timestamp": base_time + 50, "source": "windows", "event_id": 4688, "user": "bob",   "host": "wkstn-2", "process": "mimikatz.exe",   "ip": "10.0.0.6"},
        # Correlated cluster
        {"timestamp": base_time + 60, "source": "windows", "event_id": 4688, "user": "bob",   "host": "wkstn-2", "process": "powershell.exe", "ip": "10.0.0.6"},
        {"timestamp": base_time + 65, "source": "windows", "event_id": 4688, "user": "bob",   "host": "wkstn-2", "process": "cmd.exe",        "ip": "10.0.0.6"},
        # More normal records to reach 10+
        {"timestamp": base_time + 100, "source": "windows", "event_id": 4688, "user": "alice", "host": "wkstn-1", "process": "notepad.exe",   "ip": "10.0.0.5"},
        {"timestamp": base_time + 110, "source": "windows", "event_id": 4688, "user": "alice", "host": "wkstn-1", "process": "calc.exe",      "ip": "10.0.0.5"},
        {"timestamp": base_time + 120, "source": "windows", "event_id": 4688, "user": "alice", "host": "wkstn-1", "process": "svchost.exe",   "ip": "10.0.0.5"},
        # ML anomaly candidate
        {"timestamp": base_time + 10000, "source": "windows", "event_id": 4625, "user": "ANON", "host": "wkstn-99", "process": "unknown.exe", "status": "FAILURE"},
    ]

    file_content = "".join(json.dumps(r) + "\n" for r in evidence_data)

    files = {"file": ("synthetic.json", io.BytesIO(file_content.encode()), "application/json")}
    data = {"investigation_id": inv_id, "allow_duplicates": "true"}
    import_res = app_client.post("/api/v1/evidence/import", data=data, files=files)
    assert import_res.status_code == 201
    source_id = import_res.json()["source_id"]

    # Normalize
    norm_res = app_client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
    assert norm_res.status_code == 200
    assert norm_res.json()["normalized_records"] == len(evidence_data)

    # Detection
    det_res = app_client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules")
    assert det_res.status_code == 200

    findings_res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}")
    findings = findings_res.json()["items"]

    has_mimikatz = any(
        "mimikatz" in str(f["rule_id"]).lower() or "mimikatz" in str(f["description"]).lower()
        for f in findings
    )
    assert has_mimikatz, "Case B Failed: Mimikatz did not produce a finding"

    svchost_finding = next(
        (f for f in findings
         if "svchost" in str(f).lower() and "mimikatz" in str(f["rule_id"]).lower()),
        None
    )
    assert not svchost_finding, "Case C Failed: Harmless record triggered wrong rule"

    # ML
    ml_res = app_client.post(f"/api/v1/ml/sources/{source_id}/analyze")
    assert ml_res.status_code == 200

    ml_findings_res = app_client.get(
        f"/api/v1/detection/findings?investigation_id={inv_id}&finding_type=ML_ANOMALY"
    )
    ml_findings = ml_findings_res.json()["items"]

    # Correlation
    corr_res = app_client.post(f"/api/v1/correlation/sources/{source_id}/analyze")
    assert corr_res.status_code == 200

    rels_res = app_client.get(f"/api/v1/correlation/relationships?investigation_id={inv_id}")
    relationships = rels_res.json()["items"]
    assert len(relationships) > 0, "Case D Failed: No relationships synthesized"

    bob_rels = [
        r for r in relationships
        if any(
            s["type"] in ("SAME_USER", "PROCESS_FILE", "SAME_DEVICE")
            for s in r["context_attributes"].get("signals", [])
        )
    ]
    assert len(bob_rels) > 0, "Case D Failed: Expected correlations not found"

    # Activities
    act_res = app_client.post(f"/api/v1/activities/sources/{source_id}/form")
    assert act_res.status_code == 200

    acts_res = app_client.get(f"/api/v1/activities?investigation_id={inv_id}")
    activities = acts_res.json()["items"]
    assert len(activities) > 0, "Case E Failed: No activities formed"

    # Prioritization
    prio_art_res = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")
    assert prio_art_res.status_code == 200

    prio_act_res = app_client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")
    assert prio_act_res.status_code == 200

    prio_results = app_client.get(
        f"/api/v1/prioritization/results?investigation_id={inv_id}"
    ).json()["items"]
    assert len(prio_results) > 0, "Case F Failed: Prioritization did not return results"

    with open(tmp_path / "s12_test_results.json", "w") as f:
        json.dump({
            "findings":       findings,
            "ml_findings":    ml_findings,
            "relationships":  relationships,
            "activities":     activities,
            "prioritization": prio_results,
        }, f, indent=2)
