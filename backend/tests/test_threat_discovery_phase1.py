"""Automated test suite for Phase 1 Threat Discovery Interface.

Verifies:
1. Findings list retrieval.
2. Investigation-level isolation.
3. Priority sorting.
4. Search by finding ID and description.
5. Search by evidence ID.
6. Combined filters.
7. Empty findings.
8. Findings with missing optional metadata.
9. Findings with multiple evidence relationships.
10. Findings without activity relationships.
11. Existing API compatibility.
12. Regression checks for existing application functionality.
"""

import uuid
from datetime import datetime, timezone
import pytest
from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.activity import Activity
from app.models.priority_result import PriorityResult
from app.models.associations import FindingEvidence, ActivityFinding


@pytest.fixture
def sample_threat_case(db_session):
    """Creates an isolated synthetic test case with rich findings, evidence, activities, and priorities."""
    inv_id = uuid.uuid4()
    inv = Investigation(
        id=inv_id,
        title="Threat Discovery Test Case",
        case_number=f"CASE-THREAT-{inv_id.hex[:6]}",
        status="OPEN",
    )
    db_session.add(inv)

    source_id = uuid.uuid4()
    source = EvidenceSource(
        id=source_id,
        investigation_id=inv_id,
        filename="threat_sample.csv",
        file_format="CSV",
        storage_path="/tmp/threat_sample.csv",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=1024,
        total_records=3,
        ingestion_status="COMPLETED",
    )
    db_session.add(source)

    ev1 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=source_id,
        raw_record_offset=0,
        timestamp=datetime.now(timezone.utc),
        event_type="PROCESS_CREATE",
        source_type="ENDPOINT",
        process_name="powershell.exe",
        user_id="user_sec",
    )
    ev2 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=source_id,
        raw_record_offset=1,
        timestamp=datetime.now(timezone.utc),
        event_type="NETWORK_CONNECTION",
        source_type="NETWORK",
        ip_address="198.51.100.10",
        user_id="user_sec",
    )
    ev3 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=source_id,
        raw_record_offset=2,
        timestamp=datetime.now(timezone.utc),
        event_type="AUTH_LOGIN",
        source_type="AUTH",
        user_id="admin_user",
        status="FAILURE",
    )
    db_session.add_all([ev1, ev2, ev3])
    db_session.flush()

    # Activity
    act_id = uuid.uuid4()
    activity = Activity(
        id=act_id,
        investigation_id=inv_id,
        title="Suspicious Remote Execution Thread",
        activity_type="PROCESS_ACTIVITY",
        description="Correlated activity thread for execution",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        evidence_count=1,
        finding_count=1,
        status="NEW",
    )
    db_session.add(activity)
    db_session.flush()

    # Finding 1: Rule match with activity linkage & prioritized activity
    f1_id = uuid.uuid4()
    f1 = Finding(
        id=f1_id,
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-PROC-001:v1.1.0",
        severity_score=0.70,
        description="Process execution of powershell.exe observed.",
        optional_mitre_tags={"tactic": "Execution", "technique": "T1059.001"},
    )
    db_session.add(f1)
    db_session.flush()
    db_session.add(FindingEvidence(finding_id=f1_id, evidence_id=ev1.id))
    db_session.add(ActivityFinding(activity_id=act_id, finding_id=f1_id))

    # PriorityResult for Activity (which links to Finding 1)
    pr_act = PriorityResult(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        target_type="ACTIVITY",
        target_id=act_id,
        priority_score=85.0,
        priority_tier="CRITICAL",
        factor_breakdown={"factors": []},
        explanation_text="Critical contextual activity priority",
        method_type="PROPOSED_CONTEXTUAL",
    )
    db_session.add(pr_act)

    # Finding 2: IOC Match with multiple evidence records, artifact priority
    f2_id = uuid.uuid4()
    f2 = Finding(
        id=f2_id,
        investigation_id=inv_id,
        finding_type="IOC_MATCH",
        rule_id="IOC-IP-001:v1.0.0",
        severity_score=0.90,
        description="Network event matches known malicious test C2 indicator IP 198.51.100.10.",
        optional_mitre_tags={"tactic": "Command and Control", "technique": "T1071"},
    )
    db_session.add(f2)
    db_session.flush()
    db_session.add(FindingEvidence(finding_id=f2_id, evidence_id=ev2.id))
    db_session.add(FindingEvidence(finding_id=f2_id, evidence_id=ev3.id))

    # PriorityResult for Evidence 2 (Artifact Priority)
    pr_art = PriorityResult(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        target_type="ARTIFACT",
        target_id=ev2.id,
        priority_score=65.0,
        priority_tier="HIGH",
        factor_breakdown={"factors": []},
        explanation_text="High baseline evidence priority",
        method_type="BASELINE_INDEPENDENT",
    )
    db_session.add(pr_art)

    # Finding 3: ML Anomaly, no activity, no priority result
    f3_id = uuid.uuid4()
    f3 = Finding(
        id=f3_id,
        investigation_id=inv_id,
        finding_type="ML_ANOMALY",
        rule_id="ML-isolation_forest:v1.0",
        severity_score=0.45,
        description="Behavioral anomaly detected (score 0.45)",
        optional_mitre_tags={"anomaly_score": 0.45},
    )
    db_session.add(f3)
    db_session.flush()
    db_session.add(FindingEvidence(finding_id=f3_id, evidence_id=ev3.id))

    # Finding 4: Edge case: missing optional metadata (rule_id is None, mitre_tags empty)
    f4_id = uuid.uuid4()
    f4 = Finding(
        id=f4_id,
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id=None,
        severity_score=0.15,
        description="Generic low severity security signal.",
        optional_mitre_tags={},
    )
    db_session.add(f4)
    db_session.commit()

    return {
        "inv_id": str(inv_id),
        "f1_id": str(f1_id),
        "f2_id": str(f2_id),
        "f3_id": str(f3_id),
        "f4_id": str(f4_id),
        "ev1_id": str(ev1.id),
        "ev2_id": str(ev2.id),
        "ev3_id": str(ev3.id),
        "act_id": str(act_id),
    }


def test_01_findings_list_retrieval(app_client, sample_threat_case):
    """1. Findings list retrieval: verify endpoint returns 200 with rich threat metadata."""
    inv_id = sample_threat_case["inv_id"]
    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 4
    assert len(data["items"]) == 4

    # Verify first item has all required Phase 1 fields
    item = data["items"][0]
    assert "id" in item
    assert "title" in item
    assert item["title"] is not None
    assert "description" in item
    assert "severity" in item
    assert "detection_method" in item
    assert item["detection_method"] is not None
    assert "evidence_ids" in item
    assert "evidence_count" in item
    assert "activity_ids" in item
    assert "priority_score" in item
    assert "priority_tier" in item


def test_02_investigation_level_isolation(app_client, sample_threat_case):
    """2. Investigation-level isolation: verify case containment across queries."""
    inv_a = sample_threat_case["inv_id"]
    f1_id = sample_threat_case["f1_id"]

    # Create Case B
    inv_b_res = app_client.post(
        "/api/v1/investigations",
        json={"title": "Isolated Case B", "case_number": f"CASE-ISOL-{uuid.uuid4().hex[:6]}"},
    )
    assert inv_b_res.status_code == 201
    inv_b = inv_b_res.json()["id"]

    # Case B should return 0 findings
    res_b = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_b}")
    assert res_b.status_code == 200
    assert res_b.json()["total"] == 0

    # Finding 1 should return 404 when scoped to Case B
    res_detail_b = app_client.get(f"/api/v1/detection/findings/{f1_id}?investigation_id={inv_b}")
    assert res_detail_b.status_code == 404

    # Finding 1 should succeed when scoped to Case A
    res_detail_a = app_client.get(f"/api/v1/detection/findings/{f1_id}?investigation_id={inv_a}")
    assert res_detail_a.status_code == 200
    assert res_detail_a.json()["id"] == f1_id


def test_03_priority_sorting(app_client, sample_threat_case):
    """3. Priority sorting: highest-priority findings first with deterministic secondary sort and source separation."""
    inv_id = sample_threat_case["inv_id"]
    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&sort_by=priority")
    assert res.status_code == 200
    items = res.json()["items"]

    # 1. Finding 1 has Activity PriorityResult (85.0, CRITICAL, ACTIVITY)
    assert items[0]["id"] == sample_threat_case["f1_id"]
    assert items[0]["priority_tier"] == "CRITICAL"
    assert items[0]["priority_score"] == 85.0
    assert items[0]["priority_source"] == "ACTIVITY"

    # 2. Finding 2 has Artifact PriorityResult (65.0, HIGH, ARTIFACT)
    assert items[1]["id"] == sample_threat_case["f2_id"]
    assert items[1]["priority_tier"] == "HIGH"
    assert items[1]["priority_score"] == 65.0
    assert items[1]["priority_source"] == "ARTIFACT"

    # 3. Finding 3 has no PriorityResult: severity fallback (sev 0.45 -> MEDIUM, fallback)
    assert items[2]["id"] == sample_threat_case["f3_id"]
    assert items[2]["priority_score"] is None
    assert items[2]["priority_tier"] == "MEDIUM"
    assert items[2]["priority_source"] == "SEVERITY_FALLBACK"

    # 4. Finding 4 has no PriorityResult: severity fallback (sev 0.15 -> INFORMATIONAL, fallback)
    assert items[3]["id"] == sample_threat_case["f4_id"]
    assert items[3]["priority_score"] is None
    assert items[3]["priority_tier"] == "INFORMATIONAL"
    assert items[3]["priority_source"] == "SEVERITY_FALLBACK"

    # Verify prioritized items strictly precede unprioritized items
    assert items[0]["priority_score"] > items[1]["priority_score"]
    assert items[1]["priority_score"] is not None
    assert items[2]["priority_score"] is None
    assert items[3]["priority_score"] is None


def test_04_search_by_finding_id_and_description(app_client, sample_threat_case):
    """4. Search by finding ID and description: verify search query filtering."""
    inv_id = sample_threat_case["inv_id"]
    f1_id = sample_threat_case["f1_id"]

    # Search by exact finding ID
    res_id = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&search={f1_id}")
    assert res_id.status_code == 200
    items_id = res_id.json()["items"]
    assert len(items_id) == 1
    assert items_id[0]["id"] == f1_id

    # Search by keyword in description ("powershell")
    res_desc = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&search=powershell")
    assert res_desc.status_code == 200
    items_desc = res_desc.json()["items"]
    assert len(items_desc) >= 1
    assert any("powershell" in it["description"].lower() for it in items_desc)

    # Search by rule name ("PowerShell Execution")
    res_name = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&search=PowerShell+Execution")
    assert res_name.status_code == 200
    assert len(res_name.json()["items"]) >= 1


def test_05_search_by_evidence_id(app_client, sample_threat_case):
    """5. Search by evidence ID: finds analytical findings linked to a specific evidence record."""
    inv_id = sample_threat_case["inv_id"]
    ev2_id = sample_threat_case["ev2_id"]

    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&search={ev2_id}")
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == sample_threat_case["f2_id"]
    assert ev2_id in items[0]["evidence_ids"]


def test_06_combined_filters(app_client, sample_threat_case):
    """6. Combined filters: priority, detection method, and activity availability."""
    inv_id = sample_threat_case["inv_id"]

    # Rule-based + Activity linked
    res1 = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&detection_method=RULE&has_activity=true")
    assert res1.status_code == 200
    items1 = res1.json()["items"]
    assert len(items1) == 1
    assert items1[0]["id"] == sample_threat_case["f1_id"]

    # IOC match + Uncorrelated (no activity)
    res2 = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&detection_method=IOC&has_activity=false")
    assert res2.status_code == 200
    items2 = res2.json()["items"]
    assert len(items2) == 1
    assert items2[0]["id"] == sample_threat_case["f2_id"]

    # ML Anomaly
    res3 = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&detection_method=ML")
    assert res3.status_code == 200
    items3 = res3.json()["items"]
    assert len(items3) == 1
    assert items3[0]["id"] == sample_threat_case["f3_id"]


def test_07_empty_findings(app_client):
    """7. Empty findings: verify clean response for cases with zero findings."""
    inv_res = app_client.post(
        "/api/v1/investigations",
        json={"title": "Empty Test Case", "case_number": f"CASE-EMPTY-{uuid.uuid4().hex[:6]}"},
    )
    empty_inv_id = inv_res.json()["id"]

    res = app_client.get(f"/api/v1/detection/findings?investigation_id={empty_inv_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 0
    assert data["items"] == []
    assert data["has_more"] is False


def test_08_findings_with_missing_optional_metadata(app_client, sample_threat_case):
    """8. Findings with missing optional metadata: safe fallbacks for null rule_id or tags."""
    inv_id = sample_threat_case["inv_id"]
    f4_id = sample_threat_case["f4_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f4_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    item = res.json()
    assert item["rule_id"] is None
    # Title must not be None or empty
    assert item["title"] is not None
    assert len(item["title"]) > 0
    assert item["detection_method"] is not None
    assert item["mitre_tactic"] is None
    assert item["mitre_technique"] is None


def test_09_findings_with_multiple_evidence_relationships(app_client, sample_threat_case):
    """9. Findings with multiple evidence relationships: multi-evidence association count and IDs."""
    inv_id = sample_threat_case["inv_id"]
    f2_id = sample_threat_case["f2_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f2_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    item = res.json()
    assert item["evidence_count"] == 2
    assert len(item["evidence_ids"]) == 2
    assert sample_threat_case["ev2_id"] in item["evidence_ids"]
    assert sample_threat_case["ev3_id"] in item["evidence_ids"]


def test_10_findings_without_activity_relationships(app_client, sample_threat_case):
    """10. Findings without activity relationships: handle uncorrelated findings gracefully."""
    inv_id = sample_threat_case["inv_id"]
    f2_id = sample_threat_case["f2_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f2_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    item = res.json()
    assert item["activity_ids"] == []
    assert item["activity_id"] is None


def test_11_existing_api_compatibility(app_client, sample_threat_case):
    """11. Existing API compatibility: all original FindingResponse fields remain intact."""
    inv_id = sample_threat_case["inv_id"]
    res = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&limit=10")
    assert res.status_code == 200
    data = res.json()

    for item in data["items"]:
        # Original v1 fields
        assert "id" in item
        assert "investigation_id" in item
        assert "finding_type" in item
        assert "rule_id" in item
        assert "severity" in item
        assert "description" in item
        assert "mitre_tactic" in item
        assert "mitre_technique" in item
        assert "created_at" in item
        assert "evidence_ids" in item
        assert isinstance(item["evidence_ids"], list)


def test_12_regression_checks_existing_functionality(app_client, sample_threat_case):
    """12. Regression checks for existing application functionality."""
    inv_id = sample_threat_case["inv_id"]

    # 1. Investigation detail and summary
    summary_res = app_client.get(f"/api/v1/investigations/{inv_id}/summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["total_findings"] == 4

    # 2. Prioritization endpoints
    prio_res = app_client.get(f"/api/v1/prioritization/results?investigation_id={inv_id}")
    assert prio_res.status_code == 200

    # 3. Report generation endpoint
    report_res = app_client.get(f"/api/v1/investigations/{inv_id}/report")
    assert report_res.status_code == 200
    assert report_res.headers["content-type"] == "application/pdf"
    assert len(report_res.content) > 1000
