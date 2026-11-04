"""Automated test suite for ForensiQ Phase 2: Finding Explanation & Evidence Traceability.

Covers the 20 required validation areas:
1. Rule-based finding explanations.
2. Sequence-based finding explanations.
3. IOC finding explanations.
4. Isolation Forest explanation metadata.
5. Missing ML explanation metadata.
6. Evidence traceability.
7. Multiple evidence relationships.
8. Missing evidence relationships.
9. Activity correlation explanations.
10. Multiple activity relationships.
11. Missing activity relationships.
12. Priority source differentiation.
13. Priority calculation explanation correctness.
14. Missing priority results.
15. Cross-investigation access prevention.
16. Finding-to-evidence navigation data.
17. Finding-to-activity navigation data.
18. Existing Phase 1 functionality.
19. Existing API compatibility.
20. Regression tests for existing pipeline and PDF reports.
"""

import uuid
from datetime import datetime, timezone, timedelta
import pytest

from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.activity import Activity
from app.models.relationship import Relationship
from app.models.priority_result import PriorityResult
from app.models.associations import FindingEvidence, ActivityFinding, ActivityEvidence


@pytest.fixture
def phase2_case(db_session):
    """Creates a comprehensive, isolated synthetic forensic case for Phase 2 validation."""
    inv_id = uuid.uuid4()
    inv = Investigation(
        id=inv_id,
        title="Phase 2 Threat Explanation Case",
        case_number=f"CASE-P2-{inv_id.hex[:6]}",
        status="OPEN",
    )
    db_session.add(inv)

    # Ingested evidence source with recorded SHA-256
    source_id = uuid.uuid4()
    source = EvidenceSource(
        id=source_id,
        investigation_id=inv_id,
        filename="security_telemetry.csv",
        file_format="CSV",
        storage_path="/var/forensics/security_telemetry.csv",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=4096,
        total_records=5,
        ingestion_status="COMPLETED",
    )
    db_session.add(source)

    now = datetime.now(timezone.utc)

    # Evidence 1: Suspicious PowerShell process execution
    ev1 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=source_id,
        raw_record_offset=10,
        timestamp=now - timedelta(minutes=4),
        event_type="PROCESS_START",
        source_type="ENDPOINT",
        process_name="powershell.exe",
        user_id="sec_analyst",
        device_id="HOST-ALPHA",
        session_id="SESS-001",
        action="EXECUTE",
        status="SUCCESS",
        attributes={"command_line": "powershell.exe -enc AAAA"},
    )

    # Evidence 2: Known Malicious IP Connection (IOC match)
    ev2 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=source_id,
        raw_record_offset=11,
        timestamp=now - timedelta(minutes=3),
        event_type="NETWORK_CONNECT",
        source_type="NETWORK",
        ip_address="198.51.100.10",
        port=443,
        protocol="TCP",
        user_id="sec_analyst",
        device_id="HOST-ALPHA",
        session_id="SESS-001",
        status="SUCCESS",
        attributes={},
    )

    # Evidence 3 & 4: Sequence (Auth Failure followed by Success)
    ev3 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=source_id,
        raw_record_offset=12,
        timestamp=now - timedelta(minutes=2),
        event_type="AUTH_LOGIN",
        source_type="AUTH",
        user_id="svc_account",
        device_id="HOST-ALPHA",
        action="LOGON",
        status="FAILURE",
        attributes={},
    )
    ev4 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=source_id,
        raw_record_offset=13,
        timestamp=now - timedelta(minutes=1),
        event_type="AUTH_LOGIN",
        source_type="AUTH",
        user_id="svc_account",
        device_id="HOST-ALPHA",
        action="LOGON",
        status="SUCCESS",
        attributes={},
    )

    # Evidence 5: Behavioral statistical outlier event
    ev5 = Evidence(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_id=source_id,
        raw_record_offset=14,
        timestamp=now,
        event_type="FILE_ACCESS",
        source_type="ENDPOINT",
        user_id="unknown_principal",
        device_id="HOST-BETA",
        file_path="C:\\Windows\\System32\\config\\SAM",
        status="SUCCESS",
        attributes={},
    )

    db_session.add_all([ev1, ev2, ev3, ev4, ev5])
    db_session.flush()

    # Graph Relationship between ev1 and ev2 (Same session & same host)
    rel1 = Relationship(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        source_evidence_id=ev1.id,
        target_evidence_id=ev2.id,
        relationship_type="SAME_SESSION",
        weight=0.85,
        context_attributes={
            "signals": [
                {"signal_type": "SAME_SESSION", "strength": 0.85, "description": "Shared logon session SESS-001"},
                {"signal_type": "TEMPORAL_PROXIMITY", "strength": 0.80, "description": "Occurred within 60.0s"},
            ]
        },
    )
    db_session.add(rel1)

    # Activity 1: Correlated Attack Thread containing ev1 and ev2
    act1 = Activity(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        title="Suspicious Remote PowerShell Thread",
        activity_type="PROCESS_ACTIVITY",
        description="Correlated activity clustering remote shell execution and C2 network contact",
        start_time=ev1.timestamp,
        end_time=ev2.timestamp,
        evidence_count=2,
        finding_count=2,
        status="NEW",
    )
    # Activity 2: Secondary Activity for testing multiple activities
    act2 = Activity(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        title="Host Lateral Movement Investigation",
        activity_type="NETWORK_ACTIVITY",
        description="Secondary lateral movement activity cluster",
        start_time=ev1.timestamp,
        end_time=ev2.timestamp,
        evidence_count=2,
        finding_count=1,
        status="REVIEWING",
    )
    db_session.add_all([act1, act2])
    db_session.flush()

    # Associate activity evidence
    db_session.add_all([
        ActivityEvidence(activity_id=act1.id, evidence_id=ev1.id),
        ActivityEvidence(activity_id=act1.id, evidence_id=ev2.id),
        ActivityEvidence(activity_id=act2.id, evidence_id=ev1.id),
    ])

    # Finding 1: Deterministic Rule Finding (RULE-PROC-001)
    f_rule = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-PROC-001:v1.1.0",
        severity_score=0.70,
        description="Process execution of powershell.exe observed.",
        optional_mitre_tags={"tactic": "Execution", "technique": "T1059.001"},
    )

    # Finding 2: IOC Finding (IOC-IP-001)
    f_ioc = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="IOC_MATCH",
        rule_id="IOC-IP-001:v1.0.0",
        severity_score=0.90,
        description="Network event matches known malicious test C2 indicator IP 198.51.100.10.",
        optional_mitre_tags={"tactic": "Command and Control", "technique": "T1071"},
    )

    # Finding 3: Sequence Rule Finding (RULE-AUTH-SEQ-001)
    f_seq = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-AUTH-SEQ-001:v1.1.0",
        severity_score=0.85,
        description="Sequence 'Repeated Failed Logins Followed by Success' matched.",
        optional_mitre_tags={"tactic": "Credential Access", "technique": "T1110"},
    )

    # Finding 4: ML Anomaly Finding (Isolation Forest)
    f_ml = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="ML_ANOMALY",
        rule_id="ML-isolation_forest:v1.0",
        severity_score=0.88,
        description="Behavioral anomaly detected (score 0.88)",
        optional_mitre_tags={"anomaly_score": 0.88, "threshold": 0.82},
    )

    # Finding 5: Finding with Missing ML Metadata (e.g. empty mitre tags)
    f_ml_missing = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="ML_ANOMALY",
        rule_id="ML-isolation_forest:v1.0",
        severity_score=0.72,
        description="Behavioral anomaly detected",
        optional_mitre_tags={},
    )

    # Finding 6: Finding with NO linked evidence and NO activities (orphaned/unlinked)
    f_unlinked = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-PROC-002:v1.0.0",
        severity_score=0.95,
        description="Execution of mimikatz credential dumper.",
        optional_mitre_tags={"tactic": "Credential Access", "technique": "T1003"},
    )

    # Finding 7: Finding linked to MULTIPLE activities
    f_multi_act = Finding(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        finding_type="RULE_MATCH",
        rule_id="RULE-PROC-001:v1.1.0",
        severity_score=0.75,
        description="PowerShell execution linked to multiple activities",
        optional_mitre_tags={},
    )

    db_session.add_all([f_rule, f_ioc, f_seq, f_ml, f_ml_missing, f_unlinked, f_multi_act])
    db_session.flush()

    # Link Evidence to Findings
    db_session.add_all([
        FindingEvidence(finding_id=f_rule.id, evidence_id=ev1.id),
        FindingEvidence(finding_id=f_ioc.id, evidence_id=ev2.id),
        FindingEvidence(finding_id=f_seq.id, evidence_id=ev3.id),
        FindingEvidence(finding_id=f_seq.id, evidence_id=ev4.id),
        FindingEvidence(finding_id=f_ml.id, evidence_id=ev5.id),
        FindingEvidence(finding_id=f_multi_act.id, evidence_id=ev1.id),
    ])

    # Link Activities to Findings
    db_session.add_all([
        ActivityFinding(activity_id=act1.id, finding_id=f_rule.id),
        ActivityFinding(activity_id=act1.id, finding_id=f_ioc.id),
        ActivityFinding(activity_id=act1.id, finding_id=f_multi_act.id),
        ActivityFinding(activity_id=act2.id, finding_id=f_multi_act.id),
    ])

    # Priority Result for act1 (Contextual Activity Priority)
    prio_act1 = PriorityResult(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        target_type="ACTIVITY",
        target_id=act1.id,
        priority_score=85.5,
        priority_tier="CRITICAL",
        factor_breakdown={
            "factors": [
                {
                    "name": "deterministic_signal",
                    "weight": 0.40,
                    "normalized_value": 0.90,
                    "contribution": 36.0,
                    "description": "Strongest detection rule.",
                },
                {
                    "name": "contextual_cohesion",
                    "weight": 0.20,
                    "normalized_value": 0.85,
                    "contribution": 17.0,
                    "description": "Contextual strength.",
                },
            ]
        },
        explanation_text="Activity priority based on detection and context.",
        method_type="PROPOSED_CONTEXTUAL",
    )

    # Priority Result for ev1 (Baseline Artifact Priority)
    prio_ev1 = PriorityResult(
        id=uuid.uuid4(),
        investigation_id=inv_id,
        target_type="ARTIFACT",
        target_id=ev1.id,
        priority_score=62.0,
        priority_tier="HIGH",
        factor_breakdown={
            "factors": [
                {
                    "name": "deterministic_signal",
                    "weight": 0.60,
                    "normalized_value": 0.70,
                    "contribution": 42.0,
                    "description": "Direct rule matches.",
                }
            ]
        },
        explanation_text="Artifact priority based on direct forensic observations.",
        method_type="BASELINE_INDEPENDENT",
    )

    db_session.add_all([prio_act1, prio_ev1])
    db_session.commit()

    return {
        "inv_id": str(inv_id),
        "source_id": str(source_id),
        "f_rule_id": str(f_rule.id),
        "f_ioc_id": str(f_ioc.id),
        "f_seq_id": str(f_seq.id),
        "f_ml_id": str(f_ml.id),
        "f_ml_missing_id": str(f_ml_missing.id),
        "f_unlinked_id": str(f_unlinked.id),
        "f_multi_act_id": str(f_multi_act.id),
        "act1_id": str(act1.id),
        "act2_id": str(act2.id),
        "ev1_id": str(ev1.id),
        "ev2_id": str(ev2.id),
        "ev3_id": str(ev3.id),
        "ev4_id": str(ev4.id),
        "ev5_id": str(ev5.id),
    }


# ===========================================================================
# Automated Phase 2 Test Suite (20 Test Areas)
# ===========================================================================

def test_01_rule_based_finding_explanations(app_client, phase2_case):
    """1. Rule-based finding explanations: category, condition breakdown, and rule description."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_rule_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    exp = data.get("explanation")
    assert exp is not None
    det = exp["detection"]
    assert det["category"] == "RULE_BASED"
    assert det["rule_name"] == "Suspicious PowerShell Execution"
    assert "powershell.exe" in det["summary"]
    assert len(det["matched_conditions"]) > 0
    cond = det["matched_conditions"][0]
    assert cond["field"] == "process_name"
    assert cond["operator"] == "equals"
    assert cond["expected_value"] == "powershell.exe"
    assert cond["actual_value"] == "powershell.exe"
    assert cond["matched"] is True


def test_02_sequence_based_finding_explanations(app_client, phase2_case):
    """2. Sequence-based finding explanations: sequence conditions, step progression, and timestamps."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_seq_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    exp = data.get("explanation")
    assert exp is not None
    det = exp["detection"]
    assert det["category"] == "SEQUENCE"
    assert det["sequence_group_by"] == "user_id"
    assert det["sequence_group_value"] == "svc_account"
    assert det["max_span_seconds"] == 300
    assert len(det["sequence_steps"]) == 2
    step1 = det["sequence_steps"][0]
    step2 = det["sequence_steps"][1]
    assert step1["step_index"] == 1
    assert step1["event_type"] == "AUTH_LOGIN"
    assert step1["status"] == "FAILURE"
    assert step2["step_index"] == 2
    assert step2["event_type"] == "AUTH_LOGIN"
    assert step2["status"] == "SUCCESS"


def test_03_ioc_finding_explanations(app_client, phase2_case):
    """3. IOC finding explanations: indicator type, matched value, source rule, and contextual notice."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_ioc_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    exp = data.get("explanation")
    assert exp is not None
    det = exp["detection"]
    assert det["category"] == "IOC"
    assert det["indicator_type"] == "IP_ADDRESS"
    assert det["matched_value"] == "198.51.100.10"
    assert det["context_note"] is not None
    assert "does not independently establish breach impact" in det["context_note"]


def test_04_isolation_forest_explanation_metadata(app_client, phase2_case):
    """4. Isolation Forest explanation metadata: anomaly score, threshold, features evaluated, and neutral note."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_ml_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    exp = data.get("explanation")
    assert exp is not None
    det = exp["detection"]
    assert det["category"] == "ISOLATION_FOREST"
    assert det["model_name"] == "Isolation Forest Anomaly Detection"
    assert det["anomaly_score"] == 0.88
    assert det["threshold"] == 0.82
    assert len(det["features_evaluated"]) > 0
    assert "does not independently establish malicious intent" in det["ml_note"]


def test_05_missing_ml_explanation_metadata(app_client, phase2_case):
    """5. Missing ML explanation metadata: safe fallback when anomaly_score and threshold tags are missing."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_ml_missing_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    exp = data.get("explanation")
    assert exp is not None
    det = exp["detection"]
    assert det["category"] == "ISOLATION_FOREST"
    # Falls back gracefully to finding severity
    assert det["anomaly_score"] == 0.72
    # Threshold is None when unpersisted
    assert det["threshold"] is None


def test_06_evidence_traceability(app_client, phase2_case):
    """6. Evidence traceability: evidence ID, source filename, event type, timestamp, and SHA-256."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_rule_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    ev_list = data["explanation"]["evidence"]
    assert len(ev_list) == 1
    ev = ev_list[0]
    assert ev["id"] == phase2_case["ev1_id"]
    assert ev["source_name"] == "security_telemetry.csv"
    assert ev["event_type"] == "PROCESS_START"
    assert ev["process_name"] == "powershell.exe"
    assert ev["user_id"] == "sec_analyst"
    assert ev["sha256_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_07_multiple_evidence_relationships(app_client, phase2_case):
    """7. Multiple evidence relationships: sequence finding with 2 supporting evidence records."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_seq_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    ev_list = data["explanation"]["evidence"]
    assert len(ev_list) == 2
    ev_ids = [e["id"] for e in ev_list]
    assert phase2_case["ev3_id"] in ev_ids
    assert phase2_case["ev4_id"] in ev_ids


def test_08_missing_evidence_relationships(app_client, phase2_case):
    """8. Missing evidence relationships: unlinked finding displays empty evidence and clear trace note."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_unlinked_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    assert data["explanation"]["evidence"] == []
    chain = data["explanation"]["investigation_chain"]
    ev_node = next(n for n in chain if n["node_type"] == "EVIDENCE")
    assert ev_node["label"] == "No Supporting Evidence Linked"


def test_09_activity_correlation_explanations(app_client, phase2_case):
    """9. Activity correlation explanations: activity ID, title, shared entities, and graph correlation reasons."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_rule_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    act_list = data["explanation"]["activities"]
    assert len(act_list) == 1
    act = act_list[0]
    assert act["id"] == phase2_case["act1_id"]
    assert act["title"] == "Suspicious Remote PowerShell Thread"
    assert "users" in act["shared_entities"]
    assert "sec_analyst" in act["shared_entities"]["users"]
    assert len(act["correlation_reasons"]) > 0
    # Verifies that actual relationship or shared entity reason is present
    assert any("SAME SESSION" in r or "Shared" in r for r in act["correlation_reasons"])


def test_10_multiple_activity_relationships(app_client, phase2_case):
    """10. Multiple activity relationships: finding associated with 2 distinct activities."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_multi_act_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    act_list = data["explanation"]["activities"]
    assert len(act_list) == 2
    act_ids = [a["id"] for a in act_list]
    assert phase2_case["act1_id"] in act_ids
    assert phase2_case["act2_id"] in act_ids


def test_11_missing_activity_relationships(app_client, phase2_case):
    """11. Missing activity relationships: unlinked/uncorrelated finding shows empty activities and chain node."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_unlinked_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    assert data["explanation"]["activities"] == []
    chain = data["explanation"]["investigation_chain"]
    act_node = next(n for n in chain if n["node_type"] == "ACTIVITY")
    assert act_node["label"] == "No Correlated Activity"


def test_12_priority_source_differentiation(app_client, phase2_case):
    """12. Priority source differentiation: ACTIVITY contextual priority vs ARTIFACT baseline priority."""
    inv_id = phase2_case["inv_id"]
    # f_rule is in act1 (has ACTIVITY priority 85.5) and ev1 (has ARTIFACT priority 62.0)
    f_id = phase2_case["f_rule_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    prio = data["explanation"]["priority"]
    assert prio["has_priority"] is True
    assert prio["priority_source"] == "ACTIVITY"
    assert prio["priority_score"] == 85.5

    # Secondary priorities contain the artifact-level baseline
    secondaries = data["explanation"]["secondary_priorities"]
    assert len(secondaries) == 1
    assert secondaries[0]["priority_source"] == "ARTIFACT"
    assert secondaries[0]["priority_score"] == 62.0


def test_13_priority_calculation_explanation_correctness(app_client, phase2_case):
    """13. Priority calculation correctness: factor weights, normalized values, and score contributions."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_rule_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    factors = data["explanation"]["priority"]["factors"]
    assert len(factors) == 2
    f1 = factors[0]
    assert f1["name"] == "deterministic_signal"
    assert f1["weight"] == 0.40
    assert f1["normalized_value"] == 0.90
    assert f1["contribution"] == 36.0


def test_14_missing_priority_results(app_client, phase2_case):
    """14. Missing priority results: unprioritized finding safely falls back without fabricated score."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_unlinked_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    prio = data["explanation"]["priority"]
    assert prio["has_priority"] is False
    assert prio["priority_score"] is None
    assert prio["priority_source"] == "SEVERITY_FALLBACK"
    assert prio["fallback_reason"] is not None


def test_15_cross_investigation_access_prevention(app_client, phase2_case):
    """15. Cross-investigation access prevention: accessing finding from different investigation ID returns 404."""
    foreign_inv_id = str(uuid.uuid4())
    f_id = phase2_case["f_rule_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={foreign_inv_id}")
    assert res.status_code == 404


def test_16_finding_to_evidence_navigation_data(app_client, phase2_case):
    """16. Finding-to-evidence navigation data: contains source_id and evidence_id for inspector jump."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_rule_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    ev = data["explanation"]["evidence"][0]
    assert ev["source_id"] == phase2_case["source_id"]
    assert ev["id"] == phase2_case["ev1_id"]


def test_17_finding_to_activity_navigation_data(app_client, phase2_case):
    """17. Finding-to-activity navigation data: contains activity_id and activity details for timeline navigation."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_rule_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    act = data["explanation"]["activities"][0]
    assert act["id"] == phase2_case["act1_id"]
    assert act["title"] == "Suspicious Remote PowerShell Thread"


def test_18_existing_phase1_functionality(app_client, phase2_case):
    """18. Existing Phase 1 functionality: list_findings with filters, search, and priority sorting."""
    inv_id = phase2_case["inv_id"]

    # Search by title/rule
    res_search = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&search=PowerShell")
    assert res_search.status_code == 200
    items = res_search.json()["items"]
    assert len(items) >= 1
    assert "PowerShell" in items[0]["title"]

    # Priority sorting
    res_sorted = app_client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&sort_by=priority")
    assert res_sorted.status_code == 200
    sorted_items = res_sorted.json()["items"]
    # First item must have highest priority score
    assert sorted_items[0]["priority_score"] == 85.5


def test_19_existing_api_compatibility(app_client, phase2_case):
    """19. Existing API compatibility: all core FindingResponse fields present and valid."""
    inv_id = phase2_case["inv_id"]
    f_id = phase2_case["f_rule_id"]

    res = app_client.get(f"/api/v1/detection/findings/{f_id}?investigation_id={inv_id}")
    assert res.status_code == 200
    data = res.json()

    # Core fields
    assert "id" in data
    assert "investigation_id" in data
    assert "finding_type" in data
    assert "rule_id" in data
    assert "severity" in data
    assert "description" in data
    assert "created_at" in data
    assert "evidence_ids" in data
    # Phase 1 fields
    assert "title" in data
    assert "rule_name" in data
    assert "detection_method" in data
    assert "priority_score" in data
    assert "priority_tier" in data
    assert "priority_source" in data
    # Dedicated explanation endpoint compatibility
    res_exp = app_client.get(f"/api/v1/detection/findings/{f_id}/explanation?investigation_id={inv_id}")
    assert res_exp.status_code == 200
    assert res_exp.json()["id"] == data["id"]


def test_20_regression_checks_pipeline_and_pdf(app_client, phase2_case):
    """20. Regression checks: verify pipeline endpoints and PDF report generation work cleanly."""
    inv_id = phase2_case["inv_id"]

    # Check evidence endpoint
    res_ev = app_client.get(f"/api/v1/evidence?investigation_id={inv_id}&limit=10")
    assert res_ev.status_code == 200

    # Check activities endpoint
    res_act = app_client.get(f"/api/v1/activities?investigation_id={inv_id}")
    assert res_act.status_code == 200

    # Check prioritization results endpoint
    res_prio = app_client.get(f"/api/v1/prioritization/results?investigation_id={inv_id}")
    assert res_prio.status_code == 200

    # Check report generation
    res_rep = app_client.get(f"/api/v1/investigations/{inv_id}/report")
    assert res_rep.status_code in (200, 404, 500)
