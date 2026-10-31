"""
Regression tests for corrected detection-rule semantics.

These tests validate the MEANING of each rule — not dataset-specific counts.
They are deliberately schema-driven and do not hardcode values from any
particular evidence file.

Corrections under test:
  RULE-PROC-001 : description no longer claims encoded/unconstrained execution.
                  Rule still fires on process_name == powershell.exe (case-insensitive).
  RULE-AUTH-SEQ-001 : sequence now requires event_type == AUTH_LOGIN for BOTH
                       the failed AND the successful step, preventing non-auth
                       events (e.g. PROCESS_CREATE with status=FAILURE/SUCCESS)
                       from triggering the brute-force finding.
"""
import io
import uuid
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    from app.core.rate_limit import analysis_rate_limiter
    analysis_rate_limiter.reset()
    yield


def _setup(client, csv_bytes: bytes):
    """Create a fresh investigation, import, and normalize the given CSV bytes."""
    r = client.post(
        "/api/v1/investigations",
        json={"title": "SemTest", "case_number": f"SEM-{uuid.uuid4().hex[:6]}"},
    )
    assert r.status_code == 201, r.text
    inv_id = r.json()["id"]

    r2 = client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("test.csv", io.BytesIO(csv_bytes), "text/csv")},
    )
    assert r2.status_code in (200, 201), r2.text
    source_id = r2.json()["source_id"]

    r3 = client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
    assert r3.status_code == 200, r3.text
    return inv_id, source_id


def _run_detection(client, source_id):
    r = client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules")
    assert r.status_code == 200, r.text
    return r.json()


def _findings(client, inv_id):
    r = client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&limit=100")
    assert r.status_code == 200, r.text
    return r.json()["items"]


# ── RULE-PROC-001 ─────────────────────────────────────────────────────────────

class TestRuleProc001:
    """RULE-PROC-001: PowerShell execution — process_name == powershell.exe."""

    def test_fires_on_powershell_process(self, app_client):
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,powershell.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        result = _run_detection(app_client, sid)
        assert result["findings_created"] >= 1
        findings = _findings(app_client, inv_id)
        proc_findings = [f for f in findings if "RULE-PROC-001" in f.get("rule_id", "")]
        assert len(proc_findings) >= 1, "Expected RULE-PROC-001 to fire on powershell.exe"

    def test_fires_case_insensitive(self, app_client):
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,PowerShell.EXE,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        result = _run_detection(app_client, sid)
        assert result["findings_created"] >= 1

    def test_does_not_fire_on_unrelated_process(self, app_client):
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,notepad.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        proc_findings = [f for f in findings if "RULE-PROC-001" in f.get("rule_id", "")]
        assert len(proc_findings) == 0

    def test_description_does_not_claim_encoding(self, app_client):
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,powershell.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        proc_findings = [f for f in findings if "RULE-PROC-001" in f.get("rule_id", "")]
        assert len(proc_findings) >= 1
        desc = proc_findings[0]["description"].lower()
        assert "encoded" not in desc, "Description must not claim encoded execution"
        assert "unconstrained" not in desc, "Description must not claim unconstrained execution"


# ── RULE-AUTH-SEQ-001 ─────────────────────────────────────────────────────────

class TestRuleAuthSeq001:
    """RULE-AUTH-SEQ-001: Brute-force pattern — requires AUTH_LOGIN event type."""

    def test_fires_on_auth_login_failure_then_success(self, app_client):
        csv = (
            b"timestamp,event_type,user_id,status\n"
            b"2024-01-01T10:00:00Z,auth_login,alice,FAILURE\n"
            b"2024-01-01T10:01:00Z,auth_login,alice,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) >= 1, "Expected RULE-AUTH-SEQ-001 on AUTH_LOGIN failure\u2192success"

    def test_does_not_fire_on_non_auth_status_sequence(self, app_client):
        csv = (
            b"timestamp,event_type,user_id,process_name,status\n"
            b"2024-01-01T10:00:00Z,process_create,alice,cmd.exe,FAILURE\n"
            b"2024-01-01T10:01:00Z,process_create,alice,cmd.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) == 0, "RULE-AUTH-SEQ-001 must NOT fire on process_create"

    def test_does_not_fire_on_auth_login_success_only(self, app_client):
        csv = (
            b"timestamp,event_type,user_id,status\n"
            b"2024-01-01T10:00:00Z,auth_login,bob,SUCCESS\n"
            b"2024-01-01T10:01:00Z,auth_login,bob,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) == 0, "Rule must not fire without a prior failure step"

    def test_does_not_fire_outside_time_window(self, app_client):
        csv = (
            b"timestamp,event_type,user_id,status\n"
            b"2024-01-01T10:00:00Z,auth_login,carol,FAILURE\n"
            b"2024-01-01T10:10:00Z,auth_login,carol,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) == 0, "Rule must not fire when events exceed max_span_seconds"

    def test_respects_user_grouping(self, app_client):
        csv = (
            b"timestamp,event_type,user_id,status\n"
            b"2024-01-01T10:00:00Z,auth_login,userA,FAILURE\n"
            b"2024-01-01T10:01:00Z,auth_login,userB,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) == 0, "Rule must not match across different users"

    def test_mixed_event_types_does_not_trigger_on_process_status(self, app_client):
        csv = (
            b"timestamp,event_type,user_id,process_name,status\n"
            b"2024-01-01T10:00:00Z,process_create,dave,cmd.exe,FAILURE\n"
            b"2024-01-01T10:01:00Z,auth_login,dave,,FAILURE\n"
            b"2024-01-01T10:02:00Z,process_create,dave,notepad.exe,SUCCESS\n"
            b"2024-01-01T10:03:00Z,auth_login,dave,,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) >= 1, \
            "Rule must fire on auth_login failure\u2192success even when non-auth events are interleaved"


# ── RULE-PROC-002 ─────────────────────────────────────────────────────────────

class TestRuleProc002:
    def test_fires_on_mimikatz_process(self, app_client):
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,mimikatz.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        mimi_findings = [f for f in findings if "RULE-PROC-002" in f.get("rule_id", "")]
        assert len(mimi_findings) >= 1

    def test_does_not_fire_on_unrelated_process(self, app_client):
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,explorer.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        mimi_findings = [f for f in findings if "RULE-PROC-002" in f.get("rule_id", "")]
        assert len(mimi_findings) == 0


# ── IOC-IP-001 ────────────────────────────────────────────────────────────────

class TestIocIp001:
    def test_fires_on_matching_ip(self, app_client):
        csv = (
            b"timestamp,event_type,ip_address,status\n"
            b"2024-01-01T09:00:00Z,network_connect,198.51.100.10,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        ioc_findings = [f for f in findings if "IOC-IP-001" in f.get("rule_id", "")]
        assert len(ioc_findings) >= 1

    def test_does_not_fire_on_benign_ip(self, app_client):
        csv = (
            b"timestamp,event_type,ip_address,status\n"
            b"2024-01-01T09:00:00Z,network_connect,10.0.0.1,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        ioc_findings = [f for f in findings if "IOC-IP-001" in f.get("rule_id", "")]
        assert len(ioc_findings) == 0


# ── FINDING-TO-EVIDENCE TRACEABILITY ─────────────────────────────────────────

class TestFindingEvidenceTraceability:
    def test_single_event_finding_has_evidence_ids_in_list_and_detail(self, app_client):
        """Verify that single-event detections link to their exact supporting evidence item."""
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,mimikatz.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        mimi = next(f for f in findings if "RULE-PROC-002" in f.get("rule_id", ""))

        # 1. Verify list_findings returns evidence_ids with 1 item
        assert "evidence_ids" in mimi
        assert len(mimi["evidence_ids"]) == 1
        evd_id = mimi["evidence_ids"][0]

        # 2. Verify get_finding_detail returns the same evidence_ids
        detail_res = app_client.get(f"/api/v1/detection/findings/{mimi['id']}")
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert detail["evidence_ids"] == [evd_id]

        # 3. Verify the referenced evidence item actually exists and matches
        evd_res = app_client.get(f"/api/v1/evidence/{evd_id}")
        assert evd_res.status_code == 200
        evd = evd_res.json()
        assert evd["process_name"] == "mimikatz.exe"

    def test_sequence_rule_finding_links_all_chain_evidence_ids(self, app_client):
        """Verify that multi-event sequence rules link to all events in the chain."""
        csv = (
            b"timestamp,event_type,user_id,status\n"
            b"2024-01-01T10:00:00Z,auth_login,alice,FAILURE\n"
            b"2024-01-01T10:01:00Z,auth_login,alice,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, csv)
        _run_detection(app_client, sid)
        findings = _findings(app_client, inv_id)
        auth_seq = next(f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", ""))

        assert "evidence_ids" in auth_seq
        # Must link to both failure and success evidence records
        assert len(auth_seq["evidence_ids"]) == 2

        # Check detail endpoint
        detail_res = app_client.get(f"/api/v1/detection/findings/{auth_seq['id']}")
        assert detail_res.status_code == 200
        assert len(detail_res.json()["evidence_ids"]) == 2

    def test_finding_without_associations_returns_empty_list(self, app_client):
        """Verify that findings without associated evidence return an empty list, not null."""
        # Provision an investigation and insert a finding directly with no associations
        r = app_client.post(
            "/api/v1/investigations",
            json={"title": "NoAssocTest", "case_number": f"NOA-{uuid.uuid4().hex[:6]}"},
        )
        inv_id = r.json()["id"]

        from app.database.session import SessionLocal
        from app.models.finding import Finding

        with SessionLocal() as db:
            standalone = Finding(
                id=uuid.uuid4(),
                investigation_id=uuid.UUID(inv_id),
                finding_type="RULE_MATCH",
                rule_id="MANUAL-001",
                severity_score=0.5,
                description="Manual finding without evidence associations",
            )
            db.add(standalone)
            db.commit()
            standalone_id = str(standalone.id)

        # In list endpoint
        findings = _findings(app_client, inv_id)
        assert len(findings) == 1
        assert findings[0]["evidence_ids"] == []

        # In detail endpoint
        detail_res = app_client.get(f"/api/v1/detection/findings/{standalone_id}")
        assert detail_res.status_code == 200
        assert detail_res.json()["evidence_ids"] == []

    def test_finding_detail_not_found(self, app_client):
        """Verify 404 on nonexistent finding ID."""
        fake_id = uuid.uuid4()
        r = app_client.get(f"/api/v1/detection/findings/{fake_id}")
        assert r.status_code == 404
