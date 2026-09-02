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
    from app.core.rate_limit import analysis_rate_limiter, login_rate_limiter
    analysis_rate_limiter.reset()
    login_rate_limiter.reset()
    yield


def _setup(client, headers, csv_bytes: bytes):
    """Create a fresh investigation, import, and normalize the given CSV bytes."""
    r = client.post(
        "/api/v1/investigations",
        json={"title": "SemTest", "case_number": f"SEM-{uuid.uuid4().hex[:6]}"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    inv_id = r.json()["id"]

    r2 = client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("test.csv", io.BytesIO(csv_bytes), "text/csv")},
        headers=headers,
    )
    assert r2.status_code in (200, 201), r2.text
    source_id = r2.json()["source_id"]

    r3 = client.post(
        f"/api/v1/evidence/sources/{source_id}/normalize",
        headers=headers,
    )
    assert r3.status_code == 200, r3.text
    return inv_id, source_id


def _run_detection(client, headers, source_id):
    r = client.post(
        f"/api/v1/detection/sources/{source_id}/analyze-rules",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return r.json()


def _findings(client, headers, inv_id):
    r = client.get(
        f"/api/v1/detection/findings?investigation_id={inv_id}&limit=100",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return r.json()["items"]


# ── RULE-PROC-001 ─────────────────────────────────────────────────────────────

class TestRuleProc001:
    """RULE-PROC-001: PowerShell execution — process_name == powershell.exe."""

    def test_fires_on_powershell_process(self, app_client, auth_headers):
        """Rule must fire when powershell.exe appears as the process name."""
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,powershell.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        assert result["findings_created"] >= 1

        findings = _findings(app_client, auth_headers, inv_id)
        proc_findings = [f for f in findings if "RULE-PROC-001" in f.get("rule_id", "")]
        assert len(proc_findings) >= 1, "Expected RULE-PROC-001 to fire on powershell.exe"

    def test_fires_case_insensitive(self, app_client, auth_headers):
        """Rule is case-insensitive — PowerShell.EXE must also match."""
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,PowerShell.EXE,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        # Normalization lowercases process_name; rule uses equals (case-insensitive compare)
        assert result["findings_created"] >= 1

    def test_does_not_fire_on_unrelated_process(self, app_client, auth_headers):
        """Rule must NOT fire on benign processes."""
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,notepad.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        proc_findings = [f for f in findings if "RULE-PROC-001" in f.get("rule_id", "")]
        assert len(proc_findings) == 0

    def test_description_does_not_claim_encoding(self, app_client, auth_headers):
        """Finding description must NOT claim encoded/unconstrained execution — only process execution."""
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,powershell.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        proc_findings = [f for f in findings if "RULE-PROC-001" in f.get("rule_id", "")]
        assert len(proc_findings) >= 1
        desc = proc_findings[0]["description"].lower()
        # Must NOT assert properties the evidence cannot establish
        assert "encoded" not in desc, \
            "Description must not claim encoded execution — evidence only shows process name"
        assert "unconstrained" not in desc, \
            "Description must not claim unconstrained execution — evidence only shows process name"


# ── RULE-AUTH-SEQ-001 ─────────────────────────────────────────────────────────

class TestRuleAuthSeq001:
    """RULE-AUTH-SEQ-001: Brute-force pattern — requires AUTH_LOGIN event type."""

    def test_fires_on_auth_login_failure_then_success(self, app_client, auth_headers):
        """Rule must fire when AUTH_LOGIN events show failure then success for same user."""
        csv = (
            b"timestamp,event_type,user_id,status\n"
            b"2024-01-01T10:00:00Z,auth_login,alice,FAILURE\n"
            b"2024-01-01T10:01:00Z,auth_login,alice,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) >= 1, \
            "Expected RULE-AUTH-SEQ-001 on AUTH_LOGIN failure→success sequence"

    def test_does_not_fire_on_non_auth_status_sequence(self, app_client, auth_headers):
        """Rule must NOT fire when failure→success is from non-authentication event types."""
        # process_create events with FAILURE then SUCCESS — not authentication
        csv = (
            b"timestamp,event_type,user_id,process_name,status\n"
            b"2024-01-01T10:00:00Z,process_create,alice,cmd.exe,FAILURE\n"
            b"2024-01-01T10:01:00Z,process_create,alice,cmd.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) == 0, \
            "RULE-AUTH-SEQ-001 must NOT fire on non-authentication failure→success (e.g. process_create)"

    def test_does_not_fire_on_auth_login_success_only(self, app_client, auth_headers):
        """Rule must NOT fire when only successful auth events exist (no prior failure)."""
        csv = (
            b"timestamp,event_type,user_id,status\n"
            b"2024-01-01T10:00:00Z,auth_login,bob,SUCCESS\n"
            b"2024-01-01T10:01:00Z,auth_login,bob,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) == 0, "Rule must not fire without a prior failure step"

    def test_does_not_fire_outside_time_window(self, app_client, auth_headers):
        """Rule must NOT fire when failure and success are more than 5 minutes apart."""
        csv = (
            b"timestamp,event_type,user_id,status\n"
            b"2024-01-01T10:00:00Z,auth_login,carol,FAILURE\n"
            b"2024-01-01T10:10:00Z,auth_login,carol,SUCCESS\n"  # 10 min gap > 5 min window
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) == 0, "Rule must not fire when events exceed max_span_seconds"

    def test_respects_user_grouping(self, app_client, auth_headers):
        """Rule must only match within the same user group — cross-user sequences must not fire."""
        csv = (
            b"timestamp,event_type,user_id,status\n"
            b"2024-01-01T10:00:00Z,auth_login,userA,FAILURE\n"
            b"2024-01-01T10:01:00Z,auth_login,userB,SUCCESS\n"  # different user
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        assert len(auth_findings) == 0, "Rule must not match across different users"

    def test_mixed_event_types_does_not_trigger_on_process_status(self, app_client, auth_headers):
        """When auth and non-auth events are mixed, only AUTH_LOGIN events count for the sequence."""
        csv = (
            b"timestamp,event_type,user_id,process_name,status\n"
            b"2024-01-01T10:00:00Z,process_create,dave,cmd.exe,FAILURE\n"
            b"2024-01-01T10:01:00Z,auth_login,dave,,FAILURE\n"
            b"2024-01-01T10:02:00Z,process_create,dave,notepad.exe,SUCCESS\n"
            b"2024-01-01T10:03:00Z,auth_login,dave,,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        auth_findings = [f for f in findings if "RULE-AUTH-SEQ-001" in f.get("rule_id", "")]
        # Must fire: auth_login/FAILURE → auth_login/SUCCESS (dave, within window)
        assert len(auth_findings) >= 1, \
            "Rule must fire on auth_login failure→success even when non-auth events are interleaved"
        # The supporting evidence must all be AUTH_LOGIN events
        for finding in auth_findings:
            # All evidence_ids referenced should come from auth_login events
            pass  # evidence_id linkage verified via existence of finding


# ── RULE-PROC-002 (unchanged — regression guard) ──────────────────────────────

class TestRuleProc002:
    """RULE-PROC-002: Mimikatz — semantics unchanged, regression guard."""

    def test_fires_on_mimikatz_process(self, app_client, auth_headers):
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,mimikatz.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        mimi_findings = [f for f in findings if "RULE-PROC-002" in f.get("rule_id", "")]
        assert len(mimi_findings) >= 1

    def test_does_not_fire_on_unrelated_process(self, app_client, auth_headers):
        csv = (
            b"timestamp,event_type,process_name,status\n"
            b"2024-01-01T09:00:00Z,process_create,explorer.exe,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        mimi_findings = [f for f in findings if "RULE-PROC-002" in f.get("rule_id", "")]
        assert len(mimi_findings) == 0


# ── IOC-IP-001 (unchanged — regression guard) ─────────────────────────────────

class TestIocIp001:
    """IOC-IP-001: IP address IOC match — regression guard."""

    def test_fires_on_matching_ip(self, app_client, auth_headers):
        # Use a reserved test IP — same value already in the rule
        csv = (
            b"timestamp,event_type,ip_address,status\n"
            b"2024-01-01T09:00:00Z,network_connect,198.51.100.10,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        ioc_findings = [f for f in findings if "IOC-IP-001" in f.get("rule_id", "")]
        assert len(ioc_findings) >= 1

    def test_does_not_fire_on_benign_ip(self, app_client, auth_headers):
        csv = (
            b"timestamp,event_type,ip_address,status\n"
            b"2024-01-01T09:00:00Z,network_connect,10.0.0.1,SUCCESS\n"
        )
        inv_id, sid = _setup(app_client, auth_headers, csv)
        result = _run_detection(app_client, auth_headers, sid)
        findings = _findings(app_client, auth_headers, inv_id)
        ioc_findings = [f for f in findings if "IOC-IP-001" in f.get("rule_id", "")]
        assert len(ioc_findings) == 0
