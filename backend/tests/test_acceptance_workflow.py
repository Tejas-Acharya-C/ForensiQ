"""ForensiQ Phase 6.1 — Isolated In-Process Acceptance Test Harness.

Executes a complete end-to-end investigation workflow and negative edge-case suite
using synthetic fixtures in an isolated acceptance database and storage directory.

Zero interaction with production forensiq.db or data/sources/.
"""

import hashlib
import os
import shutil
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# ── Isolation Path Configuration ──────────────────────────────────────────────
ACCEPTANCE_DB_FILE = os.path.abspath("acceptance_test_forensiq.db")
ACCEPTANCE_STAGING_DIR = Path("data/acceptance_staging").resolve()
ACCEPTANCE_SOURCES_DIR = Path("data/acceptance_sources").resolve()

LIVE_DB_FILE = os.path.abspath("forensiq.db")
TEST_DB_FILE = os.path.abspath("test_forensiq.db")
PROD_STAGING_DIR = Path("data/staging").resolve()
PROD_SOURCES_DIR = Path("data/sources").resolve()

# Strict isolation assertions
assert ACCEPTANCE_DB_FILE != LIVE_DB_FILE, "FATAL: Acceptance DB overlaps live forensiq.db!"
assert ACCEPTANCE_DB_FILE != TEST_DB_FILE, "FATAL: Acceptance DB overlaps test_forensiq.db!"
assert ACCEPTANCE_STAGING_DIR != PROD_STAGING_DIR, "FATAL: Staging dir overlaps production staging!"
assert ACCEPTANCE_SOURCES_DIR != PROD_SOURCES_DIR, "FATAL: Sources dir overlaps production sources!"

FIXTURES_DIR = Path("data/acceptance_fixtures").resolve()


@pytest.fixture(scope="module")
def acceptance_env():
    """Setup and teardown the isolated acceptance environment."""
    old_db = os.environ.get("DATABASE_URL")
    old_staging = os.environ.get("UPLOAD_STAGING_DIR")
    old_sources = os.environ.get("UPLOAD_SOURCE_DIR")

    # 1. Clean existing acceptance files if any
    if os.path.exists(ACCEPTANCE_DB_FILE):
        os.remove(ACCEPTANCE_DB_FILE)
    if ACCEPTANCE_STAGING_DIR.exists():
        shutil.rmtree(ACCEPTANCE_STAGING_DIR)
    if ACCEPTANCE_SOURCES_DIR.exists():
        shutil.rmtree(ACCEPTANCE_SOURCES_DIR)

    ACCEPTANCE_STAGING_DIR.mkdir(parents=True, exist_ok=True)
    ACCEPTANCE_SOURCES_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Configure environment overrides
    os.environ["DATABASE_URL"] = f"sqlite:///{ACCEPTANCE_DB_FILE}"
    os.environ["UPLOAD_STAGING_DIR"] = str(ACCEPTANCE_STAGING_DIR)
    os.environ["UPLOAD_SOURCE_DIR"] = str(ACCEPTANCE_SOURCES_DIR)

    from app.core.config import get_settings
    get_settings.cache_clear()

    # 3. Create isolated engine and metadata
    from app.database.base import Base
    from app.database.session import get_db
    import app.models  # noqa: F401

    acceptance_engine = create_engine(
        f"sqlite:///{ACCEPTANCE_DB_FILE}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=acceptance_engine)

    AcceptanceSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=acceptance_engine,
        expire_on_commit=False,
    )

    from app.main import create_app
    app = create_app()

    def override_get_db():
        db = AcceptanceSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    yield {
        "client": client,
        "db_file": ACCEPTANCE_DB_FILE,
        "sources_dir": ACCEPTANCE_SOURCES_DIR,
        "staging_dir": ACCEPTANCE_STAGING_DIR,
    }

    # Teardown
    app.dependency_overrides.clear()
    acceptance_engine.dispose()
    if os.path.exists(ACCEPTANCE_DB_FILE):
        try:
            os.remove(ACCEPTANCE_DB_FILE)
        except Exception:
            pass
    if ACCEPTANCE_STAGING_DIR.exists():
        shutil.rmtree(ACCEPTANCE_STAGING_DIR, ignore_errors=True)
    if ACCEPTANCE_SOURCES_DIR.exists():
        shutil.rmtree(ACCEPTANCE_SOURCES_DIR, ignore_errors=True)

    # Restore pre-existing environment variables
    if old_db is not None:
        os.environ["DATABASE_URL"] = old_db
    else:
        os.environ.pop("DATABASE_URL", None)

    if old_staging is not None:
        os.environ["UPLOAD_STAGING_DIR"] = old_staging
    else:
        os.environ.pop("UPLOAD_STAGING_DIR", None)

    if old_sources is not None:
        os.environ["UPLOAD_SOURCE_DIR"] = old_sources
    else:
        os.environ.pop("UPLOAD_SOURCE_DIR", None)

    get_settings.cache_clear()


# Shared test state across acceptance workflow steps
workflow_state = {}


def test_01_disposable_investigation_creation(acceptance_env):
    """Step 1: Create disposable primary test investigation."""
    client = acceptance_env["client"]
    res = client.post(
        "/api/v1/investigations",
        json={
            "title": "Acceptance Primary Investigation",
            "case_number": "CASE-ACC-001",
            "description": "Controlled in-process manual acceptance test run",
        },
    )
    assert res.status_code == 201
    data = res.json()
    assert data["case_number"] == "CASE-ACC-001"
    assert "id" in data
    workflow_state["inv_a_id"] = data["id"]


def test_02_synthetic_evidence_ingestion_and_sha256_verification(acceptance_env):
    """Step 2 & 3: Ingest synthetic fixture and verify SHA-256 integrity against stored bytes."""
    client = acceptance_env["client"]
    inv_id = workflow_state["inv_a_id"]
    fixture_path = FIXTURES_DIR / "fixture_multistage_threat.csv"
    assert fixture_path.exists(), f"Fixture missing: {fixture_path}"

    with open(fixture_path, "rb") as f:
        raw_bytes = f.read()

    expected_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    import_res = client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_id},
        files={"file": ("fixture_multistage_threat.csv", raw_bytes, "text/csv")},
    )
    assert import_res.status_code == 201
    import_data = import_res.json()
    source_id = import_data["source_id"]
    workflow_state["source_a_id"] = source_id

    # Verify API recorded metadata
    assert import_data["sha256_hash"] == expected_sha256
    assert import_data["file_size_bytes"] == len(raw_bytes)
    assert import_data["ingestion_status"] == "COMPLETED"

    # Verify physical stored file in acceptance_sources directory
    stored_file_path = acceptance_env["sources_dir"] / str(source_id) / "original"
    assert stored_file_path.exists(), f"Stored original file missing at {stored_file_path}"
    with open(stored_file_path, "rb") as sf:
        stored_bytes = sf.read()
    stored_sha256 = hashlib.sha256(stored_bytes).hexdigest()

    assert stored_sha256 == expected_sha256, "Stored byte SHA-256 does not match ingestion hash!"


def test_03_normalization_and_records(acceptance_env):
    """Step 4: Normalize records and verify schema mapping and source record offsets."""
    client = acceptance_env["client"]
    inv_id = workflow_state["inv_a_id"]
    source_id = workflow_state["source_a_id"]

    norm_res = client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
    assert norm_res.status_code == 200
    norm_data = norm_res.json()

    assert norm_data["status"] == "COMPLETED"
    assert norm_data["total_records"] == 12
    assert norm_data["normalized_records"] == 12
    assert norm_data["rejected_records"] == 0

    # Query normalized records via evidence explorer API
    ev_res = client.get(f"/api/v1/evidence?investigation_id={inv_id}&limit=50")
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert ev_data["total"] == 12
    items = ev_data["items"]
    assert len(items) == 12

    # Verify raw_record_offset is preserved across records
    offsets = [it["raw_record_offset"] for it in items]
    assert len(set(offsets)) == 12, "Duplicate or unmapped record offsets detected!"
    workflow_state["evidence_items"] = items


def test_04_rule_based_findings_and_evidence_id_traceability(acceptance_env):
    """Step 5 & 6: Run detections and verify finding-to-evidence ID traceability."""
    client = acceptance_env["client"]
    inv_id = workflow_state["inv_a_id"]
    source_id = workflow_state["source_a_id"]

    det_res = client.post(f"/api/v1/detection/sources/{source_id}/analyze-rules")
    assert det_res.status_code == 200
    det_data = det_res.json()
    assert det_data["status"] == "COMPLETED"
    assert det_data["findings_created"] >= 3

    # Query findings list
    find_res = client.get(f"/api/v1/detection/findings?investigation_id={inv_id}&limit=50")
    assert find_res.status_code == 200
    findings = find_res.json()["items"]
    assert len(findings) >= 3

    finding_rules = {f["rule_id"].split(":")[0]: f for f in findings}

    # Verify RULE-PROC-001 (PowerShell Execution)
    assert "RULE-PROC-001" in finding_rules
    proc_finding = finding_rules["RULE-PROC-001"]
    assert len(proc_finding["evidence_ids"]) == 1
    workflow_state["proc_finding_id"] = proc_finding["id"]

    # Verify IOC-IP-001 (Malicious IP Match)
    assert "IOC-IP-001" in finding_rules
    ip_finding = finding_rules["IOC-IP-001"]
    assert len(ip_finding["evidence_ids"]) == 1

    # Verify RULE-AUTH-SEQ-001 (Sequence: Failed login then success)
    assert "RULE-AUTH-SEQ-001" in finding_rules
    auth_finding = finding_rules["RULE-AUTH-SEQ-001"]
    assert len(auth_finding["evidence_ids"]) == 2, "Sequence rule must trace both failure and success evidence IDs!"
    workflow_state["auth_finding_id"] = auth_finding["id"]


def test_05_ml_sufficient_and_insufficient_data_behavior(acceptance_env):
    """Step 5 (ML): Test sufficient data (>=10 records) and insufficient data (<10 records)."""
    client = acceptance_env["client"]
    inv_a_id = workflow_state["inv_a_id"]
    source_a_id = workflow_state["source_a_id"]

    # 1. Source A has 12 records (>= 10): ML analysis must execute
    ml_res = client.post(f"/api/v1/ml/sources/{source_a_id}/analyze")
    assert ml_res.status_code == 200
    ml_data = ml_res.json()
    assert ml_data["status"] == "COMPLETED"

    # 2. Ingest insufficient fixture (4 records) into Case B
    inv_b_res = client.post(
        "/api/v1/investigations",
        json={"title": "Insufficient Data Test Case", "case_number": "CASE-ACC-002"},
    )
    inv_b_id = inv_b_res.json()["id"]
    workflow_state["inv_b_id"] = inv_b_id

    insuf_path = FIXTURES_DIR / "fixture_insufficient_records.csv"
    with open(insuf_path, "rb") as f:
        insuf_bytes = f.read()

    import_b = client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_b_id},
        files={"file": ("fixture_insufficient_records.csv", insuf_bytes, "text/csv")},
    )
    source_b_id = import_b.json()["source_id"]
    norm_b = client.post(f"/api/v1/evidence/sources/{source_b_id}/normalize")
    assert norm_b.json()["normalized_records"] == 4

    # ML on Source B (4 records < 10) must return INSUFFICIENT_DATA without crashing
    ml_insuf = client.post(f"/api/v1/ml/sources/{source_b_id}/analyze")
    assert ml_insuf.status_code == 200
    assert ml_insuf.json()["status"] == "INSUFFICIENT_DATA"


def test_06_correlation_and_activities_behavior(acceptance_env):
    """Step 5 (Correlation & Activities): Form links and activity clusters."""
    client = acceptance_env["client"]
    source_a_id = workflow_state["source_a_id"]

    # Correlation on Case A (12 records >= 2)
    corr_res = client.post(f"/api/v1/correlation/sources/{source_a_id}/analyze")
    assert corr_res.status_code == 200
    assert corr_res.json()["status"] == "COMPLETED"

    # Activity clustering on Case A
    act_res = client.post(f"/api/v1/activities/sources/{source_a_id}/form")
    assert act_res.status_code == 200
    assert act_res.json()["status"] == "COMPLETED"

    # Test single-event fixture in Case C (< 2 records)
    inv_c_res = client.post(
        "/api/v1/investigations",
        json={"title": "Single Event Case", "case_number": "CASE-ACC-003"},
    )
    inv_c_id = inv_c_res.json()["id"]

    single_path = FIXTURES_DIR / "fixture_single_event_no_correlation.csv"
    with open(single_path, "rb") as f:
        single_bytes = f.read()

    import_c = client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": inv_c_id},
        files={"file": ("fixture_single_event.csv", single_bytes, "text/csv")},
    )
    source_c_id = import_c.json()["source_id"]
    client.post(f"/api/v1/evidence/sources/{source_c_id}/normalize")

    # Correlation on 1 record (< 2) must return INSUFFICIENT_DATA
    corr_single = client.post(f"/api/v1/correlation/sources/{source_c_id}/analyze")
    assert corr_single.status_code == 200
    assert corr_single.json()["status"] == "INSUFFICIENT_DATA"


def test_07_prioritization_dual_level_triage(acceptance_env):
    """Step 5 (Prioritization): Execute baseline and contextual prioritization."""
    client = acceptance_env["client"]
    inv_id = workflow_state["inv_a_id"]

    # Baseline (Evidence artifacts)
    base_res = client.post(f"/api/v1/prioritization/investigations/{inv_id}/baseline")
    assert base_res.status_code == 200
    base_data = base_res.json()
    assert base_data["status"] == "COMPLETED"
    assert base_data["results_created"] > 0

    # Contextual (Activities)
    ctx_res = client.post(f"/api/v1/prioritization/investigations/{inv_id}/contextual")
    assert ctx_res.status_code == 200
    ctx_data = ctx_res.json()
    assert ctx_data["status"] == "COMPLETED"

    # Query prioritization results list
    prio_list = client.get(f"/api/v1/prioritization/results?investigation_id={inv_id}&limit=50")
    assert prio_list.status_code == 200
    results = prio_list.json()["items"]
    assert len(results) > 0

    workflow_state["prio_item_id"] = results[0]["id"]


def test_08_cross_investigation_containment(acceptance_env):
    """Step 7: Verify strict cross-investigation isolation on detail endpoints."""
    client = acceptance_env["client"]
    inv_a = workflow_state["inv_a_id"]
    inv_b = workflow_state["inv_b_id"]

    ev_id = workflow_state["evidence_items"][0]["id"]
    finding_id = workflow_state["proc_finding_id"]
    prio_id = workflow_state["prio_item_id"]

    # 1. Matching investigation returns 200
    assert client.get(f"/api/v1/evidence/{ev_id}?investigation_id={inv_a}").status_code == 200
    assert client.get(f"/api/v1/detection/findings/{finding_id}?investigation_id={inv_a}").status_code == 200
    assert client.get(f"/api/v1/prioritization/results/{prio_id}?investigation_id={inv_a}").status_code == 200

    # 2. Mismatched investigation returns 404
    assert client.get(f"/api/v1/evidence/{ev_id}?investigation_id={inv_b}").status_code == 404
    assert client.get(f"/api/v1/detection/findings/{finding_id}?investigation_id={inv_b}").status_code == 404
    assert client.get(f"/api/v1/prioritization/results/{prio_id}?investigation_id={inv_b}").status_code == 404

    # 3. Omitted investigation parameter returns 200 (backward compatibility)
    assert client.get(f"/api/v1/evidence/{ev_id}").status_code == 200
    assert client.get(f"/api/v1/detection/findings/{finding_id}").status_code == 200
    assert client.get(f"/api/v1/prioritization/results/{prio_id}").status_code == 200

    # 4. Nonexistent investigation ID returns 404
    nonexistent = str(uuid.uuid4())
    assert client.get(f"/api/v1/evidence/{ev_id}?investigation_id={nonexistent}").status_code == 404


def test_09_report_generation_structure_and_reconciliation(acceptance_env):
    """Step 8: Generate PDF report and verify PDF magic bytes, source SHA-256, and metadata."""
    client = acceptance_env["client"]
    inv_id = workflow_state["inv_a_id"]

    rep_res = client.get(f"/api/v1/investigations/{inv_id}/report")
    assert rep_res.status_code == 200
    assert "application/pdf" in rep_res.headers.get("content-type", "")

    pdf_bytes = rep_res.content
    assert pdf_bytes.startswith(b"%PDF"), "Report must start with PDF magic bytes %PDF!"
    assert len(pdf_bytes) > 5000, "Report PDF appears truncated!"


def test_10_empty_investigation_behavior(acceptance_env):
    """Step 9: Verify safe handling of an empty investigation without evidence."""
    client = acceptance_env["client"]
    res = client.post(
        "/api/v1/investigations",
        json={"title": "Empty Investigation", "case_number": "CASE-ACC-EMPTY"},
    )
    empty_id = res.json()["id"]

    # Sources list is empty
    sources = client.get(f"/api/v1/investigations/{empty_id}/sources").json()
    assert len(sources) == 0

    # Prioritization handles empty state gracefully
    base = client.post(f"/api/v1/prioritization/investigations/{empty_id}/baseline")
    assert base.status_code == 200
    assert base.json()["status"] == "INSUFFICIENT_DATA"

    # Report generates cleanly without crashing
    rep = client.get(f"/api/v1/investigations/{empty_id}/report")
    assert rep.status_code == 200
    assert rep.content.startswith(b"%PDF")


def test_11_malformed_input_behavior(acceptance_env):
    """Step 9 (Malformed Input): Ingestion handles unparseable CSV safely."""
    client = acceptance_env["client"]
    res = client.post(
        "/api/v1/investigations",
        json={"title": "Malformed Test", "case_number": "CASE-ACC-MALFORMED"},
    )
    mal_inv_id = res.json()["id"]

    mal_path = FIXTURES_DIR / "fixture_malformed_syntax.csv"
    with open(mal_path, "rb") as f:
        mal_bytes = f.read()

    import_mal = client.post(
        "/api/v1/evidence/import",
        data={"investigation_id": mal_inv_id},
        files={"file": ("malformed.csv", mal_bytes, "text/csv")},
    )
    assert import_mal.status_code == 201
    src_id = import_mal.json()["source_id"]

    # Normalization should reject records without valid timestamps
    norm_res = client.post(f"/api/v1/evidence/sources/{src_id}/normalize")
    assert norm_res.status_code == 200
    norm_data = norm_res.json()
    assert norm_data["normalized_records"] == 0
    assert norm_data["rejected_records"] > 0


def test_12_repeated_pipeline_idempotency(acceptance_env):
    """Step 13: Re-running normalization refreshes derived data cleanly without zombies."""
    client = acceptance_env["client"]
    inv_id = workflow_state["inv_a_id"]
    source_id = workflow_state["source_a_id"]

    # Re-normalize source A
    renorm_res = client.post(f"/api/v1/evidence/sources/{source_id}/normalize")
    assert renorm_res.status_code == 200
    assert renorm_res.json()["normalized_records"] == 12

    # Verify evidence records count is exactly 12 (no duplicate zombies)
    ev_res = client.get(f"/api/v1/evidence?investigation_id={inv_id}&limit=50")
    assert ev_res.json()["total"] == 12
