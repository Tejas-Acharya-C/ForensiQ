"""Phase 8 & 8.1 Comprehensive Software QA and Forensic Integrity Regression Suite.

Validates:
1. Record-level hash validation without silent truncation (65-char, non-hex, missing, prefixed, valid SHA-256, valid SHA-512).
2. Entity normalization without destructive string clamping.
3. Defensive deserialization preserving original stored values with structured data quality warnings.
4. Investigation containment on detail endpoints (evidence, findings, activities, prioritization, relationships).
5. ReportLab PDF generation resilience with XML special characters (<, >, &).
6. API boundaries, UUID handling, and pagination.
"""

import uuid
import datetime
from datetime import timezone
import pytest
from fastapi.testclient import TestClient

from app.models.investigation import Investigation
from app.models.evidence_source import EvidenceSource
from app.models.evidence import Evidence
from app.models.relationship import Relationship
from app.schemas.evidence import EvidenceRead
from app.normalization.mapper import (
    validate_and_parse_file_hash,
    verify_hash_integrity,
    normalize_file_hash,
    normalize_user_id,
    normalize_device_id,
    normalize_process_name,
    normalize_action,
    normalize_status,
)
from app.api.v1.evidence import _safe_validate_evidence
from app.report import ReportData, generate_report_pdf


# ---------------------------------------------------------------------------
# 1. Forensic Hash Validation & Non-Truncation Tests (Phase 8.1 Requirements)
# ---------------------------------------------------------------------------

def test_evidence_hash_65_char_preserves_without_truncation():
    """Verify 65-character hash is preserved in full, marked INVALID_LENGTH, and NOT reported as verified SHA-256."""
    hash_65 = "4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2"
    assert len(hash_65) == 65
    
    digest, meta = validate_and_parse_file_hash(hash_65)
    # Must preserve full 65 characters without truncation
    assert digest == hash_65
    assert len(digest) == 65
    assert meta["raw_value"] == hash_65
    assert meta["normalized_digest"] == hash_65
    # Must not treat malformed digest as verified or valid
    assert meta["is_syntax_valid"] is False
    assert meta["is_byte_verified"] is False
    assert meta["is_valid"] is False
    assert meta["status"] == "INVALID_LENGTH"
    assert meta["syntax_status"] == "INVALID_LENGTH"
    assert meta["verification_status"] == "UNVERIFIED"
    assert meta["actual_length"] == 65
    # CRITICAL: Must NOT falsely report algorithm as SHA-256
    assert meta["detected_algorithm"] is None
    assert "error" in meta

    # Ensure normalize_file_hash also does not truncate
    norm = normalize_file_hash(hash_65)
    assert norm == hash_65


def test_evidence_hash_invalid_hex_chars():
    """Verify hash containing non-hex characters is preserved and marked MALFORMED_HEX."""
    bad_hash = "4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3z"  # 'z' is not hex
    digest, meta = validate_and_parse_file_hash(bad_hash)
    assert digest == bad_hash
    assert meta["raw_value"] == bad_hash
    assert meta["is_syntax_valid"] is False
    assert meta["is_byte_verified"] is False
    assert meta["is_valid"] is False
    assert meta["status"] == "MALFORMED_HEX"
    assert meta["syntax_status"] == "MALFORMED_HEX"
    assert meta["verification_status"] == "UNVERIFIED"
    assert meta["detected_algorithm"] is None
    assert "non-hexadecimal" in meta["error"].lower()


def test_evidence_hash_missing():
    """Verify missing, empty, or sentinel hash returns None and status MISSING (never valid)."""
    for empty_val in (None, "", "   ", "null", "N/A", "-", "none", "unknown"):
        digest, meta = validate_and_parse_file_hash(empty_val)
        assert digest is None
        assert meta["status"] == "MISSING"
        assert meta["syntax_status"] == "MISSING"
        assert meta["verification_status"] == "NOT_APPLICABLE"
        assert meta["is_syntax_valid"] is False
        assert meta["is_byte_verified"] is False
        assert meta["is_valid"] is False
        assert meta["raw_value"] is None
        assert meta["normalized_digest"] is None
        assert meta["detected_algorithm"] is None


def test_evidence_hash_unsupported_algorithm():
    """Verify unsupported algorithm prefixes are identified without crashing or truncating."""
    for prefix, algo in [("blake2b:", "BLAKE2B"), ("crc32:", "CRC32"), ("sha3:", "SHA3")]:
        unsupp_hash = f"{prefix}1234567890abcdef"
        digest, meta = validate_and_parse_file_hash(unsupp_hash)
        assert digest == unsupp_hash
        assert meta["raw_value"] == unsupp_hash
        assert meta["status"] == "UNSUPPORTED_ALGORITHM"
        assert meta["syntax_status"] == "UNSUPPORTED_ALGORITHM"
        assert meta["verification_status"] == "UNVERIFIED"
        assert meta["is_syntax_valid"] is False
        assert meta["is_byte_verified"] is False
        assert meta["is_valid"] is False
        assert meta["claimed_algorithm"] == algo
        assert meta["detected_algorithm"] is None
        assert "unsupported" in meta["error"].lower() or "unrecognized" in meta["error"].lower()


def test_evidence_hash_unverified_vs_verified_distinction():
    """Verify strict separation between syntax validity and byte verification."""
    data = b"forensic evidentiary test data"
    import hashlib
    true_sha256 = hashlib.sha256(data).hexdigest()

    # 1. Parsing from log: syntax is VALID, but verification against bytes is UNVERIFIED
    digest, meta = validate_and_parse_file_hash(true_sha256)
    assert meta["status"] == "VALID"
    assert meta["syntax_status"] == "VALID"
    assert meta["verification_status"] == "UNVERIFIED"
    assert meta["is_syntax_valid"] is True
    assert meta["is_byte_verified"] is False
    assert "Log-extracted hash" in meta["warnings"][0]

    # When require_byte_verification is requested, status is UNVERIFIED
    _, meta_unverified = validate_and_parse_file_hash(true_sha256, require_byte_verification=True)
    assert meta_unverified["status"] == "UNVERIFIED"
    assert meta_unverified["verification_status"] == "UNVERIFIED"
    assert meta_unverified["is_byte_verified"] is False

    # 2. Cryptographic byte verification against matching data: status becomes VERIFIED
    verified_meta = verify_hash_integrity(true_sha256, file_bytes=data)
    assert verified_meta["status"] == "VERIFIED"
    assert verified_meta["verification_status"] == "VERIFIED"
    assert verified_meta["is_byte_verified"] is True
    assert verified_meta["computed_digest"] == true_sha256

    # 3. Cryptographic byte verification against mismatching data: status becomes INTEGRITY_MISMATCH
    mismatch_meta = verify_hash_integrity(true_sha256, file_bytes=b"tampered content")
    assert mismatch_meta["status"] == "INTEGRITY_MISMATCH"
    assert mismatch_meta["verification_status"] == "FAILED"
    assert mismatch_meta["is_byte_verified"] is False
    assert "error" in mismatch_meta


def test_evidence_hash_prefixed_preserves_original_and_normalizes():
    """Verify prefixed hashes preserve raw value with prefix while deriving clean normalized digest."""
    valid_sha256 = "a" * 64
    raw_input = f"sha256:{valid_sha256}"
    digest, meta = validate_and_parse_file_hash(raw_input)
    # Original raw string preserved intact with prefix and original casing
    assert meta["raw_value"] == raw_input
    # Normalized digest extracts lowercase hex
    assert digest == valid_sha256
    assert meta["normalized_digest"] == valid_sha256
    assert meta["is_syntax_valid"] is True
    assert meta["is_byte_verified"] is False
    assert meta["verification_status"] == "UNVERIFIED"
    assert meta["status"] == "VALID"
    assert meta["claimed_algorithm"] == "SHA-256"
    assert meta["detected_algorithm"] == "SHA-256"

    # Prefixed SHA-256 with invalid length (65 chars)
    invalid_prefixed = f"sha256:{'a' * 65}"
    raw_res, meta_err = validate_and_parse_file_hash(invalid_prefixed)
    assert meta_err["raw_value"] == invalid_prefixed
    assert meta_err["is_syntax_valid"] is False
    assert meta_err["is_byte_verified"] is False
    assert meta_err["is_valid"] is False
    assert meta_err["status"] == "INVALID_LENGTH"
    assert meta_err["claimed_algorithm"] == "SHA-256"
    assert meta_err["detected_algorithm"] is None  # NOT reported as verified SHA-256
    assert meta_err["actual_length"] == 65
    assert meta_err["expected_length"] == 64


def test_evidence_hash_valid_sha256():
    """Verify valid 64-character SHA-256 hash is identified with separate syntax and verification status."""
    sha256_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    digest, meta = validate_and_parse_file_hash(sha256_val)
    assert digest == sha256_val
    assert meta["raw_value"] == sha256_val
    assert meta["normalized_digest"] == sha256_val
    assert meta["is_syntax_valid"] is True
    assert meta["is_byte_verified"] is False
    assert meta["is_valid"] is True
    assert meta["status"] == "VALID"
    assert meta["syntax_status"] == "VALID"
    assert meta["verification_status"] == "UNVERIFIED"
    assert meta["detected_algorithm"] == "SHA-256"


def test_evidence_hash_valid_sha512():
    """Verify valid 128-character SHA-512 hash is identified and marked VALID."""
    sha512_val = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    assert len(sha512_val) == 128
    digest, meta = validate_and_parse_file_hash(sha512_val)
    assert digest == sha512_val
    assert meta["raw_value"] == sha512_val
    assert meta["normalized_digest"] == sha512_val
    assert meta["is_syntax_valid"] is True
    assert meta["is_byte_verified"] is False
    assert meta["is_valid"] is True
    assert meta["status"] == "VALID"
    assert meta["detected_algorithm"] == "SHA-512"


# ---------------------------------------------------------------------------
# 2. Entity Normalization Preservation (No Silent Truncation)
# ---------------------------------------------------------------------------

def test_normalization_preserves_full_strings_no_truncation():
    """Verify mapper preserves raw strings without silent clamping."""
    long_user = "user_" + "x" * 200
    assert len(normalize_user_id(long_user)) == 205
    assert normalize_user_id(long_user) == long_user

    long_dev = "device_" + "y" * 200
    assert len(normalize_device_id(long_dev)) == 207
    assert normalize_device_id(long_dev) == long_dev

    long_proc = "C:\\Windows\\System32\\" + "z" * 300 + ".exe"
    base_name, _ = normalize_process_name(long_proc)
    assert len(base_name) == 304

    action = normalize_action("special_action")
    assert action == "SPECIAL_ACTION"

    status = normalize_status("SUCCESS")
    assert status == "SUCCESS"


# ---------------------------------------------------------------------------
# 3. Defensive Deserialization Without Truncation
# ---------------------------------------------------------------------------

def test_defensive_serialization_preserves_stored_values_and_warns():
    """Verify _safe_validate_evidence preserves original values and annotates data quality without truncation."""
    raw_hash_65 = "4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2"
    ev = Evidence(
        id=uuid.uuid4(),
        investigation_id=uuid.uuid4(),
        source_id=uuid.uuid4(),
        raw_record_offset=0,
        timestamp=datetime.datetime.now(timezone.utc),
        event_type="process_create",
        source_type="CSV",
        file_hash=raw_hash_65,
        user_id="very_long_user_" + "a" * 150,
        attributes={"existing_key": "existing_value"},
        normalized_at=datetime.datetime.now(timezone.utc),
    )
    result = _safe_validate_evidence(ev)
    assert isinstance(result, EvidenceRead)
    assert result.file_hash == raw_hash_65
    assert len(result.file_hash) == 65  # NOT truncated to 64
    assert result.user_id == "very_long_user_" + "a" * 150  # NOT truncated to 128


def test_evidence_explorer_api_lists_hashes_without_500(app_client: TestClient, db_session):
    """Verify GET /api/v1/evidence returns 200 and untruncated hashes."""
    inv = Investigation(
        title="QA Hash Investigation",
        description="Testing hash lengths",
        case_number=f"QA-HASH-{uuid.uuid4().hex[:6]}",
        status="OPEN",
    )
    db_session.add(inv)
    db_session.commit()

    src = EvidenceSource(
        investigation_id=inv.id,
        filename="test_hashes.csv",
        file_format="CSV",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=100,
        total_records=2,
        ingestion_status="COMPLETED",
        storage_path="data/test/staged.csv",
    )
    db_session.add(src)
    db_session.commit()

    hash_65 = "4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2"
    hash_sha512 = "f" * 128

    ev1 = Evidence(
        investigation_id=inv.id,
        source_id=src.id,
        raw_record_offset=0,
        timestamp=datetime.datetime.now(timezone.utc),
        event_type="process_create",
        source_type="CSV",
        file_hash=hash_65,
    )
    ev2 = Evidence(
        investigation_id=inv.id,
        source_id=src.id,
        raw_record_offset=1,
        timestamp=datetime.datetime.now(timezone.utc),
        event_type="file_create",
        source_type="CSV",
        file_hash=hash_sha512,
    )
    db_session.add_all([ev1, ev2])
    db_session.commit()

    response = app_client.get(f"/api/v1/evidence?investigation_id={inv.id}")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["total"] == 2
    hashes = [item["file_hash"] for item in data["items"]]
    assert hash_65 in hashes
    assert hash_sha512 in hashes


# ---------------------------------------------------------------------------
# 4. Investigation Containment on Detail Endpoints
# ---------------------------------------------------------------------------

def test_relationship_detail_investigation_containment(app_client: TestClient, db_session):
    """Verify GET /api/v1/correlation/relationships/{id} enforces investigation containment."""
    inv_a = Investigation(title="Case A", case_number=f"CASE-A-{uuid.uuid4().hex[:6]}", status="OPEN")
    inv_b = Investigation(title="Case B", case_number=f"CASE-B-{uuid.uuid4().hex[:6]}", status="OPEN")
    db_session.add_all([inv_a, inv_b])
    db_session.commit()

    src_a = EvidenceSource(
        investigation_id=inv_a.id,
        filename="source_a.csv",
        file_format="CSV",
        sha256_hash="a" * 64,
        storage_path="data/test/src_a.csv",
    )
    db_session.add(src_a)
    db_session.commit()

    e1 = Evidence(
        investigation_id=inv_a.id,
        source_id=src_a.id,
        timestamp=datetime.datetime.now(timezone.utc),
        event_type="login",
        source_type="CSV",
    )
    e2 = Evidence(
        investigation_id=inv_a.id,
        source_id=src_a.id,
        timestamp=datetime.datetime.now(timezone.utc),
        event_type="access",
        source_type="CSV",
    )
    db_session.add_all([e1, e2])
    db_session.commit()

    rel = Relationship(
        investigation_id=inv_a.id,
        source_evidence_id=e1.id,
        target_evidence_id=e2.id,
        relationship_type="TEMPORAL_PROXIMITY",
        weight=0.85,
        relationship_fingerprint=f"fp_{uuid.uuid4().hex}",
    )
    db_session.add(rel)
    db_session.commit()

    # 1. Unscoped lookup returns record
    resp_unscoped = app_client.get(f"/api/v1/correlation/relationships/{rel.id}")
    assert resp_unscoped.status_code == 200
    assert resp_unscoped.json()["id"] == str(rel.id)

    # 2. Matching investigation_id returns record
    resp_matching = app_client.get(f"/api/v1/correlation/relationships/{rel.id}?investigation_id={inv_a.id}")
    assert resp_matching.status_code == 200

    # 3. Mismatched investigation_id returns 404
    resp_mismatch = app_client.get(f"/api/v1/correlation/relationships/{rel.id}?investigation_id={inv_b.id}")
    assert resp_mismatch.status_code == 404


# ---------------------------------------------------------------------------
# 5. ReportLab PDF Generation Robustness Tests
# ---------------------------------------------------------------------------

def test_report_pdf_special_characters_resilience():
    """Verify PDF generator handles XML/HTML reserved characters (<, >, &, \") without syntax errors."""
    data = ReportData()
    data.investigation = {
        "id": str(uuid.uuid4()),
        "case_number": "CASE <M&A> 2026",
        "title": "Investigation into \"Project X\" & Associated Threats <CONFIDENTIAL>",
        "description": "Evidence contains command: cmd.exe /c type < test.log & calc.exe > out.txt",
        "status": "OPEN",
        "created_at": datetime.datetime.now(timezone.utc),
    }
    data.summary = {
        "total_sources": 1,
        "total_evidence": 5,
        "total_findings": 1,
        "total_anomalies": 0,
        "total_relationships": 0,
        "total_activities": 0,
        "total_priority": 0,
        "priority_tier_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0},
    }
    data.findings = [
        {
            "id": str(uuid.uuid4()),
            "finding_type": "RULE_MATCH",
            "rule_id": "RULE_<SPECIAL>&TEST",
            "severity": 0.85,
            "description": "Detected injection payload: <script>alert('xss & more')</script>",
            "mitre_tactic": "Execution & Persistence",
            "mitre_technique": "T1059 <Command Line>",
            "created_at": datetime.datetime.now(timezone.utc),
        }
    ]
    data.sources = [
        {
            "id": str(uuid.uuid4()),
            "filename": "logs_<critical>&special.csv",
            "file_format": "CSV",
            "sha256_hash": "c" * 64,
            "file_size_bytes": 1024,
            "total_records": 5,
            "normalized_records": 5,
            "ingestion_status": "COMPLETED",
            "ingested_at": datetime.datetime.now(timezone.utc),
        }
    ]

    pdf_bytes = generate_report_pdf(data)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")


def test_report_pdf_empty_investigation():
    """Verify PDF generation succeeds cleanly even with no evidence or findings."""
    data = ReportData()
    data.investigation = {
        "id": str(uuid.uuid4()),
        "case_number": "EMPTY-CASE-001",
        "title": "Empty Case",
        "status": "OPEN",
        "created_at": datetime.datetime.now(timezone.utc),
    }
    data.summary = {
        "total_sources": 0,
        "total_evidence": 0,
        "total_findings": 0,
        "total_anomalies": 0,
        "total_relationships": 0,
        "total_activities": 0,
        "total_priority": 0,
        "priority_tier_counts": {},
    }
    pdf_bytes = generate_report_pdf(data)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF-")


# ---------------------------------------------------------------------------
# 6. API Boundary, Pagination & Error Handling Tests
# ---------------------------------------------------------------------------

def test_api_invalid_uuid_handling(app_client: TestClient):
    """Verify submitting invalid UUIDs returns 422 Unprocessable Entity."""
    resp = app_client.get("/api/v1/investigations/not-a-valid-uuid")
    assert resp.status_code == 422


def test_api_nonexistent_resource_handling(app_client: TestClient):
    """Verify requesting a nonexistent UUID returns 404 Not Found."""
    fake_id = uuid.uuid4()
    resp = app_client.get(f"/api/v1/investigations/{fake_id}")
    assert resp.status_code == 404
    data = resp.json()
    assert data["success"] is False
    assert data["error"]["code"] == "NOT_FOUND"


def test_api_pagination_bounds(app_client: TestClient):
    """Verify pagination limits: limit > 500 returns 422; offset beyond total returns empty items."""
    resp_over_limit = app_client.get("/api/v1/investigations?limit=1000")
    assert resp_over_limit.status_code == 422

    resp_high_offset = app_client.get("/api/v1/investigations?offset=999999&limit=10")
    assert resp_high_offset.status_code == 200
    data = resp_high_offset.json()
    assert data["items"] == []
    assert data["has_more"] is False


def test_audit_65_character_synthetic_case_end_to_end(app_client: TestClient, db_session):
    """Synthetic audit verifying all forensic requirements for 65-char hash case (Phase 8.2 Section 5)."""
    raw_65_hash = "4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2"
    
    # 1. Normalization parsing
    digest, meta = validate_and_parse_file_hash(raw_65_hash)
    assert digest == raw_65_hash
    assert len(digest) == 65
    assert meta["status"] == "INVALID_LENGTH"
    assert meta["syntax_status"] == "INVALID_LENGTH"
    assert meta["detected_algorithm"] is None  # Must NOT report as verified SHA-256
    assert meta["is_syntax_valid"] is False
    assert meta["is_byte_verified"] is False
    assert meta["verification_status"] == "UNVERIFIED"

    # 2. Database persistence & API query
    inv = Investigation(title="Audit 65-Char Case", case_number=f"AUDIT-65-{uuid.uuid4().hex[:6]}", status="OPEN")
    db_session.add(inv)
    db_session.commit()

    # Source file has true 64-char SHA-256
    source_sha256 = "65293500628d54b1aa17bb0429921a6edf60057b86bdad833b43fc8e52e015df"
    src = EvidenceSource(
        investigation_id=inv.id,
        filename="synthetic_malware_proc.csv",
        file_format="CSV",
        sha256_hash=source_sha256,
        file_size_bytes=1024,
        total_records=1,
        ingestion_status="COMPLETED",
        storage_path="data/test/synthetic.csv",
    )
    db_session.add(src)
    db_session.commit()

    ev = Evidence(
        investigation_id=inv.id,
        source_id=src.id,
        raw_record_offset=18,
        timestamp=datetime.datetime.now(timezone.utc),
        event_type="process_create",
        source_type="CSV",
        file_hash=raw_65_hash,
        attributes={"hash_metadata": meta},
    )
    db_session.add(ev)
    db_session.commit()

    # 3. Evidence Explorer API listing returns 200 without HTTP 500
    res = app_client.get(f"/api/v1/evidence?investigation_id={inv.id}")
    assert res.status_code == 200
    item = res.json()["items"][0]
    assert item["file_hash"] == raw_65_hash
    assert len(item["file_hash"]) == 65
    assert item["attributes"]["hash_metadata"]["status"] == "INVALID_LENGTH"
    assert item["attributes"]["hash_metadata"]["detected_algorithm"] is None

    # 4. Detail endpoint returns 200 with raw value and containment check
    detail_res = app_client.get(f"/api/v1/evidence/{ev.id}?investigation_id={inv.id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["file_hash"] == raw_65_hash

    # 5. Distinction between source SHA-256 and record hash
    assert len(src.sha256_hash) == 64
    assert len(item["file_hash"]) == 65
    assert src.sha256_hash != item["file_hash"]

    # 6. ReportLab PDF generation does not crash
    from app.report import ReportData, generate_report_pdf
    rep_data = ReportData()
    rep_data.investigation = {"case_number": inv.case_number, "title": inv.title, "status": "OPEN"}
    rep_data.summary = {"total_sources": 1, "total_evidence": 1, "total_findings": 0, "total_anomalies": 0, "total_relationships": 0, "total_activities": 0, "total_priority": 0, "priority_tier_counts": {}}
    rep_data.sources = [{"filename": src.filename, "file_format": src.file_format, "sha256_hash": src.sha256_hash, "file_size_bytes": 1024, "ingestion_status": "COMPLETED", "ingested_at": datetime.datetime.now(timezone.utc)}]
    pdf_bytes = generate_report_pdf(rep_data)
    assert pdf_bytes.startswith(b"%PDF-")
