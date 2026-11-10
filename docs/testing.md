# ForensiQ Testing Strategy & Verification Guide

This document describes the test architecture, test suites, execution procedures, and verification protocols for ForensiQ.

---

## 1. Test Architecture Overview

ForensiQ employs a multi-tiered verification strategy designed for forensic software:
1. **Unit & Semantics Tests**: Validate deterministic rule matching, operator logic, feature extraction, and ML Isolation Forest scoring.
2. **Integration API Tests**: Validate end-to-end REST endpoints using FastAPI `TestClient`, SQLite in-memory / temporary test databases, and async lifecycle handlers.
3. **Pipeline Concurrency Tests**: Verify investigation isolation, asynchronous pipeline state ownership, and race-condition immunity.
4. **Sample Dataset Validation**: Ensure all bundled forensic sample datasets conform strictly to the Common Evidence Schema and parse without schema errors.
5. **Static Code Quality Checks**: Linting, syntax validation, and typing consistency across Python and JavaScript codebases.

---

## 2. Test Execution Commands

### Running the Full Test Suite
Run all automated test suites with standard verbose output:

```bash
pytest backend/tests/ -v
```

For quiet/summary output:
```bash
pytest backend/tests/ -q
```

### Running Specific Test Modules

```bash
# Deterministic rule & IOC detection semantics
pytest backend/tests/test_detection_semantics.py -v

# Machine learning anomaly detection & parameter customization
pytest backend/tests/test_detection_ml.py -v

# Multi-dimensional correlation & activity clustering
pytest backend/tests/test_correlation_semantics.py -v
pytest backend/tests/test_activities.py -v

# Dual-level prioritization algorithms
pytest backend/tests/test_prioritization.py -v

# Ingestion, parser, and SHA-256 integrity verification
pytest backend/tests/test_ingestion_csv.py -v
pytest backend/tests/test_evidence_verifier.py -v

# Pipeline orchestration & error recovery
pytest backend/tests/test_pipeline_orchestration.py -v

# End-to-end investigation workflow
pytest backend/tests/test_e2e_investigation.py -v
```

---

## 3. Pipeline Concurrency & Race-Condition Verification

To verify that active pipeline state machine controls and investigation isolation behave correctly under rapid case switching:

```bash
node scratch/test_pipeline_race_condition.js
```
*Expected output: All 4 concurrency scenarios pass with 0 invariant violations.*

This test validates:
- Investigation switching immediately locks/unlocks controls according to the *active* case's state.
- Monotonically increasing execution tokens (`pipelineExecutionCounter`) prevent stale background completions from clearing state in a newly selected case.
- Unique case ownership via `pipelineRunningByCase = new Map()`.

---

## 4. Sample Dataset Validation

ForensiQ provides pre-packaged sample forensic datasets under `data/samples/`. To ensure that these evidence files remain valid and compatible with the ingestion parser, run:

```bash
python scripts/validate_samples.py
```

This script verifies:
- File existence and non-zero byte size.
- CSV/JSON delimiter and formatting validity.
- Required forensic timestamp and entity field presence.
- ML eligibility ($\ge 10$ records).

---

## 5. Frontend & Static Validation

ForensiQ uses zero-dependency vanilla ES6 JavaScript and CSS3. Static correctness is verified without requiring heavy bundling suites:

### JavaScript Syntax Verification
Verify JavaScript syntax using Node.js:

```bash
node --check frontend/app.js
```
*Expected exit code: 0 with no errors.*

### Git Formatting & Whitespace Verification
Ensure no accidental whitespace errors or invalid line breaks:

```bash
git diff --check
```
*Expected output: Clean (no output and exit code 0).*

### Python Linting & Type Consistency
Adherence to Python standards is verified via Ruff:

```bash
ruff check backend/app
```

---

## 6. Verification Protocols & Test Coverage

The automated test suite covers 190 tests across 24 test suites:

| Suite Name | Scope & Purpose |
| :--- | :--- |
| `test_activities.py` | Activity thread clustering, root entity assignment, lifecycle status. |
| `test_app_settings.py` | Configuration loading, environment variables, default path resolution. |
| `test_canonical_event_schema.py` | Schema validation, CES fields, normalization contracts. |
| `test_case_management.py` | Investigation case creation, updates, listing, case numbers. |
| `test_correlation_api.py` | HTTP REST endpoints for correlation queries and execution. |
| `test_correlation_semantics.py` | Temporal sliding window, multi-attribute matching, relationship weights. |
| `test_detection_api.py` | Deterministic detection HTTP endpoints, finding retrieval. |
| `test_detection_ml.py` | ML Anomaly service, Isolation Forest training, parameter overrides. |
| `test_detection_rules.py` | Rule engine YAML parsing, condition matching, severity assignment. |
| `test_detection_semantics.py` | ATT&CK tactics, regex/string operators, edge case values. |
| `test_e2e_investigation.py` | Complete investigation lifecycle from upload to report generation. |
| `test_evidence_api.py` | Evidence query endpoints, filtering, pagination, sorting. |
| `test_evidence_verifier.py` | Cryptographic SHA-256 source integrity check and tamper detection. |
| `test_examples_api.py` | Sample evidence download endpoints. |
| `test_ingestion_csv.py` | CSV parsing, encoding fallback, timestamp normalization. |
| `test_ingestion_edge_cases.py` | Malformed records, empty lines, missing fields, delimiter handling. |
| `test_ml_api.py` | HTTP REST endpoints for ML anomaly detection. |
| `test_parser_json_jsonl.py` | JSON array and line-delimited JSON parser validation. |
| `test_pipeline_orchestration.py` | Multi-stage pipeline execution, error isolation, stage progress. |
| `test_prioritization.py` | Baseline evidence prioritization and contextual activity scoring. |
| `test_prioritization_api.py` | Prioritization REST endpoints and factor breakdown responses. |
| `test_report_generation.py` | PDF compilation, ReportLab document formatting, finding tables. |
| `test_report_metrics.py` | Metric aggregation accuracy for executive reporting. |
| `test_root_redirect.py` | API root redirection and health status routing. |
