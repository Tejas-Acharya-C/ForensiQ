# ForensiQ REST API Specification Reference

This document provides complete technical specifications for the ForensiQ REST API (`/api/v1`).

---

## 1. Architectural Principles & Security Boundary

- **Base URL**: `http://127.0.0.1:8000/api/v1`
- **Protocol**: HTTP/1.1 REST with JSON payloads (`multipart/form-data` for file uploads; `application/pdf` for reports).
- **Loopback Enforcement**: All endpoints bind strictly to loopback (`127.0.0.1`). External bindings are disabled.
- **Single-Investigator Access**: Operates in local workstation mode without multi-tenant authentication overhead.
- **Standard HTTP Codes**:
  - `200 OK`: Successful read or idempotent update.
  - `201 Created`: Successful entity creation or evidence ingestion.
  - `400 Bad Request`: Validation failure or insufficient data (e.g., ML on <10 records).
  - `404 Not Found`: Target entity or investigation does not exist.
  - `409 Conflict`: Duplicate file or hash collision when `allow_duplicates=false`.
  - `422 Unprocessable Entity`: Request body violates Pydantic schema validation.

---

## 2. Health & System Status

### `GET /health`
Returns application runtime health, database connectivity, and filesystem storage availability.

**Response (`200 OK`):**
```json
{
  "status": "healthy",
  "app_name": "ForensiQ",
  "environment": "development",
  "database_status": "connected",
  "storage_status": "healthy",
  "version": "0.1.0"
}
```

---

## 3. Investigation Case Management

### `GET /investigations`
Lists all investigation cases with optional status filtering.
- **Query Parameters**: `status` (optional: `OPEN`, `CLOSED`, `ARCHIVED`).

### `POST /investigations`
Creates a new isolated investigation container.
- **Request Body**:
```json
{
  "title": "Incident Triage - Server Alpha",
  "case_number": "CASE-2026-001",
  "description": "Suspected lateral movement and credential theft",
  "status": "OPEN"
}
```

### `GET /investigations/{investigation_id}`
Retrieves full details for a single investigation.

### `PATCH /investigations/{investigation_id}`
Modifies title, description, or status of an investigation.

### `GET /investigations/{investigation_id}/summary`
Aggregates case metrics for the Operations Center dashboard (evidence counts, findings tier breakdown, top priority scores, ingested sources).

### `GET /investigations/{investigation_id}/sources`
Lists all evidence files ingested into the specified investigation.

### `GET /investigations/{investigation_id}/notes` & `PUT /investigations/{investigation_id}/notes`
Reads and updates investigator free-form Markdown notes for the case.

### `GET /investigations/{investigation_id}/checklist`
Retrieves the investigator milestone checklist for the case.

---

## 4. Evidence Ingestion & Verification

### `POST /evidence/import`
Uploads a raw evidence file (`multipart/form-data`) into staging, computes SHA-256 baseline, and commits to immutable storage.
- **Form Fields**:
  - `investigation_id`: UUID string.
  - `file`: Raw log file (CSV, JSON array, or JSONL).
  - `allow_duplicates`: Boolean (default `false`).

### `POST /evidence/sources/{source_id}/normalize`
Parses raw staging records into the Common Evidence Schema (CES) and stores normalized evidence.
- **Response**: `normalized_records`, `rejected_records`, `warning_count`, `errors`.

### `POST /evidence/sources/{source_id}/verify-integrity`
Recomputes SHA-256 digest directly over the stored disk file and compares it with the immutable ingestion baseline.
- **Response (`200 OK`)**:
```json
{
  "source_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "VERIFIED",
  "stored_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "computed_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "verified_at": "2026-11-10T14:30:00Z"
}
```

### `GET /evidence`
Queries normalized evidence records with pagination and filtering.
- **Query Parameters**: `investigation_id`, `source_id`, `event_type`, `user_id`, `device_id`, `search`, `limit`, `offset`.

### `GET /evidence/{evidence_id}`
Retrieves a single normalized evidence record with raw payload and CES attributes.

### `GET /evidence/{evidence_id}/position`
Returns the 0-based index and pagination offset of a specific evidence record within its source.

---

## 5. Deterministic Threat Detection

### `POST /detection/sources/{source_id}/analyze-rules`
Executes YAML detection rules and IOC matching over normalized evidence records.
- **Response**: `findings_created`, `findings_reused`, `evidence_evaluated`, `rules_evaluated`.

### `GET /detection/findings`
Queries generated findings across the case.
- **Query Parameters**: `investigation_id`, `finding_type`, `min_severity`, `review_status`, `limit`, `offset`.

### `GET /detection/findings/{finding_id}`
Retrieves a specific finding, rule metadata, and linked evidence IDs.

### `GET /detection/findings/{finding_id}/explanation`
Returns detailed diagnostic explanation for why the rule matched.

### `GET /detection/findings/{finding_id}/review` & `PUT /detection/findings/{finding_id}/review`
Gets or updates investigator review triage status (`UNREVIEWED`, `CONFIRMED_TRUE_POSITIVE`, `SUSPECTED_FALSE_POSITIVE`, etc.) and triage notes.

---

## 6. Machine Learning Anomaly Detection

### `POST /ml/sources/{source_id}/analyze`
Runs unsupervised Isolation Forest anomaly detection over normalized event telemetry. Requires at least 10 normalized records.
- **Request Body (Optional parameter overrides)**:
```json
{
  "contamination": 0.05,
  "threshold": 0.85,
  "random_seed": 42,
  "model_override": "isolation_forest"
}
```
- **Parameter Details**:
  - `contamination`: Float in `(0.0, 0.5]`, default `0.05`. Expected proportion of outliers in the data.
  - `threshold`: Float in `[0.0, 1.0]`, default is the 95th percentile of normalized anomaly scores.
  - `random_seed`: Integer seed for deterministic Isolation Forest fitting, default `42`.
  - `model_override`: String specifying the anomaly model. Only `"isolation_forest"` is supported (unsupported models return `400 Bad Request`).
- **Response**: `findings_created`, `evidence_evaluated`, `status`.

---

## 7. Multi-Dimensional Correlation

### `POST /correlation/sources/{source_id}/analyze`
Identifies relational connections across IP addresses, user accounts, hostnames, and process lineages within configurable sliding time windows.
- **Response**: `relationships_created`, `evidence_evaluated`, `strategy_counts`.

### `GET /correlation/relationships`
Queries discovered relationships.
- **Query Parameters**: `investigation_id`, `relationship_type`, `min_weight`, `sort_by`, `order`, `limit`, `offset`.

### `GET /correlation/relationships/{relationship_id}`
Retrieves detailed relationship metadata, source/target evidence IDs, and contextual connection attributes.

---

## 8. Activity Clustering

### `POST /activities/sources/{source_id}/form`
Synthesizes correlated relationships and finding chains into coherent activity threads.
- **Response**: `activities_created`, `activities_reused`.

### `GET /activities`
Queries activity clusters for an investigation.
- **Query Parameters**: `investigation_id`, `activity_type`, `status`, `limit`, `offset`.

### `GET /activities/{activity_id}`
Retrieves a single activity cluster with root entity, timeline bounds, constituent `evidence_ids`, and `finding_ids`.

---

## 9. Dual-Level Prioritization

### `POST /prioritization/investigations/{investigation_id}/baseline`
Executes heuristic scoring over individual evidence records ($0 - 100$).

### `POST /prioritization/investigations/{investigation_id}/contextual`
Scores aggregated activity clusters based on severity, anomaly weights, and threat density ($0 - 100$).

### Priority Tier Mapping

| Score Range | Tier | Description |
| :---: | :---: | :--- |
| **80 – 100** | `CRITICAL` | Confirmed high-impact threats, credential dumps, active adversary execution. |
| **60 – 79** | `HIGH` | Suspicious scripts, anomalous admin behaviors, IOC matches. |
| **40 – 59** | `MEDIUM` | Statistical outliers, policy anomalies, unverified external connections. |
| **20 – 39** | `LOW` | Minor behavioral deviations with low threat confidence. |
| **0 – 19** | `INFORMATIONAL` | Normal baseline forensic events for contextual timeline building. |

### `GET /prioritization/results`
Queries calculated priority results.
- **Query Parameters**: `investigation_id`, `method_type`, `target_type`, `priority_tier`, `min_score`, `limit`, `offset`.

### `GET /prioritization/results/{result_id}`
Retrieves a priority score along with transparent `factor_breakdown` (explainability metrics).

---

## 10. Sample Datasets

### `GET /examples`
Lists all pre-bundled forensic example datasets available on the workstation.

### `GET /examples/{filename}`
Streams the specified sample dataset file for ingestion testing.

---

## 11. Forensic Report Generation

### `GET /investigations/{investigation_id}/report/preflight`
Verifies that all required case metadata, evidence sources, and findings exist prior to compiling the final PDF.

### `GET /investigations/{investigation_id}/report`
Compiles and streams a forensic PDF report generated with ReportLab.
- **Response**: `200 OK`, `Content-Type: application/pdf`, `Content-Disposition: attachment; filename="report-CASE-XXXX.pdf"`.
