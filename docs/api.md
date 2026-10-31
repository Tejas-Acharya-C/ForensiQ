# ForensiQ REST API Reference

All endpoints are under `/api/v1`. No authentication is required (local single-investigator mode). Endpoints return JSON unless stated otherwise.

---

## Base URL
```
http://localhost:8000/api/v1
```

---

## 1. Health

### `GET /health`
Application, database, and storage health check.

**Response (`200 OK`):**
```json
{ "status": "healthy", "app_name": "ForensiQ", "environment": "development",
  "database_status": "connected", "storage_status": "healthy", "version": "0.1.0" }
```

---

## 2. Investigations (`/investigations`)

### `GET /investigations`
List all investigations with optional `?status=OPEN|CLOSED|ARCHIVED` filter.

### `POST /investigations`
Create a new investigation.
```json
{ "title": "Insider Threat Triage", "case_number": "CASE-2026-001",
  "description": "...", "status": "OPEN" }
```
**Response: `201 Created`**

### `GET /investigations/{id}`
Retrieve investigation detail.

### `PATCH /investigations/{id}`
Update title, description, or status.

### `GET /investigations/{id}/summary`
Unified dashboard aggregation (counts, tier breakdown, top priorities, sources).

### `GET /investigations/{id}/sources`
List evidence sources for the investigation.

### `GET /investigations/{id}/report`
Generate and download a PDF report.
**Response: `200 OK`, `Content-Type: application/pdf`**

---

## 3. Evidence Ingestion (`/evidence`)

### `POST /evidence/import`
Upload a raw evidence file (`multipart/form-data`).
- `investigation_id` (form field, UUID)
- `file` (form file, CSV / JSON / JSONL)
- `allow_duplicates` (form field, bool, default false)

**Response: `201 Created`**
```json
{ "source_id": "...", "sha256_hash": "...", "total_records": 16, "ingestion_status": "COMPLETED" }
```

### `POST /evidence/sources/{source_id}/normalize`
Normalize raw records into the Common Evidence Schema.
**Response: `200 OK`** — includes `normalized_records`, `rejected_records`, `warning_count`, `errors`.

### `GET /evidence`
Query normalized evidence records. Filters: `?investigation_id=`, `source_id=`, `event_type=`, `user_id=`, `device_id=`, `limit=`, `offset=`.

### `GET /evidence/{evidence_id}`
Retrieve a single evidence record.

---

## 4. Deterministic Detection (`/detection`)

### `POST /detection/sources/{source_id}/analyze-rules`
Run YAML detection rules and IOC matching over normalized evidence.
**Response:** `findings_created`, `findings_reused`, `evidence_evaluated`, `rules_evaluated`.

### `GET /detection/findings`
Query findings. Filters: `?investigation_id=`, `finding_type=RULE_MATCH|IOC_MATCH|ML_ANOMALY`, `min_severity=`, `limit=`, `offset=`.

### `GET /detection/findings/{finding_id}`
Retrieve a single finding.

---

## 5. ML Anomaly Detection (`/ml`)

### `POST /ml/sources/{source_id}/analyze`
Run Isolation Forest anomaly detection (requires ≥ 10 normalized records).
**Response:** `findings_created`, `evidence_evaluated`, `status`.

---

## 6. Correlation (`/correlation`)

### `POST /correlation/sources/{source_id}/analyze`
Discover multi-dimensional evidence relationships.
**Response:** `relationships_created`, `evidence_evaluated`, `strategy_counts`.

### `GET /correlation/relationships`
Query relationships. Filters: `?investigation_id=`, `relationship_type=`, `min_weight=`, `sort_by=weight|id`, `order=asc|desc`, `limit=`, `offset=`.

### `GET /correlation/relationships/{relationship_id}`
Retrieve a single relationship with full `context_attributes`.

---

## 7. Activities (`/activities`)

### `POST /activities/sources/{source_id}/form`
Cluster correlated evidence into activity threads.
**Response:** `activities_created`, `activities_reused`.

### `GET /activities`
Query activities. Filters: `?investigation_id=`, `activity_type=`, `status=`, `limit=`, `offset=`.

### `GET /activities/{activity_id}`
Retrieve a single activity with `evidence_ids` and `finding_ids`.

---

## 8. Prioritization (`/prioritization`)

### `POST /prioritization/investigations/{id}/baseline`
Score individual evidence artifacts (BASELINE_INDEPENDENT, 0–100).

### `POST /prioritization/investigations/{id}/contextual`
Score activity clusters (PROPOSED_CONTEXTUAL, 0–100).

### `GET /prioritization/results`
Query priority results. Filters: `?investigation_id=`, `method_type=`, `target_type=`, `priority_tier=`, `min_score=`, `limit=`, `offset=`.

### `GET /prioritization/results/{result_id}`
Retrieve a single priority result with full `factor_breakdown`.

---

## 9. Sample Evidence (`/examples`)

### `GET /examples`
List available sample evidence files (no authentication required).

### `GET /examples/{filename}`
Download a sample evidence CSV (no authentication required).

---

## Priority Tiers

| Score range | Tier |
|---|---|
| 80–100 | CRITICAL |
| 60–79 | HIGH |
| 40–59 | MEDIUM |
| 20–39 | LOW |
| 0–19 | INFORMATIONAL |
