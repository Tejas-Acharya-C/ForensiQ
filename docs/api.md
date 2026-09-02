# ForensiQ REST API Specification

This document details the REST API endpoints available in ForensiQ (`/api/v1`). All endpoints return JSON unless specified otherwise.

---

## Base URL
```
http://localhost:8000/api/v1
```

## Authentication & Headers
Except for `/auth/login` and `/health`, all endpoints require JWT authentication passed in the request header:
```http
Authorization: Bearer <your_jwt_access_token>
```

---

## 1. Authentication (`/auth`)

### `POST /auth/login`
Authenticates a user and returns a JWT access token.
- **Request Body** (`application/x-www-form-urlencoded` or JSON):
  ```json
  {
    "username": "admin@forensiq.local",
    "password": "YourSecurePassword"
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1Ni...",
    "token_type": "bearer"
  }
  ```

---

## 2. Cases & Investigations (`/investigations`)

### `GET /investigations`
Lists all active investigation cases for the authenticated user.
- **Response** (`200 OK`):
  ```json
  [
    {
      "id": "c1f7a29e-...",
      "case_number": "CASE-2026-001",
      "title": "Insider Data Exfiltration",
      "description": "Investigating suspicious PowerShell & C2 network traffic",
      "status": "OPEN",
      "created_at": "2026-09-02T12:00:00Z"
    }
  ]
  ```

### `POST /investigations`
Creates a new investigation case.
- **Request Body**:
  ```json
  {
    "case_number": "CASE-2026-002",
    "title": "Ransomware Execution Investigation",
    "description": "Suspicious Mimikatz and LSASS dump detected",
    "status": "OPEN"
  }
  ```
- **Response** (`201 Created`)

---

## 3. Evidence Ingestion & Normalization (`/evidence`)

### `POST /evidence/upload`
Uploads a raw forensic evidence file (`.csv`, `.json`, `.jsonl`) attached to an investigation.
- **Content-Type**: `multipart/form-data`
- **Form Data**:
  - `investigation_id`: `<uuid>`
  - `file`: `<binary_file_data>`
- **Response** (`201 Created`): Returns `EvidenceSource` metadata object.

### `POST /evidence/sources/{source_id}/normalize`
Executes canonical field mapping and timestamp normalization on uploaded raw logs.
- **Response** (`200 OK`): Returns normalized count and status.

---

## 4. Detection Engine (`/detection` & `/ml`)

### `POST /detection/investigations/{investigation_id}/run`
Executes SIGMA/YARA-style deterministic rule matching and IP/Hash IOC checks.
- **Response** (`200 OK`):
  ```json
  {
    "findings_generated": 4,
    "rules_matched": ["PROC-001", "PROC-002", "IOC-IP-001"]
  }
  ```

### `POST /ml/investigations/{investigation_id}/run-anomaly`
Runs unsupervised Isolation Forest anomaly detection on log behavior (requires $\ge 10$ records).
- **Response** (`200 OK`)

---

## 5. Correlation & Activity Clustering (`/correlation` & `/activities`)

### `POST /correlation/investigations/{investigation_id}/correlate`
Discovers multi-dimensional evidence relationships across IP, Host, User, and Process fields.
- **Response** (`200 OK`)

### `POST /activities/investigations/{investigation_id}/cluster`
Assembles correlated relational graph edges into chronological attack activity threads.
- **Response** (`200 OK`)

---

## 6. Risk Prioritization (`/prioritization`)

### `POST /prioritization/investigations/{investigation_id}/prioritize-evidence`
Calculates risk scores ($0 - 100$) for individual evidence items.

### `POST /prioritization/investigations/{investigation_id}/prioritize-activities`
Calculates risk scores for grouped activity chains.

---

## 7. Executive Report Export (`/report`)

### `GET /report/investigations/{investigation_id}/export-pdf`
Generates and downloads a formatted PDF executive triage report.
- **Response**: `200 OK` with `Content-Type: application/pdf` binary stream.
