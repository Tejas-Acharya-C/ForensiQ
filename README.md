# ForensiQ

> **Local-First Digital Forensics Triage & Evidence Prioritization Platform**

ForensiQ is a local-first digital forensics investigation workstation and analytical triage system. It enables forensic investigators to ingest multi-format evidence logs (CSV, JSON, JSONL), verify cryptographic bit-level integrity, normalize records into a canonical schema, detect threats via deterministic rules and unsupervised machine learning, discover multi-dimensional correlations, cluster events into coherent activities, prioritize high-risk artifacts with transparent explainability, and compile publication-ready executive forensic PDF reports.

---

## 1. Problem Statement

Modern cybersecurity incidents and forensic investigations confront analysts with overwhelming volumes of disparate log data across host, network, authentication, and process telemetry. Investigators face significant challenges:
- High noise-to-signal ratios obscuring genuine threats.
- Fragmented evidence formats lacking unified temporal schemas.
- Manual correlation that is labor-intensive and prone to oversight.
- Risk of unintentional evidence tampering or silent file corruption during analysis.
- Difficulty tracing executive findings back to the exact supporting raw evidence artifacts.

ForensiQ solves these challenges by providing an automated, deterministic, and traceable local forensic analysis workstation that bridges the gap between raw unstructured logs and clear, defensible investigative findings.

---

## 2. Core Objectives

1. **Local-First Data Protection**: Keep all evidentiary data strictly on the investigator's local workstation, bound exclusively to loopback interfaces with zero external cloud dependencies.
2. **Defensible Evidence Provenance**: Ensure every raw evidence file ingested has an immutable cryptographic baseline with on-demand verification.
3. **Structured Canonical Normalization**: Parse diverse log formats into a unified taxonomy preserving original timestamps, entities, outcomes, and raw payload attributes.
4. **Transparent Hybrid Detection**: Combine deterministic rule matching (MITRE ATT&CK aligned) with unsupervised machine learning anomaly detection.
5. **Traceable Findings**: Ensure every generated finding, activity cluster, and report entry can be traced directly to specific underlying evidence records.
6. **Dual-Level Risk Prioritization**: Prioritize both granular evidence records and aggregated activity clusters using explainable heuristic scoring algorithms.
7. **Traceable Reporting**: Produce structured, executive-ready PDF forensic investigation reports summarizing case metrics, methodology, timeline, findings, and technical forensic disclaimers.

---

## 3. Main Features

- **Investigation Case Management**: Create, view, switch, and manage isolated investigation cases with auto-generated case numbers and strict case boundaries.
- **Multi-Format Evidence Ingestion**: Direct upload support for CSV, JSON arrays, and JSONL log files up to 50 MB with automatic header mapping.
- **Cryptographic Source Integrity Verification**: Recomputes SHA-256 digests over immutable stored evidence sources on demand to verify bit-level integrity against ingestion baselines.
- **Canonical Event Normalization**: Normalizes incoming logs across nine core dimensions: timestamp, event type, user, device/host, process, IP address, port, file path/hash, and status.
- **Rule-Based Threat Detection**: Deterministic detection rules for critical adversary techniques (e.g., suspicious PowerShell execution, credential access tools like Mimikatz, brute-force authentication sequences, and malicious IP indicators).
- **Unsupervised ML Anomaly Detection**: Isolation Forest algorithm trained on numerical and behavioral features extracted from event telemetry to flag statistical outliers.
- **Multi-Source Event Correlation**: Discovers relational connections across shared IP addresses, user accounts, host workstations, and process lineages within defined temporal sliding windows.
- **Activity Clustering**: Groups correlated events into unified chronological narrative attack chains with designated root entities.
- **Dual-Level Prioritization Engine**: Scores both individual evidence records ($0 - 100$) and composite activities with transparent factor breakdowns (severity, confidence, anomaly weight, asset criticality).
- **Comprehensive Evidence Inspector**: Search, sort, paginate, inspect, and filter evidence records and trace findings to specific evidence IDs.
- **Forensic PDF Report Generator**: Generates formatted, self-contained PDF investigation reports via ReportLab with case summaries, activity metrics, findings tables, and methodology disclaimers.

---

## 4. System Architecture

ForensiQ is built as a single-investigator local workstation platform:

```
+------------------------------------------------------------------------+
|                          ForensiQ Workstation                          |
|                                                                        |
|  +------------------------------------------------------------------+  |
|  |             Frontend Interface (Vanilla ES6 SPA / CSS3)          |  |
|  |   - Overview Dashboard   - Evidence Inspector & Traceability     |  |
|  |   - Analysis & Pipeline  - Forensic PDF Report Generator         |  |
|  +---------------------------------+--------------------------------+  |
|                                    | HTTP / JSON REST API              |
|                                    v (127.0.0.1:8000)                  |
|  +------------------------------------------------------------------+  |
|  |                Backend Services (FastAPI / Python 3.11)          |  |
|  |   - Investigation Manager       - Evidence Ingestion & Verifier  |  |
|  |   - Normalization Pipeline      - Rule Engine & ML Isolation     |  |
|  |   - Correlation Engine          - Activity Clustering            |  |
|  |   - Prioritization Engine       - PDF ReportLab Engine           |  |
|  +---------------------------------+--------------------------------+  |
|                                    | SQLAlchemy 2.0 / Alembic          |
|                                    v                                   |
|  +------------------------------------------------------------------+  |
|  |                   Isolated Local Storage Engine                  |  |
|  |   - SQLite Database: %LOCALAPPDATA%\ForensiQ\database\           |  |
|  |   - Immutable Raw Evidence: %LOCALAPPDATA%\ForensiQ\sources\     |  |
|  |   - Staging Buffer: %LOCALAPPDATA%\ForensiQ\staging\             |  |
|  +------------------------------------------------------------------+  |
+------------------------------------------------------------------------+
```

### Key Architectural Boundaries:
- **Loopback Binding**: Strictly bound to `127.0.0.1` (localhost) to prevent exposure on local networks or untrusted interfaces.
- **Single-Investigator Model**: Streamlined local workflow without authentication tokens, sessions, or multi-tenant complexity.
- **External Data Isolation**: Application data and database files reside in dedicated user-local directories outside the repository root (`%LOCALAPPDATA%\ForensiQ` on Windows).

---

## 5. Technology Stack

- **Backend Framework**: [FastAPI](https://fastapi.tiangolo.com/) `0.115.5` with [Uvicorn](https://www.uvicorn.org/) `0.32.1`
- **Data Validation & Schemas**: [Pydantic v2](https://docs.pydantic.dev/) `2.10.3`
- **Database & Migrations**: [SQLAlchemy](https://www.sqlalchemy.org/) `2.0.38` (async/sync SQLite) with [Alembic](https://alembic.sqlalchemy.org/) `1.14.0`
- **Machine Learning**: [Scikit-Learn](https://scikit-learn.org/) `1.6.0` (Isolation Forest) and [NumPy](https://numpy.org/) `2.4.6`
- **Report Generation**: [ReportLab](https://www.reportlab.com/) `4.2.5`
- **Frontend**: Vanilla HTML5, Modern CSS3 (Dark Glassmorphism Workstation UI), Vanilla JavaScript (ES6 SPA architecture, zero npm/build dependencies)
- **Testing**: [Pytest](https://pytest.org/) `9.0.3` with `pytest-asyncio`

---

## 6. Seven-Stage Analysis Workflow

ForensiQ executes a deterministic 7-stage analytical pipeline:

| Stage # | Stage Name | Responsibility |
| :---: | :--- | :--- |
| **1** | **Ingest** | Validates log format (CSV/JSON/JSONL), computes original SHA-256 hash, and stores raw artifact immutably. |
| **2** | **Normalize** | Auto-maps incoming headers to canonical schema, validates timestamps, and persists normalized records. |
| **3** | **Detect (Rules)** | Executes deterministic YAML detection rules (MITRE ATT&CK techniques, malicious commands, IOCs). |
| **4** | **Detect (ML)** | Trains an unsupervised Isolation Forest on normalized features (requires $\ge 10$ records) to flag statistical anomalies. |
| **5** | **Correlate** | Identifies relational linkages across IP, User, Device, and Process dimensions within temporal windows (requires $\ge 2$ records). |
| **6** | **Prioritize** | Computes multi-factor risk scores ($0 - 100$) for evidence items and groups correlated events into prioritized activities. |
| **7** | **Report** | Aggregates all metrics, findings, timeline items, and evidence references into an executive PDF report. |

*Pipeline Guardrails*: Upstream stage failure halts execution cleanly to prevent cascading inaccuracies. Execution is idempotent; rerunning stages refreshes findings without generating duplicate records.

---

## 7. Evidence Ingestion & SHA-256 Integrity Verification

### Ingestion
When evidence files are imported:
1. The raw stream is hashed on-the-fly using `hashlib.sha256()`.
2. The file is copied to an isolated directory structure (`%LOCALAPPDATA%\ForensiQ\sources\<source_id>/original`).
3. The source record is recorded with file name, byte size, format, line count, and SHA-256 digest.

### On-Demand Verification
Investigators can click **Verify Integrity** on any evidence source:
- The backend streams the on-disk source file in 64 KB read-only binary chunks.
- Computes the live SHA-256 digest and compares it to the original stored baseline.
- **Verification Outcomes**:
  - `VERIFIED`: The file is cryptographically intact and matches the baseline digest bit-for-bit.
  - `FAILED`: Digest mismatch detected; flagged as `integrity_compromised`.
  - `SOURCE_MISSING`: Original source file is absent from disk storage.
  - `VERIFICATION_UNAVAILABLE`: Path traversal attempt or file permission error encountered.
- **Guarantee**: Verification runs strictly in read-only mode (`"rb"`); file contents, sizes, and timestamps are never modified.

---

## 8. Rule-Based & ML Detection Capabilities

### Deterministic Rule Engine
Rules are defined in YAML (`data/rules/default_rules.yaml`) and evaluated against normalized events:
- **`RULE-PROC-001`**: Suspicious Process Execution (`powershell.exe -enc`, `cmd.exe /c`, etc.).
- **`RULE-AUTH-SEQ-001`**: Brute-Force Authentication Sequence (multiple failed logins followed by a successful login for the same user within 300 seconds).
- **`RULE-PROC-002`**: Credential Dumping Tool Execution (`mimikatz.exe`, `procdump`, etc.).
- **`IOC-IP-001`**: Malicious C2 Communication matching known threat intelligence IP indicators.

### Unsupervised Machine Learning
- Uses Scikit-Learn's `IsolationForest` to analyze multidimensional feature vectors (hour of day, day of week, event type frequency, port ranges, status codes).
- Operates without labeled training data; dynamically isolates anomalous behavior.
- Requires a minimum of 10 events to ensure statistical validity; skips gracefully with clear explanatory messaging if the dataset is insufficient.

---

## 9. Event Correlation & Activity Clustering

- **Relational Discovery**: Inspects normalized evidence across configured sliding time windows (default: 300s) to discover co-occurring attributes:
  - `same_user`: Events initiated by the same account.
  - `same_ip`: Traffic to or from identical network endpoints.
  - `same_device`: Actions occurring on the same endpoint workstation.
  - `parent_child`: Process execution hierarchy linkages.
- **Activity Formation**: Assembles connected relationships into unified graph-connected components termed **Activities**. Each activity highlights root entities, event sequences, and total threat weight.

---

## 10. Evidence Prioritization & Explainability

ForensiQ provides dual-level risk scoring ($0 - 100$ scale) with full factor explainability:
- **Evidence Risk Score**: Combines rule severity weight, ML anomaly classification, IOC match weight, and asset criticality.
- **Activity Priority Score**: Aggregates component evidence scores and correlation breadth into an overall activity priority score.
- **Explainability**: Every prioritized item details the exact formula contributions (e.g., `severity_factor: 40`, `ml_anomaly_boost: 25`, `ioc_match: 20`) so analysts understand why an alert was elevated.

---

## 11. Finding-to-Evidence Traceability

ForensiQ guarantees bidirectionally linked evidence provenance:
- Every detection finding records the specific IDs of the evidence items that triggered it.
- In the **Evidence Inspector**, clicking a finding highlights and filters the exact supporting evidence records.
- In the finding detail view, analysts can inspect the full raw and normalized event telemetry directly supporting the finding.

---

## 12. Forensic PDF Reporting

Clicking **Download Report** invokes the ReportLab PDF compilation engine:
- **Header & Case Information**: Case number, investigator notes, creation timestamp, and total evidence counts.
- **Methodology & Forensic Disclaimer**: Explicit technical caveats regarding scope and verification standards.
- **Executive Summary Metrics**: High-level counts of evidence sources, records, findings, anomalies, and activities.
- **Findings Table**: Detailed tabular breakdown of all findings with severity, confidence, rule ID, and count of linked evidence items.
- **Timeline & Chronology**: Key events ordered by timestamp.
- **Activity Clusters**: Correlated event chains with root entities and risk scores.

---

## 13. Project Structure

```
ForensiQ/
├── .env.example                       # Safe configuration template
├── .gitignore                         # Comprehensive ignore rules
├── Dockerfile                         # Container build specification
├── docker-compose.yml                 # Local container orchestration
├── README.md                          # Project documentation
├── pyproject.toml                     # Pytest and tooling configuration
├── requirements.txt                   # Production dependencies
├── requirements-dev.txt               # Testing & development dependencies
├── alembic.ini                        # Database migration configuration
├── backend/
│   ├── alembic/                       # Alembic migration scripts
│   ├── app/
│   │   ├── api/v1/                    # REST API route handlers
│   │   ├── core/                      # Configuration, storage, and security
│   │   ├── database/                  # SQLAlchemy sessions and base models
│   │   ├── ingestion/                 # Log parsers and file handlers
│   │   ├── models/                    # Database ORM entity models
│   │   ├── normalization/             # Field mapping and canonical schemas
│   │   ├── schemas/                   # Pydantic request/response schemas
│   │   ├── activities.py              # Activity clustering logic
│   │   ├── correlation.py             # Relational correlation engine
│   │   ├── detection.py               # Rule-based and ML detection logic
│   │   ├── main.py                    # FastAPI application entrypoint
│   │   ├── prioritization.py          # Risk scoring and triage engine
│   │   └── report.py                  # ReportLab PDF generation service
│   └── tests/                         # Complete automated test suite
├── data/
│   ├── acceptance_fixtures/           # Synthetic CSV fixtures for acceptance testing
│   ├── examples/                      # Sample forensic logs (CSV) for demonstrations
│   └── rules/                         # Detection rule definitions (default_rules.yaml)
├── docs/                              # Architecture and REST API documentation
├── frontend/                          # Web workstation UI (HTML5 / CSS3 / JS)
└── scripts/
    ├── check_db.py                    # Database connectivity verification script
    ├── start.ps1                      # Windows PowerShell application launcher
    └── validate_samples.py            # Sample dataset validation script
```

---

## 14. Installation & Setup Instructions (Windows)

### Prerequisites
- **Python**: Version `3.11` or higher installed and added to `PATH`.
- **PowerShell**: Windows PowerShell 5.1 or PowerShell 7+.

### 1. Clone the Repository
```powershell
git clone https://github.com/Tejas-Acharya-C/ForensiQ.git
cd ForensiQ
```

### 2. Create and Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

---

## 15. Environment Configuration

Copy the example configuration to `.env`:
```powershell
Copy-Item .env.example .env
```

By default, ForensiQ stores data in your user-local application directory:
- **Windows**: `%LOCALAPPDATA%\ForensiQ\` (e.g. `C:\Users\<username>\AppData\Local\ForensiQ\`)
- **Linux/macOS**: `~/.local/share/forensiq`

To specify a custom storage directory, edit `.env`:
```ini
FORENSIQ_APP_DATA_DIR=C:/ForensiQData
```

---

## 16. Database Initialization & Migrations

The launcher checks the database selected by the current `.env` and environment
variables. It will not create a missing database or automatically upgrade an
existing database. To explicitly initialize a new SQLite database in
development, use:
```powershell
.\scripts\start.ps1 -InitializeDatabase
```

This option is limited to `APP_ENV=development`, an absolute SQLite path, and
an existing parent directory. Existing databases that are behind the current
Alembic head are left unchanged; back them up and review the pending migration
scripts before applying migrations manually.

To check connectivity without changing the database:
```powershell
.\.venv\Scripts\python.exe scripts\check_db.py
```

---

## 17. Running the Application

### Option A: Standard PowerShell Launcher (Recommended)
Use the included startup script, which uses only `.venv`, validates dependencies
and application imports, checks the configured database and migration revision,
and launches the server. It does not automatically migrate existing databases:
```powershell
.\scripts\start.ps1
```

### Option B: Direct Uvicorn Launch
```powershell
.\.venv\Scripts\uvicorn.exe app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

### Option C: Docker Compose
```powershell
docker compose up -d --build
```

### Accessing the Web Console
Open your web browser and navigate to:
```
http://127.0.0.1:8000
```
The ForensiQ investigation dashboard opens immediately.

---

## 18. Running the Automated Tests

ForensiQ includes a comprehensive test suite covering the full investigation lifecycle. Tests execute in complete isolation using a temporary SQLite database, guaranteeing that local data is never touched.

### Run the Full Test Suite
```powershell
$env:PYTHONPATH="backend"
python -m pytest backend/tests/ -v
```

### Verification Result
- **Total Tests Collected**: 101 tests
- **Passed**: 101 tests (100% pass rate)
- **Failed**: 0
- **Duration**: ~88 seconds

```
backend/tests/test_acceptance_workflow.py .......... [ 11%]
backend/tests/test_correlation_activities.py ..      [ 13%]
backend/tests/test_detection_ml.py .....             [ 18%]
backend/tests/test_detection_semantics.py ........... [ 36%]
backend/tests/test_idempotency.py ...........        [ 47%]
backend/tests/test_ingestion_normalization.py .      [ 48%]
backend/tests/test_investigations.py ....            [ 51%]
backend/tests/test_phase3_traceability.py ...        [ 54%]
backend/tests/test_phase4_workflow_hardening.py ...... [ 60%]
backend/tests/test_phase5_containment.py .           [ 61%]
backend/tests/test_phase8_qa.py ...................  [ 79%]
backend/tests/test_pipeline_errors.py ..             [ 81%]
backend/tests/test_prioritization.py ..              [ 83%]
backend/tests/test_report.py ...............         [ 98%]
backend/tests/test_s12_end_to_end.py ..              [100%]
======================= 101 passed =======================
```

---

## 19. Accepted Forensic Log Formats

| Format | Structure | Example Headers |
| :--- | :--- | :--- |
| **CSV** | Comma-separated with header row | `timestamp,event_type,user_id,device_id,process_name,ip_address,status` |
| **JSON** | JSON array of record objects | `[{"timestamp": "2026-10-29T10:00:00Z", "event_type": "process_create", ...}]` |
| **JSONL** | Newline-delimited JSON objects | `{"timestamp": "2026-10-29T10:00:00Z", "event_type": "auth_login", ...}\n` |

Sample datasets for immediate testing are available in `data/examples/`:
- `sample_auth_attack.csv` (Brute-force credential attempts)
- `sample_malware_process.csv` (Malicious process execution)
- `sample_network_c2.csv` (C2 beaconing activity)
- `sample_multistage_compromise.csv` (Full kill-chain simulation)
- `sample_normal_workstation.csv` (Baseline workstation activity)

---

## 20. Known Limitations & Forensic Disclaimer

### Technical Limitations
- **Single-Investigator Scope**: ForensiQ is designed strictly as a local single-investigator workstation bound to `127.0.0.1`. It does not include authentication, user accounts, or multi-tenant RBAC.
- **Network Interface**: ForensiQ must not be bound to public or external network interfaces without a reverse proxy providing TLS termination and authentication.
- **Cryptographic Scope**: The on-demand SHA-256 verification checks whether the stored raw evidence file matches its original ingestion digest. It verifies local bit-level integrity against accidental modification or tampering; **it does not establish external authenticity, hardware write-blocking, or statutory legal chain of custody**.
- **PDF Signature**: Generated PDF investigation reports are self-contained executive summaries; they do not contain X.509 cryptographic digital signatures.
- **Regulatory Status**: ForensiQ is an analytical triage and prioritization platform. It does not replace statutory evidence collection standards or formal forensic certification (e.g., ISO/IEC 17025).

---

## License

This project is open-source under the MIT License.
