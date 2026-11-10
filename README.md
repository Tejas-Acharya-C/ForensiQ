# ForensiQ

> **Local-First Digital Forensics Triage & Evidence Prioritization Platform**

ForensiQ is an offline, local-first digital forensics workstation and analytical triage system. It enables incident responders and forensic investigators to ingest multi-format evidence logs (CSV, JSON, JSONL), verify cryptographic bit-level integrity, normalize records into a canonical schema, detect threats via deterministic rules and unsupervised machine learning, discover multi-dimensional correlations, cluster events into coherent activities, prioritize high-risk artifacts with transparent explainability, and compile publication-ready executive forensic PDF reports.

---

## 1. Problem Statement

Modern cybersecurity incidents and digital investigations confront analysts with overwhelming volumes of disparate log data across host, network, authentication, and process telemetry. Investigators face severe operational hurdles:
- **High Noise-to-Signal Ratios**: Thousands of benign system events obscure genuinely malicious adversary actions.
- **Fragmented Evidence Formats**: Disparate logs lack unified temporal schemas, field names, and entity representations.
- **Manual Correlation Burden**: Manually cross-referencing IP addresses, user accounts, and process trees across separate log files is labor-intensive and prone to oversight.
- **Risk of Silent Corruption**: Accidental modification, disk degradation, or improper storage can undermine evidence validity.
- **Opaque Risk Scoring**: Many commercial security tools generate black-box alert scores without clear provenance back to the underlying raw log records.

ForensiQ solves these challenges by providing an automated, deterministic, and traceable local forensic analysis workstation that transforms raw unstructured logs into clear, defensible investigative findings.

---

## 2. Core Features

- **Investigation Case Management**: Create, view, switch, and manage isolated investigation containers with case tracking and investigator milestone checklists.
- **Multi-Format Evidence Ingestion**: Direct upload support for CSV, JSON arrays, and JSONL log files up to 50 MB with automatic header detection and encoding fallback.
- **Cryptographic Source Integrity Verification**: Recomputes SHA-256 digests over immutable stored evidence sources on demand to verify bit-level integrity against ingestion baselines.
- **Canonical Event Schema (CES) Normalization**: Normalizes incoming logs across nine core dimensions: timestamp, event type, user, device/host, process, IP address, port, file path/hash, and status.
- **Deterministic Threat Detection**: YAML-based rule matching mapped to MITRE ATT&CK techniques (e.g., suspicious PowerShell flags, Mimikatz credential dumping, brute-force patterns, and malicious IP indicators).
- **Unsupervised ML Anomaly Detection**: Isolation Forest algorithm trained on behavioral telemetry to detect statistical outliers without requiring prior attack labels.
- **Multi-Dimensional Correlation Engine**: Automatically discovers relational connections across shared IP addresses, user accounts, host workstations, and process lineages within configurable sliding time windows.
- **Activity Clustering**: Synthesizes correlated relationships into unified chronological attack chains with designated root entities.
- **Dual-Level Prioritization Engine**: Scores both individual evidence records ($0 - 100$) and composite activities with transparent factor breakdowns (severity, confidence, anomaly weight, asset criticality).
- **Comprehensive Evidence Inspector**: Search, sort, paginate, inspect, and filter normalized evidence records with slide-out raw payload viewing and interactive SHA-256 status badges.
- **Forensic PDF Report Generator**: Generates formatted, self-contained executive PDF investigation reports via ReportLab with case summaries, activity metrics, findings tables, and methodology disclaimers.

---

## 3. System Architecture

ForensiQ is architected as a local-first modular workstation:

```
+------------------------------------------------------------------------+
|                          ForensiQ Workstation                          |
|                                                                        |
|  +------------------------------------------------------------------+  |
|  |             Frontend Interface (Vanilla ES6 SPA / CSS3)          |  |
|  |   - Investigation Operations Center   - Evidence Inspector       |  |
|  |   - Findings Quick Filters            - Correlations & Clustering|  |
|  |   - Priority Results & Explainability - PDF Report Generator     |  |
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

### Key Architectural Boundaries
- **Strict Loopback Binding**: All endpoints bind strictly to `127.0.0.1` (localhost), preventing exposure on local networks or untrusted interfaces.
- **Single-Investigator Operation**: Streamlined local workflow without authentication tokens, sessions, or multi-tenant complexity.
- **External Data Isolation**: Application databases and stored evidence files reside in dedicated user-local directories outside the repository root (`%LOCALAPPDATA%\ForensiQ` on Windows).

---

## 4. Technology Stack

- **Backend Framework**: [FastAPI](https://fastapi.tiangolo.com/) `0.115.5` with [Uvicorn](https://www.uvicorn.org/) `0.32.1`
- **Data Validation & Schemas**: [Pydantic v2](https://docs.pydantic.dev/) `2.10.3` & `pydantic-settings` `2.6.1`
- **Database & Migrations**: [SQLAlchemy](https://www.sqlalchemy.org/) `2.0.38` (async SQLite) with [Alembic](https://alembic.sqlalchemy.org/) `1.14.0`
- **Machine Learning**: [Scikit-Learn](https://scikit-learn.org/) `1.6.0` (Isolation Forest) and [NumPy](https://numpy.org/) `2.4.6`
- **Report Generation**: [ReportLab](https://www.reportlab.com/) `4.2.5`
- **Frontend Architecture**: Vanilla HTML5, Modern CSS3 (Dark Glassmorphism Workstation UI), Vanilla JavaScript (ES6 SPA architecture, zero npm/build dependencies)
- **Testing**: [Pytest](https://pytest.org/) `9.0.3` with `pytest-asyncio` `0.24.0`

---

## 5. Security & Privacy Model

- **Zero Cloud Dependencies**: ForensiQ never sends evidentiary data, metrics, or telemetry to external servers. All computation runs 100% locally.
- **Bit-Level Integrity Guarantee**: Raw evidence files are hashed immediately upon arrival. On-demand verification recomputes SHA-256 hashes against disk files to detect tampering or corruption.
- **Air-Gapped Operation**: Completely operational on isolated or air-gapped forensic analysis machines without Internet access.

---

## 6. Prerequisites

- **Python**: `3.11.x` or newer (tested on Python 3.11/3.12).
- **Git**: 2.30+ for repository management.
- **Operating System**: Windows 10/11, macOS, or Linux.

---

## 7. Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/your-org/forensiq.git
cd forensiq
```

### 2. Set Up Virtual Environment
```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux / macOS (Bash)
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r backend/requirements.txt
```

### 4. Verify Environment Preflight
```bash
python scripts/check_environment.py --import-app --check-migrations
```

### 5. Initialize the Database
```bash
cd backend
alembic upgrade head
cd ..
```

---

## 8. Running the Application

### Option A: PowerShell Helper (Windows)
```powershell
.\scripts\start.ps1
```

### Option B: Direct Uvicorn Launch
```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Accessing the Web Interface
Open your web browser and navigate to:
```
http://127.0.0.1:8000
```
The ForensiQ Investigation Operations Center loads immediately.

- **Interactive API Documentation (Swagger)**: `http://127.0.0.1:8000/docs`
- **Alternative API Documentation (ReDoc)**: `http://127.0.0.1:8000/redoc`

---

## 9. Quickstart: 5-Step Investigation Walkthrough

1. **Create an Investigation**:
   Click **"New Investigation"** on the Operations Center, assign a title (e.g. `Server Alpha Triage`), and select `Create`.
2. **Ingest Evidence**:
   Drag and drop `data/samples/insider_threat_triage.csv` into the Evidence Ingestion panel and click **"Upload Evidence"**.
3. **Verify Integrity**:
   Inspect the evidence source in the Evidence Inspector and click **"Verify Integrity"** to confirm the SHA-256 digest matches the ingestion baseline.
4. **Execute Analysis**:
   Click **"Analyze Investigation"** in the Operations Center. The 7 pipeline stages run automatically (Normalization $\rightarrow$ Rules $\rightarrow$ ML $\rightarrow$ Correlation $\rightarrow$ Activities $\rightarrow$ Prioritization).
5. **Review Findings & Export Report**:
   Filter findings using the interactive metric pills (`Critical`, `High`, `Medium`, `Low`), inspect correlated attack chains, and click **"Export PDF Report"** to compile the executive summary.

---

## 10. Common Evidence Schema (CES)

ForensiQ normalizes heterogeneous log formats into a standardized Common Evidence Schema:

| Field | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `timestamp` | ISO-8601 UTC | Event occurrence timestamp | `2026-10-29T14:32:00Z` |
| `event_type` | String | Standardized action category | `PROCESS_START`, `AUTH_LOGIN` |
| `user_id` | String | Subject username or principal | `admin_svc`, `jdoe` |
| `device_id` | String | Target hostname or system ID | `WKSTN-SEC-01` |
| `process_name` | String | Executable name | `powershell.exe`, `mimikatz.exe` |
| `process_command_line` | String | Full invocation arguments | `powershell -enc ...` |
| `source_ip` | IPv4 / IPv6 | Originating IP address | `192.168.1.105` |
| `destination_ip` | IPv4 / IPv6 | Target IP address | `10.0.0.5` |
| `destination_port` | Integer | Network service port | `445`, `4444` |
| `file_hash_sha256` | String | SHA-256 hash of target file | `e3b0c442...` |
| `status` | String | Execution outcome | `SUCCESS`, `FAILURE` |

---

## 11. Deterministic Rule Authoring

Rules are declared in YAML under `data/rules/default_rules.yaml`. Example rule definition:

```yaml
rules:
  - id: "PROC-001"
    name: "Suspicious PowerShell Execution"
    description: "Detects PowerShell execution with bypass flags or encoded commands"
    severity: "HIGH"
    category: "PROCESS_EXECUTION"
    conditions:
      process_name: "powershell.exe"
      process_command_line_contains:
        - "-EncodedCommand"
        - "-enc"
        - "-ExecutionPolicy Bypass"
        - "-nop"
```

For comprehensive rule matching criteria, condition operators, and IOC configuration, see the [Rule Authoring Guide](docs/rule-authoring.md).

---

## 12. Automated Verification & Testing

ForensiQ maintains an automated test suite guaranteeing zero regressions across the analytical engine:

```bash
# Run all automated tests
pytest backend/tests/ -v

# Run sample evidence dataset validation
python scripts/validate_samples.py

# Run static syntax and formatting checks
node --check frontend/app.js
git diff --check
```

**Test Verification Status**:
- **Total Tests**: 190 passed (100% pass rate)
- **Execution Time**: ~99 seconds
- **Zero Regressions**: Ingestion, ML Anomaly Detection, Rule Matching, Correlation, Clustering, Prioritization, Report Generation.

---

## 13. Documentation Directory

Detailed technical references are organized in `docs/`:

- [System Architecture & Forensic Pipeline](docs/architecture.md): Architectural boundaries, local storage engine, and technical deep dive into all 7 analytical stages.
- [Setup & Troubleshooting Guide](docs/setup.md): Environment prerequisites, virtual environment initialization, preflight checks, and diagnostics catalog.
- [REST API Specification Reference](docs/api-reference.md): Complete specifications for all endpoints across all 11 router domains.
- [Rule & IOC Authoring Guide](docs/rule-authoring.md): Schema, condition matchers, IOC feeds, and test validation for threat detection rules.
- [Testing Strategy & Verification Guide](docs/testing.md): Test architecture, suite execution commands, pipeline concurrency verification, and sample validation.

---

## 14. Forensic Disclaimer & Limitations

> [!IMPORTANT]
> **Forensic Disclaimer**:
> ForensiQ is designed as an analytical triage, correlation, and evidence prioritization platform. It is intended to accelerate the initial investigative phases of incident response.
>
> - **Not a Substitute for Forensic Disk Imaging**: ForensiQ parses and analyzes log files; it does not replace certified hardware write-blockers or disk imaging suites (e.g., FTK Imager, dd, EnCase).
> - **Integrity vs. Courtroom Chain-of-Custody**: The on-demand SHA-256 verification confirms bit-level file integrity against the local ingestion baseline. It verifies that stored files have not suffered local tampering or disk corruption; it does not establish statutory legal chain of custody or legal evidence admissibility under ISO/IEC 17025.
> - **Digital Signatures**: Exported PDF reports are structured investigative summaries; they do not include cryptographic X.509 digital signatures.

---

## 15. License

ForensiQ is licensed under the [MIT License](LICENSE).
