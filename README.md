# ForensiQ

> **AI-Assisted Digital Forensic Triage & Evidence Prioritization Platform**

ForensiQ is an enterprise-grade digital forensic investigation platform designed to ingest raw forensic logs (CSV, JSON, JSONL), normalize them into a canonical schema, detect threats using deterministic SIGMA/YARA-style rules and unsupervised machine learning, correlate multi-source events, cluster activities, score risk priorities, and export comprehensive executive PDF investigation reports.

---

## Technical Stack

- **Backend**: FastAPI (`0.115.5`), Uvicorn (`0.32.1`), Pydantic v2 (`2.10.3`), SQLAlchemy (`2.0.38`), Alembic (`1.14.0`)
- **Machine Learning & Analysis**: Scikit-Learn (`1.6.0`), Pandas (`2.2.3`), NumPy (`2.4.6`)
- **PDF Reporting**: ReportLab (`4.2.5`)
- **Authentication**: JWT Bearer Auth (`python-jose`, `bcrypt`, `cryptography`)
- **Frontend**: Vanilla HTML5, JetBrains Mono & Inter Google Fonts, Vanilla CSS3 (Dark Glassmorphism UI), Vanilla JavaScript (ES6 SPA architecture)
- **Database**: SQLite (Development / Single-node) / PostgreSQL (Production ready via SQLAlchemy)

---

## Quick Start & First-Time Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

For development and testing dependencies:

```bash
pip install -r requirements-dev.txt
```

### 2. Run Database Migrations

Initialize the database schema using Alembic:

```bash
alembic -c alembic.ini upgrade head
```

### 3. Create First Administrative User

Execute the interactive user creation utility script:

```bash
python scripts/create_first_user.py
```

*Note: The script will prompt for your email address and password. It will safely refuse to execute if an admin user already exists.*

### 4. Start Application Server

Start the Uvicorn dev server:

```bash
uvicorn app.main:app --app-dir backend --reload
```

Or using Docker Compose:

```bash
docker compose up -d --build
```

### 5. Access the Web Console

Open your web browser and navigate to:
```
http://localhost:8000
```
Log in using the administrator credentials created in **Step 3**.

---

## End-to-End Investigation Workflow

1. **Create an Investigation Case**:
   - Click **+ New Case** in the top navigation bar to initialize a dedicated investigation environment.
2. **Import Evidence**:
   - Click **Import Evidence** and upload forensic log files (`.csv`, `.json`, or `.jsonl`).
   - Sample datasets are available in `data/examples/` (e.g., `sample_auth_attack.csv`, `sample_malware_process.csv`, `sample_network_c2.csv`, `sample_multistage_compromise.csv`).
3. **Normalize Evidence**:
   - Click **Normalize** on the source row to parse raw key-value logs into ForensiQ's canonical schema.
4. **Execute Analytical Pipeline Stages**:
   - **Run Detections**: Executes deterministic SIGMA-style rule matching (`data/rules/default_rules.yaml`) and IP/Hash IOC matching.
   - **Run ML Anomaly**: Runs unsupervised Isolation Forest anomaly detection on log behavior (requires $\ge 10$ records).
   - **Correlate**: Discovers relationships across IP, User, Host, and Process dimensions (requires $\ge 2$ records).
   - **Cluster Activities**: Assembles correlated events into chronological attack chains/threads.
   - **Prioritize Evidence**: Calculates risk scores ($0 - 100$) for individual evidence items.
   - **Prioritize Activities**: Aggregates risk scores to rank investigation activities by threat severity.
5. **Export PDF Executive Report**:
   - Navigate to **Reports** and click **Export PDF Report** to generate a formatted forensic triage report.

---

## Accepted Forensic Log Formats

ForensiQ automatically auto-maps incoming fields during normalization. Supported input file formats:

| Format | Structure |
| :--- | :--- |
| **CSV** | Comma-separated values with header row |
| **JSON** | JSON array of record objects (`[{...}, {...}]`) |
| **JSONL** | Newline-delimited JSON objects |

### Field Auto-Mapping Reference

| Canonical Field | Recognized Incoming Headers |
| :--- | :--- |
| **Timestamp** *(Mandatory)* | `timestamp`, `time`, `event_time`, `created_at`, `TimeCreated`, `date` |
| **Event Type** | `event_type`, `event`, `EventID`, `action_type`, `type`, `log_type` |
| **User / Account** | `user_id`, `user`, `username`, `UserName`, `account`, `SubjectUserName` |
| **Host / Device** | `device_id`, `host`, `hostname`, `computer`, `machine`, `Workstation` |
| **Process** | `process_name`, `process`, `Image`, `exe`, `ProcessName` |
| **IP Address** | `ip_address`, `ip`, `DestinationIp`, `src_ip`, `client_ip`, `IpAddress` |
| **Port** | `port`, `DestinationPort`, `dest_port`, `src_port` |
| **File Path / Hash** | `file_path`, `path`, `TargetFilename`, `hash`, `sha256`, `md5` |
| **Status / Outcome** | `status`, `result`, `outcome`, `Status`, `sub_status` |

---

## Development & Utility Scripts

All maintenance utilities are located in the `scripts/` directory:

| Utility Script | Description |
| :--- | :--- |
| `python scripts/check_db.py` | Validates SQLite database connection and table integrity. |
| `python scripts/create_first_user.py` | Interactive script to create initial admin user. |
| `python scripts/reset_local_data.py` | Permanently resets local SQLite database and clears uploaded file caches. |
| `python scripts/validate_samples.py` | Validates format compatibility of sample CSV files in `data/examples/`. |

---

## Running Test Suite

ForensiQ features an automated test suite powered by `pytest` covering authentication, ingestion, normalization, detection, correlation, ML, prioritization, and PDF report generation.

Run the test suite:

```bash
pytest backend/tests -v
```

All 61 test cases run in isolation using a separate test database (`test_forensiq.db`).
