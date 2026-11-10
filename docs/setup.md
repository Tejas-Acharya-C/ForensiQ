# ForensiQ Setup, Configuration & Troubleshooting Guide

This guide details installation, environment configuration, database initialization, launch procedures, and troubleshooting for the ForensiQ local forensic workstation.

---

## 1. Prerequisites

- **Operating System**: Windows 10/11, macOS, or Linux.
- **Python**: Version `3.11.x` or higher (verified with Python 3.11 and 3.12).
- **Git**: 2.30+ for version control.
- **Node.js**: (Optional) Only used for static syntax validation (`node --check frontend/app.js`). Not required for running the application.

---

## 2. Installation & Environment Setup

### Step 1: Clone Repository & Create Virtual Environment

```powershell
# Clone the repository
git clone https://github.com/your-org/forensiq.git
cd forensiq

# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux / macOS (Bash)
python3 -m venv .venv
source .venv/bin/activate
```

### Step 2: Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r backend/requirements.txt
```

#### Core Pinned Packages
- **FastAPI** (`0.115.5`) & **Uvicorn** (`0.32.1`): REST API framework and ASGI server.
- **SQLAlchemy** (`2.0.38`) & **Alembic** (`1.14.0`): Asynchronous ORM and schema migrations.
- **Pydantic** (`2.10.3`) & **pydantic-settings** (`2.6.1`): Typed schema validation and settings.
- **Scikit-learn** (`1.6.0`) & **NumPy** (`2.4.6`): Machine learning (Isolation Forest) and numerical analysis.
- **ReportLab** (`4.2.5`): Forensic PDF generation.
- **Pytest** (`9.0.3`) & **pytest-asyncio** (`0.24.0`): Automated test execution.

---

## 3. Configuration & Environment Variables

ForensiQ configuration is managed via `pydantic-settings` in `backend/app/core/config.py`. All variables have secure local defaults and can be customized via `.env`:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite+aiosqlite:///${LOCALAPPDATA}/ForensiQ/database/forensiq.db` | Async SQLite database URI. |
| `SYNC_DATABASE_URL` | `sqlite:///${LOCALAPPDATA}/ForensiQ/database/forensiq.db` | Synchronous SQLite URI for Alembic migrations. |
| `STORAGE_BASE_DIR` | `%LOCALAPPDATA%\ForensiQ\sources` | Immutable evidence storage directory. |
| `STAGING_BASE_DIR` | `%LOCALAPPDATA%\ForensiQ\staging` | Upload staging directory. |
| `HOST` | `127.0.0.1` | Loopback binding (external access disabled). |
| `PORT` | `8000` | Local HTTP port. |
| `ENVIRONMENT` | `development` | Deployment environment (`development`, `testing`, `production`). |

---

## 4. Preflight Check & Database Initialization

### Run Preflight Diagnostics
ForensiQ provides a preflight diagnostic script that verifies dependencies, imports, and database paths:

```bash
python scripts/check_environment.py --import-app --check-migrations
```

### Apply Alembic Database Migrations
Initialize or upgrade the local SQLite database schema:

```bash
cd backend
alembic upgrade head
cd ..
```

To verify the current database revision without making changes:
```bash
python scripts/check_db.py
```

---

## 5. Launching the Application

### Option A: PowerShell Helper (Windows)
```powershell
.\scripts\start.ps1
```

### Option B: Direct Uvicorn Launch
```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Accessing the Interface
- **Workstation UI**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **Alternative ReDoc**: `http://127.0.0.1:8000/redoc`
- **Health Check**: `http://127.0.0.1:8000/api/v1/health`

---

## 6. Troubleshooting & Diagnostics

### 1. `check_environment.py` Reports Missing Modules
- **Cause**: Active shell is not using `.venv`, or packages were installed to a different global Python environment.
- **Fix**:
  ```powershell
  .\.venv\Scripts\Activate.ps1
  pip install -r backend/requirements.txt
  ```

### 2. Port 8000 Conflict (`Address already in use` / `Errno 10048`)
- **Cause**: Another local process or previous Uvicorn instance is listening on port 8000.
- **Fix**:
  ```powershell
  # Locate and terminate the process
  Get-NetTCPConnection -LocalPort 8000
  Stop-Process -Id <PID> -Force

  # Or start Uvicorn on an alternate port
  python -m uvicorn backend.app.main:app --port 8080
  ```

### 3. Missing Tables (`OperationalError: no such table`)
- **Cause**: Database file was created without applying migrations.
- **Fix**:
  ```bash
  cd backend
  alembic upgrade head
  cd ..
  ```

### 4. Database Locked (`sqlite3.OperationalError: database is locked`)
- **Cause**: A hanging test or background process holds a write lock on SQLite.
- **Fix**: Close open server windows, terminate background Python processes (`Stop-Process -Name python -Force`), and restart.

### 5. ML Anomaly Detection Returns "Insufficient records"
- **Cause**: Isolation Forest requires $\ge 10$ records to compute meaningful statistical distributions.
- **Fix**: Ingest a dataset with at least 10 rows (such as `data/samples/insider_threat_triage.csv`). Datasets with fewer records are safely skipped by the pipeline.

### 6. File Encoding Errors During Ingestion
- **Cause**: Evidence file uses an uncommon character encoding (UTF-16 without BOM, Windows-1252 byte sequences).
- **Fix**: The parser automatically attempts fallback across UTF-8, UTF-8-SIG, and Latin-1. If issues persist, convert the file to standard UTF-8 before uploading.
