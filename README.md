# ForensiQ

AI-Assisted Digital Forensic Triage & Evidence Prioritization Platform.

---

## First-Time Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run database migrations

```bash
alembic -c alembic.ini upgrade head
```

This creates an empty schema. No data is inserted.

### 3. Create the first user

```bash
python scripts/create_first_user.py
```

The script will prompt for an email address and password.
It will refuse to run if a user already exists.

### 4. Start the application

```bash
uvicorn app.main:app --app-dir backend --reload
```

Or with Docker:

```bash
docker compose up -d
```

### 5. Log in

Open your browser at `http://localhost:8000` and log in with the credentials you just created.

### 6. Create a case

Click **+ New Case** to create your first investigation.

### 7. Upload evidence

Click **Import Evidence** and upload a CSV, JSON, or JSONL file.

**See `data/examples/example_evidence.csv` for an optional example input file.**

### 8. Normalize

Click **Normalize** (or the Normalize button on the source row) to parse the raw records into the canonical evidence schema.

### 9. Run analysis stages

Run each stage in order from the Pipeline Controls bar:

- **Run Detections** — applies deterministic rules and IOC matching
- **Run ML Anomaly** — unsupervised behavioral anomaly detection (requires ≥10 records)
- **Correlate** — discovers multi-dimensional evidence linkages (requires ≥2 records)
- **Cluster Activities** — groups related evidence into coherent activity threads
- **Prioritize Evidence** — scores each evidence record
- **Prioritize Activities** — scores each activity cluster

---

## Accepted Evidence Formats

ForensiQ accepts three file formats:

| Format | Description |
|--------|-------------|
| **CSV** | Comma-separated values with a header row |
| **JSON** | A top-level JSON array of objects (`[{...}, {...}]`) |
| **JSONL** | One JSON object per line (newline-delimited JSON) |

**The only mandatory field is a valid timestamp.** All other fields are optional and are mapped automatically when recognized.

Common recognized field names:

| Field | Example column names |
|-------|---------------------|
| Timestamp | `timestamp`, `time`, `event_time`, `created_at`, `TimeCreated` |
| Event type | `event_type`, `event`, `EventID`, `action_type`, `type` |
| User | `user_id`, `user`, `username`, `UserName`, `account` |
| Device / host | `device_id`, `host`, `hostname`, `computer`, `machine` |
| Process | `process_name`, `process`, `Image`, `exe` |
| IP address | `ip_address`, `ip`, `DestinationIp`, `src_ip`, `client_ip` |
| Port | `port`, `DestinationPort`, `dest_port` |
| Protocol | `protocol`, `proto` |
| File path | `file_path`, `path`, `TargetFilename`, `filename` |
| File hash | `file_hash`, `hash`, `sha256`, `md5` |
| Status | `status`, `result`, `outcome` |
| Action | `action`, `command`, `operation`, `method` |

See `data/examples/example_evidence.csv` for a minimal working example.

---

## Developer Utilities

### Reset local development data

```bash
python scripts/reset_local_data.py
```

**WARNING:** This permanently deletes the local SQLite database and clears uploaded evidence files.
Requires typed confirmation. Only works on local SQLite databases — refuses PostgreSQL.

---

## Running Tests

```bash
python -m pytest backend/tests/ -v
```
