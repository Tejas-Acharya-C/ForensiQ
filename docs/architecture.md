# ForensiQ — Current Architecture

## 1. Project Structure
The repository contains the following core directories:
- `backend/`: FastAPI application, APIs, SQLite models, migrations, and core analytical pipeline logic.
- `frontend/`: Vanilla HTML/JS frontend application connecting to the REST API.
- `data/`: Contains sample datasets (e.g. `example_evidence.csv`) and rule definitions.
- `scripts/`: Development utilities (e.g., reset DB, create user).

## 2. Frontend Architecture
The frontend is a lightweight Single Page Application using vanilla HTML (`index.html`), Javascript (`app.js`), and CSS (`styles.css`). It communicates directly with the FastAPI backend via REST. State management is manual via DOM manipulation.

## 3. Backend Architecture
The backend is built with FastAPI and runs on Uvicorn. It is structured into clearly separated domains:
- `api/`: REST routing and controllers.
- `core/`: Config, auth, error handling, rate limiting.
- `database/`: Session management and SQLAlchemy base.
- `models/` and `schemas/`: SQLAlchemy ORM and Pydantic validation respectively.
- `ingestion/`, `normalization/`: ETL pipeline modules.
- Core pipeline logic files (`detection.py`, `correlation.py`, `activities.py`, `prioritization.py`, `report.py`).

## 4. Database Architecture
Uses SQLite (`forensiq.db`) with SQLAlchemy ORM.
Models include `User`, `Investigation`, `EvidenceSource`, `Evidence`, `Finding`, `Relationship`, `Activity`, and `PriorityResult`. Alembic is used for migrations (found in `backend/alembic`).

## 5. Processing Pipeline
The analytical pipeline executes in the following strict stages:
1. **Evidence Ingestion** & **Normalization**: Parses CSV/JSON/JSONL to unified format.
2. **Detection**: Applies deterministic rules (`data/rules/default_rules.yaml`).
3. **ML Anomaly**: Behavioral ML anomaly scoring (requires >= 10 records).
4. **Correlation**: Discovers relationships (same host, user, process).
5. **Activity Clustering**: Groups correlated evidence into coherent threads.
6. **Prioritization**: Generates risk scoring for individual evidence and grouped activities.

## 6. API Structure
Key endpoints found in `backend/app/api/v1`:
- `/auth`: Login and token generation.
- `/investigations`: Case management.
- `/evidence`: File upload and normalization.
- `/detection`, `/ml`, `/correlation`, `/activities`, `/prioritization`: Triggering pipeline stages and retrieving results.
- `/report`: End-of-case exports.

## 7. Authentication
Simple JWT Bearer authentication is implemented. Users are stored in the SQLite DB and passwords are hashed.

## 8. Testing
A robust `pytest` suite is located in `backend/tests/`, thoroughly verifying the analytical pipeline (e.g., `test_s12_end_to_end.py` for full lifecycle tests), idempotency, and error handling. Tests use an isolated `test_forensiq.db`.

## 9. Known Limitations
- The frontend state management is manual vanilla JS, which is brittle for complex interactions.
- ML and Clustering stages mandate minimal threshold data (e.g., >= 10 records) to fire correctly.
- SQLite limits concurrency.

## 10. Technical Debt
- Lack of a robust frontend framework (React/Vue/Svelte) will hinder scaling UI complexity.
- Testing currently leaves some generated files behind which we mitigated in this cleanup iteration, but test generation scripts could be improved.
- Duplicate models/schemas naming overlaps could be consolidated.

## 11. Future Development Considerations
- **Architecture Refactoring**: Migrate from SQLite to PostgreSQL if multi-user concurrent ingestion is required.
- **Frontend Refactor**: Port the vanilla JS interface to a framework like React/Next.js for better component reusability and maintainability.
- **Pipeline Extensibility**: Implement a plugin architecture for the Detection and ML phases rather than hardcoded logic.
