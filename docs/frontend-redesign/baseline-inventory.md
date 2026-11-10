# ForensiQ Frontend Baseline Inventory

**Inspection Date:** 2026-11-09  
**Branch:** `feature/threat-discovery-phase1`  
**Application Entry Point:** `backend/app/main.py` (FastAPI serving static files from `frontend/` at `/`)  
**Frontend Architecture:** HTML5, CSS3, Vanilla JavaScript SPA (No build step, no npm/webpack/vite required at runtime)

---

## 1. Existing Working-Tree & Git Status

- **Current Git Branch:** `feature/threat-discovery-phase1` (tracking `origin/feature/threat-discovery-phase1`)
- **Uncommitted modified files:**
  - `README.md`
  - `backend/app/api/v1/detection.py`
  - `backend/app/api/v1/evidence.py`
  - `backend/app/api/v1/investigations.py`
  - `backend/app/api/v1/report.py`
  - `backend/app/ingestion/service.py`
  - `backend/app/models/__init__.py`
  - `backend/app/models/investigation.py`
  - `backend/app/report.py`
  - `backend/app/schemas/evidence.py`
  - `backend/app/schemas/finding.py`
  - `backend/app/schemas/investigation.py`
  - `frontend/app.js`
  - `frontend/index.html`
  - `frontend/styles.css`
  - `pyproject.toml`
  - `requirements.txt`
  - `scripts/check_db.py`
  - `scripts/start.ps1`
- **Untracked files (strictly preserved):**
  - `backend/alembic/versions/c1d2e3f4a5b6_add_finding_reviews_table.py`
  - `backend/alembic/versions/d2e3f4a5b6c7_add_investigator_notes_to_investigations.py`
  - `backend/app/models/finding_review.py`
  - `backend/app/schemas/finding_review.py`
  - `backend/app/schemas/report.py`
  - `backend/tests/test_ux_phase1.py`
  - `backend/tests/test_ux_phase2.py`
  - `backend/tests/test_ux_phase3.py`
  - `scripts/check_environment.py`

---

## 2. Existing Test Baseline & Execution Commands

### Test Execution Commands
- **Backend Test Suite (Pytest):**
  ```powershell
  pytest
  ```
  *Baseline result:* `169 passed in 186.79s (0:03:06)` (100% pass rate).
- **UX Phase Specific Suites:**
  ```powershell
  pytest backend/tests/test_ux_phase1.py backend/tests/test_ux_phase2.py backend/tests/test_ux_phase3.py
  ```
  *Baseline result:* `36 passed` (Phase 1: 8 tests, Phase 2: 9 tests, Phase 3: 19 tests).
- **JavaScript Syntax Check:**
  ```powershell
  node -c frontend/app.js
  ```
  *Baseline result:* Clean exit (code 0).
- **Git Diff Whitespace Check:**
  ```powershell
  git diff --check
  ```
  *Baseline result:* Clean (only existing CRLF notices on Windows).

---

## 3. Existing Screens & Primary Responsibilities

ForensiQ is structured as a single-page application with a persistent application header (`#app-header`), global alert banners, an active investigation context banner, and a 4-tab primary navigation structure (`.dashboard-nav`).

### A. Global Shell & Context Header
- **Top Header (`#app-header`):** Brand wordmark logo, case selector dropdown (`#investigation-select`), "+ New Case" button (`#btn-new-case`), and "Import Evidence" button (`#btn-action-import`).
- **Global Alert Banner (`#dashboard-alert`):** Live assertive feedback for warnings, pipeline lock alerts, and success messages with close button (`#dashboard-alert-close`).
- **Example Evidence Banner (`#example-evidence-banner`):** Quick-start guidance for demo workstation compromise data.
- **Active Case Context Banner (`.case-banner`):** Displays active case title (`#case-title-display`), status badge (`#case-status-badge`), Case ID (`#case-number-badge`), created timestamp (`#case-created-display`), last active time (`#case-updated-display`), description (`#case-desc-display`), and quick pipeline state (`#case-pipeline-quick-status`).

### B. Destination 1: Overview (`#tab-overview`)
- **Guided Investigation Workflow (`#workflow-guide-panel`):** 5-step visual process tracker (1: Create Case, 2: Upload Evidence, 3: Analyze Investigation, 4: Review Findings, 5: Download Report) with status indicators and quick-action trigger (`#workflow-action-btn`).
- **Pipeline Coordinator (`.pipeline-coordinator-card`):** Primary trigger "Analyze Investigation" (`#btn-run-full-analysis`), stage progress chips (`#chip-stage-1` through `#chip-stage-7`), live status banner (`#pipeline-log-banner`), advanced single-stage dropdown (`#select-pipeline-stage`), and post-run completion card (`#pipeline-completion-banner`) with direct navigation button (`#btn-pipeline-view-findings`).
- **Core Investigation Metrics Grid (`.metrics-grid`):** 4 metric cards: Evidence Sources (`#metric-sources`), Normalized Events (`#metric-evidence`), Detected Findings (`#metric-findings`), and Priority Activities (`#metric-activities`).
- **Triage Breakdown Split Grid (`.dashboard-split-grid`):**
  - Left: Prioritization Tier Distribution meters (`#tier-meters-container`) with visual progress bars and counts for Critical, High, Medium, Low, Informational.
  - Right: Top Priority Artifacts & Activities table (`#top-priority-table`, `#top-priority-tbody`).

### C. Destination 2: Evidence Management (`#tab-evidence`)
- **Ingested Evidence Sources Table (`#sources-tbody`):** Lists raw forensic files registered with ingestion filename, format, SHA-256 cryptographic digest recorded at ingestion, file size, total records, normalization status, and intake timestamp.
- **Master-Detail Evidence Explorer (`#evidence-master-detail`):**
  - Left Pane (~65% width, `#evidence-records-panel`): Normalized event stream table (`#evidence-records-table`, `#evidence-records-tbody`) with filtering (Source file `#filter-evidence-source`, Event Type `#filter-evidence-event-type`, User ID `#filter-evidence-user`, Device ID `#filter-evidence-device`) and pagination controls (`#btn-evidence-prev`, `#btn-evidence-next`, `#evidence-page-size`, `#evidence-page-info`, `#evidence-record-summary`).
  - Right Pane (~35% width, `#evidence-inspector-pane`): Synchronized forensic record inspector displaying Common Evidence Schema attributes, raw source provenance, user/device pivots, and JSON payload viewer with clear button (`#btn-close-inspector`).

### D. Destination 3: Analysis & Findings (`#tab-analysis`)
- **Clustered Activity Threads (`#activities-tbody`):** Synthesized multi-event attack threads with start/end timestamps, evidence count, finding links, and narrative details.
- **Findings Triage Summary Header (`.findings-summary-grid`):** Interactive counter cards for Total (`#findings-count-total`), High/Critical (`#findings-count-high`), Medium (`#findings-count-medium`), and Low/Info (`#findings-count-low`) findings with click-to-filter capability.
- **Findings Filter & Search Toolbar (`.findings-toolbar`):**
  - Search input (`#findings-search-input`) with clear button (`#findings-search-clear`).
  - Priority filter (`#filter-findings-priority`).
  - Detection method filter (`#filter-findings-method` with legacy shim `#filter-finding-type`).
  - Correlated activity filter (`#filter-findings-activity`).
  - Review status filter (`#filter-findings-review-status`).
  - Reset filters button (`#btn-reset-findings-filters`).
  - Keyboard hint badge (`J`/`K` or `Up`/`Down`).
- **Findings Table (`#findings-table`, `#findings-tbody`):** Detailed list of security threats with priority tags, detection methods, supporting evidence linkages, activity links, and triage action buttons.
- **Synchronized Finding Investigation & Traceability Card (`#selected-finding-summary-card`):**
  - Title, finding UUID display (`#selected-finding-id-display`), priority badge (`#selected-finding-prio-badge`), detection method (`#selected-finding-method-badge`), severity badge (`#selected-finding-severity-badge`), review status badge (`#selected-finding-status-badge`).
  - Review status dropdown (`#select-finding-review-status`: `NEW`, `REVIEWED`, `FALSE_POSITIVE`, `ESCALATED`).
  - Finding review notes editor (`#finding-notes-editor-box`, `#selected-finding-notes-input`, `#btn-save-finding-note`).
  - Investigation Traceability Chain track (`#finding-chain-track`).
  - Detection rule, MITRE ATT&CK identifier (`#selected-finding-mitre`), timestamps, supporting evidence, and threat narrative.
  - "Why Was This Detected?" explanation box (`#finding-section-why`, `#finding-why-detected-content`).
  - Supporting Evidence traceability records (`#finding-section-evidence`, `#finding-evidence-trace-content`).
  - Correlated Activity linkages (`#finding-section-activity`, `#finding-activity-trace-content`).
  - Priority factor breakdown (`#finding-section-priority`, `#finding-priority-trace-content`).
  - Expandable technical fingerprint & raw JSON viewer (`#selected-finding-fingerprint`, `#selected-finding-raw-json`).
- **Advanced Technical Forensics (Collapsible, `#advanced-analysis-details`):**
  - Discovered Evidence Correlations graph table (`#correlations-tbody`, `#filter-rel-type`).
  - All Prioritization Results table (`#all-prio-tbody`, `#filter-prio-tier`, `#filter-prio-method`).

### E. Destination 4: Executive Report (`#tab-report`)
- **Executive Report Header & Download Trigger (`.report-export-panel`):** Trigger button (`#btn-findings-download-report`) with progress status (`#btn-findings-download-report-spinner`) and disclaimer regarding ingestion SHA-256 digest scope.
- **Investigation Quality & Readiness Checklist (`#report-checklist-container`, `#checklist-summary-badge`):** Evaluates local pipeline readiness (evidence ingested, normalized, detection executed, anomalies evaluated, activities clustered, prioritization ranked) with distinct visual states (`COMPLETE`, `ATTENTION_REQUIRED`, `INCOMPLETE`).
- **Report Configuration Workspace Grid (`.report-workspace-grid`):**
  - Left: Findings priority inclusion dropdown (`#report-filter-priority`) and 7 selectable section checkboxes (`#cfg-sec-exec`, `#cfg-sec-meta`, `#cfg-sec-evidence`, `#cfg-sec-findings`, `#cfg-sec-prio`, `#cfg-sec-activities`, `#cfg-sec-notes`).
  - Right: Live Preflight Audit panel (`#btn-refresh-preflight`, stats for active case `#report-preview-case`, sources `#report-preview-sources`, findings `#report-preview-threats`, referenced evidence `#report-preview-referenced-ev`, audit observations `#report-preflight-missing-box`, and integrity verification note `#report-integrity-notice-text`).
- **Investigator Commentary & Case Notes Editor (`.report-notes-box`):** Markdown/text commentary editor (`#report-investigator-notes-input`) with character counter (`#report-notes-counter`), save status (`#report-notes-status`), and manual save trigger (`#btn-save-investigator-notes`).

### F. Modals & Dialogs
1. **New Case Modal (`#modal-new-case`):** Title (`#new-case-title`), case identifier (`#new-case-number`), description (`#new-case-desc`), example case autofill button (`#btn-use-example-case`), error box (`#new-case-error`), and submit button.
2. **Import Evidence Modal (`#modal-import-evidence`):** Accepted format guidance, sample dataset dropdown (`#sample-evidence-select`, `#btn-download-example`), drag-and-drop staging zone (`#evidence-drop-zone`, `#import-file`, `#drop-zone-filename`, `#drop-zone-file-info`, `#btn-drop-zone-clear`), allow duplicates checkbox (`#import-allow-dup`), error banner (`#import-error`, `#import-error-msg`, `#import-error-action`), success banner (`#import-success`), and upload button (`#btn-submit-import`).
3. **Forensic Artifact Detail Inspection Modal (`#modal-detail`):**
   - Header with title (`#modal-detail-title`) and tier badge (`#modal-detail-tier-badge`).
   - Finding proof panel (`#modal-finding-proof-panel`, `#modal-finding-proof-content`).
   - Evidence record detail panel (`#modal-evidence-detail-panel`, `#modal-evidence-detail-content`).
   - Priority explainability factor grid (`#modal-explainability-panel`, `#modal-score-value`, `#modal-explanation-text`, `#modal-factor-grid`).
   - Provenance traceability chain (`#modal-provenance-panel`, `#modal-provenance-chain`).
   - Generic JSON/key-value panel (`#modal-generic-panel`, `#modal-generic-content`).

---

## 4. Navigation & Route Behavior

- **Hash-based Routing:**
  - Route pattern: `#/case/{caseId}/{tab}?finding={findingId}&evidence={evidenceId}`
  - Supported tabs: `overview`, `evidence`, `analysis`, `report`.
  - Browser Back / Forward (`hashchange` event listener) updates UI without page reloads.
  - Deep linking preserves selected finding in Analysis tab and selected evidence record across pagination in Evidence tab.
  - Case switching updates route hash and synchronizes with `localStorage` (`forensiq_active_inv_id`).
- **Keyboard Shortcuts:**
  - `1`, `2`, `3`, `4`: Quick navigation to Overview, Evidence, Analysis, Report.
  - `J` / `ArrowDown`: Next finding (in Analysis tab) or next evidence row (in Evidence tab).
  - `K` / `ArrowUp`: Previous finding (in Analysis tab) or previous evidence row (in Evidence tab).
  - `Escape`: Closes open modals, or deselects active inspector if no modal is open.
  - Input & Modal Guards: All keyboard shortcuts are suppressed when typing in `input`, `textarea`, `select`, `contenteditable`, or when any modal dialog is open.

---

## 5. API Integrations & Contracts

The vanilla JS client calls FastAPI backend endpoints under `/api/v1`:
- `GET /api/v1/health`: Backend liveness probe.
- `GET /api/v1/investigations?limit=100`: List cases.
- `POST /api/v1/investigations`: Create new case `{title, case_number, description, status: 'OPEN'}`.
- `GET /api/v1/investigations/{id}`: Case metadata.
- `GET /api/v1/investigations/{id}/summary`: Authoritative summary counts, pipeline status, tier distributions.
- `POST /api/v1/evidence/upload`: Multipart upload with `allow_duplicates` flag.
- `GET /api/v1/evidence/sources`: List uploaded evidence source files for case.
- `GET /api/v1/evidence`: Paginated evidence records with filters (`source_id`, `event_type`, `user_id`, `device_id`, `offset`, `limit`).
- `GET /api/v1/evidence/{id}`: Detailed single evidence record.
- `GET /api/v1/evidence/position/{id}`: Returns page offset of an evidence item for deep linking across pagination.
- `POST /api/v1/detection/run`: Run deterministic threat detection.
- `POST /api/v1/detection/ml/run`: Run ML Isolation Forest anomaly detection.
- `GET /api/v1/detection/findings`: List findings for case with priority, method, activity, review status filters.
- `GET /api/v1/detection/findings/{id}`: Detailed finding record.
- `PATCH /api/v1/detection/findings/{id}/review`: Update review decision (`review_status`: `NEW`, `REVIEWED`, `FALSE_POSITIVE`, `ESCALATED`) and `notes`.
- `POST /api/v1/correlation/run`: Contextual correlation.
- `GET /api/v1/correlation/relationships`: Graph linkages.
- `POST /api/v1/correlation/activities/synthesize`: Synthesize activity threads.
- `GET /api/v1/correlation/activities`: List activity clusters.
- `POST /api/v1/prioritization/run`: Baseline evidence prioritization.
- `POST /api/v1/prioritization/contextual/run`: Contextual activity prioritization.
- `GET /api/v1/prioritization/results`: Triage rankings and factor breakdowns.
- `GET /api/v1/report/preflight`: Pre-publication audit of included entities and integrity checks.
- `GET /api/v1/report/checklist`: 6-operation readiness audit.
- `PATCH /api/v1/investigations/{id}/notes`: Save investigator case commentary.
- `GET /api/v1/report/pdf`: Stream compiled forensic report PDF.

---

## 6. Preserved DOM Hooks (Complete Inventory)

All 186 DOM IDs and structural selectors must be preserved exactly:

### Shell & Context
- `app-header`, `brand`, `brand-wordmark-img`, `case-selector-container`, `investigation-select`, `btn-new-case`, `btn-action-import`
- `main-content`, `dashboard-view`, `dashboard-alert`, `dashboard-alert-content`, `dashboard-alert-action`, `dashboard-alert-close`
- `example-evidence-banner`, `btn-import-example-evidence`, `btn-download-example-evidence`, `btn-dismiss-example-banner`
- `case-title-display`, `case-status-badge`, `case-number-badge`, `case-created-display`, `case-updated-display`, `case-desc-display`, `case-pipeline-quick-status`
- Navigation tabs: `nav-tab-overview`, `nav-tab-evidence`, `nav-tab-analysis`, `nav-tab-report`, data-tab attributes.

### Overview Tab (`#tab-overview`)
- `workflow-guide-panel`, `workflow-steps-track`, `workflow-step-hint`, `workflow-action-btn`, `wf-step-1` to `wf-step-5`, `wf-status-1` to `wf-status-5`
- `pipeline-status-summary`, `pipeline-state-badge`, `btn-run-full-analysis`, `advanced-pipeline-details`, `select-pipeline-stage`, `btn-run-single-stage`
- `stage-chips-container`, `chip-stage-1` to `chip-stage-7`, `pipeline-log-banner`, `pipeline-completion-banner`, `pipeline-completion-icon`, `pipeline-completion-title`, `pipeline-completion-desc`, `btn-pipeline-view-findings`, `btn-pipeline-dismiss-banner`
- Metrics: `metric-sources`, `metric-evidence`, `metric-findings`, `metric-activities`
- Triage meters: `tier-meters-container`, `bar-critical`, `bar-high`, `bar-medium`, `bar-low`, `bar-info`, `count-critical`, `count-high`, `count-medium`, `count-low`, `count-info`
- `top-priority-table`, `top-priority-tbody`

### Evidence Tab (`#tab-evidence`)
- `sources-tbody`
- `evidence-master-detail`, `evidence-records-panel`, `filter-evidence-source`, `filter-evidence-event-type`, `filter-evidence-user`, `filter-evidence-device`, `btn-filter-evidence`, `btn-reset-evidence-filters`
- `evidence-records-table`, `evidence-records-tbody`
- `evidence-page-size`, `evidence-record-summary`, `btn-evidence-prev`, `evidence-page-info`, `btn-evidence-next`
- `evidence-inspector-pane`, `inspector-quick-badge`, `btn-close-inspector`, `evidence-inspector-content`

### Analysis & Findings Tab (`#tab-analysis`)
- `activities-tbody`
- `findings-count-total`, `findings-count-high`, `findings-count-medium`, `findings-count-low`, `metric-card-total`, `metric-card-high`, `metric-card-medium`, `metric-card-low`
- `findings-search-input`, `findings-search-clear`, `filter-findings-priority`, `filter-findings-method`, `filter-finding-type`, `filter-findings-activity`, `filter-findings-review-status`, `btn-reset-findings-filters`, `findings-filter-status`, `findings-match-count`, `btn-clear-active-filters`
- `findings-table`, `findings-tbody`
- Finding Summary Card: `selected-finding-summary-card`, `selected-finding-title`, `selected-finding-id-display`, `selected-finding-prio-badge`, `selected-finding-method-badge`, `selected-finding-severity-badge`, `selected-finding-status-badge`, `select-finding-review-status`, `btn-selected-finding-inspect`
- Finding Notes: `finding-notes-editor-box`, `btn-save-finding-note`, `selected-finding-notes-input`
- Traceability: `finding-chain-track`, `selected-finding-rule`, `selected-finding-method-detail`, `selected-finding-mitre`, `selected-finding-timestamp`, `selected-finding-activity`, `selected-finding-evidence`, `selected-finding-desc`
- Finding Sections: `finding-section-why`, `finding-why-category-badge`, `finding-why-detected-content`, `finding-section-evidence`, `finding-evidence-count-badge`, `finding-evidence-trace-content`, `finding-section-activity`, `finding-activity-count-badge`, `finding-activity-trace-content`, `finding-section-priority`, `finding-priority-source-badge`, `finding-priority-trace-content`
- Technical Details: `finding-technical-details`, `selected-finding-fingerprint`, `selected-finding-raw-json`
- Advanced Analysis: `advanced-analysis-details`, `filter-rel-type`, `correlations-tbody`, `filter-prio-tier`, `filter-prio-method`, `all-prio-tbody`

### Report Tab (`#tab-report`)
- `btn-findings-download-report`, `btn-findings-download-report-spinner`
- `checklist-summary-badge`, `report-checklist-container`
- `report-filter-priority`, `cfg-sec-exec`, `cfg-sec-meta`, `cfg-sec-evidence`, `cfg-sec-findings`, `cfg-sec-prio`, `cfg-sec-activities`, `cfg-sec-notes`
- `btn-refresh-preflight`, `report-preview-case`, `report-preview-sources`, `report-preview-threats`, `report-preview-referenced-ev`, `report-preflight-missing-box`, `report-preflight-missing-list`, `report-integrity-notice-text`
- `report-notes-status`, `btn-save-investigator-notes`, `report-investigator-notes-input`, `report-notes-counter`

### Modals (`#modals-container`)
- `modal-new-case`, `new-case-title-heading`, `form-new-case`, `new-case-title`, `new-case-number`, `new-case-desc`, `btn-use-example-case`, `new-case-error`
- `modal-import-evidence`, `import-evidence-heading`, `form-import-evidence`, `sample-evidence-select`, `btn-download-example`, `evidence-drop-zone`, `import-file`, `drop-zone-filename`, `drop-zone-file-info`, `btn-drop-zone-clear`, `import-allow-dup`, `import-error`, `import-error-msg`, `import-error-action`, `import-success`, `btn-submit-import`
- `modal-detail`, `modal-detail-title`, `modal-detail-tier-badge`, `modal-finding-proof-panel`, `modal-finding-proof-content`, `modal-evidence-detail-panel`, `modal-evidence-detail-content`, `modal-explainability-panel`, `modal-score-value`, `modal-explanation-text`, `modal-factor-grid`, `modal-provenance-panel`, `modal-provenance-chain`, `modal-generic-panel`, `modal-generic-content`

---

## 7. Existing Responsive Behavior & Limitations

- **Current Breakpoints:** Handled via media queries at `900px`, `960px`, `1024px`, and `768px`.
- **Known Limitations of Previous Design:**
  - Inconsistent color tokens: previous phases mixed GitHub Dark palettes (`#0e1117`, `#161b22`, `#21262d`, `#30363d`) with Tailwind-style slate colors (`#0f172a`, `#1e293b`, `#334155`), resulting in fragmented surface contrast and uneven border weights.
  - Inline styles: Numerous sections in `index.html` used hardcoded inline styles (e.g., `style="display: flex; gap: 8px; ..."` or `style="padding: 16px;"`), bypassing the design system and degrading responsive adaptability.
  - Information density imbalance: In the Findings and Evidence tabs, table headers and cells lacked consistent monospace alignment for hashes and IDs.
  - Buttons and form controls had divergent padding, heights, and corner radii across modals vs toolbar vs inline buttons.
  - Mobile/tablet viewport squishing: When screens narrowed below 1024px, the master-detail evidence pane and findings toolbar experienced awkward wrapping.

---

## 8. Summary of Inspection Findings

1. The application logic (`app.js`) is stable, robust, and completely decoupled from specific CSS visual styling, provided that all DOM IDs, classes used as JS selectors, and data attributes are preserved.
2. The backend test suite passes cleanly with 169 tests.
3. The redesign can be executed cleanly and comprehensively by establishing the new unified design system tokens in `styles.css` and refining `index.html` structure (removing hardcoded inline styles in favor of semantic CSS classes) while strictly retaining 100% of functional IDs, attributes, event listeners, and API contracts.
