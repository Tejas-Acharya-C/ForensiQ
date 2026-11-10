# ForensiQ — Comprehensive Functional Logic Baseline Inventory

**Date:** 2026-11-09  
**Branch:** `feature/threat-discovery-phase1`  
**Working Tree Status:** 19 modified tracked files, 10 untracked files/directories. Clean of conflicts; all uncommitted Phase 1–3 changes preserved.  
**Audit Scope:** Deep functional analysis of Report Preview workflow, Priority Sorting (Critical/High) workflow, cross-cutting investigation state boundaries, and API contract fidelity.

---

## 1. Environment & Test Baseline

- **Python Runtime:** Python 3.11.9
- **Test Runner:** pytest-8.4.2 (asyncio-1.4.0, anyio-4.13.0)
- **Node Runtime:** Node.js v22.22.0
- **Syntax Verification:** `node -c frontend/app.js` (Exit code: 0)
- **Baseline Test Suite Execution:**
  ```powershell
  pytest backend/tests/test_ux_phase1.py backend/tests/test_ux_phase2.py backend/tests/test_ux_phase3.py
  ```
  **Result:** `36 passed in 132.93s (100% pass rate)`
  - `test_ux_phase1.py`: 8 passed (evidence pagination, deep links, sorting, integrity, error recovery)
  - `test_ux_phase2.py`: 9 passed (finding traceability, explanations, review triage persistence)
  - `test_ux_phase3.py`: 19 passed (checklist evaluation, report preflight schema, PDF compilation, note persistence)

---

## 2. Identified Functional Defects

### Issue A — Report Preview Workflow Defects

1. **DOM Overwrite Collision between `updateReportPreview` and `loadReportPreflight`:**
   - **Mechanism:** In `frontend/app.js`, `renderInvestigationSummary(s)` and `refreshActiveDestinationView()` call `updateReportPreview(state.summary)`. This function directly writes to `#report-preview-threats` (`${s.total_findings || 0} findings`) and `#report-preview-sources` (`${s.total_sources || 0} files (${s.total_evidence || 0} events)`).
   - **Defect:** When `loadReportPreflight()` executes asynchronously or when summary updates, `updateReportPreview()` clobbers the preflight calculations (e.g. `X of Y findings` based on `priority_filter`, and the `UNNORMALIZED — 0 records` warning state). Preflight data is overwritten with un-filtered overview counts.
   - **Root Cause:** Dual writers targeting the exact same DOM elements with different semantic data without coordinating precedence or state ownership.

2. **Backend Preflight Ignores `sections` Query Parameter:**
   - **Mechanism:** `GET /investigations/{id}/report/preflight` declares `sections: Optional[str] = Query(None)` at line 65 of `backend/app/api/v1/report.py`.
   - **Defect:** The query parameter is parsed but completely ignored in the body of `get_report_preflight`. The `sections_available` response is static and does not reflect enabled/disabled state or recalculate section readiness based on user selection.

3. **Discrepancy in Priority Classification between Detections and Report Modules:**
   - **Mechanism:** `backend/app/api/v1/report.py` uses `_classify_severity_tier(sev)` solely based on raw `severity_score` (thresholds: 0.8, 0.6, 0.4, 0.2).
   - **Defect:** Findings prioritized by the pipeline (via linked activities or artifact scoring) receive priority scores and tiers in `PriorityResult`. However, the report module ignores these `PriorityResult` entities and falls back strictly to raw severity. A finding displayed as `CRITICAL` in the Analysis tab (e.g., linked to a critical activity thread) is treated as `MEDIUM` by the report module if its raw rule severity was 0.5. As a result, filtering for "Critical & High Only" erroneously drops valid prioritized findings.

4. **Incomplete State Teardown on Investigation Switch:**
   - **Mechanism:** `resetCaseScopedState()` resets evidence pagination, but does not reset `state.reportConfig.preflight`, `#report-preflight-missing-box`, or report preview labels.
   - **Defect:** Switching cases temporarily renders stale preflight counts from the previous investigation until the new preflight request resolves. If the request fails, obsolete case metrics persist in the preview card.

---

### Issue B — High/Critical Priority Sorting Defects

1. **Flawed Priority Sort Key in Backend `list_findings`:**
   - **Mechanism:** In `backend/app/api/v1/detection.py` lines 599–605:
     ```python
     def priority_sort_key(item: FindingResponse):
         has_prio = 1 if item.priority_score is not None else 0
         effective_score = item.priority_score if item.priority_score is not None else (item.severity * 100.0)
         created_ts = item.created_at.timestamp() if item.created_at else 0.0
         return (has_prio, effective_score, created_ts, str(item.id))
     dto_items.sort(key=priority_sort_key, reverse=True)
     ```
   - **Defect 1:** `has_prio = 1 if item.priority_score is not None else 0` forces ANY prioritized finding (e.g. an Informational or Low finding with priority score 15.0) to sort **ABOVE** an unprioritized Critical finding (e.g. severity 0.95 -> 95.0), because `(1, 15.0)` > `(0, 95.0)`. Critical threats are thereby pushed below Low threats.
   - **Defect 2:** Sorting does not sort by canonical forensic priority tier (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFORMATIONAL`).
   - **Defect 3:** The frontend comparator does not sort findings at all. In `frontend/app.js`, `applyFindingsFilters()` filters `state.findingsState.rawFindings` into `filteredFindings` and immediately calls `renderFindingsTable(filteredFindings)` with zero sorting or tie-breaking logic.

2. **Findings Table Lacks Interactive Column Header Sorting:**
   - **Mechanism:** `<table id="findings-table">` headers (`Priority`, `Threat / Finding Title`, `Detected At`, etc.) have no sort click handlers, sort state indicators (`▲`/`▼`), or keyboard accessibility.
   - **Defect:** Analysts cannot sort findings by priority, title, or detection time by clicking headers.

3. **Summary Metric Card "High Priority" Click Inconsistency:**
   - **Mechanism:** In `frontend/index.html`, `metric-card-high` is labeled "High Priority" with subtext "Critical & High tier" and displays the combined count of Critical and High findings.
   - **Defect:** Clicking the card sets `state.findingsState.priorityFilter = 'HIGH'`, which instructs `applyFindingsFilters` to display ONLY `HIGH` findings and filter out all `CRITICAL` findings.

4. **Inaccurate Fallback Priority Tier in `frontend/app.js`:**
   - **Mechanism:** `app.js` line 3486:
     ```javascript
     const tier = (f.priority_tier || (f.severity >= 0.8 ? 'CRITICAL' : f.severity >= 0.6 ? 'HIGH' : f.severity >= 0.4 ? 'MEDIUM' : 'LOW')).toUpperCase();
     ```
   - **Defect:** When `f.priority_tier` is undefined and `f.severity < 0.2`, it defaults to `'LOW'` instead of `'INFORMATIONAL'`.

---

## 3. Corrective Remediation Strategy

1. **Remediate Issue A (Report Preview):**
   - Refactor `updateReportPreview(s)` to only populate fallback metadata when no authoritative preflight has loaded.
   - Update `loadReportPreflight()` to be the sole authoritative updater for preflight elements.
   - In `backend/app/api/v1/report.py`, integrate existing `PriorityResult` records into preflight and PDF export classification so findings prioritized by the pipeline are accurately classified as CRITICAL/HIGH/MEDIUM/LOW/INFO in the report.
   - Respect `sections` in preflight evaluation.
   - Reset report preflight state cleanly on investigation switch.

2. **Remediate Issue B (Priority Sorting):**
   - Fix backend `list_findings` sort key:
     Rank tiers canonically: `CRITICAL (5)` > `HIGH (4)` > `MEDIUM (3)` > `LOW (2)` > `INFORMATIONAL (1)`.
     Sort by: `(tier_rank, effective_score, created_ts, str(id))` descending.
   - In `frontend/app.js`: Implement deterministic client-side sorting comparator supporting canonical tier ranking, numeric score, date, and title.
   - Implement interactive table header sorting on `#findings-table` (Priority, Title, Detected At) with visual indicators (`▲`/`▼`), preserving selected finding and keyboard navigation.
   - Fix `metric-card-high` click handler to filter both `CRITICAL` and `HIGH` tier findings matching its visual label and count.
   - Fix fallback tier classification in `frontend/app.js` to accurately include `INFORMATIONAL` for severity < 0.2.

