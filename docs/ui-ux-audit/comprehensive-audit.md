# ForensiQ — Comprehensive UI/UX Audit & Usability Evaluation

**Date:** 2026-11-10  
**Evaluator:** Principal Digital Forensics Software Architect & Senior UI/UX Engineer  
**Workstation Scope:** Complete application audit across all 4 destinations (Overview, Evidence, Analysis & Findings, Report), modal dialogs, navigation systems, and interactive inspection workflows.  
**Evaluation Mode:** Human-Centred Expert Review & Code-Level Verification (*Not browser-tested by instruction*).

---

## 1. Executive Summary

ForensiQ is a specialized, local-first digital forensics workstation designed for single investigators analyzing high-volume forensic logs, detecting cyber threats, correlating multi-stage attack activities, and publishing executive forensic reports.

The dark theme visual identity ("Dark Forensic Workstation") establishes an appropriate mood for technical operations. However, a rigorous human-centred heuristic evaluation reveals that **excessive compactness, compressed font scales, undersized interactive controls, and ambiguities in metric definitions** impair prolonged analytical usage.

### Key Audit Findings
1. **Overly Compressed Typography Scale:**
   - Base document font size is `13px`; utility classes `.text-sm` (`11px`) and `.text-xs` (`10px`) force critical metadata, captions, timestamps, and column headers below comfortable desktop reading thresholds (WCAG 2.2 recommendations suggest &ge;14px for primary content, &ge;12px for supporting captions).
   - Case titles (`16px`) and panel headers (`13px`) fail to command clear hierarchical authority.
2. **Undersized Interactive Targets:**
   - Buttons (`.btn-sm` at ~26px height, `.btn-xs` at ~20px height) and form controls (`.form-control-sm` at ~28px height) fail modern ergonomics standards (target height 38–44px for primary controls, 32–36px for compact controls).
3. **Finding Count Discrepancy Explained:**
   - A visible divergence exists across the UI: Case Header/Quick Status reports **7 findings**, while Overview Metric Card, Guided Sequence, and Pipeline Coordinator report **8 findings**, and Analysis & Findings lists **7 items**.
   - *Root cause:* The backend generates **7 deterministic rule/IOC findings** and **1 Isolation Forest ML statistical outlier (anomaly)**. `elFindings` displays `total_findings + total_anomalies` (8), while `quickStatus` displays `total_findings` (7). This is an information architecture defect rather than an algorithmic bug; metrics must be explicitly labeled so investigators understand the distinction.
4. **Cryptographic SHA-256 Digest Presentation:**
   - SHA-256 digests in evidence tables were truncated to `8…8` characters in narrow cells with wrapping buttons, risking misinterpretation and awkward wrapping during evidence intake.
5. **Contrast and Accessibility Gaps:**
   - `--color-text-muted` (`#778794`) against canvas surfaces (`#111820` / `#19232D`) yields ~4.2:1 contrast ratio, failing WCAG AA (4.5:1) for small body text.
   - Several interactive table rows lacked keyboard focus indicators and clear row-selected visual anchors.

---

## 2. Typography & Element Sizing Assessment

### Current vs Recommended Scale
| Component / Role | Current Size | Recommended Size | Evaluation & Impact |
|---|---|---|---|
| **Page / Brand Header** | 14px | 18–20px | Current brand text is small; needs clear presence |
| **Active Investigation Title** | 16px | 22–24px | Too small; investigator cannot immediately identify active case |
| **Major Panel Headings (`h3`)** | 13px | 17–19px | Under-emphasized; cards lack clear visual anchor |
| **Card / Sub-Panel Headings (`h4`)** | 13px | 15–16px | Needs clear distinction from body text |
| **Primary Body Text** | 13px | 14–15px | 13px causes eye strain during multi-hour investigations |
| **Table Header Cells (`th`)** | 10px uppercase | 12px uppercase | 10px is illegible at normal viewing distance |
| **Table Content Cells (`td`)** | 12px | 13–14px | Squeezed; lacks vertical breathing space |
| **Secondary Metadata / Labels** | 10–11px | 12–13px | Difficult to parse timestamps and offsets |
| **Technical Values (Hashes, IDs)** | 10–11px mono | 12–13px mono | Monospace at 10px is too condensed |
| **Primary Buttons (`.btn`)** | ~30px height | 38–42px height | Awkward click target; needs comfortable padding |
| **Compact Buttons (`.btn-sm`)** | ~26px height | 32–36px height | Fails touch/click ergonomics |
| **Micro Buttons (`.btn-xs`)** | ~20px height | 26–28px height | Tiny target; difficult to click accurately |
| **Form Inputs & Dropdowns** | ~28px height | 36–40px height | Form inputs feel cramped and narrow |

---

## 3. Component Dimensions & Spacing Assessment

- **Table Row Height:** Currently ~32px in `.forensic-table`. Squeezes multi-attribute forensic records into narrow bands. Increasing to **44–48px** with `padding: 11px 14px;` allows comfortable scanning of forensic timestamps, entity chips, and status pills.
- **Card Padding:** Currently `16px`. Standardizing to **20–24px** for major panels and **16–18px** for nested sub-cards establishes consistent white space without wasting screen real estate.
- **Section Spacing:** Gaps between cards are currently `12–16px`. Increasing to **18–22px** creates clear grouping and reduces visual clutter.
- **Dropdown Widths:** The case selector dropdown was limited to `max-width: 440px`, but in smaller desktop viewports, options with long case numbers truncate abruptly.

---

## 4. Screen-by-Screen Heuristic Evaluation

### A. Global Header & Navigation
- **Problem:** Case selector is cramped (`font-size: 12px`, height ~28px). Navigation tabs (`.nav-tab`) are `12px` font with thin `2px` underline indicator.
- **Impact:** Investigators switching between cases or destinations experience subtle lag in spatial recognition.
- **Remediation:** Increase case dropdown height to 38px, font-size to 13px. Increase nav tabs to 14px font, padding 12px 18px, and 3px active indicator bar with accent glow.

### B. Destination 1: Overview Dashboard
- **Problem 1 (Discrepancy):** The quick status badge in the case header displays `7 FINDINGS`, whereas the Metric Card displays `8`, Guided Step 4 says `8 Findings`, and Pipeline completion banner reports `7 deterministic findings + 1 anomaly`.
- **Impact:** An investigator cannot tell if an 8th finding went missing or was dropped.
- **Remediation:** Clarify metric labels:
  - Metric Card 3: Change title to *"Detected Findings & Outliers"*, subtext to *"7 Detections · 1 ML Outlier"*.
  - Case header quick status: Display *"7 DETECTIONS · 1 ANOMALY"* or authoritative total with clear tooltip.
  - Guided sequence: *"Step 4: Review 7 Findings & 1 Anomaly"*.
- **Problem 2 (Tier Meter Labeling):** The "Prioritization Tier Distribution" header says *"Dual-Level Triage"*, but does not explain that it counts both Evidence Artifacts (Stage 6) and Activity Threads (Stage 7).
- **Remediation:** Add explanatory subtitle: *"Combined tier ranking across prioritized evidence artifacts and synthesized attack activities."*
- **Problem 3 (Pipeline Stage Chips):** 7 pipeline chips sit in a single horizontal flex line that can wrap unpredictably on mid-size monitors (1280–1366px).
- **Remediation:** Provide robust horizontal scrolling or clean responsive wrap with structured stage numbers and indicators.

### C. Destination 2: Evidence Management & Normalized Explorer
- **Problem 1 (SHA-256 Digest Usability):** In the sources table, SHA-256 digests are truncated to `8...8` characters in a narrow cell containing copy and verify buttons that wrap onto two lines.
- **Impact:** Investigators cannot verify full hashes at a glance and experience button overlap.
- **Remediation:** 
  - Style hash container as a dedicated monospace digest chip with full digest readable or accessible via clean non-wrapping layout.
  - Ensure copy button has clear spacing and feedback.
  - Dedicate a clean sub-row or column for the integrity verification badge.
- **Problem 2 (Evidence Explorer Table & Filters):** Filter inputs (`User ID`, `Device ID`, `Event Type`) are short (`min-width: 120px`) and labels are `10px`. Table cell text is `12px`.
- **Remediation:** Increase filter field heights to 36px, labels to 12px, table text to 13–14px, and row height to 44px.
- **Problem 3 (Evidence Detail Inspector Pane):** In desktop split view, the inspector panel on the right (~35%) has tight `12px` padding and small `11px` monospace code blocks.
- **Remediation:** Expand inspector padding to 18px, increase monospace font to 12px, add clear visual section headers with contrasting background.

### D. Destination 3: Analysis & Findings
- **Problem 1 (Findings Table Scanability):** Findings table rows have minimal vertical padding; Critical severity findings do not visually pop compared to High or Medium findings.
- **Impact:** In high-pressure forensic incident response, critical indicators must be immediately noticeable.
- **Remediation:**
  - Add a distinct left border accent to Critical (`border-left: 3px solid var(--color-danger)`) and High rows.
  - Increase row padding to 12px 14px.
  - Make selected row clearly distinct (`border-left: 3px solid var(--color-accent); background: var(--color-surface-raised)`).
- **Problem 2 (Selected Finding Investigation Panel):** The summary card below the table contains dense metadata with small `10px` kickers and labels. The review notes textarea has small placeholder text.
- **Remediation:** Enhance title hierarchy (`18px` title), increase label size to 12px, provide structured card sections (Threat Identification, Evidence Proof, Triage Decision), and enlarge textarea with comfortable 14px typography.

### E. Destination 4: Executive Report & Preflight
- **Problem 1 (Button Hierarchy):** In the Executive Report panel header, "Download Executive Report (PDF)" and "Preview Report" were visually unbalanced.
- **Remediation:** Maintain clear hierarchy: Download as Primary Teal Action, Preview as Secondary Slate Action with Eye icon.
- **Problem 2 (Preflight Audit Stat Cards):** Preflight stat cards in `.report-preview-stat` have `10px` filter labels and `13px` values.
- **Remediation:** Increase labels to 12px uppercase, stat values to 16–18px font-mono, and highlight zero/unnormalized warning states with distinct amber backgrounds.

---

## 5. Prioritized Issue Register

| ID | Screen / Component | Issue Description | Severity | Impact | Affects Behavior? |
|---|---|---|---|---|---|
| **ISS-01** | Global Typography | Base document font is 13px; `.text-sm` (11px) and `.text-xs` (10px) cause severe eye strain | **Critical** | Readability / Accessibility | Visual only |
| **ISS-02** | Global Buttons & Controls | `.btn-sm` (26px) and `.form-control-sm` (28px) are undersized click targets | **High** | Ergonomics / Usability | Visual only |
| **ISS-03** | Overview Dashboard | Finding count discrepancy between header (7), metric card (8), and analysis table (7) | **High** | Cognitive load / Credibility | Labeling & copy |
| **ISS-04** | Ingested Evidence Sources | SHA-256 digest truncated to 8…8 chars with overlapping copy/verify buttons | **High** | Forensic provenance & review | Layout & CSS |
| **ISS-05** | Forensic Tables | Row height is ~32px with 10px uppercase headers; dense records are tightly cramped | **High** | Table scanability | Visual only |
| **ISS-06** | Color & Contrast | `--color-text-muted` has 4.2:1 contrast against dark background (fails WCAG AA 4.5:1) | **Medium** | Accessibility | Visual only |
| **ISS-07** | Selected Table Rows | Selected rows in Findings and Evidence tables lack prominent edge accent | **Medium** | Spatial awareness | Visual only |
| **ISS-08** | Case Banner | Active investigation title is only 16px; case status badge is understated | **Medium** | Visual hierarchy | Visual only |
| **ISS-09** | Analysis Findings Panel | Selected finding summary card has cramped metadata and small review textarea | **Medium** | Triage efficiency | Visual only |
| **ISS-10** | Responsive Layouts | Viewports at 1024px–1366px show tight filter toolbars and wrapped buttons | **Medium** | Mid-size desktop usability | CSS rules |
| **ISS-11** | Report Preflight Cards | Preflight stat cards have small 10px labels and 13px text | **Low** | Pre-export confidence | Visual only |

---

## 6. Preserved Invariants & Safety Guarantees

During all visual and usability refinements:
1. All 18 existing backend models, schemas, detection rules, Isolation Forest algorithms, correlation logic, and report compilation pipelines remain 100% untouched.
2. All DOM element IDs, class bindings required by JavaScript selectors, and event listener contracts are strictly preserved.
3. No external CSS/JS frameworks or dependencies are introduced.
4. Investigation state management, URL hash routing, pagination offsets, and review notes persistence remain identical.
5. All 6 unrelated pre-existing files (`README.md`, `pyproject.toml`, `requirements.txt`, `scripts/check_db.py`, `scripts/start.ps1`, `scripts/check_environment.py`) remain completely untouched.

