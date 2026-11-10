# ForensiQ — UI/UX Design Refinement Plan

**Date:** 2026-11-10  
**Phase:** Stage 2 Implementation Roadmap  
**Target:** Professional Digital Forensics Investigation Workstation  

---

## 1. Refinement Objectives & Principles

1. **Human-Centred Forensics Ergonomics:**
   - Optimize for long hours of investigative reading, log analysis, threat triage, and report compilation.
   - Establish a deliberate, comfortable typography hierarchy where critical threat attributes stand out instantly.
2. **Balanced Information Density:**
   - Support high forensic data density without sacrificing readability, click target sizes, or scanability.
   - Prevent cramped cells, illegible abbreviations, and broken cryptographic hashes.
3. **Information Clarity & Cognitive Precision:**
   - Unify and clarify metrics: explicitly distinguish between deterministic threat detections (7) and AI statistical outliers (1), eliminating confusion across dashboard, pipeline, and findings views.
4. **Zero Functionality Compromise:**
   - Retain 100% of existing DOM IDs, data attributes, event handlers, API routes, pagination contracts, and backend services.

---

## 2. Refined Design Tokens

### A. Typography Scale (`frontend/styles.css`)
```css
/* Refined Workstation Typography Hierarchy */
--font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
--font-mono: 'JetBrains Mono', SFMono-Regular, Menlo, Monaco, Consolas, monospace;

/* Font Sizes */
--text-root: 14px;         /* Base document body font size (raised from 13px) */
--text-xs: 12px;           /* Subtle captions, subtext, badges (raised from 10px) */
--text-sm: 13px;           /* Supporting metadata, table subtext (raised from 11px) */
--text-base: 14px;         /* Standard content, table cells, form inputs */
--text-md: 15px;           /* Section headers, emphasized items */
--text-lg: 18px;           /* Panel titles, modal titles (raised from 13-14px) */
--text-xl: 20px;           /* Sub-destinations, major kickers */
--text-2xl: 24px;          /* Active Investigation Case Title (raised from 16px) */

/* Line Heights */
--leading-tight: 1.25;
--leading-normal: 1.5;
--leading-relaxed: 1.65;
```

### B. Contrast & Accessibility Tokens
```css
/* Color adjustments for strict WCAG 2.2 AA compliance */
--color-text: #EBF1F6;           /* Contrast ratio: > 14:1 against canvas (AAA) */
--color-text-secondary: #B0BFCB; /* Contrast ratio: > 7.5:1 against canvas (AAA) */
--color-text-muted: #8E9FAA;     /* Raised from #778794; contrast ratio: 5.2:1 against canvas (AA) */

/* Threat Tier Visual Accents */
--prio-critical-border: #E16D73;
--prio-critical-bg: rgba(225, 109, 115, 0.16);
--prio-high-border: #E89445;
--prio-high-bg: rgba(232, 148, 69, 0.16);
--prio-medium-border: #E5AD56;
--prio-medium-bg: rgba(229, 173, 86, 0.14);
```

### C. Component Dimensions & Spacing Scale
```css
/* Component Ergonomics */
--btn-height-default: 38px;      /* Raised from ~30px */
--btn-height-sm: 32px;           /* Raised from ~26px */
--btn-height-xs: 26px;           /* Raised from ~20px */

--input-height: 38px;            /* Raised from ~28px */
--input-height-sm: 34px;         /* Raised from ~28px */

--table-row-height: 46px;        /* Raised from ~32px */
--table-cell-padding: 11px 14px; /* Raised from 8px 12px */

--card-padding-default: 20px;    /* Raised from 16px */
--card-padding-lg: 24px;         /* Raised from 18px */
--card-gap-default: 18px;        /* Raised from 12px */
```

---

## 3. Step-by-Step Implementation Roadmap

### Step 1: Update Global Design Tokens & Typography Scale (`frontend/styles.css`)
- Update `:root` variables: increase font scale, adjust `--color-text-muted` to `#8E9FAA` for WCAG AA compliance.
- Update `body.forensic-theme`: set `font-size: 14px;`, `line-height: 1.5;`.
- Update `.text-sm` (`13px`), `.text-xs` (`12px`).
- Update headings: `.case-title` (`22px`), `.panel-header h3` (`17px`), `.summary-card-title` (`18px`).
- Update interactive component sizing:
  - `.btn`: `padding: 8px 16px; font-size: 13px; min-height: 38px;`
  - `.btn-sm`: `padding: 5px 12px; font-size: 12px; min-height: 32px;`
  - `.btn-xs`: `padding: 3px 8px; font-size: 11px; min-height: 26px;`
  - Form inputs (`.form-control-sm`, `.case-dropdown`, `.findings-search-field`): `min-height: 36px; font-size: 13px;`

### Step 2: Table Scanability & SHA-256 Digest Usability (`frontend/styles.css` & `frontend/app.js`)
- Table headers: `.forensic-table thead th`: `font-size: 11px; padding: 10px 14px; letter-spacing: 0.6px;`.
- Table cells: `.forensic-table tbody td`: `padding: 11px 14px; font-size: 13px;`.
- Row selection & highlights:
  - `.finding-row.row-selected`: add prominent `border-left: 3px solid var(--color-accent);`.
  - High and Critical priority finding rows: distinct subtle left border accent (`border-left: 3px solid var(--color-danger);`) for instant threat recognition.
- SHA-256 presentation:
  - In `renderSourcesTable()`, display full digest inside a clean monospace code container with copy button separated by a non-wrapping layout.
  - Dedicate clear alignment for the integrity verification badge.

### Step 3: Information Architecture & Metric Discrepancy Resolution (`frontend/index.html` & `frontend/app.js`)
- In `frontend/index.html` and `frontend/app.js`:
  - Clarify Metric Card 3:
    - Title: `"Detected Findings & Outliers"`
    - Footnote: `"Rule, IOC & ML detections"`
  - Clarify quick status in `renderInvestigationSummary()`:
    - Format as: `quickStatus.textContent = s.total_findings > 0 ? (s.total_anomalies > 0 ? `${s.total_findings} FINDINGS · ${s.total_anomalies} ANOMALY` : `${s.total_findings} FINDINGS`) : ...`
    - This eliminates investigator confusion between total deterministic rule matches (7) and ML statistical outliers (1).
  - Clarify "Prioritization Tier Distribution" subtext:
    - Subtitle: `"Dual-Level Triage (Evidence Artifacts & Activities Ranked)"`

### Step 4: Analysis & Findings Layout Polish (`frontend/styles.css` & `frontend/index.html`)
- Filter bar: increase filter label visibility (`font-size: 12px; font-weight: 500;`).
- Search input: increase height to 36px, placeholder font-size to 13px.
- Findings investigation card: expand padding to 20px, increase review notes textarea to `min-height: 100px; font-size: 13px;`, and clarify section headings.

### Step 5: Report Preflight Workspace Polish (`frontend/styles.css`)
- Preflight stat cards: enlarge stat numbers to `16px font-mono font-bold`, labels to `11px uppercase`.
- Checklist items: add comfortable padding (`14px`), increase title font to `14px`, badges to `11px`.

### Step 6: Responsive Rules Verification
- Ensure clean collapse at 1200px, 1024px, 768px breakpoints without horizontal clipping.
- Tables retain horizontal scrolling with sticky headers.

---

## 4. Verification Checklist
- Run `pytest backend/tests/test_ux_phase1.py backend/tests/test_ux_phase2.py backend/tests/test_ux_phase3.py backend/tests/test_functional_audit.py backend/tests/test_report.py`.
- Run `node --check frontend/app.js`.
- Run `git diff --check`.
- Confirm zero regressions in all 59 existing test cases.
- Confirm all 6 pre-existing unrelated files remain untouched.

