# ForensiQ — AI-Slop Detection & Professional Product Design Audit

**Audit Date**: November 2026  
**Auditor**: Senior Digital Forensics Product Architect & Systems UX Engineer  
**Scope**: Full frontend audit of `frontend/index.html`, `frontend/styles.css`, and `frontend/app.js`  
**Application**: ForensiQ — Local-first Digital Forensics & Triage Workstation  
**Methodology**: Code inspection, DOM structure evaluation, typography/color audit, interaction flow analysis  

---

## Executive Summary

ForensiQ possesses a strong foundational domain architecture: it implements deterministic rule matching, unsupervised Isolation Forest anomaly detection, event correlation graph linking, dual-tier prioritization, persistent investigator review decisions, and cryptographic SHA-256 provenance tracking.

However, several visual and interaction layers exhibit hallmarks of generic AI-generated interfaces ("AI slop"). These patterns occur when generative tools assemble web applications by combining generic SaaS dashboard conventions (e.g., metric cards with colored icon boxes, redundant onboarding wizards, ubiquitous subtitles under every heading, system emojis as section headers, card-within-card nesting, and verbose disclaimer boilerplate) rather than adhering to the ergonomics, density, and workflow of a specialized digital forensics workstation.

This audit systematically catalogues genuine AI-slop patterns across the interface, details their impact on investigative workflow, identifies existing strong architectural choices that must be preserved, and provides an actionable, prioritized improvement proposal.

---

## Audit Checklist & Heuristic Evaluation

### A. Generic Dashboard Patterns
1. **Redundant Two-Tiered Sequence Tracks**: The Overview dashboard places a consumer-style 5-step guided sequence ("Guided Investigation: 5-Step Investigation Sequence") directly above an industrial 7-stage pipeline coordinator ("Investigation Pipeline Coordinator"). Stacking two separate horizontal progress tracks on top of each other consumes ~320px of vertical space above the fold before the investigator even sees evidence or threat data.
2. **Generic SaaS Metric Cards with Colored Icon Boxes**: Metric cards in the Overview tab use rounded pastel-tinted square icon boxes (`box-blue`, `box-purple`, `box-red`, `box-teal`) housing generic feather icons. This is a ubiquitous template design trope from consumer SaaS dashboards (e.g., Stripe, Shopify) that adds visual noise without forensic relevance.
3. **Card-Within-Card Nesting**: The Analysis & Findings view nests multiple deep card layers: an outer panel contains a 4-card metric grid, a toolbar, a table, and a massive finding summary card which itself nests 8 distinct sub-cards, notice boxes, and tables. This creates excessive inset borders and artificial visual barriers.

### B. Typography & Labels
1. **Ubiquitous Explanatory Subtitles**: Virtually every `<h3>` and `<h4>` element throughout the application has a subtitle beneath it explaining the obvious to the investigator (e.g., "Report Configuration: Select report sections and filter findings for PDF inclusion", "Evidence Sources: Raw forensic evidence files registered in this case..."). This pattern stems from LLMs generating commentary for every section rather than designing clear visual headers.
2. **System Emojis as Section Headers**: Five core sections in the finding detail view use consumer-grade system emojis (`🔗`, `🔍`, `📄`, `⚡`, `⚖️`, `⬇`) as section icons. Emojis render inconsistently across platforms and look distinctly amateurish in a courtroom-grade forensic tool.
3. **Overuse of All-Caps in Badges and Phrases**: Full multi-word phrases are forced into uppercase (`CLAIMED (UNVERIFIED)`, `0 OF 6 REQUIRED OPS COMPLETE`, `DETECTION LOGIC`, `BEHAVIORAL OUTLIER`, `RAW SEV: 0.80 / 1.00`). All-caps should be reserved for technical acronyms (SHA-256, IOC, CSV, MITRE) and standard triage tiers (CRITICAL, HIGH).
4. **Repetitive Buzzword Qualifiers**: Repeated use of self-aggrandizing qualifiers like "Authoritative operational audit", "Authoritative narrative observations", "Authoritative pre-compilation summary". Professional software demonstrates authority through precision and data integrity, not by repeatedly declaring itself "authoritative."

### C. Colors & Decoration
1. **Clipart Security Icons**: The case header displays a shield with a checkmark inside a decorative container box, resembling generic antivirus software or SaaS marketing pages.
2. **Arbitrary Color Accents on Metrics**: The metric cards apply arbitrary color themes (purple for normalized events, teal for activities) that have no semantic relationship with threat triage severity.
3. **Notice Box Proliferation**: Multiple notice boxes (`forensic-notice-box`, `notice-ml`) with distinct background colors clutter the finding detail panel, often repeating information already displayed in metadata fields.

### D. Layout & Spacing
1. **Symmetrical 4-Card Grid Repetition**: The exact same 4-card symmetrical grid layout is repeated across multiple screens (Overview metrics, Findings summary metrics, Report preflight metrics).
2. **Hidden Core Forensics in Collapsible Details**: Core forensic analytical tables—Evidence Correlations and All Prioritization Results—are buried inside an HTML `<details>` accordion labeled "Advanced: Evidence Correlations & Priority Scores" at the bottom of the Analysis tab. Correlation graphs and explainable priority scores are ForensiQ's key differentiators; hiding them in an accordion devalues them.
3. **Inefficient Master-Detail Density**: The Evidence Inspector lists normalized attributes in a tall vertical key-value list where null/empty fields still consume full rows and whitespace, forcing excessive scrolling.

### E. Interaction Quality
1. **Duplicate Action Buttons**: Both the 5-step guided workflow (Step 3) and the 7-stage pipeline coordinator feature an "Analyze Investigation" button that execute the exact same asynchronous backend routine.
2. **Dashed-Border Placeholder Button**: The New Case modal features a "Use Example Case" button styled with a dashed border (`border: 1px dashed var(--color-border-strong)`), resembling an unfinished wireframe template.
3. **Scattered Legal Disclaimers**: Long, repetitive disclaimer paragraphs regarding SHA-256 digests, X.509 signatures, and legal certifications are rendered as prominent text blocks across the main Report tab and Checklist, distracting from the export workflow.

---

## Strong Design Decisions to Preserve (Do Not Change)

Before categorizing issues, the following existing design choices are evaluated as strong, professional, and authentic to digital forensics; they must be strictly preserved:

1. **Dark Forensic Workstation Palette**: The deep blue-gray canvas (`--color-bg: #111820`, `--color-surface: #19232D`) provides an ergonomic, non-fatiguing workspace for prolonged investigation sessions with WCAG 2.2 AA compliant contrast ($>5.2:1$).
2. **Cryptographic SHA-256 Provenance at Ingestion**: Ingested evidence sources display full cryptographic hashes in sunken monospace chips with copy affordances and verified intake records.
3. **Condition-Level Detection Explainability**: The evaluated rule condition table displaying target field, operator, configured value, observed evidence value, and `MATCHED` / `UNMATCHED` pills is exemplary forensic explainability.
4. **Keyboard-Driven Triage**: Seamless <kbd>J</kbd>/<kbd>K</kbd> and Arrow navigation for browsing findings and evidence records satisfies professional high-speed triage requirements.
5. **Human-in-the-Loop Review Triage**: The four-state review status model (`NEW`, `REVIEWED`, `FALSE_POSITIVE`, `ESCALATED`) with persistent investigator notes maintains a clear demarcation between machine detection and investigator determination.
6. **Live Preflight Report Audit**: The preflight verification engine that reconciles included evidence, findings, and notes before PDF compilation ensures zero discrepancies between UI preview and exported forensic documentation.
7. **Explicit Separation of Deterministic vs ML Detections**: Distinctly presenting deterministic rule/IOC matches alongside Isolation Forest statistical outliers prevents black-box AI confusion.

---

## Prioritized Issue Register (AI-Slop Catalog)

| Issue ID | Screen / Component | Exact Observed Pattern | Why It Resembles Generic AI Slop | Usability Impact | Severity | Classification | Nature |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SLOP-01** | Overview Tab | 5-Step Guided Investigation track stacked immediately above the 7-Stage Pipeline Coordinator | LLMs combine an onboarding "wizard" pattern with an operational pipeline, producing two conflicting linear progress bars | Wastes ~140px vertical space; creates confusion over which step/stage is active; redundant action triggers | **High** | **Consolidate** | Functional / Layout |
| **SLOP-02** | Finding Detail Panel | System emojis used as section headers: `🔗`, `🔍`, `📄`, `⚡`, `⚖️`, `⬇` | Quick LLM prompt injection of emojis as pseudo-icons; platform-dependent rendering (looks cartoonish on Windows/macOS) | Undermines technical credibility in courtroom or audit contexts; visually distracting | **High** | **Simplify** | Visual-only |
| **SLOP-03** | Overview & Analysis Tabs | Generic SaaS metric cards with pastel colored icon boxes (`box-blue`, `box-purple`, etc.) | Direct import of generic Bootstrap/Tailwind admin dashboard templates designed for marketing/sales KPIs | Draws eye to decorative icon squares rather than critical forensic quantities and triage deltas | **Medium** | **Simplify** | Visual-only |
| **SLOP-04** | Global Shell & Panels | Ubiquitous explanatory subtitles beneath almost every `<h3>` and `<h4>` heading | Prompt-engineered templates where every header has an AI-generated subtitle explaining self-evident concepts | Visual clutter; lowers content density; forces investigators to scroll past boilerplate | **Medium** | **Simplify** | Visual-only |
| **SLOP-05** | Analysis Tab | 4 static metric cards (`Total Findings`, `High Priority`, etc.) duplicated directly above the findings filter toolbar | Template pattern where every dashboard view must start with a 4-card metric summary | Consumes vertical space without offering interactive filtering or drilldown capability | **Medium** | **Consolidate** | Visual / Layout |
| **SLOP-06** | Analysis Tab | Evidence Correlations and Prioritization Results hidden inside `<details>` accordion at page bottom | LLM treating complex relational data as "advanced options" to keep the page superficially tidy | Investigators miss critical multi-event attack correlation graphs and priority scoring breakdowns | **High** | **Redesign** | Layout / Structural |
| **SLOP-07** | Finding Detail & Inspector | Verbose all-caps badges: `CLAIMED (UNVERIFIED)`, `0 OF 6 REQUIRED OPS COMPLETE`, `DETECTION LOGIC`, `BEHAVIORAL OUTLIER` | AI tendency to shout status using uppercase strings rather than clean typography and semantic color coding | Visual fatigue; reduces readability; makes ordinary operational status look like critical system errors | **Medium** | **Simplify** | Visual-only |
| **SLOP-08** | Case Header Banner | Clipart shield icon with checkmark in a dedicated colored container box | Generic cybersecurity cliché ("shield = secure") commonly generated by AI layout prompts | Decorative fluff that adds zero investigative context to the active case | **Low** | **Remove** | Visual-only |
| **SLOP-09** | Global & Report Views | Self-aggrandizing labels ("Authoritative operational audit", "Authoritative pre-compilation summary") | AI prompts instructed to sound "authoritative" literally embedding the word into every UI heading | Decreases perceived professionalism; reads as marketing copy rather than forensic tooling | **Low** | **Simplify** | Visual-only |
| **SLOP-10** | New Case Modal | "Use Example Case" button styled with dashed wireframe border (`border: 1px dashed ...`) | Looks like a developer mock-up placeholder left over in production code | Looks unpolished and prototype-like | **Low** | **Simplify** | Visual-only |
| **SLOP-11** | Report Tab | Giant verbose legal disclaimer text blocks rendered inside the primary export card body | AI prompt injecting full disclaimer text blocks directly into interactive operational panels | Clutters the workspace; should be a concise, professional footnote or discrete audit notice | **Medium** | **Simplify** | Visual / Layout |
| **SLOP-12** | Evidence Inspector | Flat vertical key-value list with empty fields (`—`) occupying full rows and redundant sub-notes | Generic property inspector that renders every schema field identically regardless of value presence | Excessive scrolling; dilutes focus away from observed forensic entities (User, IP, Hash, Process) | **Medium** | **Redesign** | Visual / Density |

---

## Detailed Issue Analysis & Proposed Solutions

### SLOP-01: Consolidate Guided Investigation & Pipeline Coordinator
- **Current State**: Overview has both `#workflow-guide-panel` (5-step sequence) and `.pipeline-coordinator-card` (7-stage pipeline). Both have buttons that trigger `runFullPipeline()`.
- **Proposed Solution**: Consolidate into a single, cohesive **Investigation Operations Center**. The 7-stage pipeline is the true forensic engine; embed case readiness and next recommended action directly into the pipeline header. Eliminate the artificial 5-step wizard track. All existing DOM IDs (`#btn-run-full-analysis`, stage chips, pipeline log banner) are retained.

### SLOP-02: Replace Consumer Emojis with Professional Monochromatic SVG or Clean Typographic Kickers
- **Current State**: Finding detail headers use `🔗`, `🔍`, `📄`, `⚡`, `⚖️`, `⬇`.
- **Proposed Solution**: Replace emoji characters with sleek, inline SVG icons or remove them in favor of crisp uppercase kickers (`TRACEABILITY`, `DETECTION LOGIC`, `EVIDENCE PROVENANCE`, `ATTACK CORRELATION`, `PRIORITY FACTORS`). This restores visual sobriety.

### SLOP-03: De-SaaS-ify Metric Cards
- **Current State**: Metric cards feature colored pastel background boxes (`box-blue`, `box-purple`, `box-red`, `box-teal`) housing generic icons.
- **Proposed Solution**: Remove the colored icon boxes. Format metric cards as data-dense forensic telemetry cards: prominent value, concise label, and clear contextual delta (e.g., "7 Threat Matches · 1 ML Outlier").

### SLOP-04: Prune Boilerplate Subtitles
- **Current State**: 12 distinct panels have 1–2 sentence explanatory subtitles that state obvious facts.
- **Proposed Solution**: Prune redundant subtitles across panels. Keep subtitles only where genuine forensic guidance is required (e.g., explaining Common Evidence Schema normalization or priority score weights).

### SLOP-05: Integrate Findings Metrics into the Toolbar
- **Current State**: 4 redundant metric cards take up 90px of vertical space directly above a filter toolbar with identical options.
- **Proposed Solution**: Consolidate the 4 metric counters directly into the findings toolbar as interactive filter pills (e.g., `All (8)`, `Critical & High (3)`, `Medium (3)`, `Low (2)`). Clicking a pill filters the table instantly, turning passive decoration into an ergonomic workflow control.

### SLOP-06: Elevate Evidence Correlations & Priority Score Breakdowns
- **Current State**: Discovered correlations and prioritization results are buried in an accordion at the bottom of the Analysis tab.
- **Proposed Solution**: Give correlations and prioritization results dedicated tabs or clean visual sub-panels within the Analysis workstation rather than hiding them in a `<details>` dropdown.

### SLOP-07: Normalize Badge Typography & Formatting
- **Current State**: Verbose phrases are forced into all-caps (`CLAIMED (UNVERIFIED)`, `0 OF 6 REQUIRED OPS COMPLETE`).
- **Proposed Solution**: Standardize badges to title-case or sentence-case for descriptors (`Claimed · Unverified`, `0 of 6 operations complete`), reserving uppercase strictly for technical acronyms (`SHA-256`, `IOC`, `ML`, `CES`) and triage tiers (`CRITICAL`, `HIGH`).

### SLOP-08 & SLOP-09: Remove Antivirus Clipart & Tone Down Rhetoric
- **Current State**: Shield clipart in case banner; "Authoritative" prefixed to multiple section titles.
- **Proposed Solution**: Replace shield clipart with a sleek case metadata badge. Replace "Authoritative operational audit" with "Operational Readiness Checklist" and "Authoritative narrative observations" with "Investigator Case Notes".

### SLOP-10: Professionalize Modal Actions
- **Current State**: "Use Example Case" has a dashed border.
- **Proposed Solution**: Style as a standard secondary or ghost button (`.btn-secondary` or `.btn-ghost`), removing the dashed wireframe border.

### SLOP-11: Streamline Legal / Disclaimer Notices
- **Current State**: Multi-sentence disclaimers dominate the Report card body.
- **Proposed Solution**: Format disclaimers as compact, professional audit notices (`.audit-notice`) with clean muted typography positioned in the report footer area.

### SLOP-12: Compact Entity Grid in Evidence Inspector
- **Current State**: Long vertical key-value list displaying empty `—` fields.
- **Proposed Solution**: Adopt a compact two-column entity grid that prominently highlights populated attributes (User, Process, IP, Command Line, Digest) while cleanly de-emphasizing or compacting null values.

---

## Proposed Implementation Roadmap & Execution Status

The improvements are structured into three targeted increments that preserve all DOM IDs, backend contracts, and event listeners:

1. **Increment 1 — Visual Refinement (STATUS: COMPLETED)**:
   - **Emojis Replaced:** Replaced consumer system emojis (`🔗`, `🔍`, `📄`, `⚡`, `⚖️`, `⬇`, `⚠️`) with consistent monochromatic inline SVG icons with clean $13\text{--}14\text{px}$ stroke weights or concise text labels.
   - **Metric Cards De-SaaS-ified:** Removed decorative colored background icon boxes (`.metric-icon-box`, `box-blue`, `box-purple`, `box-red`, `box-teal`) from the Overview metrics grid; cards now display data-dense forensic telemetry cleanly.
   - **Subtitles Pruned & Streamlined:** Removed repetitive explanatory subtitles under Pipeline Coordinator, Clustered Activity Threads, Threat Discovery & Findings, Report Configuration, and Executive Report. Preserved genuinely technical subtitles (Dual-level triage distribution, CES normalized entities, graph relationships).
   - **Badge Typography Normalized:** Converted verbose multi-word badges to sentence/title case (`Claimed (unverified)`, `0 of 6 required operations complete`, `Behavioral outlier`, `Raw severity`, `Contextual activity priority`, `Baseline artifact priority`) while preserving all uppercase triage tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`) and technical acronyms (`SHA-256`, `IOC`, `ML`, `CES`, `MITRE`, `ATT&CK`).
   - **Labels De-sensationalized:** Replaced self-aggrandizing qualifiers ("Authoritative operational audit" &rarr; "Operational verification of pipeline stages, evidence integrity, and review completeness prior to report compilation"; "Authoritative pre-compilation summary" &rarr; "Pre-compilation summary"; "Authoritative narrative observations" &rarr; "Narrative observations and conclusions for executive report").
   - **Modal Button Standardized:** Replaced dashed wireframe border on `#btn-use-example-case` with a conventional secondary button style (`.btn .btn-secondary .btn-sm`).
   - **Report Disclaimer Restyled:** Replaced bulky, prominent card body border/padding on `.report-export-body` with an understated left-bordered audit notice (`border-left: 2px solid var(--color-border-strong)`), maintaining every word of the legal and evidence integrity text.
   - **Workstation Identity Preserved:** The approved dark graphite, slate, and teal workstation visual identity remains completely intact.

2. **Increment 2 — Layout & Information Density (STATUS: COMPLETED)**:
   - **Unified Investigation Operations Center (Task 1 / SLOP-01):**
     - Consolidated the 5-step guided investigation track and the 7-stage engine coordinator into a single cohesive card (`#workflow-guide-panel`).
     - Preserved both the high-level investigator milestone progress track (`#workflow-steps-track`, `#wf-step-1`..`5`) and the distinct 7 technical engine stage chips (`#stage-chips-container`, `#chip-stage-1`..`7`).
     - Established a single unambiguous primary action button: `#btn-run-full-analysis` ("Analyze Investigation"), eliminating duplicate triggers while maintaining step-specific secondary shortcuts during onboarding/review/report stages.
     - Preserved all pipeline telemetry, execution state banners (`#pipeline-log-banner`, `#pipeline-completion-banner`), and the advanced single-stage selector.
   - **Findings Summary & Quick Priority Filter Pills (Task 2 / SLOP-05):**
     - Replaced the passive 4-card metric block with compact, interactive triage quick-filter pills (`.triage-pills-group` containing `#metric-card-total`, `#metric-card-high`, `#metric-card-medium`, `#metric-card-low`).
     - Added `#findings-breakdown-display` to explicitly delineate deterministic Rule/IOC threat detections from unsupervised Isolation Forest ML outliers, ensuring machine-learning anomalies are never conflated with verified threat signatures.
     - Preserved all click handlers, counter elements (`#count-total-findings`, `#count-high-findings`, etc.), active indicator classes (`.active-metric-filter`), and table filter event bindings.
   - **Evidence Inspector Redesign (Task 3 / SLOP-12):**
     - Transformed the long, sparse vertical key-value list into a dense two-column grid (`.ces-two-col-grid`) that prioritizes populated CES entities.
     - Added dedicated prominent display cards for command-line execution (`.inspector-cmdline-card`) and highlighted endpoint/user attributes (`.ces-cell-prominent`).
     - Introduced an accessible, collapsible details block (`.unpopulated-fields-details`) for unpopulated/empty schema fields, eliminating vertical scrolling while maintaining full field discoverability.
     - Clearly distinguished authoritative ingestion digests (calculated from source files at intake) from log-extracted claimed hashes (marked `Claimed (unverified)`).
     - Fully preserved all copy buttons, stream offset badges, finding proof modal triggers, raw JSON inspection modals, and keyboard triage navigation (<kbd>J</kbd>/<kbd>K</kbd>/<kbd>Esc</kbd>).

3. **Increment 3 — Analytical Elevation: Evidence Correlations & Prioritization Visibility (STATUS: COMPLETED)**:
   - **Elevated Evidence Correlations Panel (Task A / SLOP-06):**
     - Replaced the hidden `<details id="advanced-analysis-details">` disclosure with a dedicated, elevated analysis panel (`#panel-evidence-correlations`) inside `.analysis-elevated-section`.
     - Preserved relationship type distinctions (Shared Entity, Network Pivot, Process Lineage, Temporal Proximity, Activity Cluster) via semantic badges.
     - Added authoritative numerical strength/weight indicators (`weight.toFixed(2)`).
     - Added direct 1-click drilldown into the Evidence Explorer for source and target evidence records (`jumpToEvidenceRecord('', id)`).
     - Displayed inline context signals extracted from `context_attributes` with clean key-value badges and a "+N more" indicator.
     - Preserved the full context attributes inspection modal (`viewDetailModal`).
     - Added dynamic count telemetry badge (`#correlations-count-badge`).
   - **Elevated Prioritization Results Panel (Task B / SLOP-06):**
     - Elevated Prioritization Results from collapsed disclosure into a dedicated, prominent analysis panel (`#panel-prioritization-results`).
     - Standardized priority tier badges using workstation-grade styling (`getFindingTierBadgeClass`: `badge-tier-critical`, `badge-tier-high`, etc.).
     - Distinctly formatted calculated composite priority score (0.0–100.0) alongside target type badges.
     - Provided 1-click evidence drilldown for artifact targets (`jumpToEvidenceRecord('', r.target_id)`).
     - Distinguish prioritization methods via semantic badges (`Artifact Baseline` vs `Activity Contextual`).
     - Integrated inline factor breakdown previews with a "View Factors" modal trigger.
     - Added dynamic count telemetry badge (`#prioritization-count-badge`).
   - **Analysis Layout Integration & Auto-Loading (Task C):**
     - Integrated both elevated panels side-by-side / stacked within the Analysis view without excessive vertical density (`.analysis-elevated-section`).
     - Added sticky table headers (`thead th`) inside scrollable containers with `max-height: 420px; overflow-y: auto;`.
     - Updated `refreshActiveDestinationView()` to automatically fetch Correlations and Prioritizations concurrently with Activities and Findings whenever the Analysis tab is viewed or when investigations are switched, removing the requirement to click open a disclosure widget.
     - Preserved backward compatibility by retaining `#advanced-analysis-details` on the container, ensuring all legacy DOM queries succeed without null exceptions.

---

## Verification Results (Increments 1, 2, and 3)

- **JavaScript Syntax Check:** `node --check frontend/app.js` passed with code 0 (zero errors).
- **Git Diff Hygiene Check:** `git diff --check` passed with code 0 (no whitespace or conflict errors).
- **Regression Test Suite:** 67 of 67 tests passed across all suites (`test_findings_quick_filter.py`, `test_ux_phase1.py`, `test_ux_phase2.py`, `test_ux_phase3.py`, `test_functional_audit.py`, `test_report.py`).
- **DOM & Contract Integrity:** All existing DOM IDs, data attributes, API routes, and event-handler contracts are strictly preserved.
- **Backend / Evidence Integrity:** Zero backend, database, migration, or evidence runtime files were altered.

---

## Conclusion & Implementation Gate

Increments 1, 2, and 3 have been fully implemented, integrated, and verified against all functional regression suites. ForensiQ presents a cohesive, professional digital forensics workstation identity with high analytical discoverability, authoritative data presentation, and direct evidence traceability.

---

*Not browser-tested by instruction.*

