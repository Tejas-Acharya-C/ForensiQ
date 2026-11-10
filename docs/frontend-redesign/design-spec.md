# ForensiQ — Frontend Visual Design Specification
**Theme:** Dark Forensic Workstation  
**Design Philosophy:** Balanced, professional, restrained, high-clarity investigative intelligence workstation.

---

## 1. Design Principles & Aesthetic Direction

1. **Credible Investigative Workstation:**
   The interface must look and feel like an enterprise forensic analysis console used by digital forensics analysts, CIRT responders, and incident investigators—not a generic marketing landing page, glowing gamer tool, or neon-accented cyber dashboard.

2. **Restrained Technical Palette:**
   A deep slate-graphite surface architecture (`#111820` canvas, `#19232D` surface panels, `#202D38` raised components) with subtle technical borders (`#2B3945`). Muted, precise contrast allows critical forensic indicators (evidence SHA-256 hashes, threat detections, ML anomaly scores) to stand out without visual exhaustion.

3. **High Information Density with Clear Hierarchy:**
   Data tables, inspector cards, and analysis views are compact and easily scannable. Typography differentiates structural UI labels from technical data (hashes, timestamps, identifiers) through deliberate font selection and weight hierarchy.

4. **Honest, Deterministic Status Presentation:**
   Color never stands alone. Triage tiers (Critical, High, Medium, Low, Informational), review states (New, Reviewed, False Positive, Escalated), and pipeline readiness statuses (Complete, Attention Required, Incomplete) always pair semantic colors with explicit textual badges and structured metadata. Incomplete or unnormalized evidence is clearly distinguished from verified data.

5. **Local-First, Zero-Flicker SPA Performance:**
   Pure CSS3 transitions with zero heavy JavaScript animation libraries. Rapid, crisp component updates, predictable tab switching, and full keyboard-navigable triage.

---

## 2. Design Tokens & Color Palette

```css
:root {
  /* Surfaces & Canvas Hierarchy */
  --color-bg: #111820;             /* Root canvas background */
  --color-surface: #19232D;        /* Primary panels, cards, and panes */
  --color-surface-raised: #202D38; /* Dropdowns, hover states, active modals */
  --color-surface-muted: #16212A;  /* Inactive tracks, secondary headers */
  --color-surface-sunken: #0D131A; /* Monospace code blocks, raw JSON displays */

  /* Borders & Dividers */
  --color-border: #2B3945;         /* Standard subtle borders and dividers */
  --color-border-strong: #3A4B58;  /* Table borders, active panel outlines */
  --color-border-focus: #45C5B0;   /* Interactive input focus indicator */

  /* Typography Colors */
  --color-text: #E8EEF3;           /* Primary high-contrast text */
  --color-text-secondary: #A7B4BF; /* Explanations, metadata, secondary text */
  --color-text-muted: #778794;     /* Captions, subtle labels, timestamps */
  --color-text-inverse: #0D131A;   /* Text on bright badges or buttons */

  /* Accent & Action Colors */
  --color-accent: #45C5B0;         /* Primary brand teal: actions, active tabs */
  --color-accent-hover: #63D4C1;   /* Hover state for primary action */
  --color-accent-active: #32A894;  /* Pressed state for primary action */
  --color-accent-dim: rgba(69, 197, 176, 0.12); /* Subtle teal background fill */

  /* Semantic Status & Triage Colors */
  --color-success: #54BD8A;        /* Confirmed, verified, valid SHA-256 */
  --color-success-bg: rgba(84, 189, 138, 0.12);
  --color-success-border: rgba(84, 189, 138, 0.35);

  --color-warning: #E5AD56;        /* Attention required, pending, review needed */
  --color-warning-bg: rgba(229, 173, 86, 0.12);
  --color-warning-border: rgba(229, 173, 86, 0.35);

  --color-danger: #E16D73;         /* Critical priority, threat IOC match, errors */
  --color-danger-bg: rgba(225, 109, 115, 0.12);
  --color-danger-border: rgba(225, 109, 115, 0.35);

  --color-info: #73AEE8;           /* Informational, temporal linkages */
  --color-info-bg: rgba(115, 174, 232, 0.12);
  --color-info-border: rgba(115, 174, 232, 0.35);

  --color-neutral-slate: #8F9FA9;  /* Unreviewed or standard metadata */

  /* Backward Compatibility Aliases */
  --bg-canvas: var(--color-bg);
  --bg-pane: var(--color-surface);
  --bg-raised: var(--color-surface-raised);
  --bg-secondary: var(--color-surface-muted);
  --border-subtle: var(--color-border);
  --border-active: var(--color-border-strong);
  --border-focus: var(--color-border-focus);
  --text-primary: var(--color-text);
  --text-secondary: var(--color-text-secondary);
  --text-muted: var(--color-text-muted);
  --accent-primary: var(--color-accent);
  --accent-technical: var(--color-info);
  --accent-danger: var(--color-danger);

  /* Spacing Scale */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 20px;
  --space-6: 24px;
  --space-8: 32px;

  /* Corner Radii */
  --radius-xs: 3px;
  --radius-sm: 5px;
  --radius-md: 8px;
  --radius-lg: 12px;

  /* Transitions */
  --transition-fast: 120ms ease;
  --transition-normal: 180ms ease;

  /* Elevation Shadows */
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.35);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.45);
  --shadow-lg: 0 8px 24px rgba(0, 0, 0, 0.60);
}
```

---

## 3. Typography & Hierarchy

### Font Families
- **UI & Prose:** `'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`
- **Technical & Cryptographic Data:** `'JetBrains Mono', 'SF Mono', Consolas, Menlo, monospace`
  - Applied to SHA-256 hashes, UUIDs, case numbers, timestamps, raw JSON, MITRE ATT&CK IDs, detection rules, and table offsets.

### Type Scale
| Level | Font Size | Line Height | Weight | Usage |
|---|---|---|---|---|
| Display / Case Title | 18px (1.125rem) | 1.3 | 600 SemiBold | Active investigation header |
| Section Title (H3) | 14px (0.875rem) | 1.4 | 600 SemiBold | Panel headers, modal titles |
| Card Subhead (H4) | 13px (0.8125rem) | 1.4 | 600 SemiBold | Inspector section headers |
| UI Body / Standard | 13px (0.8125rem) | 1.5 | 400 Regular | Paragraphs, descriptions, table cells |
| Compact Data / Table | 12px (0.75rem) | 1.4 | 400 / 500 | Dense table cells, form labels |
| Micro / Monospace Tag | 11px (0.6875rem) | 1.3 | 500 / 600 | Badges, status chips, metadata counters |
| Hash / Offset Value | 11px (0.6875rem) | 1.3 | 400 Regular | JetBrains Mono for SHA-256 strings |

---

## 4. Shared Component Patterns

### Buttons
- **Primary (`.btn-primary`):** Solid teal background (`var(--color-accent)`), dark text (`var(--color-text-inverse)`), subtle shadow. On hover: brighter teal (`var(--color-accent-hover)`). Used for main workflow actions: "Analyze Investigation", "Upload Evidence", "Download Report".
- **Secondary (`.btn-secondary`):** Raised dark surface (`var(--color-surface-raised)`), crisp border (`var(--color-border)`), primary text (`var(--color-text)`). Used for filters, stage execution, modals.
- **Ghost (`.btn-ghost`):** Transparent background, muted text, subtle hover outline. Used for dismissals, pagination buttons, utility resets.
- **Danger (`.btn-danger`):** Red accent tint for destructive actions.
- **Sizes:** Standard (32px height), Small (`.btn-sm`, 26px height), Extra-Small (`.btn-xs`, 22px height).

### Form Controls
- Inputs, selects, and textareas share:
  - Background: `var(--color-surface-sunken)` or `var(--color-surface-muted)`.
  - Border: 1px solid `var(--color-border)`.
  - Radius: `var(--radius-sm)` (5px).
  - Focus state: 1px solid `var(--color-border-focus)` with a soft `0 0 0 2px rgba(69, 197, 176, 0.2)` ring.
  - Text: `var(--color-text)` with muted placeholder text.

### Badges & Triage Status Pills
- **Review Statuses:**
  - `NEW`: Slate background (`rgba(143, 159, 169, 0.15)`), slate border and text (`#A7B4BF`).
  - `REVIEWED`: Blue background (`var(--color-info-bg)`), blue border and text (`var(--color-info)`).
  - `FALSE_POSITIVE`: Amber background (`var(--color-warning-bg)`), amber border and text (`var(--color-warning)`).
  - `ESCALATED`: Red background (`var(--color-danger-bg)`), red border and text (`var(--color-danger)`).
- **Priority Tiers:**
  - `CRITICAL`: Red pill with dark red backing.
  - `HIGH`: Amber-orange pill.
  - `MEDIUM`: Amber-gold pill.
  - `LOW`: Blue pill.
  - `INFORMATIONAL`: Slate-gray pill.
- **Readiness Checklist Badges:**
  - `COMPLETE`: Green border/pill with check indicator.
  - `ATTENTION_REQUIRED`: Amber border/pill with warning indicator.
  - `INCOMPLETE`: Muted slate border/pill.

### Data Tables (`.forensic-table`)
- Table Header: Sticky background (`var(--color-surface-muted)`), 11px uppercase bold labels with `letter-spacing: 0.05em`.
- Rows: Alternating subtle striping or clean border-bottom (`var(--color-border)`), hover highlight (`var(--color-surface-raised)`).
- Row Selection: Active/inspected row receives a prominent left border highlight in `var(--color-accent)` and background `var(--color-surface-raised)`.
- Hashes and IDs: Rendered inside `<code class="font-mono">` with safe truncation and full inspectability.

---

## 5. Application Shell & Layout

- **Top Navigation Bar (`#app-header`):**
  - Height: 52px, fixed/sticky at the top.
  - Background: `var(--color-surface)` with a 1px solid `var(--color-border)` bottom edge.
  - Brand: ForensiQ wordmark logo, sharp 1px vertical divider, followed by Case Selector dropdown and quick-action buttons.
- **Main Container (`.main-container`):**
  - Max-width: 1440px, centered with responsive horizontal padding (`20px` on desktop, `12px` on mobile).
- **Investigation Context Banner (`.case-banner`):**
  - Displays current case identity, status pill, case ID, creation metadata, and quick pipeline status.
- **Navigation Tabs (`.dashboard-nav`):**
  - 4 major destinations: Overview, Evidence, Analysis & Findings, Report.
  - Active tab indicated by solid teal bottom bar (`3px solid var(--color-accent)`), bright white text, and teal icon tint.

---

## 6. Screen Redesign Architecture

### A. Overview / Investigation Dashboard (`#tab-overview`)
- **Workflow Guide Panel:** A sleek horizontal step tracker showing the 5 stages of forensic investigation (Create Case, Upload Evidence, Analyze, Review, Report). Active and completed steps are highlighted in teal/green.
- **Pipeline Coordinator Card:** Central command for running all 7 stages or individual stages. Visual stage chips (`#chip-stage-1` to `#chip-stage-7`) reflect Idle, Running, Done, or Error states. Post-pipeline completion card offers a 1-click jump to Findings.
- **4 Core Metrics:** Clean, uninflated counts (Evidence Sources, Normalized Events, Detected Findings, Priority Activities).
- **Split Grid:**
  - Left: Dual-level triage distribution meters with horizontal progress fills.
  - Right: Top priority artifacts and activities table with explainable scores.

### B. Evidence Management (`#tab-evidence`)
- **Ingested Evidence Sources:** High-density inventory of raw evidence files with cryptographic SHA-256 digests recorded at ingestion.
- **Master-Detail Explorer:**
  - Left (~65%): Paginated normalized event stream with live filters (Source, Event Type, User, Device).
  - Right (~35%): Evidence Record Inspector with Common Evidence Schema mappings, timeline context, and JSON attribute view.

### C. Analysis & Findings (`#tab-analysis`) — Analytical Core
- **Clustered Activity Threads Table:** Attack narratives synthesizing multi-event activities.
- **Findings Summary Header:** 4 interactive metric cards (Total, High/Critical, Medium, Low/Info) that filter findings on click.
- **Filtering & Search Toolbar:** Multi-attribute filtering (Priority, Detection Method, Correlated Activity, Review Status, and live text search) with keyboard shortcut badges.
- **Findings Table:** High-density scannable threat list.
- **Synchronized Finding Detail & Traceability Card:** Displays detection rationale ("Why Was This Detected?"), supporting evidence records, correlated activities, explainable priority score breakdown, investigator review notes editor, and raw SHA-256 detection fingerprint.
- **Collapsible Technical Forensics:** Graph correlations and dual-level prioritization score tables.

### D. Reporting (`#tab-report`)
- **Executive Export Card:** Preflight download trigger with disclaimer on SHA-256 ingestion digest integrity semantics.
- **Investigation Readiness Checklist:** 6 operational audit cards (Ingestion, Normalization, Detections, Anomalies, Activities, Prioritization) displaying authoritative audit statuses.
- **Report Configuration & Preflight Workspace:**
  - Section checkboxes and priority filter.
  - Live preflight audit showing count of included entities and observations.
- **Investigator Case Notes:** Textarea with live character counter (up to 20,000 chars) and auto-save on blur.

---

## 7. Responsive Behavior & Breakpoints

- **Wide Desktop (> 1440px):** Full layout with generous margins and max-width 1440px container.
- **Standard Laptop (1025px - 1440px):** Default compact view, master-detail layout remains side-by-side (65% / 35%).
- **Small Laptop / Tablet Landscape (769px - 1024px):**
  - Master-detail stacks vertically when inspector is active.
  - 4-metric grid adjusts from 4 columns to 2 columns.
  - Report workspace grid stacks vertically.
- **Mobile / Portrait (< 768px):**
  - Navigation tabs scroll horizontally if needed without wrapping awkwardly.
  - Header reorganizes into a compact vertical or wrapped flex layout.
  - Tables enable horizontal touch scrolling (`.table-responsive`) with preserved sticky headers.

---

## 8. Accessibility (WCAG 2.1 AA Compliance)

- **Contrast:** All text tokens meet or exceed 4.5:1 contrast against their respective surface backgrounds (`#E8EEF3` on `#19232D` is > 10:1).
- **Keyboard Navigation:**
  - Clear `:focus-visible` outline (`2px solid var(--color-border-focus)` with 2px offset).
  - Tab cycle trap inside active modals with focus restoration upon dismissal.
  - Full support for `1`, `2`, `3`, `4` tab switching, `J`/`K` and `ArrowUp`/`ArrowDown` row navigation.
  - Input guards to prevent shortcut collisions during text entry.
- **Multi-Modal Communication:** Badges never rely on color alone; every badge includes textual status labels and ARIA attributes.
- **Reduced Motion:** `@media (prefers-reduced-motion: reduce)` disables all animations and transitions.
