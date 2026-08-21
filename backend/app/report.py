"""
ForensiQ Investigation Report Generator
Produces a professional A4 PDF from live investigation data using ReportLab.
No database writes. No persistent storage. Pure in-memory generation.
"""

import io
from datetime import datetime, timezone
from typing import List, Optional, Any, Dict

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)


# ── Palette ────────────────────────────────────────────────────────────────────
C_NAVY     = colors.HexColor("#0d1b2a")
C_BLUE     = colors.HexColor("#1e3a5f")
C_ACCENT   = colors.HexColor("#3a86ff")
C_LIGHT_BG = colors.HexColor("#f0f4f8")
C_ALT_ROW  = colors.HexColor("#e8eef6")
C_BORDER   = colors.HexColor("#c5d0de")
C_WHITE    = colors.white
C_TEXT     = colors.HexColor("#1a1a2e")
C_MUTED    = colors.HexColor("#5a6a7a")
C_CRITICAL = colors.HexColor("#dc2626")
C_HIGH     = colors.HexColor("#ea580c")
C_MEDIUM   = colors.HexColor("#ca8a04")
C_LOW      = colors.HexColor("#2563eb")
C_INFO_C   = colors.HexColor("#4b5563")


def _tier_color(tier: str) -> Any:
    return {"CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
            "MEDIUM": C_MEDIUM, "LOW": C_LOW}.get(tier, C_INFO_C)


# ── Human-readable label maps ──────────────────────────────────────────────────
FINDING_TYPE_LABELS = {
    "RULE_MATCH":  "Rule Match",
    "IOC_MATCH":   "IOC Match",
    "ML_ANOMALY":  "ML Anomaly",
}
ACTIVITY_TYPE_LABELS = {
    "PROCESS_ACTIVITY":    "Process Activity",
    "NETWORK_ACTIVITY":    "Network Activity",
    "FILE_ACTIVITY":       "File Activity",
    "AUTHENTICATION":      "Authentication",
    "MIXED_ACTIVITY":      "Mixed Activity",
}
STATUS_LABELS = {
    "NEW":       "New",
    "REVIEWING": "Reviewing",
    "REVIEWED":  "Reviewed",
    "DISMISSED": "Dismissed",
    "COMPLETED": "Completed",
    "FAILED":    "Failed",
    "OPEN":      "Open",
    "CLOSED":    "Closed",
}


def _label(val: str, mapping: Dict[str, str]) -> str:
    return mapping.get(str(val).upper(), str(val).replace("_", " ").title())


# ── Styles ─────────────────────────────────────────────────────────────────────
def _styles() -> Dict[str, ParagraphStyle]:
    s: Dict[str, ParagraphStyle] = {}

    s["cover_title"] = ParagraphStyle("cover_title",
        fontSize=26, fontName="Helvetica-Bold",
        textColor=C_WHITE, alignment=TA_CENTER,
        spaceBefore=0, spaceAfter=0, leading=32)

    s["cover_sub"] = ParagraphStyle("cover_sub",
        fontSize=12, fontName="Helvetica",
        textColor=colors.HexColor("#b0c8e8"), alignment=TA_CENTER,
        spaceBefore=0, spaceAfter=0, leading=16)

    s["cover_meta"] = ParagraphStyle("cover_meta",
        fontSize=10, fontName="Helvetica",
        textColor=colors.HexColor("#d0dff0"), alignment=TA_CENTER,
        spaceBefore=0, spaceAfter=0, leading=14)

    s["section_heading"] = ParagraphStyle("section_heading",
        fontSize=12, fontName="Helvetica-Bold",
        textColor=C_BLUE, spaceBefore=12, spaceAfter=4)

    s["body"] = ParagraphStyle("body",
        fontSize=9, fontName="Helvetica",
        textColor=C_TEXT, spaceAfter=4, leading=13)

    s["disclaimer"] = ParagraphStyle("disclaimer",
        fontSize=8, fontName="Helvetica-Oblique",
        textColor=C_MUTED, spaceAfter=4, leading=12)

    s["metric_val"] = ParagraphStyle("metric_val",
        fontSize=20, fontName="Helvetica-Bold",
        textColor=C_ACCENT, alignment=TA_CENTER, spaceAfter=1, leading=24)

    s["metric_lbl"] = ParagraphStyle("metric_lbl",
        fontSize=7, fontName="Helvetica",
        textColor=C_MUTED, alignment=TA_CENTER, leading=10)

    s["cell"] = ParagraphStyle("cell",
        fontSize=8, fontName="Helvetica",
        textColor=C_TEXT, leading=11)

    s["cell_mono"] = ParagraphStyle("cell_mono",
        fontSize=7, fontName="Courier",
        textColor=C_TEXT, leading=10)

    s["th_style"] = ParagraphStyle("th_style",
        fontSize=8, fontName="Helvetica-Bold",
        textColor=C_WHITE, leading=10)

    s["label"] = ParagraphStyle("label",
        fontSize=8, fontName="Helvetica-Bold",
        textColor=C_MUTED, spaceAfter=2)

    return s


# ── Page chrome ────────────────────────────────────────────────────────────────
class _ForensiqDoc(BaseDocTemplate):
    def __init__(self, buf: io.BytesIO, case_number: str, generated_at: str):
        self.case_number  = case_number
        self.generated_at = generated_at
        margin = 18 * mm
        super().__init__(
            buf, pagesize=A4,
            leftMargin=margin, rightMargin=margin,
            topMargin=26 * mm, bottomMargin=22 * mm,
            title=f"ForensiQ Report — {case_number}",
            author="ForensiQ",
        )
        cw = A4[0] - 2 * margin
        ch = A4[1] - 26 * mm - 22 * mm
        frame = Frame(margin, 22 * mm, cw, ch, id="main", leftPadding=0, rightPadding=0)
        tpl = PageTemplate(id="main", frames=[frame], onPage=self._chrome)
        self.addPageTemplates([tpl])

    def _chrome(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # ── Running header bar ──────────────────────────────────────────────
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, h - 22 * mm, w, 22 * mm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 11)
        canvas.drawString(18 * mm, h - 11 * mm, "ForensiQ")
        canvas.setFont("Helvetica", 8.5)
        canvas.setFillColor(colors.HexColor("#b0c8e8"))
        canvas.drawString(18 * mm, h - 18 * mm, "Digital Forensic Triage Report")
        canvas.setFillColor(colors.HexColor("#b0c8e8"))
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 18 * mm, h - 11 * mm, self.case_number)
        canvas.drawRightString(w - 18 * mm, h - 18 * mm, self.generated_at)

        # ── Footer ──────────────────────────────────────────────────────────
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, 18 * mm, w - 18 * mm, 18 * mm)
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(18 * mm, 13 * mm, "ForensiQ — Digital Forensic Triage Report")
        canvas.drawRightString(w - 18 * mm, 13 * mm, f"Page {doc.page}")
        canvas.restoreState()


# ── Cell / header helpers ───────────────────────────────────────────────────────
def _th(text: str, s: Dict) -> Paragraph:
    return Paragraph(text, s["th_style"])


def _td(text: str, s: Dict, mono: bool = False) -> Paragraph:
    st = s["cell_mono"] if mono else s["cell"]
    return Paragraph("—" if (text is None or str(text).strip() == "") else str(text), st)


def _base_style() -> List:
    return [
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ALT_ROW]),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]


def _tbl(rows: List, col_widths: List, extra_cmds: List = None) -> Table:
    cmds = _base_style() + (extra_cmds or [])
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(cmds))
    return t


# ── Utility ────────────────────────────────────────────────────────────────────
def _safe(val: Any, max_len: int = 300) -> str:
    if val is None: return "—"
    text = str(val).strip()
    if len(text) > max_len: text = text[:max_len] + "…"
    return text or "—"


def _fmt_dt(dt: Optional[datetime]) -> str:
    if dt is None: return "—"
    if isinstance(dt, str):
        # parse ISO string coming from API layer
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except Exception:
            return str(dt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M")


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _section(title: str, s: Dict) -> List:
    return [
        Spacer(1, 5 * mm),
        KeepTogether([
            Paragraph(title, s["section_heading"]),
            HRFlowable(width="100%", thickness=1.0, color=C_ACCENT, spaceAfter=4),
        ]),
    ]


# ── Data container ─────────────────────────────────────────────────────────────
class ReportData:
    def __init__(self):
        self.investigation:   Dict       = {}
        self.summary:         Dict       = {}
        self.findings:        List[Dict] = []
        self.relationships:   List[Dict] = []
        self.activities:      List[Dict] = []
        self.priority_results:List[Dict] = []
        self.sources:         List[Dict] = []
        self.generated_at:    datetime   = datetime.now(timezone.utc)


# ── Main generator ─────────────────────────────────────────────────────────────
def generate_report_pdf(data: ReportData) -> bytes:
    buf = io.BytesIO()
    s   = _styles()

    inv          = data.investigation
    case_number  = inv.get("case_number", "UNKNOWN")
    generated_str = data.generated_at.strftime("%Y-%m-%d %H:%M UTC")

    doc   = _ForensiqDoc(buf, case_number, generated_str)
    story: List = []
    pw    = A4[0] - 36 * mm   # usable page width

    # ── 1. COVER ───────────────────────────────────────────────────────────────
    # Use a single dark background table with clear vertical spacing between rows
    cover_rows = [
        [Paragraph("ForensiQ", s["cover_title"])],
        [Spacer(1, 4 * mm)],
        [Paragraph("Digital Forensic Triage Report", s["cover_sub"])],
        [Spacer(1, 6 * mm)],
        [Paragraph(f"Case Number: {case_number}", s["cover_meta"])],
        [Paragraph(f"Title: {_safe(inv.get('title', ''), 120)}", s["cover_meta"])],
        [Spacer(1, 2 * mm)],
        [Paragraph(f"Status: {_label(inv.get('status','OPEN'), STATUS_LABELS)}", s["cover_meta"])],
        [Paragraph(f"Created: {_fmt_dt(inv.get('created_at'))}", s["cover_meta"])],
        [Paragraph(f"Generated: {generated_str}", s["cover_meta"])],
        [Spacer(1, 8 * mm)],
    ]
    cover_tbl = Table(cover_rows, colWidths=[pw])
    cover_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 18),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 18),
    ]))
    story.append(cover_tbl)
    story.append(Spacer(1, 6 * mm))

    # ── 2. EXECUTIVE SUMMARY ───────────────────────────────────────────────────
    story.extend(_section("Executive Summary", s))

    sm = data.summary
    metrics = [
        ("Evidence\nSources",  sm.get("total_sources", 0)),
        ("Evidence\nRecords",  sm.get("total_evidence", 0)),
        ("Total\nFindings",    sm.get("total_findings", 0)),
        ("ML\nAnomalies",      sm.get("total_anomalies", 0)),
        ("Correla-\ntions",    sm.get("total_relationships", 0)),
        ("Activi-\nties",      sm.get("total_activities", 0)),
    ]
    col_w = pw / len(metrics)
    metric_cells = []
    for label, value in metrics:
        cell = Table(
            [[Paragraph(str(value), s["metric_val"])],
             [Paragraph(label, s["metric_lbl"])]],
            colWidths=[col_w - 2 * mm],
        )
        cell.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_LIGHT_BG),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 2),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 2),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ]))
        metric_cells.append(cell)
    story.append(Table([metric_cells], colWidths=[col_w] * len(metrics),
        style=TableStyle([("TOPPADDING",(0,0),(-1,-1),0),("BOTTOMPADDING",(0,0),(-1,-1),0)])))
    story.append(Spacer(1, 4 * mm))

    # ── 3. PRIORITY OVERVIEW ───────────────────────────────────────────────────
    story.extend(_section("Priority Overview", s))

    tc = sm.get("priority_tier_counts", {})
    tier_rows = [
        [_th("Tier", s), _th("Count", s), _th("Description", s)],
        [_td("CRITICAL",      s), _td(str(tc.get("CRITICAL",0)),      s), _td("Requires immediate investigator action", s)],
        [_td("HIGH",          s), _td(str(tc.get("HIGH",0)),          s), _td("High-priority review recommended", s)],
        [_td("MEDIUM",        s), _td(str(tc.get("MEDIUM",0)),        s), _td("Review within normal workflow", s)],
        [_td("LOW",           s), _td(str(tc.get("LOW",0)),           s), _td("Low urgency — monitor for escalation", s)],
        [_td("INFORMATIONAL", s), _td(str(tc.get("INFORMATIONAL",0)), s), _td("Background context record", s)],
    ]
    tier_extra = [
        ("TEXTCOLOR",(0,1),(0,1),C_CRITICAL), ("FONTNAME",(0,1),(0,1),"Helvetica-Bold"),
        ("TEXTCOLOR",(0,2),(0,2),C_HIGH),      ("FONTNAME",(0,2),(0,2),"Helvetica-Bold"),
        ("TEXTCOLOR",(0,3),(0,3),C_MEDIUM),    ("FONTNAME",(0,3),(0,3),"Helvetica-Bold"),
        ("TEXTCOLOR",(0,4),(0,4),C_LOW),       ("FONTNAME",(0,4),(0,4),"Helvetica-Bold"),
        ("TEXTCOLOR",(0,5),(0,5),C_INFO_C),    ("FONTNAME",(0,5),(0,5),"Helvetica-Bold"),
    ]
    story.append(_tbl(tier_rows, [46*mm, 20*mm, pw-66*mm], tier_extra))

    # Top priority results
    top = data.priority_results[:10]
    if top:
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("Top Priority Results", s["label"]))
        top_rows = [[_th("Tier", s), _th("Score", s), _th("Target", s), _th("Explanation", s)]]
        for pr in top:
            top_rows.append([
                _td(pr.get("priority_tier", ""), s),
                _td(f"{pr.get('priority_score', 0):.1f}", s),
                _td(pr.get("target_type", ""), s),
                _td(_safe(pr.get("explanation_text", ""), 200), s),
            ])
        story.append(_tbl(top_rows, [28*mm, 16*mm, 22*mm, pw-66*mm]))

    # ── 4. FINDINGS & DETECTION RESULTS ───────────────────────────────────────
    story.extend(_section("Findings & Detection Results", s))

    if data.findings:
        f_rows = [[
            _th("Type", s), _th("Severity", s), _th("Rule / IOC ID", s),
            _th("MITRE Tactic", s), _th("Description", s), _th("Detected", s),
        ]]
        for f in data.findings:
            ftype = _label(f.get("finding_type", ""), FINDING_TYPE_LABELS)
            mitre = _safe(f.get("mitre_tactic", ""), 30)
            f_rows.append([
                _td(ftype, s),
                _td(f"{f.get('severity', 0):.2f}", s),
                _td(_safe(f.get("rule_id", ""), 36), s),
                _td(mitre, s),
                _td(_safe(f.get("description", ""), 180), s),
                _td(_fmt_dt(f.get("created_at")), s),
            ])
        # Type=28, Sev=16, RuleID=38, MITRE=30, Desc=fill, Date=30
        desc_w = pw - 142*mm
        story.append(_tbl(f_rows, [28*mm, 16*mm, 38*mm, 30*mm, max(desc_w, 25*mm), 30*mm]))
    else:
        story.append(Paragraph("No findings recorded for this investigation.", s["body"]))

    # ── 5. ML ANOMALIES ────────────────────────────────────────────────────────
    story.extend(_section("ML Anomalies", s))

    ml_findings = [f for f in data.findings if f.get("finding_type") == "ML_ANOMALY"]
    if ml_findings:
        ml_rows = [[_th("Rule ID", s), _th("Anomaly Score", s), _th("Description", s), _th("Detected At", s)]]
        for f in ml_findings:
            ml_rows.append([
                _td(_safe(f.get("rule_id", ""), 32), s),
                _td(f"{f.get('severity', 0):.4f}", s),
                _td(_safe(f.get("description", ""), 200), s),
                _td(_fmt_dt(f.get("created_at")), s),
            ])
        story.append(_tbl(ml_rows, [38*mm, 26*mm, pw-94*mm, 30*mm]))
    else:
        story.append(Paragraph("No ML anomalies detected for this investigation.", s["body"]))

    # ── 6. CORRELATIONS ────────────────────────────────────────────────────────
    story.extend(_section("Correlations", s))

    if data.relationships:
        display_rels = data.relationships[:100]
        # rel_type=50, weight=18, src uuid=fill/2, tgt uuid=fill/2
        id_w = (pw - 68*mm) / 2
        r_rows = [[
            _th("Relationship Type", s), _th("Weight", s),
            _th("Source Evidence ID", s), _th("Target Evidence ID", s),
        ]]
        for r in display_rels:
            rel_type = r.get("relationship_type", "")
            # human-friendly: replace _ with space, title-case
            rel_label = rel_type.replace("_", " ").title()
            r_rows.append([
                _td(rel_label, s),
                _td(f"{r.get('weight', 0):.3f}", s),
                _td(_safe(str(r.get("source_evidence_id", "")), 36), s, mono=True),
                _td(_safe(str(r.get("target_evidence_id", "")), 36), s, mono=True),
            ])
        story.append(_tbl(r_rows, [50*mm, 18*mm, id_w, id_w]))

        total_rels = sm.get("total_relationships", len(data.relationships))
        if total_rels > 100:
            story.append(Paragraph(
                f"Showing first 100 of {total_rels} correlations.", s["body"]))
    else:
        story.append(Paragraph("No correlations discovered for this investigation.", s["body"]))

    # ── 7. INVESTIGATION ACTIVITIES ────────────────────────────────────────────
    story.extend(_section("Investigation Activities", s))

    if data.activities:
        a_rows = [[
            _th("Activity Title", s), _th("Type", s), _th("Status", s),
            _th("Start Time", s), _th("End Time", s), _th("Evid.", s), _th("Find.", s),
        ]]
        for a in data.activities:
            act_type = _label(a.get("activity_type", ""), ACTIVITY_TYPE_LABELS)
            act_status = _label(a.get("status", ""), STATUS_LABELS)
            a_rows.append([
                _td(_safe(a.get("title", ""), 55), s),
                _td(act_type, s),
                _td(act_status, s),
                _td(_fmt_dt(a.get("start_time")), s),
                _td(_fmt_dt(a.get("end_time")), s),
                _td(str(a.get("evidence_count", 0)), s),
                _td(str(a.get("finding_count", 0)), s),
            ])
        # title=fill, type=32, status=18, start=30, end=30, evd=12, find=12
        title_w = max(pw - 134*mm, 30*mm)
        story.append(_tbl(a_rows, [title_w, 32*mm, 18*mm, 30*mm, 30*mm, 12*mm, 12*mm]))
    else:
        story.append(Paragraph("No activities formed for this investigation.", s["body"]))

    # ── 8. EVIDENCE SOURCES ────────────────────────────────────────────────────
    story.extend(_section("Evidence Sources", s))

    if data.sources:
        src_rows = [[
            _th("Filename", s), _th("Format", s), _th("SHA-256 (first 16 chars)", s),
            _th("Size", s), _th("Records", s), _th("Normalized", s),
            _th("Status", s), _th("Ingested At", s),
        ]]
        for src in data.sources:
            sha = str(src.get("sha256_hash", ""))
            sha_display = sha[:16] + "…" if len(sha) > 16 else sha
            ing_status  = _label(src.get("ingestion_status", ""), STATUS_LABELS)
            src_rows.append([
                _td(_safe(src.get("filename", ""), 40), s),
                _td(src.get("file_format", ""), s),
                _td(sha_display, s, mono=True),
                _td(_fmt_bytes(src.get("file_size_bytes", 0)), s),
                _td(str(src.get("total_records", 0)), s),
                _td(str(src.get("normalized_records", 0)), s),
                _td(ing_status, s),
                _td(_fmt_dt(src.get("ingested_at")), s),
            ])
        story.append(_tbl(
            src_rows,
            [36*mm, 14*mm, 26*mm, 14*mm, 15*mm, 18*mm, 20*mm, 29*mm],
        ))
    else:
        story.append(Paragraph("No evidence sources ingested for this investigation.", s["body"]))

    # ── 9. TRIAGE DISCLAIMER ───────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=4))
    story.append(Paragraph("Triage Disclaimer", s["section_heading"]))
    story.append(Paragraph(
        "This report summarises the current forensic triage results produced by ForensiQ. "
        "Detection, anomaly, correlation, and prioritisation results are analytical outputs for "
        "investigator review and do not by themselves establish malicious intent, attribution, "
        "guilt, or legal conclusions. All findings should be verified by a qualified investigator "
        "before being used as the basis for any legal, disciplinary, or enforcement action.",
        s["disclaimer"],
    ))

    doc.build(story)
    return buf.getvalue()
