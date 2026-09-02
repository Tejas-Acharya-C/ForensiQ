"""
ForensiQ Investigation Report Generator
Produces a professional A4 PDF from live investigation data using ReportLab.
No database writes. No persistent storage. Pure in-memory generation.
"""

import io
import os
from pathlib import Path
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
    Image,
)
from reportlab.lib.utils import ImageReader

# Resolve absolute paths to assets
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
LOGO_PATH = PROJECT_ROOT / "images" / "logo.png"
WORDMARK_PATH = PROJECT_ROOT / "images" / "logo_wordmap.png"

# ── Palette ────────────────────────────────────────────────────────────────────
C_NAVY     = colors.HexColor("#0f172a")
C_BLUE     = colors.HexColor("#1e293b")
C_ACCENT   = colors.HexColor("#0284c7")
C_LIGHT_BG = colors.HexColor("#f8fafc")
C_ALT_ROW  = colors.HexColor("#f1f5f9")
C_BORDER   = colors.HexColor("#cbd5e1")
C_WHITE    = colors.white
C_WHITE_TRANS = colors.Color(1, 1, 1, alpha=0.5)
C_ALT_ROW_TRANS = colors.Color(0.945, 0.961, 0.976, alpha=0.5)
C_TEXT     = colors.HexColor("#334155")
C_MUTED    = colors.HexColor("#64748b")
C_CRITICAL = colors.HexColor("#b91c1c")
C_HIGH     = colors.HexColor("#c2410c")
C_MEDIUM   = colors.HexColor("#a16207")
C_LOW      = colors.HexColor("#1d4ed8")
C_INFO_C   = colors.HexColor("#475569")

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
        fontSize=24, fontName="Helvetica-Bold",
        textColor=C_NAVY, alignment=TA_CENTER, spaceAfter=8, leading=30)

    s["cover_sub"] = ParagraphStyle("cover_sub",
        fontSize=14, fontName="Helvetica",
        textColor=C_MUTED, alignment=TA_CENTER, spaceAfter=20, leading=18)

    s["cover_meta_lbl"] = ParagraphStyle("cover_meta_lbl",
        fontSize=10, fontName="Helvetica-Bold",
        textColor=C_NAVY, alignment=TA_LEFT, spaceAfter=2, leading=14)

    s["cover_meta_val"] = ParagraphStyle("cover_meta_val",
        fontSize=10, fontName="Helvetica",
        textColor=C_TEXT, alignment=TA_LEFT, spaceAfter=10, leading=14)

    s["section_heading"] = ParagraphStyle("section_heading",
        fontSize=14, fontName="Helvetica-Bold",
        textColor=C_NAVY, spaceBefore=16, spaceAfter=6)

    s["body"] = ParagraphStyle("body",
        fontSize=9, fontName="Helvetica",
        textColor=C_TEXT, spaceAfter=6, leading=13)

    s["disclaimer"] = ParagraphStyle("disclaimer",
        fontSize=8, fontName="Helvetica-Oblique",
        textColor=C_MUTED, spaceAfter=4, leading=12)

    s["metric_val"] = ParagraphStyle("metric_val",
        fontSize=18, fontName="Helvetica-Bold",
        textColor=C_ACCENT, alignment=TA_CENTER, spaceAfter=2, leading=22)

    s["metric_lbl"] = ParagraphStyle("metric_lbl",
        fontSize=8, fontName="Helvetica",
        textColor=C_MUTED, alignment=TA_CENTER, leading=11)

    s["cell"] = ParagraphStyle("cell",
        fontSize=8, fontName="Helvetica",
        textColor=C_TEXT, leading=11, wordWrap='CJK')

    s["cell_mono"] = ParagraphStyle("cell_mono",
        fontSize=7.5, fontName="Courier",
        textColor=C_TEXT, leading=10, wordWrap='CJK')

    s["th_style"] = ParagraphStyle("th_style",
        fontSize=8.5, fontName="Helvetica-Bold",
        textColor=C_WHITE, leading=11)

    s["label"] = ParagraphStyle("label",
        fontSize=9, fontName="Helvetica-Bold",
        textColor=C_NAVY, spaceAfter=4)

    return s


# ── Page chrome ────────────────────────────────────────────────────────────────
class _ForensiqDoc(BaseDocTemplate):
    def __init__(self, buf: io.BytesIO, case_number: str, generated_at: str):
        self.case_number  = case_number
        self.generated_at = generated_at
        margin = 15 * mm
        super().__init__(
            buf, pagesize=A4,
            leftMargin=margin, rightMargin=margin,
            topMargin=25 * mm, bottomMargin=22 * mm,
            title=f"ForensiQ Report — {case_number}",
            author="ForensiQ",
        )
        cw = A4[0] - 2 * margin
        ch = A4[1] - 25 * mm - 22 * mm
        frame = Frame(margin, 22 * mm, cw, ch, id="main", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        tpl = PageTemplate(id="main", frames=[frame], onPage=self._chrome)
        self.addPageTemplates([tpl])

    def _chrome(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # ── Background Watermark ───────────────────────────────────────────
        if os.path.exists(WORDMARK_PATH):
            try:
                canvas.saveState()
                opacity = 0.03 if doc.page == 1 else 0.07
                canvas.setFillAlpha(opacity)
                
                # Center without rotation for perfect visual centering
                canvas.translate(w / 2.0, h / 2.0)
                
                img_reader = ImageReader(str(WORDMARK_PATH))
                iw, ih = img_reader.getSize()
                
                # Scale nicely across the page
                scale = (w * 0.7) / iw
                draw_w = iw * scale
                draw_h = ih * scale
                
                canvas.drawImage(img_reader, -draw_w / 2.0, -draw_h / 2.0, draw_w, draw_h, mask='auto')
                canvas.restoreState()
            except Exception:
                pass # Safe fallback if image reading fails

        # ── Header (Content pages only) ────────────────────────────────────
        if doc.page > 1:
            if os.path.exists(LOGO_PATH):
                try:
                    img_reader = ImageReader(str(LOGO_PATH))
                    # 10mm high logo
                    canvas.drawImage(img_reader, 15 * mm, h - 18 * mm, 10 * mm, 10 * mm, mask='auto', preserveAspectRatio=True)
                except Exception:
                    pass
            
            canvas.setFillColor(C_NAVY)
            canvas.setFont("Helvetica-Bold", 10)
            canvas.drawString(28 * mm, h - 13 * mm, "ForensiQ")
            
            canvas.setFillColor(C_MUTED)
            canvas.setFont("Helvetica", 8)
            canvas.drawString(28 * mm, h - 17 * mm, "Digital Forensic Investigation Report")
            
            canvas.drawRightString(w - 15 * mm, h - 13 * mm, f"Case: {self.case_number}")
            canvas.drawRightString(w - 15 * mm, h - 17 * mm, self.generated_at)
            
            # Header line
            canvas.setStrokeColor(C_BORDER)
            canvas.setLineWidth(0.5)
            canvas.line(15 * mm, h - 22 * mm, w - 15 * mm, h - 22 * mm)

        # ── Footer ──────────────────────────────────────────────────────────
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(15 * mm, 16 * mm, w - 15 * mm, 16 * mm)
        
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(15 * mm, 11 * mm, f"ForensiQ — Case {self.case_number}")
        canvas.drawRightString(w - 15 * mm, 11 * mm, f"Page {doc.page}")
        
        canvas.restoreState()


# ── Cell / header helpers ───────────────────────────────────────────────────────
def _th(text: str, s: Dict) -> Paragraph:
    return Paragraph(text, s["th_style"])


def _td(text: str, s: Dict, mono: bool = False) -> Paragraph:
    st = s["cell_mono"] if mono else s["cell"]
    return Paragraph("—" if (text is None or str(text).strip() == "") else str(text), st)


def _base_style() -> List:
    return [
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE_TRANS, C_ALT_ROW_TRANS]),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]


def _tbl(rows: List, col_widths: List, extra_cmds: List = None) -> Table:
    cmds = _base_style() + (extra_cmds or [])
    t = Table(rows, colWidths=col_widths, repeatRows=1, splitByRow=True)
    t.setStyle(TableStyle(cmds))
    return t


# ── Utility ────────────────────────────────────────────────────────────────────
def _fmt_dt(dt: Optional[datetime]) -> str:
    if dt is None: return "—"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except Exception:
            return str(dt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _section(title: str, s: Dict) -> List:
    return [
        Spacer(1, 6 * mm),
        KeepTogether([
            Paragraph(title, s["section_heading"]),
            HRFlowable(width="100%", thickness=1.0, color=C_NAVY, spaceAfter=6),
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
    pw    = A4[0] - 30 * mm   # usable page width (left 15mm, right 15mm)

    # ── 1. COVER ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 35 * mm))
    
    if os.path.exists(WORDMARK_PATH):
        story.append(Image(str(WORDMARK_PATH), width=130*mm, height=32.5*mm, kind='proportional', hAlign='CENTER'))
        story.append(Spacer(1, 15 * mm))
    else:
        story.append(Paragraph("ForensiQ", s["cover_title"]))

    story.append(Paragraph("Digital Forensic Investigation Report", s["cover_sub"]))
    story.append(Spacer(1, 20 * mm))

    # Clean Cover Metadata Grid
    meta_rows = [
        [Paragraph("CASE IDENTIFIER", s["cover_meta_lbl"]), Paragraph("INVESTIGATION TITLE", s["cover_meta_lbl"])],
        [Paragraph(case_number, s["cover_meta_val"]), Paragraph(str(inv.get('title', '—')), s["cover_meta_val"])],
        [Paragraph("STATUS", s["cover_meta_lbl"]), Paragraph("CREATED", s["cover_meta_lbl"])],
        [Paragraph(_label(inv.get('status','OPEN'), STATUS_LABELS), s["cover_meta_val"]), Paragraph(_fmt_dt(inv.get('created_at')), s["cover_meta_val"])],
        [Paragraph("GENERATED", s["cover_meta_lbl"]), Paragraph("", s["cover_meta_lbl"])],
        [Paragraph(generated_str, s["cover_meta_val"]), Paragraph("", s["cover_meta_val"])],
    ]
    meta_tbl = Table(meta_rows, colWidths=[pw / 2.0, pw / 2.0])
    meta_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(meta_tbl)
    
    story.append(Spacer(1, 15 * mm))

    # ── EXECUTIVE SUMMARY (Still on Cover Page) ────────────────────────────────
    story.extend(_section("Executive Overview", s))
    
    sm = data.summary
    overview_text = (
        f"This report details the forensic triage and automated analysis for Case {case_number}. "
        f"The investigation ingested {sm.get('total_sources', 0)} evidence sources, extracting "
        f"{sm.get('total_evidence', 0)} individual records. Automated engines produced "
        f"{sm.get('total_findings', 0)} findings, {sm.get('total_anomalies', 0)} anomalies, "
        f"and {sm.get('total_relationships', 0)} forensic correlations, which were subsequently "
        f"grouped into {sm.get('total_activities', 0)} investigation activities."
    )
    story.append(Paragraph(overview_text, s["body"]))

    story.append(Spacer(1, 15 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=4))
    story.append(Paragraph(
        "CONFIDENTIAL: This document contains sensitive forensic triage data. "
        "Do not distribute without authorization.", s["disclaimer"]
    ))
    
    # ── PAGE BREAK ──
    from reportlab.platypus import PageBreak
    story.append(PageBreak())

    # ── 2. INVESTIGATION FINDINGS (Page 2) ─────────────────────────────────────
    story.extend(_section("Priority Assessment", s))

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
    story.append(_tbl(tier_rows, [40*mm, 20*mm, pw-60*mm], tier_extra))

    # Top priority results
    top = data.priority_results[:10]
    if top:
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("Top Priority Results", s["label"]))
        top_rows = [[_th("Tier", s), _th("Score", s), _th("Target", s), _th("Explanation", s)]]
        for pr in top:
            top_rows.append([
                _td(pr.get("priority_tier", ""), s),
                _td(f"{pr.get('priority_score', 0):.1f}", s),
                _td(pr.get("target_type", ""), s),
                _td(pr.get("explanation_text", ""), s),
            ])
        story.append(_tbl(top_rows, [25*mm, 15*mm, 25*mm, pw-65*mm]))

    story.extend(_section("Key Findings", s))

    if data.findings:
        f_rows = [[
            _th("Type", s), _th("Sev.", s), _th("Rule / IOC", s),
            _th("MITRE", s), _th("Description", s), _th("Detected", s),
        ]]
        for f in data.findings:
            ftype = _label(f.get("finding_type", ""), FINDING_TYPE_LABELS)
            f_rows.append([
                _td(ftype, s),
                _td(f"{f.get('severity', 0):.2f}", s),
                _td(f.get("rule_id", ""), s, mono=True),
                _td(f.get("mitre_tactic", ""), s),
                _td(f.get("description", ""), s),
                _td(_fmt_dt(f.get("created_at")).replace(" UTC",""), s),
            ])
        desc_w = pw - (25 + 12 + 35 + 25 + 28) * mm
        story.append(_tbl(f_rows, [25*mm, 12*mm, 35*mm, 25*mm, desc_w, 28*mm]))
    else:
        story.append(Paragraph("No findings recorded for this investigation.", s["body"]))

    # ── 3. EVIDENCE & CORRELATION ANALYSIS ─────────────────────────────────────
    story.extend(_section("Evidence Sources", s))

    if data.sources:
        src_rows = [[
            _th("Filename", s), _th("Format", s), _th("SHA-256 (truncated)", s),
            _th("Size", s), _th("Status", s), _th("Ingested At", s),
        ]]
        for src in data.sources:
            sha = str(src.get("sha256_hash", ""))
            sha_display = sha[:32] + "…" if len(sha) > 32 else sha
            ing_status  = _label(src.get("ingestion_status", ""), STATUS_LABELS)
            src_rows.append([
                _td(src.get("filename", ""), s),
                _td(src.get("file_format", ""), s),
                _td(sha_display, s, mono=True),
                _td(_fmt_bytes(src.get("file_size_bytes", 0)), s),
                _td(ing_status, s),
                _td(_fmt_dt(src.get("ingested_at")).replace(" UTC",""), s),
            ])
        file_w = pw - (16 + 50 + 18 + 20 + 26) * mm
        story.append(_tbl(
            src_rows,
            [file_w, 16*mm, 50*mm, 18*mm, 20*mm, 26*mm],
        ))
    else:
        story.append(Paragraph("No evidence sources ingested for this investigation.", s["body"]))

    story.extend(_section("Correlations", s))

    if data.relationships:
        display_rels = data.relationships[:100]
        id_w = (pw - 55*mm) / 2
        r_rows = [[
            _th("Relationship Type", s), _th("Weight", s),
            _th("Source Evidence ID", s), _th("Target Evidence ID", s),
        ]]
        for r in display_rels:
            rel_label = r.get("relationship_type", "").replace("_", " ").title()
            r_rows.append([
                _td(rel_label, s),
                _td(f"{r.get('weight', 0):.3f}", s),
                _td(str(r.get("source_evidence_id", "")), s, mono=True),
                _td(str(r.get("target_evidence_id", "")), s, mono=True),
            ])
        story.append(_tbl(r_rows, [40*mm, 15*mm, id_w, id_w]))

        total_rels = sm.get("total_relationships", len(data.relationships))
        if total_rels > 100:
            story.append(Spacer(1, 4 * mm))
            story.append(Paragraph(
                f"Showing first 100 of {total_rels} correlations.", s["body"]))
    else:
        story.append(Paragraph("No correlations discovered for this investigation.", s["body"]))

    story.extend(_section("ML Anomalies", s))

    ml_findings = [f for f in data.findings if f.get("finding_type") == "ML_ANOMALY"]
    if ml_findings:
        ml_rows = [[_th("Rule ID", s), _th("Score", s), _th("Description", s), _th("Detected At", s)]]
        for f in ml_findings:
            ml_rows.append([
                _td(f.get("rule_id", ""), s, mono=True),
                _td(f"{f.get('severity', 0):.4f}", s),
                _td(f.get("description", ""), s),
                _td(_fmt_dt(f.get("created_at")).replace(" UTC",""), s),
            ])
        story.append(_tbl(ml_rows, [35*mm, 15*mm, pw-80*mm, 30*mm]))
    else:
        story.append(Paragraph("No ML anomalies detected for this investigation.", s["body"]))

    # ── 4. ACTIVITY & TECHNICAL DETAILS ────────────────────────────────────────
    story.extend(_section("Investigation Activities", s))

    if data.activities:
        a_rows = [[
            _th("Activity Title", s), _th("Type", s), _th("Status", s),
            _th("Start Time", s), _th("Evid.", s), _th("Find.", s),
        ]]
        for a in data.activities:
            act_type = _label(a.get("activity_type", ""), ACTIVITY_TYPE_LABELS)
            act_status = _label(a.get("status", ""), STATUS_LABELS)
            a_rows.append([
                _td(a.get("title", ""), s),
                _td(act_type, s),
                _td(act_status, s),
                _td(_fmt_dt(a.get("start_time")).replace(" UTC",""), s),
                _td(str(a.get("evidence_count", 0)), s),
                _td(str(a.get("finding_count", 0)), s),
            ])
        title_w = pw - (30 + 18 + 28 + 12 + 12) * mm
        story.append(_tbl(a_rows, [title_w, 30*mm, 18*mm, 28*mm, 12*mm, 12*mm]))
    else:
        story.append(Paragraph("No activities formed for this investigation.", s["body"]))

    # ── 5. TRIAGE DISCLAIMER ───────────────────────────────────────────────────
    story.append(Spacer(1, 10 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))
    story.append(Paragraph("Methodology Limitations & Disclaimer", s["section_heading"]))
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
