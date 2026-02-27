"""
SentinelAI - PDF Report Exporter
Generates a professional security audit PDF from a sentinel_report.json file.

Usage:
    python export_pdf.py output/sentinel_report.json
    python export_pdf.py output/sentinel_report.json --out my_report.pdf
"""
import json
import sys
import os
import argparse
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.pdfgen import canvas as rl_canvas


# ── Colour palette (matches dashboard dark theme) ─────────────────────────
C_BG         = colors.HexColor("#080c12")
C_CARD       = colors.HexColor("#0d1117")
C_BORDER     = colors.HexColor("#1e2d40")
C_TEXT       = colors.HexColor("#c9d4e0")
C_MUTED      = colors.HexColor("#4a6a7a")
C_ACCENT     = colors.HexColor("#00d4ff")
C_CRITICAL   = colors.HexColor("#ff4444")
C_HIGH       = colors.HexColor("#ff8c00")
C_MEDIUM     = colors.HexColor("#ffd200")
C_LOW        = colors.HexColor("#00c878")
C_WHITE      = colors.white
C_BLACK      = colors.black

SEV_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
}

SEV_LABELS = {
    "CRITICAL": "Must Fix Now",
    "HIGH":     "Fix Before Launch",
    "MEDIUM":   "Fix Soon",
    "LOW":      "Fix When Possible",
}

SEV_BG = {
    "CRITICAL": colors.HexColor("#2a0808"),
    "HIGH":     colors.HexColor("#2a1a08"),
    "MEDIUM":   colors.HexColor("#1a1a00"),
    "LOW":      colors.HexColor("#001a0a"),
}


# ── Styles ─────────────────────────────────────────────────────────────────
def make_styles():
    return {
        "title": ParagraphStyle("title",
            fontName="Helvetica-Bold", fontSize=28,
            textColor=C_ACCENT, spaceAfter=4, leading=32),
        "subtitle": ParagraphStyle("subtitle",
            fontName="Helvetica", fontSize=11,
            textColor=C_MUTED, spaceAfter=2),
        "section": ParagraphStyle("section",
            fontName="Helvetica-Bold", fontSize=13,
            textColor=C_ACCENT, spaceBefore=18, spaceAfter=8,
            borderPad=4),
        "finding_title": ParagraphStyle("finding_title",
            fontName="Helvetica-Bold", fontSize=11,
            textColor=C_WHITE, spaceAfter=4),
        "body": ParagraphStyle("body",
            fontName="Helvetica", fontSize=9,
            textColor=C_TEXT, spaceAfter=4, leading=14),
        "body_small": ParagraphStyle("body_small",
            fontName="Helvetica", fontSize=8,
            textColor=C_MUTED, spaceAfter=3, leading=12),
        "code": ParagraphStyle("code",
            fontName="Courier", fontSize=8,
            textColor=colors.HexColor("#e07a5f"),
            backColor=colors.HexColor("#050810"),
            spaceAfter=4, leading=12,
            leftIndent=6, rightIndent=6,
            borderPad=4),
        "fix": ParagraphStyle("fix",
            fontName="Helvetica", fontSize=8.5,
            textColor=colors.HexColor("#7abf8a"),
            spaceAfter=3, leading=13),
        "meta": ParagraphStyle("meta",
            fontName="Helvetica", fontSize=8,
            textColor=C_MUTED, leading=12),
        "risk_score": ParagraphStyle("risk_score",
            fontName="Helvetica-Bold", fontSize=52,
            leading=56, spaceAfter=2),
        "risk_label": ParagraphStyle("risk_label",
            fontName="Helvetica-Bold", fontSize=14,
            spaceAfter=6),
        "centered": ParagraphStyle("centered",
            fontName="Helvetica", fontSize=9,
            textColor=C_TEXT, alignment=TA_CENTER),
        "header_right": ParagraphStyle("header_right",
            fontName="Helvetica", fontSize=8,
            textColor=C_MUTED, alignment=TA_RIGHT),
    }


# ── Page template with header/footer ──────────────────────────────────────
class SentinelPage:
    def __init__(self, target: str, scan_time: str):
        self.target = target
        self.scan_time = scan_time

    def __call__(self, canvas, doc):
        canvas.saveState()
        W, H = A4

        # Dark header bar
        canvas.setFillColor(C_CARD)
        canvas.rect(0, H - 28*mm, W, 28*mm, fill=1, stroke=0)

        # Logo / title in header
        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(C_ACCENT)
        canvas.drawString(15*mm, H - 14*mm, "SentinelAI")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(15*mm, H - 20*mm, "Security Audit Report")

        # Right side of header
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(C_MUTED)
        canvas.drawRightString(W - 15*mm, H - 13*mm, self.scan_time)
        canvas.drawRightString(W - 15*mm, H - 20*mm, self.target[:60])

        # Accent line under header
        canvas.setStrokeColor(C_ACCENT)
        canvas.setLineWidth(0.5)
        canvas.line(0, H - 28*mm, W, H - 28*mm)

        # Footer
        canvas.setFillColor(C_CARD)
        canvas.rect(0, 0, W, 14*mm, fill=1, stroke=0)
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.3)
        canvas.line(0, 14*mm, W, 14*mm)

        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(15*mm, 5*mm, "Generated by SentinelAI - Multi-Agent Security Auditor")
        canvas.drawRightString(W - 15*mm, 5*mm, f"Page {doc.page}")

        canvas.restoreState()


# ── Helpers ────────────────────────────────────────────────────────────────
def sev_badge_table(sev: str, styles: dict):
    """Render a colored severity badge as a small table cell."""
    color = SEV_COLORS.get(sev, C_MUTED)
    label = SEV_LABELS.get(sev, sev)
    badge = Table(
        [[Paragraph(f'<b>{sev}</b>', ParagraphStyle("b",
            fontName="Helvetica-Bold", fontSize=7.5,
            textColor=C_WHITE, alignment=TA_CENTER))]],
        colWidths=[22*mm], rowHeights=[5.5*mm]
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), color),
        ("ROUNDEDCORNERS", [3]),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
    ]))
    return badge


def hr(color=C_BORDER, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness,
                      color=color, spaceAfter=6, spaceBefore=6)


def clean(text: str, max_len: int = 600) -> str:
    """Escape XML chars and truncate for ReportLab."""
    if not text:
        return ""
    text = str(text)[:max_len]
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text


# ── Main PDF builder ───────────────────────────────────────────────────────
def build_pdf(report_path: str, output_path: str):
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)

    summary  = data.get("summary", {})
    findings = data.get("findings", [])

    risk_score    = summary.get("risk_score", 0)
    risk_level    = summary.get("risk_level", "UNKNOWN")
    total         = summary.get("total_findings", 0)
    sev_breakdown = summary.get("severity_breakdown", {})
    duration      = summary.get("scan_duration_seconds", 0)
    target        = summary.get("target_path", "unknown")
    scanned_files = summary.get("files_scanned", [])

    scan_time = datetime.fromtimestamp(
        os.path.getmtime(report_path)
    ).strftime("%d %b %Y at %H:%M")

    risk_short = risk_level.split(" - ")[0] if " - " in risk_level else risk_level
    risk_color = SEV_COLORS.get(risk_short, C_MUTED)

    styles = make_styles()
    page_cb = SentinelPage(target, scan_time)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=35*mm, bottomMargin=20*mm,
        title="SentinelAI Security Report",
        author="SentinelAI",
    )

    story = []
    W = A4[0] - 30*mm  # usable width

    # ── Cover / Summary ────────────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph("Security Audit Report", styles["title"]))
    story.append(Paragraph(f"Generated on {scan_time}", styles["subtitle"]))
    story.append(Paragraph(f"Target: {clean(target)}", styles["subtitle"]))
    story.append(Spacer(1, 6*mm))
    story.append(hr(C_ACCENT, 1))

    # Risk score card + stat boxes side by side
    n_crit = sev_breakdown.get("CRITICAL", 0)
    n_high = sev_breakdown.get("HIGH", 0)
    n_med  = sev_breakdown.get("MEDIUM", 0)
    n_low  = sev_breakdown.get("LOW", 0)

    # Build risk score using hex directly
    def hex_color(c):
        # hexval() returns e.g. 0xff4444, we strip the '0x' prefix
        h = hex(c.int_rgb())[2:].zfill(6)
        return h

    risk_hex = hex_color(risk_color)

    summary_table = Table([
        [
            # Left: risk score
            Table([
                [Paragraph("OVERALL RISK SCORE", ParagraphStyle("rl",
                    fontName="Helvetica", fontSize=7.5, textColor=C_MUTED,
                    spaceAfter=2))],
                [Paragraph(f'<font color="#{risk_hex}"><b>{risk_score}</b></font>',
                    ParagraphStyle("rs", fontName="Helvetica-Bold",
                    fontSize=48, leading=52, textColor=risk_color))],
                [Paragraph(f'<font color="#{risk_hex}"><b>{risk_short}</b></font>',
                    ParagraphStyle("rsl", fontName="Helvetica-Bold",
                    fontSize=13, textColor=risk_color))],
                [Paragraph(f"{total} findings  |  {duration}s scan  |  {len(scanned_files)} file(s)",
                    ParagraphStyle("rsm", fontName="Helvetica", fontSize=8, textColor=C_MUTED))],
            ], colWidths=[55*mm]),

            # Right: 4 severity boxes
            Table([
                [
                    _stat_cell("🚨", n_crit, "CRITICAL", "Must Fix Now",    C_CRITICAL),
                    _stat_cell("🔴", n_high, "HIGH",     "Fix Before Launch",C_HIGH),
                    _stat_cell("🟡", n_med,  "MEDIUM",   "Fix Soon",         C_MEDIUM),
                    _stat_cell("🟢", n_low,  "LOW",      "When Possible",    C_LOW),
                ]
            ], colWidths=[W/4 - 15, W/4 - 15, W/4 - 15, W/4 - 15])
        ]
    ], colWidths=[60*mm, W - 60*mm])

    summary_table.setStyle(TableStyle([
        ("VALIGN",      (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
        ("RIGHTPADDING",(0,0), (-1,-1), 0),
        ("TOPPADDING",  (0,0), (-1,-1), 0),
        ("BOTTOMPADDING",(0,0),(-1,-1), 0),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 6*mm))
    story.append(hr())

    # ── Scanned files ──────────────────────────────────────────────────────
    if scanned_files:
        story.append(Paragraph("Files Scanned", styles["section"]))
        for sf in scanned_files[:20]:
            story.append(Paragraph(f"  • {clean(sf)}", styles["body_small"]))
        if len(scanned_files) > 20:
            story.append(Paragraph(f"  ...and {len(scanned_files)-20} more files", styles["body_small"]))
        story.append(Spacer(1, 4*mm))

    # ── Severity breakdown table ───────────────────────────────────────────
    story.append(Paragraph("Severity Breakdown", styles["section"]))
    bk_data = [
        [Paragraph("<b>Severity</b>", styles["body"]),
         Paragraph("<b>Count</b>",    styles["body"]),
         Paragraph("<b>Meaning</b>",  styles["body"]),
         Paragraph("<b>Action</b>",   styles["body"])],
    ]
    for sev, count, meaning, action in [
        ("CRITICAL", n_crit, "Can lead to hacking or data theft", "Fix immediately"),
        ("HIGH",     n_high, "Serious vulnerability",              "Fix before going live"),
        ("MEDIUM",   n_med,  "Moderate security concern",          "Fix in next update"),
        ("LOW",      n_low,  "Minor issue",                        "Fix when convenient"),
    ]:
        c = SEV_COLORS.get(sev, C_MUTED)
        bk_data.append([
            Paragraph(f'<font color="#{hex_color(c)}"><b>{sev}</b></font>', styles["body"]),
            Paragraph(f'<font color="#{hex_color(c)}"><b>{count}</b></font>', styles["body"]),
            Paragraph(clean(meaning), styles["body_small"]),
            Paragraph(clean(action),  styles["body_small"]),
        ])

    bk_table = Table(bk_data, colWidths=[28*mm, 18*mm, 70*mm, W-116*mm])
    bk_table.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0),  C_CARD),
        ("TEXTCOLOR",    (0,0), (-1,0),  C_ACCENT),
        ("GRID",         (0,0), (-1,-1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_BG, C_CARD]),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 6),
    ]))
    story.append(bk_table)
    story.append(PageBreak())

    # ── Findings ───────────────────────────────────────────────────────────
    story.append(Paragraph("Security Findings", styles["section"]))
    story.append(Paragraph(
        f"The following {total} security issues were detected, ordered by severity.",
        styles["body"]))
    story.append(Spacer(1, 4*mm))

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings_sorted = sorted(findings,
        key=lambda x: sev_order.get(x.get("severity","LOW"), 4))

    for i, f in enumerate(findings_sorted):
        sev      = f.get("severity", "LOW")
        title    = f.get("title", "Unknown Issue")
        desc     = f.get("description", "")
        rec      = f.get("recommendation", "")
        snippet  = f.get("code_snippet", "")
        lineno   = f.get("lineno")
        filepath = f.get("filepath", "")
        cwe      = f.get("cwe_id", "")
        agent    = f.get("agent", "").split(" - ")[0]
        filename = filepath.replace("\\", "/").split("/")[-1] if filepath else ""

        fc     = SEV_COLORS.get(sev, C_MUTED)
        fc_hex = hex_color(fc)
        bg     = SEV_BG.get(sev, C_CARD)

        # Finding number + title row
        title_row = Table([[
            Paragraph(f'<font color="#{fc_hex}"><b>{i+1}. {clean(title)}</b></font>',
                ParagraphStyle("ft", fontName="Helvetica-Bold", fontSize=10.5,
                               textColor=fc, leading=14)),
            Paragraph(
                f'<font color="#{fc_hex}"><b>{sev}</b></font>  '
                f'<font color="#4a6a7a">{SEV_LABELS.get(sev,"")}</font>',
                ParagraphStyle("fs", fontName="Helvetica-Bold", fontSize=8.5,
                               alignment=TA_RIGHT, textColor=fc)),
        ]], colWidths=[W*0.65, W*0.35])
        title_row.setStyle(TableStyle([
            ("VALIGN",       (0,0),(-1,-1),"MIDDLE"),
            ("LEFTPADDING",  (0,0),(-1,-1), 0),
            ("RIGHTPADDING", (0,0),(-1,-1), 0),
            ("TOPPADDING",   (0,0),(-1,-1), 0),
            ("BOTTOMPADDING",(0,0),(-1,-1), 0),
        ]))

        # Meta line
        meta_parts = []
        if filename: meta_parts.append(f"File: {filename}")
        if lineno:   meta_parts.append(f"Line: {lineno}")
        if cwe:      meta_parts.append(f"Ref: {cwe}")
        if agent:    meta_parts.append(f"Detected by: {agent}")
        meta_str = "  |  ".join(meta_parts)

        elements = [
            title_row,
            Paragraph(clean(meta_str), styles["meta"]),
            Spacer(1, 2*mm),
            Paragraph(clean(desc), styles["body"]),
        ]

        if snippet:
            elements.append(Paragraph(
                f'<font color="#3d6b8a">Problematic code:</font>', styles["body_small"]))
            elements.append(Paragraph(clean(snippet[:250]), styles["code"]))

        if rec:
            elements.append(Paragraph(
                f'<font color="#2a8a4a"><b>How to fix it:</b></font>', styles["body_small"]))
            elements.append(Paragraph(clean(rec[:400]), styles["fix"]))

        # Wrap in a card-like table
        card = Table([[elements]], colWidths=[W])
        card.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), bg),
            ("LINEAFTER",     (0,0),(0,-1),  1.5, fc),  # left accent bar
            ("LINEBEFORE",    (0,0),(0,-1),  1.5, fc),
            ("BOX",           (0,0),(-1,-1), 0.3, C_BORDER),
            ("TOPPADDING",    (0,0),(-1,-1), 8),
            ("BOTTOMPADDING", (0,0),(-1,-1), 8),
            ("LEFTPADDING",   (0,0),(-1,-1), 10),
            ("RIGHTPADDING",  (0,0),(-1,-1), 8),
        ]))

        story.append(KeepTogether([card, Spacer(1, 3*mm)]))

    # ── Back page ──────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Spacer(1, 30*mm))
    story.append(Paragraph("Report Complete", ParagraphStyle("end",
        fontName="Helvetica-Bold", fontSize=18,
        textColor=C_ACCENT, alignment=TA_CENTER)))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        f"This report was generated by SentinelAI on {scan_time}.<br/>"
        f"Total issues found: <b>{total}</b>  |  Risk Score: <b>{risk_score}</b>  |  "
        f"Risk Level: <b>{risk_short}</b>",
        ParagraphStyle("end2", fontName="Helvetica", fontSize=9,
                       textColor=C_MUTED, alignment=TA_CENTER, leading=16)))

    doc.build(story, onFirstPage=page_cb, onLaterPages=page_cb)
    print(f"[OK] PDF saved to: {output_path}")
    return output_path


def _stat_cell(icon, count, sev, label, color):
    """Build a single stat cell for the summary table."""
    hex_c = hex(color.int_rgb())[2:].zfill(6)
    t = Table([
        [Paragraph(f'<font color="#{hex_c}"><b>{count}</b></font>',
            ParagraphStyle("sc", fontName="Helvetica-Bold",
            fontSize=26, leading=28, alignment=TA_CENTER, textColor=color))],
        [Paragraph(f'<font color="#{hex_c}"><b>{label}</b></font>',
            ParagraphStyle("sl", fontName="Helvetica-Bold", fontSize=7.5,
            alignment=TA_CENTER, textColor=color))],
    ], colWidths=[None])
    t.setStyle(TableStyle([
        ("ALIGN",        (0,0),(-1,-1),"CENTER"),
        ("TOPPADDING",   (0,0),(-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
    ]))
    return t


# ── CLI entry point ────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export SentinelAI report to PDF")
    parser.add_argument("report", help="Path to sentinel_report.json")
    parser.add_argument("--out", help="Output PDF path", default=None)
    args = parser.parse_args()

    if not os.path.exists(args.report):
        print(f"[X] Report not found: {args.report}")
        sys.exit(1)

    out = args.out or args.report.replace(".json", ".pdf")
    build_pdf(args.report, out)
