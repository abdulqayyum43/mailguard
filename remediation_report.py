"""
MailGuard — Professional Remediation PDF Report Generator
Produces a branded, compliance-ready remediation guide suitable for
delivery to clients, IT teams, or executive stakeholders.
"""
from io import BytesIO
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas as pdfcanvas

# ── Colour Palette ─────────────────────────────────────────────────────────────
_BG         = colors.HexColor("#020817")
_SURFACE    = colors.HexColor("#0f172a")
_SURFACE2   = colors.HexColor("#1e293b")
_BORDER     = colors.HexColor("#334155")
_TEXT       = colors.HexColor("#f8fafc")
_MUTED      = colors.HexColor("#94a3b8")
_ACCENT     = colors.HexColor("#38bdf8")
_ACCENT2    = colors.HexColor("#818cf8")
_WHITE      = colors.white

_SEV_COLORS = {
    "CRITICAL": (colors.HexColor("#ef4444"), colors.HexColor("#3b1212")),
    "HIGH":     (colors.HexColor("#f97316"), colors.HexColor("#3b1a0a")),
    "MEDIUM":   (colors.HexColor("#eab308"), colors.HexColor("#3b2e05")),
    "LOW":      (colors.HexColor("#22c55e"), colors.HexColor("#0d2b15")),
    "INFO":     (colors.HexColor("#38bdf8"), colors.HexColor("#0c1f2e")),
}

_GRADE_COLORS = {
    "A+": colors.HexColor("#22c55e"), "A": colors.HexColor("#4ade80"),
    "B":  colors.HexColor("#a3e635"), "C": colors.HexColor("#fbbf24"),
    "D":  colors.HexColor("#f97316"), "F": colors.HexColor("#ef4444"),
}

PW, PH = A4  # 595.27 x 841.89 pts
LM = RM = 1.8 * cm
TM = BM = 1.6 * cm
CONTENT_W = PW - LM - RM


# ── Page canvas callbacks ──────────────────────────────────────────────────────

class _PageDeco:
    """Adds header band, footer line, page numbers, and confidentiality notice."""

    def __init__(self, domain: str, report_date: str, total_pages_ref: list):
        self.domain = domain
        self.date = report_date
        self.total_pages_ref = total_pages_ref  # mutable ref filled after build

    def __call__(self, canv: pdfcanvas.Canvas, doc):
        canv.saveState()
        page = doc.page

        # ── Top header band ──
        canv.setFillColor(_SURFACE)
        canv.rect(0, PH - 28, PW, 28, fill=1, stroke=0)

        # Brand left
        canv.setFont("Helvetica-Bold", 9)
        canv.setFillColor(_ACCENT)
        canv.drawString(LM, PH - 18, "MailGuard")
        canv.setFont("Helvetica", 9)
        canv.setFillColor(_MUTED)
        canv.drawString(LM + 52, PH - 18, "Email Security Remediation Report")

        # Domain right
        canv.setFont("Helvetica", 8)
        canv.setFillColor(_MUTED)
        domain_str = f"Domain: {self.domain}"
        canv.drawRightString(PW - RM, PH - 18, domain_str)

        # Header bottom border
        canv.setStrokeColor(_BORDER)
        canv.setLineWidth(0.5)
        canv.line(LM, PH - 29, PW - RM, PH - 29)

        # ── Footer ──
        canv.setStrokeColor(_BORDER)
        canv.setLineWidth(0.4)
        canv.line(LM, BM + 14, PW - RM, BM + 14)

        # Page number
        canv.setFont("Helvetica", 8)
        canv.setFillColor(_MUTED)
        canv.drawString(LM, BM + 4, f"Generated: {self.date}")
        canv.drawCentredString(PW / 2, BM + 4, "CONFIDENTIAL — For authorised recipients only")
        canv.drawRightString(PW - RM, BM + 4, f"Page {page}")

        canv.restoreState()

    def cover(self, canv: pdfcanvas.Canvas, doc):
        """Cover page — no header/footer chrome."""
        pass


# ── Style helpers ──────────────────────────────────────────────────────────────

def _s(name, **kw):
    defaults = dict(fontName="Helvetica", fontSize=10, textColor=_TEXT,
                    leading=14, spaceAfter=0, spaceBefore=0)
    defaults.update(kw)
    return ParagraphStyle(name, **defaults)


_H1 = _s("H1", fontSize=22, fontName="Helvetica-Bold", textColor=_ACCENT,
          spaceAfter=6, leading=26)
_H2 = _s("H2", fontSize=14, fontName="Helvetica-Bold", textColor=_TEXT,
          spaceAfter=4, spaceBefore=10, leading=18)
_H3 = _s("H3", fontSize=11, fontName="Helvetica-Bold", textColor=_ACCENT,
          spaceAfter=3, spaceBefore=8, leading=14)
_BODY = _s("BODY", fontSize=9, textColor=colors.HexColor("#cbd5e1"),
           leading=14, spaceAfter=4)
_BODY_J = _s("BODY_J", fontSize=9, textColor=colors.HexColor("#cbd5e1"),
             leading=14, spaceAfter=4, alignment=TA_JUSTIFY)
_SMALL = _s("SMALL", fontSize=8, textColor=_MUTED, leading=11, spaceAfter=2)
_MONO = _s("MONO", fontSize=8, fontName="Courier", textColor=colors.HexColor("#7dd3fc"),
           leading=12, spaceAfter=2, leftIndent=4)
_CENTER = _s("CENTER", fontSize=9, textColor=_MUTED, alignment=TA_CENTER, leading=12)
_LABEL = _s("LABEL", fontSize=8, fontName="Helvetica-Bold",
            textColor=_MUTED, leading=10, spaceAfter=2)


def _hr(color=_BORDER):
    return HRFlowable(width="100%", color=color, thickness=0.5, spaceAfter=8, spaceBefore=4)


def _spacer(h=8):
    return Spacer(1, h)


def _colored_table(data, col_widths, bg=_SURFACE2, header_bg=_SURFACE):
    t = Table(data, colWidths=col_widths)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR",  (0, 0), (-1, 0), _TEXT),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_SURFACE, _SURFACE2]),
        ("TEXTCOLOR",  (0, 1), (-1, -1), colors.HexColor("#cbd5e1")),
        ("GRID",       (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING",    (0, 0), (-1, -1), 5),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]
    t.setStyle(TableStyle(style))
    return t


# ── Cover page ─────────────────────────────────────────────────────────────────

def _build_cover(story: list, edu: dict):
    domain = edu["domain"]
    grade = edu["scan_grade"]
    score = edu["scan_score"]
    date_str = datetime.now(timezone.utc).strftime("%d %B %Y")
    gc = _GRADE_COLORS.get(grade, colors.HexColor("#ef4444"))
    risk = edu["spoofability_risk"]
    risk_fg, risk_bg = _SEV_COLORS.get(risk if risk in _SEV_COLORS else "HIGH",
                                        _SEV_COLORS["HIGH"])

    # Full-page dark background block
    story.append(Table(
        [[Paragraph(
            f"<font color='#38bdf8' size='26'><b>MailGuard</b></font>"
            f"<br/><br/>"
            f"<font color='#f8fafc' size='18'><b>Email Security</b></font><br/>"
            f"<font color='#f8fafc' size='18'><b>Remediation Report</b></font>",
            _s("COV_TITLE", fontSize=18, fontName="Helvetica-Bold",
               textColor=_TEXT, leading=26, alignment=TA_CENTER)
        )]],
        colWidths=[CONTENT_W],
    ))
    story.append(_spacer(24))

    # Grade + score block
    grade_data = [[
        Paragraph(f"<font color='{gc.hexval() if hasattr(gc,'hexval') else '#22c55e'}' size='52'><b>{grade}</b></font>",
                  _s("GR", fontSize=52, fontName="Helvetica-Bold", textColor=gc, alignment=TA_CENTER)),
        Table([
            [Paragraph("Security Score", _LABEL)],
            [Paragraph(f"<font size='28'><b>{score}/100</b></font>",
                       _s("SC", fontSize=28, fontName="Helvetica-Bold", textColor=_TEXT))],
            [Paragraph(f"Spoofability Risk: <font color='{risk_fg.hexval() if hasattr(risk_fg,\"hexval\") else \"#f87171\"}'><b>{risk}</b></font>",
                       _s("RISK", fontSize=10, textColor=_MUTED))],
        ], colWidths=[CONTENT_W * 0.5]),
    ]]
    gt = Table(grade_data, colWidths=[CONTENT_W * 0.3, CONTENT_W * 0.7])
    gt.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, -1), _SURFACE),
        ("GRID", (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING", (0, 0), (-1, -1), 16),
        ("ROUNDEDCORNERS", [8]),
    ]))
    story.append(gt)
    story.append(_spacer(20))

    # Domain and date info table
    info = Table([
        ["Domain", domain],
        ["Report Date", date_str],
        ["Scan Engine", "MailGuard v1.0"],
        ["Issues Found", str(edu["vulnerability_count"])],
        ["Classification", "CONFIDENTIAL"],
    ], colWidths=[CONTENT_W * 0.35, CONTENT_W * 0.65])
    info.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), _MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), _TEXT),
        ("BACKGROUND", (0, 0), (-1, -1), _SURFACE),
        ("GRID", (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_SURFACE, _SURFACE2]),
    ]))
    story.append(info)
    story.append(_spacer(28))

    # Severity summary strip
    sev_row = []
    sev_labels = [
        ("CRITICAL", edu.get("critical_count", 0)),
        ("HIGH",     edu.get("high_count", 0)),
        ("MEDIUM",   edu.get("medium_count", 0)),
        ("LOW",      edu.get("low_count", 0)),
    ]
    for sev, cnt in sev_labels:
        fg, bg = _SEV_COLORS[sev]
        sev_row.append(Table(
            [[Paragraph(str(cnt), _s(f"SN_{sev}", fontSize=22, fontName="Helvetica-Bold",
                                      textColor=fg, alignment=TA_CENTER))],
             [Paragraph(sev, _s(f"SL_{sev}", fontSize=8, fontName="Helvetica-Bold",
                                 textColor=fg, alignment=TA_CENTER))]],
            colWidths=[(CONTENT_W - 30) / 4]
        ))
    sev_t = Table([sev_row], colWidths=[(CONTENT_W - 30) / 4] * 4,
                  hAlign="LEFT")
    sev_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _SURFACE),
        ("GRID", (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(sev_t)
    story.append(_spacer(28))

    # Disclaimer box
    disclaimer_t = Table([[
        Paragraph(
            "⚖ Legal Notice &amp; Disclaimer",
            _s("DH", fontSize=9, fontName="Helvetica-Bold", textColor=_MUTED)
        ),
        Paragraph(edu.get("disclaimer", ""), _s("DB", fontSize=8, textColor=_MUTED,
                                                  leading=11, alignment=TA_JUSTIFY)),
    ]], colWidths=[CONTENT_W * 0.22, CONTENT_W * 0.78])
    disclaimer_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _SURFACE),
        ("GRID", (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(disclaimer_t)

    story.append(PageBreak())


# ── Executive Summary ──────────────────────────────────────────────────────────

def _build_executive_summary(story: list, edu: dict):
    story.append(Paragraph("Executive Summary", _H1))
    story.append(_hr(_ACCENT))
    story.append(_spacer(6))

    domain = edu["domain"]
    grade = edu["scan_grade"]
    score = edu["scan_score"]
    risk_text = edu.get("overall_risk", "")
    risk_detail = edu.get("risk_detail", "")

    story.append(Paragraph(
        f"This report presents the results of an automated email security audit conducted "
        f"on <b>{domain}</b> on {datetime.now(timezone.utc).strftime('%d %B %Y')}. "
        f"The domain received an overall security grade of <b>{grade} ({score}/100)</b>.",
        _BODY_J
    ))
    story.append(_spacer(6))

    story.append(Paragraph(
        f"<b>Overall Risk Assessment:</b> {risk_text}. {risk_detail}",
        _s("RISK_BODY", fontSize=9, textColor=colors.HexColor("#fca5a5") if "CRITICAL" in risk_text
           else colors.HexColor("#fdba74") if "HIGH" in risk_text
           else colors.HexColor("#fbbf24") if "MEDIUM" in risk_text
           else colors.HexColor("#86efac"),
           leading=14, spaceAfter=6, alignment=TA_JUSTIFY)
    ))
    story.append(_spacer(8))

    # Issue count table
    vuln_count = edu.get("vulnerability_count", 0)
    critical_c = edu.get("critical_count", 0)
    high_c     = edu.get("high_count", 0)
    medium_c   = edu.get("medium_count", 0)
    low_c      = edu.get("low_count", 0)
    spoof      = edu.get("spoofability_risk", "UNKNOWN")

    summary_data = [
        ["Metric", "Value", "Assessment"],
        ["Security Score", f"{score}/100", grade],
        ["Spoofability Risk", spoof, "Domain can be impersonated" if spoof == "HIGH"
         else "Partial protection" if spoof == "MEDIUM" else "Protected"],
        ["Total Issues", str(vuln_count), "See detail sections below"],
        ["Critical Issues", str(critical_c), "Require immediate action"],
        ["High Severity", str(high_c), "Address within 48 hours"],
        ["Medium Severity", str(medium_c), "Address within 2 weeks"],
        ["Low Severity", str(low_c), "Address at next maintenance window"],
    ]
    st = _colored_table(summary_data, [CONTENT_W * 0.35, CONTENT_W * 0.25, CONTENT_W * 0.40])
    # Colour score row
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _SURFACE),
        ("TEXTCOLOR",  (0, 0), (-1, 0), _TEXT),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_SURFACE, _SURFACE2]),
        ("TEXTCOLOR",  (0, 1), (-1, -1), colors.HexColor("#cbd5e1")),
        ("GRID",       (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING",    (0, 0), (-1, -1), 5),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TEXTCOLOR",  (2, 1), (2, 1), _GRADE_COLORS.get(grade, _MUTED)),
        ("FONTNAME",   (2, 1), (2, 1), "Helvetica-Bold"),
    ]))
    story.append(st)
    story.append(_spacer(12))

    # Recommended priorities
    priorities = edu.get("recommended_priority", [])
    if priorities:
        story.append(Paragraph("Top Priority Actions", _H3))
        for i, p in enumerate(priorities, 1):
            story.append(Paragraph(f"{i}. {p}", _BODY))
        story.append(_spacer(8))

    # Regulatory context
    story.append(Paragraph("Regulatory &amp; Standards Context", _H3))
    story.append(Paragraph(
        "Email security controls addressed in this report are relevant to the following "
        "frameworks and mandates:",
        _BODY
    ))
    reg_data = [
        ["Framework", "Relevant Controls", "Requirement Level"],
        ["PCI-DSS v4.0",     "SPF, DMARC p=reject, DKIM, STARTTLS",     "Requirement 6.4.1, 4.2.2"],
        ["SOC 2 Type II",    "DMARC, SPF, MTA-STS, Blacklist",           "CC6.6, CC6.7, CC9.2"],
        ["ISO/IEC 27001:2022","DKIM, STARTTLS, SPF+DMARC, MTA-STS",      "A.10.1.1, A.13.2.1–3, A.14.1.2"],
        ["NCSC / Cyber Essentials", "SPF, DMARC, DKIM, MTA-STS",         "Mail Security Guidance"],
        ["NIST SP 800-177",  "SPF, DKIM, DMARC, S/MIME",                 "Email Security Recommendations"],
        ["CISA Binding Directive", "DMARC p=reject, reporting",          "BOD 18-01 (US Federal)"],
    ]
    rt = _colored_table(reg_data, [CONTENT_W * 0.28, CONTENT_W * 0.42, CONTENT_W * 0.30])
    story.append(rt)
    story.append(PageBreak())


# ── Risk Matrix ────────────────────────────────────────────────────────────────

def _build_risk_matrix(story: list, vulns: list):
    story.append(Paragraph("Risk Assessment Matrix", _H1))
    story.append(_hr(_ACCENT))
    story.append(_spacer(6))
    story.append(Paragraph(
        "The table below summarises all identified vulnerabilities, their severity, "
        "estimated remediation effort, and expected security impact upon resolution.",
        _BODY_J
    ))
    story.append(_spacer(8))

    matrix_data = [["#", "Protocol", "Severity", "Issue", "Effort", "Impact"]]
    for i, v in enumerate(vulns, 1):
        sev = v.get("severity", "MEDIUM")
        matrix_data.append([
            str(i),
            v.get("protocol", ""),
            sev,
            v.get("title", "")[:55],
            (v.get("estimated_effort", "–") or "–")[:25],
            (v.get("estimated_impact", "–") or "–")[:50],
        ])

    mt = Table(matrix_data, colWidths=[
        CONTENT_W * 0.04, CONTENT_W * 0.10,
        CONTENT_W * 0.10, CONTENT_W * 0.36,
        CONTENT_W * 0.18, CONTENT_W * 0.22,
    ])

    sev_style = []
    for row_i, v in enumerate(vulns, 1):
        sev = v.get("severity", "MEDIUM")
        fg, _ = _SEV_COLORS.get(sev, _SEV_COLORS["MEDIUM"])
        sev_style.append(("TEXTCOLOR", (2, row_i), (2, row_i), fg))
        sev_style.append(("FONTNAME", (2, row_i), (2, row_i), "Helvetica-Bold"))

    mt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _SURFACE),
        ("TEXTCOLOR",  (0, 0), (-1, 0), _TEXT),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_SURFACE, _SURFACE2]),
        ("TEXTCOLOR",  (0, 1), (-1, -1), colors.HexColor("#cbd5e1")),
        ("GRID",       (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING",    (0, 0), (-1, -1), 5),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        *sev_style,
    ]))
    story.append(mt)
    story.append(PageBreak())


# ── Individual vulnerability sections ─────────────────────────────────────────

def _sev_banner(sev: str, title: str) -> Table:
    fg, bg = _SEV_COLORS.get(sev, _SEV_COLORS["MEDIUM"])
    data = [[
        Paragraph(f"<b>{sev}</b>", _s(f"SB_{sev}", fontSize=10, fontName="Helvetica-Bold",
                                       textColor=fg, alignment=TA_CENTER)),
        Paragraph(f"<b>{title}</b>", _s(f"ST_{sev}", fontSize=11, fontName="Helvetica-Bold",
                                          textColor=_TEXT)),
    ]]
    t = Table(data, colWidths=[CONTENT_W * 0.14, CONTENT_W * 0.86])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), bg),
        ("BACKGROUND", (1, 0), (1, 0), _SURFACE),
        ("GRID",       (0, 0), (-1, -1), 0.5, fg),
        ("PADDING",    (0, 0), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (1, 0), (1, 0), 12),
    ]))
    return t


def _info_box(label: str, text: str, color: colors.Color = None) -> Table:
    c = color or colors.HexColor("#0c1f2e")
    t = Table([[
        Paragraph(f"<b>{label}</b>", _s(f"IB_{label[:4]}", fontSize=8, fontName="Helvetica-Bold",
                                         textColor=_MUTED, alignment=TA_CENTER, leading=10)),
        Paragraph(text, _s("IB_TEXT", fontSize=9, textColor=colors.HexColor("#cbd5e1"),
                            leading=13, alignment=TA_JUSTIFY)),
    ]], colWidths=[CONTENT_W * 0.16, CONTENT_W * 0.84])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), c),
        ("GRID",         (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING",      (0, 0), (-1, -1), 8),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (1, 0), (1, 0), 10),
    ]))
    return t


def _dns_record_block(records: list) -> list:
    if not records:
        return []
    items = []
    items.append(Paragraph("DNS Records to Add", _H3))
    items.append(Paragraph(
        "Add the following DNS TXT records via your domain registrar or DNS provider "
        "(Cloudflare, Route53, GoDaddy, Namecheap, etc.).",
        _BODY
    ))
    items.append(_spacer(4))

    for rec in records:
        label = rec.get("label", "DNS Record")
        items.append(Paragraph(f"<b>{label}</b>", _s("DREC_LBL", fontSize=9,
                                                       fontName="Helvetica-Bold",
                                                       textColor=_ACCENT)))
        rec_data = [
            ["Type", "Name / Host", "TTL", "Value"],
            [
                rec.get("type", "TXT"),
                rec.get("name", "@"),
                rec.get("ttl", "3600"),
                rec.get("value", ""),
            ]
        ]
        rt = Table(rec_data, colWidths=[
            CONTENT_W * 0.08,
            CONTENT_W * 0.20,
            CONTENT_W * 0.08,
            CONTENT_W * 0.64,
        ])
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _SURFACE),
            ("TEXTCOLOR",  (0, 0), (-1, 0), _TEXT),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 1), (-1, 1), _SURFACE2),
            ("TEXTCOLOR",  (0, 1), (-1, 1), colors.HexColor("#7dd3fc")),
            ("FONTNAME",   (0, 1), (-1, 1), "Courier"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.4, _BORDER),
            ("PADDING",    (0, 0), (-1, -1), 6),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("WORDWRAP",   (3, 1), (3, 1), True),
        ]))
        items.append(rt)
        items.append(_spacer(6))

    return items


def _policy_file_block(pf: dict) -> list:
    if not pf:
        return []
    items = []
    items.append(Paragraph("Policy File to Host", _H3))
    items.append(Paragraph(
        f"Host this file at: <font color='#38bdf8'><b>{pf.get('url', '')}</b></font> "
        f"(HTTPS required).",
        _BODY
    ))
    content = pf.get("content", "")
    pft = Table([[Paragraph(content, _MONO)]],
                colWidths=[CONTENT_W])
    pft.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0d1b2a")),
        ("GRID",       (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING",    (0, 0), (-1, -1), 10),
    ]))
    items.append(pft)
    note = pf.get("note", "")
    if note:
        items.append(Paragraph(f"Note: {note}", _SMALL))
    items.append(_spacer(6))
    return items


def _delisting_block(delinks: list) -> list:
    if not delinks:
        return []
    items = []
    items.append(Paragraph("Blacklist Removal Portals", _H3))
    dl_data = [["Blacklist", "Removal URL"]]
    for d in delinks:
        dl_data.append([d.get("name", ""), d.get("url", "")])
    dlt = _colored_table(dl_data, [CONTENT_W * 0.30, CONTENT_W * 0.70])
    items.append(dlt)
    items.append(_spacer(6))
    return items


def _build_vuln_section(story: list, v: dict, index: int):
    sev = v.get("severity", "MEDIUM")
    title = v.get("title", "")
    protocol = v.get("protocol", "")
    rfc = v.get("rfc", "")
    standard = v.get("standard", "")

    elements = []
    elements.append(Paragraph(f"Issue {index}: {protocol}", _s("V_SUB", fontSize=10,
                                                                  textColor=_MUTED,
                                                                  fontName="Helvetica-Bold")))
    elements.append(_sev_banner(sev, title))
    elements.append(_spacer(6))

    ref_parts = []
    if rfc:
        ref_parts.append(f"Reference: {rfc}")
    if standard:
        ref_parts.append(f"Standard: {standard}")
    if ref_parts:
        elements.append(Paragraph(" · ".join(ref_parts), _SMALL))
    elements.append(_spacer(8))

    # What is it
    elements.append(_info_box("WHAT IS IT?", v.get("what_is_it", ""),
                               colors.HexColor("#0c1f2e")))
    elements.append(_spacer(6))

    # Why it matters
    elements.append(_info_box("BUSINESS IMPACT", v.get("why_it_matters", ""),
                               colors.HexColor("#1a1205")))
    elements.append(_spacer(6))

    # Current status
    fg, bg = _SEV_COLORS.get(sev, _SEV_COLORS["MEDIUM"])
    elements.append(_info_box("CURRENT STATUS", v.get("current_status", ""), bg))
    elements.append(_spacer(10))

    # Fix steps
    fix_steps = v.get("fix_steps", [])
    if fix_steps:
        elements.append(Paragraph("Remediation Steps", _H3))
        for i, step in enumerate(fix_steps, 1):
            elements.append(Paragraph(f"{i}. {step}",
                                       _s("STEP", fontSize=9,
                                          textColor=colors.HexColor("#cbd5e1"),
                                          leading=13, spaceAfter=4, leftIndent=6)))
        elements.append(_spacer(6))

    # DNS records
    elements.extend(_dns_record_block(v.get("dns_records", [])))

    # Policy file (MTA-STS)
    elements.extend(_policy_file_block(v.get("policy_file")))

    # Delisting links (blacklist)
    elements.extend(_delisting_block(v.get("delisting_urls", [])))

    # Config examples (STARTTLS)
    config = v.get("config_examples", {})
    if config:
        elements.append(Paragraph("Server Configuration Examples", _H3))
        for server, conf_text in config.items():
            elements.append(Paragraph(f"<b>{server.capitalize()}</b>",
                                       _s("CE_H", fontSize=9, fontName="Helvetica-Bold",
                                          textColor=_ACCENT)))
            ct = Table([[Paragraph(conf_text, _MONO)]], colWidths=[CONTENT_W])
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0d1b2a")),
                ("GRID",       (0, 0), (-1, -1), 0.4, _BORDER),
                ("PADDING",    (0, 0), (-1, -1), 10),
            ]))
            elements.append(ct)
            elements.append(_spacer(6))

    # Effort / Impact row
    effort = v.get("estimated_effort", "")
    impact = v.get("estimated_impact", "")
    if effort or impact:
        ei_data = [[
            Paragraph(f"<b>Effort:</b> {effort}", _SMALL),
            Paragraph(f"<b>Impact:</b> {impact}", _SMALL),
        ]]
        eit = Table(ei_data, colWidths=[CONTENT_W * 0.38, CONTENT_W * 0.62])
        eit.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _SURFACE),
            ("GRID",       (0, 0), (-1, -1), 0.4, _BORDER),
            ("PADDING",    (0, 0), (-1, -1), 6),
        ]))
        elements.append(eit)

    story.append(KeepTogether(elements[:6]))  # keep banner + first cards together
    for el in elements[6:]:
        story.append(el)
    story.append(_spacer(10))
    story.append(_hr())


# ── Glossary ───────────────────────────────────────────────────────────────────

def _build_glossary(story: list):
    story.append(PageBreak())
    story.append(Paragraph("Appendix A — Glossary of Terms", _H1))
    story.append(_hr(_ACCENT))
    story.append(_spacer(6))

    terms = [
        ("SPF", "Sender Policy Framework (RFC 7208). A DNS record listing authorised mail-sending servers for a domain."),
        ("DMARC", "Domain-based Message Authentication, Reporting and Conformance (RFC 7489). Policy framework that combines SPF and DKIM to instruct receivers on how to handle unauthenticated mail."),
        ("DKIM", "DomainKeys Identified Mail (RFC 6376). Cryptographic email signing using a private key; receiving servers verify against the public key published in DNS."),
        ("MTA-STS", "Mail Transfer Agent Strict Transport Security (RFC 8461). Mechanism to enforce TLS encryption for inbound mail delivery."),
        ("STARTTLS", "SMTP command (RFC 3207) that upgrades a plain-text connection to TLS-encrypted. Encrypts email in transit between servers."),
        ("DNSBL / RBL", "DNS-based Blackhole List / Real-time Blackhole List. Databases of IP addresses known to send spam, queried by receiving mail servers."),
        ("DANE / TLSA", "DNS-Based Authentication of Named Entities (RFC 6698). Binds TLS certificates to domain names via TLSA records in DNSSEC-signed zones."),
        ("BIMI", "Brand Indicators for Message Identification. Allows organisations to display a verified logo next to authenticated emails in supported mail clients."),
        ("BEC", "Business Email Compromise. A class of attack where criminals impersonate executives or suppliers to redirect payments or steal data."),
        ("p=reject", "The strongest DMARC policy value. Instructs receiving servers to discard emails that fail DMARC checks rather than delivering them."),
        ("~all / -all", "SPF all mechanisms. ~all (softfail) marks failures as suspicious; -all (hardfail) causes outright rejection of unauthorised senders."),
        ("RUA", "DMARC Reporting URI for Aggregate reports. Email address that receives daily XML reports of all mail claiming to be from your domain."),
        ("PermError", "Permanent error in SPF evaluation, typically caused by exceeding the 10 DNS lookup limit. Treated as an SPF failure."),
        ("TLS", "Transport Layer Security. Cryptographic protocol that provides encrypted communication over a network, successor to SSL."),
    ]

    gdata = [["Term", "Definition"]]
    for term, defn in terms:
        gdata.append([term, defn])
    gt = Table(gdata, colWidths=[CONTENT_W * 0.20, CONTENT_W * 0.80])
    gt.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), _SURFACE),
        ("TEXTCOLOR",   (0, 0), (-1, 0), _TEXT),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_SURFACE, _SURFACE2]),
        ("TEXTCOLOR",   (0, 1), (0, -1), _ACCENT),
        ("FONTNAME",    (0, 1), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",   (1, 1), (1, -1), colors.HexColor("#cbd5e1")),
        ("GRID",        (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING",     (0, 0), (-1, -1), 6),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(gt)
    story.append(_spacer(16))

    # Standards references
    story.append(Paragraph("Appendix B — Standards &amp; Regulatory References", _H2))
    story.append(_spacer(4))
    refs = [
        ("RFC 7208", "SPF — Sender Policy Framework", "https://tools.ietf.org/html/rfc7208"),
        ("RFC 7489", "DMARC — Domain-based Message Authentication, Reporting and Conformance", "https://tools.ietf.org/html/rfc7489"),
        ("RFC 6376", "DKIM — DomainKeys Identified Mail Signatures", "https://tools.ietf.org/html/rfc6376"),
        ("RFC 8461", "MTA-STS — SMTP MTA Strict Transport Security", "https://tools.ietf.org/html/rfc8461"),
        ("RFC 3207", "STARTTLS — SMTP Service Extension for Secure SMTP over TLS", "https://tools.ietf.org/html/rfc3207"),
        ("RFC 6698", "DANE/TLSA — The TLSA DNS Resource Record", "https://tools.ietf.org/html/rfc6698"),
        ("PCI-DSS v4.0", "Payment Card Industry Data Security Standard", "https://www.pcisecuritystandards.org"),
        ("NIST SP 800-177", "Trustworthy Email (NIST guidelines)", "https://doi.org/10.6028/NIST.SP.800-177r1"),
        ("CISA BOD 18-01", "Enhance Email and Web Security (US Federal mandate)", "https://cyber.dhs.gov/bod/18-01/"),
        ("NCSC Mail Check", "UK National Cyber Security Centre email guidance", "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing"),
    ]
    rdata = [["Reference", "Description", "URL"]]
    for ref, desc, url in refs:
        rdata.append([ref, desc, url])
    rt = Table(rdata, colWidths=[CONTENT_W * 0.18, CONTENT_W * 0.38, CONTENT_W * 0.44])
    rt.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), _SURFACE),
        ("TEXTCOLOR",   (0, 0), (-1, 0), _TEXT),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_SURFACE, _SURFACE2]),
        ("TEXTCOLOR",   (0, 1), (0, -1), _ACCENT),
        ("FONTNAME",    (0, 1), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",   (1, 1), (-1, -1), colors.HexColor("#cbd5e1")),
        ("GRID",        (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING",     (0, 0), (-1, -1), 5),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(rt)


# ── Main entry point ───────────────────────────────────────────────────────────

def generate_remediation_report(edu: dict) -> bytes:
    """
    Build a complete professional remediation PDF from an education/remediation dict.
    Returns PDF bytes.
    """
    buf = BytesIO()
    report_date = datetime.now(timezone.utc).strftime("%d %B %Y at %H:%M UTC")
    domain = edu.get("domain", "unknown")

    total_pages_ref = [0]
    deco = _PageDeco(domain=domain, report_date=report_date,
                     total_pages_ref=total_pages_ref)

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=LM, rightMargin=RM,
        topMargin=TM + 20,   # extra space for top header band
        bottomMargin=BM + 20,
        title=f"MailGuard Remediation Report — {domain}",
        author="MailGuard Email Security",
        subject=f"Email Security Remediation Report for {domain}",
        keywords="email security, SPF, DMARC, DKIM, remediation",
        creator="MailGuard v1.0",
    )

    story = []

    # Cover
    _build_cover(story, edu)

    # Executive summary
    _build_executive_summary(story, edu)

    # Risk matrix
    vulns = edu.get("vulnerabilities", [])
    if vulns:
        _build_risk_matrix(story, vulns)

        # Per-vulnerability detail sections
        story.append(Paragraph("Detailed Vulnerability Analysis", _H1))
        story.append(_hr(_ACCENT))
        story.append(Paragraph(
            "Each section below provides a full explanation of the vulnerability, "
            "its business impact, current status on your domain, and exact remediation "
            "steps including ready-to-use DNS records.",
            _BODY_J
        ))
        story.append(_spacer(10))

        for i, v in enumerate(vulns, 1):
            _build_vuln_section(story, v, i)

    else:
        story.append(Paragraph("No Vulnerabilities Found", _H1))
        story.append(_hr(_ACCENT))
        story.append(Paragraph(
            f"No email security vulnerabilities were detected for {domain}. "
            "Your domain has strong email security controls in place.",
            _BODY
        ))
        story.append(_spacer(16))

    # Glossary + references
    _build_glossary(story)

    # Final page — about MailGuard
    story.append(PageBreak())
    story.append(Paragraph("About MailGuard", _H2))
    story.append(_spacer(4))
    story.append(Paragraph(
        "MailGuard is an automated email security analysis platform that checks SPF, DMARC, "
        "DKIM, MTA-STS, STARTTLS, blacklist status, and spoofability for any domain via a "
        "simple REST API. Reports can be generated in PDF, compliance (PCI-DSS, SOC 2, "
        "ISO 27001), and remediation formats.",
        _BODY_J
    ))
    story.append(_spacer(8))
    story.append(Paragraph(
        "This report was generated automatically. While every effort has been made to ensure "
        "accuracy, the findings are based on publicly available DNS and SMTP data at the time "
        "of the scan. Configuration changes should be tested carefully before deployment.",
        _s("ABOUT_D", fontSize=8, textColor=_MUTED, leading=11, alignment=TA_JUSTIFY)
    ))

    doc.build(story, onFirstPage=deco.cover, onLaterPages=deco)
    return buf.getvalue()
