"""ReportLab PDF generator for MailGuard email security reports."""
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

_GRADE_COLORS = {
    "A+": colors.HexColor("#16a34a"), "A": colors.HexColor("#22c55e"),
    "B": colors.HexColor("#84cc16"),  "C": colors.HexColor("#eab308"),
    "D": colors.HexColor("#f97316"),  "F": colors.HexColor("#ef4444"),
}
_RISK_COLORS = {
    "LOW": colors.HexColor("#22c55e"),
    "MEDIUM": colors.HexColor("#f97316"),
    "HIGH": colors.HexColor("#ef4444"),
}


def _table(data, col_widths=None):
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0f172a"), colors.HexColor("#1e293b")]),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#cbd5e1")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def generate_report(scan_result: dict) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    W = A4[0] - 4*cm

    heading = ParagraphStyle("h", fontSize=13, fontName="Helvetica-Bold", textColor=colors.HexColor("#38bdf8"), spaceAfter=6)
    body = ParagraphStyle("b", fontSize=9, textColor=colors.HexColor("#94a3b8"), spaceAfter=4)
    issue_style = ParagraphStyle("issue", fontSize=9, textColor=colors.HexColor("#f87171"), leftIndent=12, spaceAfter=3)
    rec_style = ParagraphStyle("rec", fontSize=9, textColor=colors.HexColor("#7dd3fc"), leftIndent=12, spaceAfter=3)

    story = []
    domain = scan_result.get("domain", "")
    grade = scan_result.get("grade", "F")
    score = scan_result.get("score", 0)
    gc = _GRADE_COLORS.get(grade, colors.red)

    # Header
    story.append(Paragraph(f"<font color='#38bdf8'>MailGuard</font> Email Security Report", ParagraphStyle("title", fontSize=20, fontName="Helvetica-Bold", textColor=colors.white, spaceAfter=4)))
    story.append(Paragraph(f"Domain: <b>{domain}</b>  ·  Scan duration: {scan_result.get('scan_duration_ms', 0)}ms", body))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#334155"), spaceAfter=12))

    # Grade
    grade_data = [["Grade", "Score", "Issues", "Spoofability Risk"]]
    spoof_risk = scan_result.get("spoofability", {}).get("risk", "UNKNOWN")
    grade_data.append([grade, f"{score}/100", str(scan_result.get("issue_count", 0)), spoof_risk])
    gt = _table(grade_data, col_widths=[W*0.2]*4)
    gt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, 1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 1), (0, 1), gc),
        ("FONTSIZE", (0, 1), (0, 1), 28),
        ("TEXTCOLOR", (3, 1), (3, 1), _RISK_COLORS.get(spoof_risk, colors.white)),
        ("FONTNAME", (3, 1), (3, 1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0f172a")]),
        ("TEXTCOLOR", (1, 1), (2, 1), colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
    ]))
    story.append(gt)
    story.append(Spacer(1, 12))

    # SPF
    spf = scan_result.get("spf", {})
    story.append(Paragraph("SPF (Sender Policy Framework)", heading))
    story.append(_table([
        ["Found", "Record", "All Mechanism", "DNS Lookups", "Exceeds Limit"],
        [
            "Yes" if spf.get("found") else "No",
            (spf.get("record") or "–")[:60],
            spf.get("all_mechanism") or "–",
            str(spf.get("dns_lookup_count", 0)),
            "Yes ⚠" if spf.get("exceeds_lookup_limit") else "No",
        ]
    ], col_widths=[W*0.08, W*0.42, W*0.15, W*0.15, W*0.20]))
    story.append(Spacer(1, 10))

    # DMARC
    dmarc = scan_result.get("dmarc", {})
    story.append(Paragraph("DMARC", heading))
    story.append(_table([
        ["Found", "Policy", "Pct", "Reporting (rua)", "Enforced"],
        [
            "Yes" if dmarc.get("found") else "No",
            dmarc.get("policy") or "–",
            str(dmarc.get("pct") or 100),
            "Yes" if dmarc.get("has_reporting") else "No",
            "Yes" if dmarc.get("enforced") else "No",
        ]
    ], col_widths=[W*0.12, W*0.18, W*0.12, W*0.28, W*0.30]))
    story.append(Spacer(1, 10))

    # DKIM
    dkim = scan_result.get("dkim", {})
    story.append(Paragraph("DKIM", heading))
    found_sels = dkim.get("selectors_found", [])
    sel_names = ", ".join(s["selector"] for s in found_sels) if found_sels else "None found"
    story.append(_table([
        ["Found", "Selectors Found", "Weakest Key (bits)", "Weak Key"],
        [
            "Yes" if dkim.get("found") else "No",
            sel_names[:60],
            str(dkim.get("weakest_key_bits") or "–"),
            "Yes ⚠" if dkim.get("has_weak_key") else "No",
        ]
    ], col_widths=[W*0.10, W*0.45, W*0.25, W*0.20]))
    story.append(Spacer(1, 10))

    # MTA-STS
    mta = scan_result.get("mta_sts", {})
    story.append(Paragraph("MTA-STS", heading))
    story.append(_table([
        ["DNS Record", "Policy File", "Mode", "Fully Configured"],
        [
            "Found" if mta.get("dns_record_found") else "Missing",
            "Fetched" if mta.get("policy_fetched") else f"Missing ({mta.get('fetch_error','') or ''})",
            mta.get("policy_mode") or "–",
            "Yes ✓" if mta.get("fully_configured") else "No",
        ]
    ], col_widths=[W*0.20, W*0.35, W*0.20, W*0.25]))
    story.append(Spacer(1, 10))

    # MX Servers
    mx = scan_result.get("mx", {})
    story.append(Paragraph("MX Servers & STARTTLS", heading))
    mx_data = [["Hostname", "Priority", "STARTTLS", "TLS Version", "Cipher"]]
    for srv in mx.get("records", []):
        mx_data.append([
            srv.get("hostname", "")[:35],
            str(srv.get("priority", "")),
            "Yes ✓" if srv.get("starttls_supported") else "No ✗",
            srv.get("tls_version") or "–",
            (srv.get("tls_cipher") or "–")[:25],
        ])
    if len(mx_data) == 1:
        mx_data.append(["No MX records found", "", "", "", ""])
    story.append(_table(mx_data, col_widths=[W*0.35, W*0.10, W*0.15, W*0.18, W*0.22]))
    story.append(Spacer(1, 10))

    # Blacklist
    bl = scan_result.get("blacklist", {})
    story.append(Paragraph("Blacklist Status", heading))
    story.append(_table([
        ["IPs Checked", "Listed IPs", "Status"],
        [
            str(len(bl.get("ips_checked", []))),
            str(bl.get("listed_count", 0)),
            "Clean ✓" if bl.get("clean") else f"BLACKLISTED ✗ ({bl.get('listed_count')} IP(s))",
        ]
    ], col_widths=[W*0.25, W*0.25, W*0.50]))
    story.append(Spacer(1, 10))

    # Spoofability
    spoof = scan_result.get("spoofability", {})
    story.append(Paragraph("Spoofability Assessment", heading))
    risk_color = _RISK_COLORS.get(spoof.get("risk", ""), colors.white)
    story.append(_table([
        ["Risk Level", "Can Spoof From Header", "SPF Status", "DMARC Status"],
        [
            spoof.get("risk", "UNKNOWN"),
            "Yes ✗" if spoof.get("can_spoof_from_header") else "No ✓",
            spoof.get("spf_contribution", "")[:40],
            spoof.get("dmarc_contribution", "")[:40],
        ]
    ], col_widths=[W*0.15, W*0.20, W*0.32, W*0.33]))
    story.append(Spacer(1, 12))

    # Issues
    issues = scan_result.get("issues", [])
    if issues:
        story.append(Paragraph("Issues Found", heading))
        for issue in issues:
            story.append(Paragraph(f"✗  {issue}", issue_style))
        story.append(Spacer(1, 10))

    # Recommendations
    recs = scan_result.get("recommendations", [])
    if recs:
        story.append(Paragraph("Recommendations", heading))
        for rec in recs:
            story.append(Paragraph(f"→  {rec}", rec_style))

    doc.build(story)
    return buf.getvalue()
