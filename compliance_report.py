"""Compliance PDF report generator for MailGuard."""
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

_PASS = colors.HexColor("#22c55e")
_FAIL = colors.HexColor("#ef4444")


def _evaluate_controls(framework: str, r: dict) -> list[dict]:
    spf = r.get("spf", {})
    dmarc = r.get("dmarc", {})
    dkim = r.get("dkim", {})
    mta = r.get("mta_sts", {})
    mx = r.get("mx", {})
    bl = r.get("blacklist", {})
    spoof = r.get("spoofability", {})

    spf_ok = spf.get("found") and spf.get("hardfail_all")
    dmarc_ok = dmarc.get("found") and dmarc.get("policy") in ("quarantine", "reject")
    dmarc_reject = dmarc.get("found") and dmarc.get("policy") == "reject"
    dkim_ok = dkim.get("found") and not dkim.get("has_weak_key")
    starttls_ok = mx.get("all_support_starttls")
    mta_ok = mta.get("fully_configured")
    bl_ok = bl.get("clean")
    spoof_low = spoof.get("risk") == "LOW"

    if framework == "pci-dss":
        return [
            {"ref": "4.2.2",  "name": "Email encryption in transit (STARTTLS)", "status": "PASS" if starttls_ok else "FAIL", "note": "All MX servers must support STARTTLS" if not starttls_ok else "All MX servers support STARTTLS"},
            {"ref": "6.4.1",  "name": "Phishing protection (DMARC enforcement)", "status": "PASS" if dmarc_reject else "FAIL", "note": "DMARC p=reject required" if not dmarc_reject else "DMARC p=reject configured"},
            {"ref": "6.4.2",  "name": "SPF enforcement (-all)", "status": "PASS" if spf_ok else "FAIL", "note": "SPF with -all required" if not spf_ok else "SPF -all configured"},
            {"ref": "12.3.3", "name": "Cryptographic inventory — DKIM key strength", "status": "PASS" if dkim_ok else "FAIL", "note": "DKIM 2048-bit key recommended" if not dkim_ok else "DKIM key meets strength requirements"},
            {"ref": "12.6.3", "name": "Security awareness — DMARC aggregate reporting", "status": "PASS" if dmarc.get("has_reporting") else "FAIL", "note": "DMARC rua required for reporting" if not dmarc.get("has_reporting") else "DMARC aggregate reporting configured"},
        ]
    elif framework == "soc2":
        return [
            {"ref": "CC6.1",  "name": "Logical access controls (SPF prevents spoofing)", "status": "PASS" if spf_ok else "FAIL", "note": "SPF -all prevents unauthorized senders" if not spf_ok else "SPF controls unauthorized access"},
            {"ref": "CC6.6",  "name": "Transmission encryption (MTA-STS/STARTTLS)", "status": "PASS" if (mta_ok or starttls_ok) else "FAIL", "note": "Enable MTA-STS or ensure STARTTLS on all MX" if not (mta_ok or starttls_ok) else "Email transmission is encrypted"},
            {"ref": "CC6.7",  "name": "DMARC policy enforcement", "status": "PASS" if dmarc_ok else "FAIL", "note": "DMARC p=quarantine or p=reject required" if not dmarc_ok else "DMARC enforcement is active"},
            {"ref": "CC7.2",  "name": "System monitoring (DMARC reporting)", "status": "PASS" if dmarc.get("has_reporting") else "FAIL", "note": "Configure DMARC rua for monitoring" if not dmarc.get("has_reporting") else "DMARC reporting is configured"},
            {"ref": "CC9.2",  "name": "Vendor risk — blacklist status", "status": "PASS" if bl_ok else "FAIL", "note": "Mail server IPs are blacklisted" if not bl_ok else "Mail server IPs are clean"},
        ]
    else:  # iso27001
        return [
            {"ref": "A.10.1.1", "name": "Cryptographic policy — DKIM key strength", "status": "PASS" if dkim_ok else "FAIL", "note": "DKIM key must be at least 1024 bits" if not dkim_ok else "DKIM key meets policy"},
            {"ref": "A.13.2.1", "name": "Information transfer — STARTTLS", "status": "PASS" if starttls_ok else "FAIL", "note": "Enable STARTTLS on all MX servers" if not starttls_ok else "STARTTLS is configured"},
            {"ref": "A.13.2.3", "name": "Electronic messaging security — SPF/DMARC", "status": "PASS" if (spf_ok and dmarc_ok) else "FAIL", "note": "Both SPF -all and DMARC enforcement required" if not (spf_ok and dmarc_ok) else "SPF and DMARC are configured"},
            {"ref": "A.14.1.2", "name": "Securing application services — MTA-STS", "status": "PASS" if mta_ok else "FAIL", "note": "Configure MTA-STS in enforce mode" if not mta_ok else "MTA-STS is fully configured"},
            {"ref": "A.16.1.2", "name": "Incident reporting — DMARC rua", "status": "PASS" if dmarc.get("has_reporting") else "FAIL", "note": "Configure DMARC rua for incident visibility" if not dmarc.get("has_reporting") else "DMARC reporting enables incident visibility"},
        ]


def generate_compliance_report(scan_result: dict, framework: str) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    W = A4[0] - 4*cm
    body_style = ParagraphStyle("b", fontSize=9, textColor=colors.HexColor("#94a3b8"), spaceAfter=4)
    heading = ParagraphStyle("h", fontSize=13, fontName="Helvetica-Bold", textColor=colors.HexColor("#38bdf8"), spaceAfter=6)

    controls = _evaluate_controls(framework, scan_result)
    passed = sum(1 for c in controls if c["status"] == "PASS")
    total = len(controls)
    compliant = passed == total
    banner_color = colors.HexColor("#16a34a") if compliant else colors.HexColor("#dc2626")
    banner_text = "COMPLIANT" if compliant else "NON-COMPLIANT"
    fw_names = {"pci-dss": "PCI-DSS v4.0", "soc2": "SOC 2 Type II", "iso27001": "ISO/IEC 27001:2022"}

    story = []
    story.append(Paragraph(f"<font color='#38bdf8'>MailGuard</font> Compliance Report — {fw_names.get(framework, framework)}", ParagraphStyle("title", fontSize=18, fontName="Helvetica-Bold", textColor=colors.white, spaceAfter=4)))
    story.append(Paragraph(f"Domain: <b>{scan_result.get('domain','')}</b>  ·  Grade: <b>{scan_result.get('grade','')}</b>  ·  Score: <b>{scan_result.get('score',0)}/100</b>", body_style))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#334155"), spaceAfter=12))

    # Banner
    banner_t = Table([[banner_text]], colWidths=[W])
    banner_t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), banner_color), ("TEXTCOLOR", (0,0), (-1,-1), colors.white), ("FONTNAME", (0,0), (-1,-1), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 20), ("ALIGN", (0,0), (-1,-1), "CENTER"), ("PADDING", (0,0), (-1,-1), 14)]))
    story.append(banner_t)
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"{passed}/{total} controls passing", ParagraphStyle("sub", fontSize=11, textColor=colors.HexColor("#94a3b8"), alignment=1, spaceAfter=16)))

    # Controls table
    story.append(Paragraph("Control Assessment", heading))
    ctrl_data = [["Ref", "Control Name", "Status", "Notes"]]
    for c in controls:
        ctrl_data.append([c["ref"], c["name"], c["status"], c["note"]])
    ct = Table(ctrl_data, colWidths=[W*0.12, W*0.33, W*0.13, W*0.42])
    ct.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#0f172a"), colors.HexColor("#1e293b")]),
        ("TEXTCOLOR", (0,1), (-1,-1), colors.HexColor("#cbd5e1")),
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#334155")),
        ("PADDING", (0,0), (-1,-1), 6),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        *[("TEXTCOLOR", (2, i+1), (2, i+1), _PASS if controls[i]["status"] == "PASS" else _FAIL)
          for i in range(len(controls))],
        *[("FONTNAME", (2, i+1), (2, i+1), "Helvetica-Bold") for i in range(len(controls))],
    ]))
    story.append(ct)
    doc.build(story)
    return buf.getvalue()
