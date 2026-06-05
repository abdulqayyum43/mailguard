"""
MailGuard — Authenticated Remediation & Fix Guide PDF
Professional layout: education + step-by-step fix instructions per issue.
Every page is stamped with report ID, SHA-256 fingerprint, and page number.
"""
import hashlib
import uuid
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, KeepTogether,
)

# ── Page geometry ──────────────────────────────────────────────────────────────
PAGE_W, PAGE_H = A4
MARGIN    = 1.8 * cm
CONTENT_W = PAGE_W - (MARGIN * 2)

# ── Colours ────────────────────────────────────────────────────────────────────
C_BG     = colors.HexColor("#020817")
C_CARD   = colors.HexColor("#0f172a")
C_CARD2  = colors.HexColor("#111827")
C_BORDER = colors.HexColor("#1e293b")
C_BORDER2= colors.HexColor("#334155")
C_ACCENT = colors.HexColor("#38bdf8")
C_BLUE2  = colors.HexColor("#0ea5e9")
C_TEXT   = colors.HexColor("#cbd5e1")
C_MUTED  = colors.HexColor("#64748b")
C_MUTED2 = colors.HexColor("#94a3b8")
C_RED    = colors.HexColor("#ef4444")
C_ORANGE = colors.HexColor("#f97316")
C_YELLOW = colors.HexColor("#eab308")
C_GREEN  = colors.HexColor("#22c55e")
C_CODE   = colors.HexColor("#7dd3fc")
C_WHITE  = colors.white

SEV_CLR  = {"HIGH": C_RED,   "MEDIUM": C_ORANGE, "LOW": C_YELLOW}
GRD_CLR  = {
    "A+": C_GREEN, "A": C_GREEN, "B": colors.HexColor("#84cc16"),
    "C":  C_YELLOW, "D": C_ORANGE, "F": C_RED,
}

# Safe hex string for inline Paragraph markup
def _hex(c) -> str:
    return "#{:02x}{:02x}{:02x}".format(
        int(c.red * 255), int(c.green * 255), int(c.blue * 255)
    )


# ── Style helpers ──────────────────────────────────────────────────────────────
def _st(**kw) -> ParagraphStyle:
    base = dict(fontName="Helvetica", fontSize=9, textColor=C_TEXT,
                leading=13, spaceAfter=0, spaceBefore=0)
    base.update(kw)
    return ParagraphStyle(str(uuid.uuid4())[:8], **base)


# Pre-built styles used across the document
ST_BRAND    = _st(fontSize=22, fontName="Helvetica-Bold", textColor=C_WHITE, leading=28)
ST_DOCTYPE  = _st(fontSize=9,  fontName="Helvetica-Bold", textColor=C_MUTED2, alignment=2)
ST_SUBTITLE = _st(fontSize=11, textColor=C_MUTED2)
ST_CERTIFIED= _st(fontSize=8,  fontName="Helvetica-Bold", textColor=C_BLUE2, alignment=2)
ST_META_KEY = _st(fontSize=8,  fontName="Helvetica-Bold", textColor=C_MUTED)
ST_META_VAL = _st(fontSize=8,  textColor=C_TEXT)
ST_META_HASH= _st(fontSize=7,  fontName="Courier",        textColor=C_MUTED)
ST_SEC_HDR  = _st(fontSize=12, fontName="Helvetica-Bold", textColor=C_ACCENT,
                  spaceAfter=6)
ST_ISS_TITLE= _st(fontSize=11, fontName="Helvetica-Bold", textColor=C_WHITE)
ST_LBL      = _st(fontSize=8,  fontName="Helvetica-Bold", textColor=C_ACCENT,
                  spaceBefore=4)
ST_BODY     = _st(fontSize=9,  textColor=C_TEXT,  leading=14)
ST_STEP     = _st(fontSize=9,  textColor=C_TEXT,  leading=14, leftIndent=10)
ST_SUBHDR   = _st(fontSize=8,  fontName="Helvetica-Bold", textColor=C_MUTED2,
                  spaceBefore=6, spaceAfter=1)
ST_CODE     = _st(fontSize=8,  fontName="Courier", textColor=C_CODE,
                  leftIndent=10, leading=12)
ST_INV_ISS  = _st(fontSize=8,  textColor=C_RED)
ST_CERT     = _st(fontSize=8,  textColor=C_MUTED, leading=12)


# ── Table factory ──────────────────────────────────────────────────────────────
def _tbl(data, widths, cmds):
    t = Table(data, colWidths=widths, hAlign="LEFT")
    t.setStyle(TableStyle(cmds))
    return t


def _sev_badge(sev: str) -> Table:
    c = SEV_CLR.get(sev, C_MUTED)
    t = Table([[sev]], colWidths=[1.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), c),
        ("TEXTCOLOR",     (0, 0), (-1, -1), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]))
    return t


# ── Issue Knowledge Base ───────────────────────────────────────────────────────
def _kb(domain: str) -> list[dict]:
    d = domain
    return [
        # ── SPF ───────────────────────────────────────────────────────────────
        {
            "pattern": "no spf record",
            "title":   "Missing SPF Record",
            "severity": "HIGH",
            "what": (
                "SPF (Sender Policy Framework) is a DNS TXT record that lists every mail server "
                "authorised to send email on behalf of your domain. When a receiving server gets "
                "a message claiming to be from your domain, it checks the sending IP address "
                "against your SPF record to decide if the email is legitimate."
            ),
            "why": (
                f"Without SPF, any server on the internet can send email claiming to be from "
                f"@{d}. Attackers exploit this for phishing, business email compromise (BEC), "
                f"and brand impersonation. Your domain is fully unprotected right now."
            ),
            "steps": [
                "Step 1 — Log in to your DNS provider (Cloudflare, GoDaddy, Route 53, etc.).",
                "Step 2 — Create a new TXT record at your root domain:",
                f"§  Name:  {d}  (or '@')",
                "§  Type:  TXT",
                "§  Value: v=spf1 include:_spf.google.com -all",
                "Step 3 — Replace the include: with your actual mail provider's SPF include:",
                "§§ Common provider includes",
                "§  Google Workspace  →  include:_spf.google.com",
                "§  Microsoft 365    →  include:spf.protection.outlook.com",
                "§  Mailgun          →  include:mailgun.org",
                "§  SendGrid         →  include:sendgrid.net",
                "§  Amazon SES       →  include:amazonses.com",
                "§  Zoho Mail        →  include:zoho.com",
                "Step 4 — Always end the record with -all to reject all unauthorised senders.",
                "Step 5 — Wait up to 24 hours for DNS propagation.",
                "Step 6 — Verify:",
                f"§  nslookup -type=TXT {d}",
                "§  or:  https://mxtoolbox.com/spf.aspx",
            ],
        },
        {
            "pattern": "spf uses +all",
            "title":   "SPF Permits Any Sender (+all)",
            "severity": "HIGH",
            "what": (
                "Your SPF record ends with +all — the 'pass all' qualifier. This explicitly "
                "tells every receiving server that ALL senders are authorised, including attackers."
            ),
            "why": (
                f"+all is worse than no SPF. Phishing emails sent against {d} from attacker "
                "servers will pass SPF checks, bypass spam filters, and land in inboxes. "
                "Anti-spam platforms will permanently down-rank your domain's reputation."
            ),
            "steps": [
                f"Step 1 — Open your DNS provider and find the TXT record at {d}.",
                "Step 2 — Change +all to -all:",
                "§  Before:  v=spf1 include:... +all",
                "§  After:   v=spf1 include:... -all",
                "Step 3 — -all tells receivers: REJECT mail from any unlisted server.",
                "Step 4 — If transitioning carefully, use ~all (softfail) for 2 weeks first,",
                "         then upgrade to -all.",
            ],
        },
        {
            "pattern": "softfail",
            "title":   "SPF Softfail (~all) — Upgrade to Hard Fail",
            "severity": "MEDIUM",
            "what": (
                "Your SPF record uses ~all (softfail). This marks unauthorised senders as "
                "suspicious but still allows delivery. Spoofed emails reach inboxes — "
                "typically in the spam folder."
            ),
            "why": (
                "Softfail provides only partial protection. Without a strict DMARC p=reject "
                "policy, spoofed messages can still reach recipients. Hard fail (-all) "
                "instructs receivers to reject unauthorised messages outright."
            ),
            "steps": [
                f"Step 1 — Locate the SPF TXT record at {d}.",
                "Step 2 — Change ~all to -all:",
                "§  Before:  v=spf1 include:... ~all",
                "§  After:   v=spf1 include:... -all",
                f"Step 3 — Before changing, verify every service sending as {d} is listed.",
                "Step 4 — Monitor delivery logs for 48 hours after the change.",
            ],
        },
        {
            "pattern": "neutral",
            "title":   "SPF Neutral (?all) — No Protection",
            "severity": "MEDIUM",
            "what": (
                "Your SPF record ends with ?all (neutral). This means the domain owner makes "
                "no assertion about unlisted senders — receivers treat it as 'don't know, "
                "deliver anyway'. It provides zero spoofing protection."
            ),
            "why": (
                "?all is functionally equivalent to having no SPF record at all. Any server "
                "can spoof your domain and the SPF result will be NEUTRAL — receivers will "
                "not block it."
            ),
            "steps": [
                f"Step 1 — Find the SPF TXT record at {d} in your DNS dashboard.",
                "Step 2 — Replace ?all with -all:",
                "§  Before:  v=spf1 ... ?all",
                "§  After:   v=spf1 ... -all",
                "Step 3 — Allow up to 24 hours for DNS propagation.",
                f"Step 4 — Confirm:  nslookup -type=TXT {d}",
            ],
        },
        {
            "pattern": "lookup limit",
            "title":   "SPF Exceeds 10 DNS Lookup Limit",
            "severity": "MEDIUM",
            "what": (
                "RFC 7208 limits SPF evaluation to 10 DNS lookups. Each include:, a:, and mx: "
                "mechanism counts as one. Exceeding this limit causes a PermError, which most "
                "receivers treat as SPF failure."
            ),
            "why": (
                "PermError can cause legitimate emails to be rejected or spam-flagged. It adds "
                "DNS latency to every email delivery and can be exploited by spammers to "
                "bypass your SPF checks entirely."
            ),
            "steps": [
                f"Step 1 — Audit your SPF record at {d} and count all mechanisms.",
                "Step 2 — Use an SPF survey tool to visualise all lookups:",
                "§  https://dmarcian.com/spf-survey/",
                "§  https://mxtoolbox.com/spf.aspx",
                "Step 3 — Remove include: entries for services you no longer use.",
                "Step 4 — Flatten remaining includes into direct IP ranges to save lookups:",
                "§  Instead of:  include:_spf.mailprovider.com",
                "§  Use:         ip4:192.0.2.0/24 ip4:198.51.100.0/24",
                "Step 5 — Example flattened record:",
                f"§  v=spf1 ip4:209.85.128.0/17 ip4:74.125.0.0/16 -all",
                "Step 6 — Use Valimail or dmarcian to automate ongoing SPF flattening.",
            ],
        },
        # ── DMARC ──────────────────────────────────────────────────────────────
        {
            "pattern": "no dmarc record",
            "title":   "Missing DMARC Record",
            "severity": "HIGH",
            "what": (
                "DMARC (Domain-based Message Authentication, Reporting & Conformance) is a DNS "
                "policy that tells receiving servers what to do when an email fails SPF and DKIM "
                "checks. It is the final enforcement layer of email authentication — without it, "
                "even properly configured SPF and DKIM cannot stop spoofed mail from being delivered."
            ),
            "why": (
                f"Without DMARC, spoofed emails from {d} can reach inboxes. Google and Yahoo now "
                "require DMARC for bulk senders. Enterprise mail gateways increasingly require it "
                "for all inbound mail acceptance."
            ),
            "steps": [
                "Step 1 — Create a new DNS TXT record:",
                f"§  Name:  _dmarc.{d}",
                "§  Type:  TXT",
                f"§  Value: v=DMARC1; p=none; pct=100; rua=mailto:dmarc@{d}",
                "Step 2 — Start with p=none (monitoring only) — no mail is blocked,",
                "         but reports are collected so you can see your email flows.",
                "Step 3 — Sign up for free DMARC report analysis:",
                "§  https://dmarcian.com",
                "§  https://dmarc.postmarkapp.com",
                "Step 4 — After 2-4 weeks of monitoring, upgrade to p=quarantine:",
                f"§  v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@{d}",
                "Step 5 — Increase pct to 100 over 2-4 weeks, then upgrade to p=reject:",
                f"§  v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@{d}",
                f"Step 6 — Verify:  nslookup -type=TXT _dmarc.{d}",
            ],
        },
        {
            "pattern": "p=none",
            "title":   "DMARC Monitoring Only (p=none)",
            "severity": "HIGH",
            "what": (
                "Your DMARC record uses p=none — monitoring mode. Reports are collected but no "
                "action is taken. Spoofed emails are delivered exactly as if DMARC did not exist."
            ),
            "why": (
                "p=none provides zero protection. It is a temporary starting point only. "
                "Leaving it at p=none long-term gives a false sense of security while "
                "attackers continue spoofing your domain freely."
            ),
            "steps": [
                "Step 1 — Review aggregate reports at your rua= inbox.",
                f"         Look for any sources sending as {d} that you don't recognise.",
                "Step 2 — Confirm SPF and DKIM pass for all legitimate senders.",
                "Step 3 — Upgrade to p=quarantine (partial rollout first):",
                f"§  v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@{d}",
                "Step 4 — Increase pct to 100 over 1-2 weeks.",
                "Step 5 — Then upgrade to full enforcement:",
                f"§  v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@{d}",
            ],
        },
        {
            "pattern": "p=quarantine",
            "title":   "DMARC at Quarantine — Upgrade to p=reject",
            "severity": "MEDIUM",
            "what": (
                "Your DMARC policy is p=quarantine. Failing messages are sent to the recipient's "
                "spam folder rather than rejected. This is a good intermediate step, "
                "but not full protection."
            ),
            "why": (
                "Quarantined messages still reach recipients in their spam folder. Only p=reject "
                "completely blocks spoofed email — it is rejected during the SMTP session, "
                "before any delivery occurs."
            ),
            "steps": [
                f"Step 1 — Verify SPF and DKIM pass for ALL senders using {d}.",
                f"§  https://mxtoolbox.com/emailhealth/{d}",
                "Step 2 — Update the DMARC record to p=reject:",
                "§  Before:  v=DMARC1; p=quarantine; ...",
                f"§  After:   v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@{d}",
                "Step 3 — Monitor DMARC reports for 1 week after the change.",
                "Step 4 — If any legitimate mail is rejected, add the missing sender to SPF/DKIM.",
            ],
        },
        {
            "pattern": "pct=",
            "title":   "DMARC Not Applied to All Messages (pct < 100)",
            "severity": "LOW",
            "what": (
                "Your DMARC pct= tag is below 100, so enforcement only applies to that "
                "percentage of messages. The remainder are processed as if the policy were "
                "p=none regardless of your policy setting."
            ),
            "why": (
                "Partial pct is appropriate during a rollout but should not be permanent. "
                "Attackers can potentially land spoofed emails in the unprotected percentage."
            ),
            "steps": [
                f"Step 1 — Update _dmarc.{d} to pct=100:",
                f"§  v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@{d}",
                "Step 2 — Only do this after all legitimate senders are passing DMARC.",
            ],
        },
        {
            "pattern": "rua reporting",
            "title":   "DMARC Has No Reporting Address (rua missing)",
            "severity": "LOW",
            "what": (
                "Your DMARC record has no rua= tag. Receivers have nowhere to send DMARC "
                "feedback reports, so you have no visibility into who is sending email "
                "from your domain."
            ),
            "why": (
                "DMARC reports are your early-warning system. They reveal unauthorised senders, "
                "misconfigured services, and spoofing attempts. Without them, you are blind."
            ),
            "steps": [
                f"Step 1 — Add rua= to your _dmarc.{d} TXT record:",
                f"§  v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@{d}",
                "Step 2 — Use a free report parser to read incoming XML reports:",
                "§  https://dmarcian.com",
                "§  https://dmarc.postmarkapp.com",
                "§  https://parsedmarc.readthedocs.io  (self-hosted)",
            ],
        },
        # ── DKIM ──────────────────────────────────────────────────────────────
        {
            "pattern": "no dkim",
            "title":   "Missing DKIM Configuration",
            "severity": "HIGH",
            "what": (
                "DKIM (DomainKeys Identified Mail) adds a cryptographic signature to outgoing "
                "emails. Your mail server signs each message with a private key; the public key "
                "is published in DNS. Receivers verify the signature to confirm the email is "
                "authentic and has not been altered in transit."
            ),
            "why": (
                "Without DKIM, emails can be forged or modified after leaving your server with "
                "no detection. DKIM is required for DMARC to work correctly — without it, "
                "DMARC depends solely on SPF alignment. Gmail and Yahoo require DKIM for all "
                "bulk senders since February 2024."
            ),
            "steps": [
                "§§ Option A — Hosted email provider (recommended)",
                "§§ Google Workspace",
                f"§  Admin Console → Apps → Gmail → Authenticate Email → Generate DKIM Key",
                f"§  Publish the provided TXT record at:  google._domainkey.{d}",
                "§§ Microsoft 365",
                f"§  Admin Center → Settings → Domains → {d} → DKIM tab → Enable",
                "§§ Mailgun / SendGrid",
                f"§  Sending → Domains → {d} → DKIM → Copy TXT record to DNS",
                "",
                "§§ Option B — Self-hosted Postfix + OpenDKIM",
                "Step 1 — Install OpenDKIM:",
                "§  sudo apt install opendkim opendkim-tools",
                "Step 2 — Generate a 2048-bit keypair:",
                f"§  opendkim-genkey -b 2048 -d {d} -s mail -D /etc/opendkim/keys/",
                "Step 3 — Publish the public key in DNS:",
                f"§  Name:  mail._domainkey.{d}",
                "§  Type:  TXT",
                "§  Value: (contents of /etc/opendkim/keys/mail.txt)",
                "Step 4 — Configure /etc/opendkim.conf and integrate with Postfix.",
                "Step 5 — Verify:",
                f"§  nslookup -type=TXT mail._domainkey.{d}",
                "Step 6 — Test full signing:  https://www.mail-tester.com",
            ],
        },
        {
            "pattern": "dkim key is",
            "title":   "Weak DKIM Key (Below Minimum Strength)",
            "severity": "HIGH",
            "what": (
                "Your DKIM key is shorter than 1024 bits. RFC 8301 deprecated keys below this "
                "threshold. Short RSA keys can be factored by adversaries, allowing them to "
                "forge DKIM signatures for your domain."
            ),
            "why": (
                "A compromised DKIM key lets attackers send emails that pass DKIM verification, "
                "bypass DMARC, and evade spam filters — with your domain's cryptographic seal. "
                "2048-bit RSA is the current minimum; Ed25519 is recommended for new setups."
            ),
            "steps": [
                "Step 1 — Generate a new 2048-bit keypair under a new selector:",
                f"§  opendkim-genkey -b 2048 -d {d} -s mail2048 -D /etc/opendkim/keys/",
                "Step 2 — Publish the NEW public key in DNS first (keep old key active):",
                f"§  Name:  mail2048._domainkey.{d}",
                "§  Type:  TXT",
                "§  Value: (contents of mail2048.txt)",
                "Step 3 — Update mail server config to sign with the new selector.",
                "Step 4 — Wait 48 hours, verify signing works, then remove the old DNS record.",
                "Step 5 — For hosted providers: use their admin panel key rotation feature.",
            ],
        },
        {
            "pattern": "upgrade to 2048",
            "title":   "DKIM Key Below Recommended Size",
            "severity": "LOW",
            "what": (
                "Your DKIM key is valid but below the recommended 2048-bit size. 1024-bit RSA "
                "keys have been deprecated by NIST and are expected to become insufficient "
                "as computing power increases."
            ),
            "why": (
                "Rotating to 2048-bit keys now is a proactive security measure and improves "
                "compatibility with strict receivers that enforce minimum key size requirements."
            ),
            "steps": [
                "Step 1 — Generate a 2048-bit key with a new selector name:",
                f"§  opendkim-genkey -b 2048 -d {d} -s mail2048",
                "Step 2 — Publish the new key in DNS alongside the old one.",
                "Step 3 — Update mail server config to sign with the new selector.",
                "Step 4 — Confirm delivery works, then remove the old 1024-bit DNS record.",
            ],
        },
        # ── MTA-STS ───────────────────────────────────────────────────────────
        {
            "pattern": "no mta-sts",
            "title":   "MTA-STS Not Configured",
            "severity": "MEDIUM",
            "what": (
                "MTA-STS allows domain owners to declare that their mail servers support TLS "
                "and that sending servers should refuse delivery if a valid TLS connection cannot "
                "be established. It prevents SMTP TLS downgrade (stripping) attacks."
            ),
            "why": (
                f"Without MTA-STS, a network attacker between mail servers can strip the "
                f"STARTTLS command from the SMTP negotiation, causing all email delivered to "
                f"{d} to travel in cleartext without either party realising it."
            ),
            "steps": [
                f"Step 1 — Set up HTTPS hosting for mta-sts.{d} (valid TLS cert required).",
                "Step 2 — Create the policy file at:",
                f"§  https://mta-sts.{d}/.well-known/mta-sts.txt",
                "§§ Policy file content (start in testing mode)",
                "§  version: STSv1",
                "§  mode: testing",
                f"§  mx: mail.{d}",
                f"§  mx: *.{d}",
                "§  max_age: 86400",
                "Step 3 — Add a DNS TXT record:",
                f"§  Name:  _mta-sts.{d}",
                "§  Type:  TXT",
                "§  Value: v=STSv1; id=20240101000000Z",
                "         Update the id= each time you change the policy.",
                "Step 4 — Optionally add TLS-RPT for failure reports:",
                f"§  Name:  _smtp._tls.{d}",
                "§  Type:  TXT",
                f"§  Value: v=TLSRPTv1; rua=mailto:tls-reports@{d}",
                "Step 5 — After testing confirms no issues, change mode: testing → mode: enforce.",
                "Step 6 — Validate:  https://aykevl.nl/apps/mta-sts/",
            ],
        },
        {
            "pattern": "mta-sts is in testing",
            "title":   "MTA-STS in Testing Mode — Not Enforcing",
            "severity": "LOW",
            "what": (
                "Your MTA-STS policy is set to mode: testing. Policy violations are reported "
                "but do not block delivery. TLS downgrade attacks still succeed."
            ),
            "why": (
                "Testing mode provides no actual protection. It should only be used during "
                "initial validation. Switch to mode: enforce to prevent TLS stripping attacks."
            ),
            "steps": [
                "Step 1 — Review TLS-RPT reports to confirm no delivery issues.",
                "Step 2 — Update the policy file:",
                f"§  URL:    https://mta-sts.{d}/.well-known/mta-sts.txt",
                "§  Change: mode: testing",
                "§  To:     mode: enforce",
                "Step 3 — Increment the id= in your _mta-sts DNS record to trigger re-fetch:",
                "§  v=STSv1; id=20240201000000Z",
            ],
        },
        # ── MX / STARTTLS ─────────────────────────────────────────────────────
        {
            "pattern": "starttls",
            "title":   "STARTTLS Not Supported on Mail Servers",
            "severity": "HIGH",
            "what": (
                "STARTTLS is an SMTP command that upgrades a plaintext port-25 connection to an "
                "encrypted TLS session before any email data is sent. All mail servers receiving "
                "email for your domain must support STARTTLS."
            ),
            "why": (
                f"Without STARTTLS, every email delivered to {d} travels across the internet in "
                "plaintext. Every ISP, transit provider, and network device along the path can "
                "read the full contents of every email — exposing credentials, confidential "
                "communications, and attachments."
            ),
            "steps": [
                "§§ Option A — Hosted email provider",
                "Google, Microsoft 365, and Zoho all support STARTTLS by default.",
                f"Verify your MX records point to the correct provider hostnames for {d}.",
                "",
                "§§ Option B — Self-hosted Postfix",
                "Step 1 — Get a free TLS certificate from Let's Encrypt:",
                f"§  sudo certbot certonly --standalone -d mail.{d}",
                "Step 2 — Add to /etc/postfix/main.cf:",
                f"§  smtpd_tls_cert_file      = /etc/letsencrypt/live/mail.{d}/fullchain.pem",
                f"§  smtpd_tls_key_file       = /etc/letsencrypt/live/mail.{d}/privkey.pem",
                "§  smtpd_tls_security_level = may",
                "§  smtpd_tls_protocols      = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
                "Step 3 — Restart:  sudo systemctl restart postfix",
                "",
                "§§ Option C — Self-hosted Exim",
                "Add to /etc/exim4/exim4.conf.template:",
                f"§  tls_certificate = /etc/letsencrypt/live/mail.{d}/fullchain.pem",
                f"§  tls_privatekey  = /etc/letsencrypt/live/mail.{d}/privkey.pem",
                "§  sudo service exim4 restart",
                "",
                "Step 4 — Test STARTTLS:",
                f"§  openssl s_client -connect mail.{d}:25 -starttls smtp",
            ],
        },
        {
            "pattern": "only",
            "title":   "Some MX Servers Lack STARTTLS",
            "severity": "MEDIUM",
            "what": (
                "At least one of your MX servers does not support STARTTLS. When sending servers "
                "connect to that server, email is delivered in plaintext with no encryption."
            ),
            "why": (
                "Even if your primary MX supports STARTTLS, any MX server without it becomes "
                "a plaintext delivery path that adversaries can exploit by routing mail through it."
            ),
            "steps": [
                "Step 1 — Identify which MX server(s) lack STARTTLS from the scan results above.",
                "Step 2 — For each affected server, follow the STARTTLS steps above.",
                "Step 3 — Test each server individually:",
                f"§  openssl s_client -connect <mx-hostname>:25 -starttls smtp",
                "Step 4 — If a server cannot be upgraded, consider removing it from your MX records.",
            ],
        },
        # ── Blacklist ─────────────────────────────────────────────────────────
        {
            "pattern": "blacklisted",
            "title":   "Mail Server IP on Spam Blacklist",
            "severity": "HIGH",
            "what": (
                "One or more of your mail server IPs appear on Real-time Blackhole Lists (RBLs) "
                "— databases of IPs known to send spam or malware. Gmail, Outlook, Yahoo, and "
                "all major mail gateways query these lists before accepting messages."
            ),
            "why": (
                "Being blacklisted causes legitimate emails to be rejected or silently dropped. "
                "Customer notifications, invoices, and business communications all fail to "
                "deliver. It also indicates your server may be compromised."
            ),
            "steps": [
                "Step 1 — Run a full blacklist check:",
                "§  https://mxtoolbox.com/blacklists.aspx",
                "§  https://multirbl.valli.org",
                "Step 2 — Diagnose the root cause BEFORE requesting delisting:",
                "         Check mail logs for unusual outbound volumes.",
                "         Check for compromised accounts or weak passwords.",
                "         Test for open relay:  https://mxtoolbox.com/diagnostic.aspx",
                "Step 3 — Request delisting from each blacklist:",
                "§  Spamhaus:   https://www.spamhaus.org/query/ip/YOUR-IP",
                "§  SpamCop:    https://www.spamcop.net/bl.shtml",
                "§  Barracuda:  https://www.barracudacentral.org/lookups",
                "Step 4 — If the IP is permanently tainted, provision a new IP from your host.",
                "Step 5 — Implement SPF, DKIM, and DMARC to prevent future listings.",
            ],
        },
        # ── TLS ───────────────────────────────────────────────────────────────
        {
            "pattern": "deprecated tls",
            "title":   "Deprecated TLS Version in Use (TLS 1.0 or 1.1)",
            "severity": "MEDIUM",
            "what": (
                "Your mail server accepts connections using TLS 1.0 or TLS 1.1. These were "
                "officially deprecated by RFC 8996 in 2021 and are disabled by default in all "
                "modern systems. They contain known cryptographic weaknesses."
            ),
            "why": (
                "TLS 1.0/1.1 are vulnerable to BEAST, POODLE, and related attacks. They use "
                "deprecated hash functions (MD5, SHA-1) and lack forward secrecy support. "
                "PCI-DSS v4.0 requires TLS 1.2 minimum — failing this causes compliance failures."
            ),
            "steps": [
                "§§ Postfix",
                "Add to /etc/postfix/main.cf:",
                "§  smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
                "§  smtp_tls_protocols  = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
                "§  sudo systemctl restart postfix",
                "",
                "§§ Exim",
                "Add to /etc/exim4/exim4.conf:",
                "§  tls_require_ciphers = SECURE256:-VERS-TLS1.0:-VERS-TLS1.1",
                "§  sudo service exim4 restart",
                "",
                "Test TLS 1.0 is rejected:",
                f"§  openssl s_client -connect mail.{d}:25 -starttls smtp -tls1",
                "         (Expected: handshake failure)",
                "Test TLS 1.2 is accepted:",
                f"§  openssl s_client -connect mail.{d}:25 -starttls smtp -tls1_2",
                "         (Expected: successful connection)",
            ],
        },
        {
            "pattern": "weak cipher",
            "title":   "Weak TLS Cipher Suites Detected",
            "severity": "MEDIUM",
            "what": (
                "Your mail server negotiates weak cipher suites including RC4, DES, 3DES, NULL, "
                "or EXPORT-grade ciphers. These provide inadequate encryption and are vulnerable "
                "to known attacks including SWEET32 and BEAST."
            ),
            "why": (
                "Weak ciphers allow adversaries to decrypt intercepted email. The SWEET32 "
                "attack against 3DES enables decryption after ~68GB of captured data. "
                "PCI-DSS, HIPAA, and GDPR all require strong encryption — weak ciphers "
                "create regulatory liability."
            ),
            "steps": [
                "§§ Postfix",
                "Add to /etc/postfix/main.cf:",
                "§  smtpd_tls_ciphers         = high",
                "§  smtpd_tls_exclude_ciphers = aNULL,eNULL,EXPORT,DES,RC4,MD5,PSK,SRP,3DES",
                "§  smtp_tls_ciphers          = high",
                "§  smtp_tls_exclude_ciphers  = aNULL,eNULL,EXPORT,DES,RC4,MD5,PSK,SRP,3DES",
                "§  sudo systemctl restart postfix",
                "",
                "Reference config (Mozilla recommended):",
                "§  https://ssl-config.mozilla.org/#server=postfix",
                "",
                "Test RC4 is rejected:",
                f"§  openssl s_client -connect mail.{d}:25 -starttls smtp -cipher RC4",
                "         (Expected: handshake failure)",
            ],
        },
        {
            "pattern": "banner exposes",
            "title":   "SMTP Banner Reveals Server Version",
            "severity": "LOW",
            "what": (
                "Your SMTP server's greeting banner includes the mail software name and version. "
                "This is visible to anyone who connects on port 25, including attackers."
            ),
            "why": (
                "Knowing your exact mail server version lets attackers instantly search for "
                "known CVEs for that version. CIS Benchmarks and security hardening guides "
                "recommend removing version strings from all service banners."
            ),
            "steps": [
                "§§ Postfix",
                "Edit /etc/postfix/main.cf:",
                "§  smtpd_banner = $myhostname ESMTP",
                "§  sudo systemctl restart postfix",
                "",
                "§§ Exim",
                "Edit /etc/exim4/exim4.conf:",
                "§  smtp_banner = $smtp_active_hostname ESMTP",
                "§  sudo service exim4 restart",
                "",
                "Verify banner no longer contains version info:",
                f"§  telnet mail.{d} 25",
                "         Response must NOT contain 'Postfix', 'Exim', or version numbers.",
            ],
        },
    ]


# ── Matcher ────────────────────────────────────────────────────────────────────
def _match(issues: list[str], domain: str) -> list[dict]:
    kb = _kb(domain)
    issues_lower = " | ".join(issues).lower()
    seen = set()
    out  = []
    for entry in kb:
        if entry["pattern"] in issues_lower and entry["title"] not in seen:
            out.append(entry)
            seen.add(entry["title"])
    return out


# ── Fingerprinting ─────────────────────────────────────────────────────────────
def _report_id(domain: str, ts: str) -> str:
    return "MG-" + hashlib.sha256(f"{domain}:{ts}:{uuid.uuid4()}".encode()).hexdigest()[:16].upper()


def _report_hash(scan: dict) -> str:
    return hashlib.sha256(
        (f"{scan.get('domain')}:{scan.get('score')}:" + ":".join(scan.get("issues", []))).encode()
    ).hexdigest()


# ── Step renderer ──────────────────────────────────────────────────────────────
def _render_steps(steps: list[str]) -> list:
    out = []
    for line in steps:
        if not line.strip():
            out.append(Spacer(1, 4))
        elif line.startswith("§§"):
            out.append(Paragraph(line[2:].strip(), ST_SUBHDR))
        elif line.startswith("§"):
            out.append(Paragraph(line[1:].strip(), ST_CODE))
        else:
            out.append(Paragraph(line.strip(), ST_STEP))
    return out


# ── Main PDF builder ───────────────────────────────────────────────────────────
def generate_remediation_report(scan_result: dict) -> bytes:
    buf         = BytesIO()
    ts          = datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M:%S  UTC")
    rid         = _report_id(scan_result.get("domain", ""), ts)
    rhash       = _report_hash(scan_result)
    domain      = scan_result.get("domain", "")
    grade       = scan_result.get("grade",  "F")
    score       = scan_result.get("score",  0)
    issue_count = scan_result.get("issue_count", 0)
    issues      = scan_result.get("issues", [])
    spoof_risk  = scan_result.get("spoofability", {}).get("risk", "UNKNOWN")
    W = CONTENT_W

    gc = GRD_CLR.get(grade, C_RED)
    sc = SEV_CLR.get(spoof_risk, C_MUTED)

    # ── Per-page footer ────────────────────────────────────────────────────────
    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(C_BORDER2)
        canvas.setLineWidth(0.4)
        canvas.line(MARGIN, 1.55 * cm, PAGE_W - MARGIN, 1.55 * cm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(MARGIN, 1.18 * cm,
                          f"MailGuard Remediation Report  ·  ID: {rid}  ·  {ts}")
        canvas.drawRightString(PAGE_W - MARGIN, 1.18 * cm,
                               f"SHA-256: {rhash[:20]}...   Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=1.6 * cm, bottomMargin=2.4 * cm,
    )

    story = []

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 1 — HEADER  (single flat Table, 4 columns, SPAN for branding rows)
    # Col widths:  key-left | val-left | key-right | val-right
    # ══════════════════════════════════════════════════════════════════════════
    CW = [W * 0.18, W * 0.33, W * 0.18, W * 0.31]   # 4 cols, total = W

    hdr_data = [
        # Row 0 — Brand title (spans cols 0-1) | Doc type (spans cols 2-3)
        [
            Paragraph("<font color='#38bdf8'><b>MailGuard</b></font>", ST_BRAND),
            "",
            Paragraph("REMEDIATION &amp; FIX GUIDE", ST_DOCTYPE),
            "",
        ],
        # Row 1 — Subtitle (spans 0-1) | Certified badge (spans 2-3)
        [
            Paragraph("Email Security Assessment", ST_SUBTITLE),
            "",
            Paragraph("&#9679;  CERTIFIED REPORT", ST_CERTIFIED),
            "",
        ],
        # Row 2 — thin separator spanning all 4 cols
        ["", "", "", ""],
        # Row 3 — metadata grid
        [
            Paragraph("DOMAIN",       ST_META_KEY),
            Paragraph(domain,         ST_META_VAL),
            Paragraph("REPORT ID",    ST_META_KEY),
            Paragraph(rid,            ST_META_VAL),
        ],
        [
            Paragraph("GRADE",        ST_META_KEY),
            Paragraph(
                f"<font color='{_hex(gc)}'><b>{grade}</b></font>"
                f"&nbsp;&nbsp;{score} / 100",
                ST_META_VAL),
            Paragraph("GENERATED",    ST_META_KEY),
            Paragraph(ts,             ST_META_VAL),
        ],
        [
            Paragraph("ISSUES",       ST_META_KEY),
            Paragraph(str(issue_count), ST_META_VAL),
            Paragraph("SHA-256",      ST_META_KEY),
            Paragraph(rhash[:32] + "...", ST_META_HASH),
        ],
        [
            Paragraph("SPOOFABILITY", ST_META_KEY),
            Paragraph(
                f"<font color='{_hex(sc)}'><b>{spoof_risk}</b></font>",
                ST_META_VAL),
            Paragraph("ISSUED BY",    ST_META_KEY),
            Paragraph("MailGuard v1.0", ST_META_VAL),
        ],
    ]

    hdr_cmds = [
        # Spans for branding rows
        ("SPAN",          (0, 0), (1, 0)),   # MailGuard brand
        ("SPAN",          (2, 0), (3, 0)),   # doc type
        ("SPAN",          (0, 1), (1, 1)),   # subtitle
        ("SPAN",          (2, 1), (3, 1)),   # certified
        ("SPAN",          (0, 2), (3, 2)),   # separator row
        # Background
        ("BACKGROUND",    (0, 0), (-1, 1),   C_CARD),   # branding rows
        ("BACKGROUND",    (0, 2), (-1, 2),   C_BORDER), # separator
        ("BACKGROUND",    (0, 3), (-1, -1),  C_CARD2),  # meta rows
        # Padding — branding rows
        ("TOPPADDING",    (0, 0), (-1, 0),   14),
        ("BOTTOMPADDING", (0, 0), (-1, 0),   10),
        ("TOPPADDING",    (0, 1), (-1, 1),   0),
        ("BOTTOMPADDING", (0, 1), (-1, 1),   14),
        ("LEFTPADDING",   (0, 0), (-1, 1),   14),
        ("RIGHTPADDING",  (0, 0), (-1, 1),   14),
        # Padding — separator
        ("TOPPADDING",    (0, 2), (-1, 2),   1),
        ("BOTTOMPADDING", (0, 2), (-1, 2),   1),
        # Padding — meta rows
        ("TOPPADDING",    (0, 3), (-1, -1),  5),
        ("BOTTOMPADDING", (0, 3), (-1, -1),  5),
        ("LEFTPADDING",   (0, 3), (-1, -1),  14),
        ("RIGHTPADDING",  (0, 3), (-1, -1),  8),
        # Vertical alignment
        ("VALIGN",        (0, 0), (-1, -1),  "MIDDLE"),
        # Vertical divider between left and right meta columns
        ("LINEAFTER",     (1, 3), (1, -1),   0.4, C_BORDER),
        # Bottom border of entire block
        ("LINEBELOW",     (0, -1), (-1, -1), 0.4, C_BORDER),
        # Grid for meta rows (very faint)
        ("LINEBELOW",     (0, 3), (-1, -2),  0.3, C_BORDER),
        ("FONTSIZE",      (0, 0), (-1, -1),  9),
    ]

    story.append(_tbl(hdr_data, CW, hdr_cmds))
    story.append(Spacer(1, 18))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 2 — ISSUES INVENTORY
    # ══════════════════════════════════════════════════════════════════════════
    if issues:
        story.append(Paragraph("Issues Discovered", ST_SEC_HDR))

        inv_hdr_st = _st(fontSize=8, fontName="Helvetica-Bold", textColor=C_WHITE)
        inv_data   = [[
            Paragraph("#",        _st(fontSize=8, fontName="Helvetica-Bold",
                                      textColor=C_WHITE, alignment=1)),
            Paragraph("Issue",    inv_hdr_st),
            Paragraph("Severity", _st(fontSize=8, fontName="Helvetica-Bold",
                                      textColor=C_WHITE, alignment=1)),
            Paragraph("Status",   _st(fontSize=8, fontName="Helvetica-Bold",
                                      textColor=C_WHITE, alignment=1)),
        ]]

        for i, iss in enumerate(issues, 1):
            sev = "MEDIUM"
            for entry in _kb(domain):
                if entry["pattern"] in iss.lower():
                    sev = entry["severity"]
                    break
            sc2 = SEV_CLR.get(sev, C_MUTED)
            inv_data.append([
                Paragraph(str(i),  _st(fontSize=8, textColor=C_MUTED, alignment=1)),
                Paragraph(iss,     ST_INV_ISS),
                Paragraph(sev,     _st(fontSize=8, fontName="Helvetica-Bold",
                                       textColor=sc2, alignment=1)),
                Paragraph("OPEN",  _st(fontSize=8, fontName="Helvetica-Bold",
                                       textColor=C_ORANGE, alignment=1)),
            ])

        story.append(_tbl(
            data=inv_data,
            widths=[W * 0.05, W * 0.65, W * 0.14, W * 0.16],
            cmds=[
                ("BACKGROUND",    (0, 0), (-1, 0),  C_BORDER),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_CARD, C_CARD2]),
                ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ],
        ))
        story.append(Spacer(1, 20))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 3 — REMEDIATION GUIDE
    # ══════════════════════════════════════════════════════════════════════════
    matched = _match(issues, domain)

    if matched:
        story.append(Paragraph("Remediation Guide", ST_SEC_HDR))
        story.append(Paragraph(
            "Each card explains the issue, why it is dangerous, and provides exact "
            "step-by-step fix instructions tailored to your domain. "
            "Address HIGH severity issues first.",
            ST_BODY
        ))
        story.append(Spacer(1, 12))

        for idx, entry in enumerate(matched, 1):
            sev   = entry["severity"]
            sev_c = SEV_CLR.get(sev, C_MUTED)

            # ── Card header ───────────────────────────────────────────────────
            card_hdr = _tbl(
                data=[[
                    Paragraph(f"{idx}.  {entry['title']}", ST_ISS_TITLE),
                    _sev_badge(sev),
                ]],
                widths=[W - 1.5 * cm - 10, 1.5 * cm],
                cmds=[
                    ("BACKGROUND",    (0, 0), (-1, -1), C_CARD),
                    ("LINEABOVE",     (0, 0), (-1, 0),  2.5, sev_c),
                    ("TOPPADDING",    (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                    ("LEFTPADDING",   (0, 0), (0, -1),  12),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                    ("LEFTPADDING",   (1, 0), (1, -1),  0),
                    ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN",         (1, 0), (1, 0),   "RIGHT"),
                ],
            )

            # ── Card body ─────────────────────────────────────────────────────
            body_rows = [
                [Paragraph("WHAT IS THIS?",  ST_LBL)],
                [Paragraph(entry["what"],    ST_BODY)],
                [Spacer(1, 4)],
                [Paragraph("WHY IT MATTERS", ST_LBL)],
                [Paragraph(entry["why"],     ST_BODY)],
                [Spacer(1, 4)],
                [Paragraph("HOW TO FIX IT",  ST_LBL)],
            ]
            for item in _render_steps(entry["steps"]):
                body_rows.append([item])
            body_rows.append([Spacer(1, 4)])

            card_body = _tbl(
                data=body_rows,
                widths=[W],
                cmds=[
                    ("BACKGROUND",    (0, 0), (-1, -1), C_BG),
                    ("BOX",           (0, 0), (-1, -1), 0.4, C_BORDER),
                    ("TOPPADDING",    (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 12),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
                    ("GRID",          (0, 0), (-1, -1), 0, C_BG),
                ],
            )

            story.append(KeepTogether([card_hdr, card_body]))
            story.append(Spacer(1, 14))

    else:
        story.append(Paragraph(
            "No remediable issues found. Domain email security is in good standing.",
            ST_BODY
        ))

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 4 — CERTIFICATION BLOCK
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 6))
    story.append(_tbl(
        data=[[
            Paragraph(
                f"<b>Certified by MailGuard v1.0</b><br/>"
                f"Report ID: {rid}<br/>"
                f"SHA-256 Fingerprint: {rhash}<br/>"
                f"Scan performed: {ts}  ·  Target domain: <b>{domain}</b><br/>"
                "This document is an authenticated record of email security assessment and may "
                "be presented to developers, security engineers, and auditors as evidence.",
                ST_CERT
            )
        ]],
        widths=[W],
        cmds=[
            ("BACKGROUND",    (0, 0), (-1, -1), C_CARD),
            ("BOX",           (0, 0), (-1, -1), 1.0, C_BLUE2),
            ("TOPPADDING",    (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ],
    ))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
