"""
Remediation engine — generates educational content and exact fix instructions
for every email security vulnerability found in a scan result.
"""
from datetime import datetime, timezone


# ── Severity levels ────────────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"


# ── Protocol education library ─────────────────────────────────────────────────
# Each entry covers: what_is_it, why_it_matters, rfc_reference, learn_more_url

PROTOCOL_LIBRARY = {
    "SPF": {
        "what_is_it": (
            "SPF (Sender Policy Framework) is a DNS-based email authentication protocol "
            "defined in RFC 7208. It works by publishing a list of authorised mail servers "
            "in a DNS TXT record at your domain root. When a receiving mail server gets an "
            "email claiming to be from your domain, it checks whether the sending server's "
            "IP address is in that list. If not, the email fails SPF."
        ),
        "why_it_matters": (
            "Without SPF, anyone on the internet can send email that appears to come from "
            "your domain. Attackers exploit this for phishing, business email compromise (BEC), "
            "and brand impersonation. A missing or weak SPF record is one of the top causes of "
            "domain spoofing attacks. Most major email providers (Gmail, Microsoft 365, Yahoo) "
            "use SPF as a primary spam signal."
        ),
        "rfc": "RFC 7208",
        "standard": "IETF",
    },
    "DMARC": {
        "what_is_it": (
            "DMARC (Domain-based Message Authentication, Reporting and Conformance) is an "
            "email authentication policy standard defined in RFC 7489. It builds on top of "
            "SPF and DKIM and tells receiving servers what to do when an email fails "
            "authentication — nothing (p=none), send to spam (p=quarantine), or reject it "
            "entirely (p=reject). It also enables aggregate reporting so you can see who is "
            "sending email using your domain."
        ),
        "why_it_matters": (
            "DMARC is the only protocol that gives you active control over what happens to "
            "spoofed mail. Without DMARC, even if SPF and DKIM are configured, receivers "
            "have no instruction on how to handle failures. DMARC at p=reject is the "
            "gold standard required by PCI-DSS v4.0 (req 6.4.1) and strongly recommended "
            "by CISA, NCSC, and the UK HMRC/NIST guidelines. It also provides visibility "
            "into phishing attempts via daily aggregate reports sent to your rua address."
        ),
        "rfc": "RFC 7489",
        "standard": "IETF / PCI-DSS v4.0",
    },
    "DKIM": {
        "what_is_it": (
            "DKIM (DomainKeys Identified Mail) is a cryptographic email signing standard "
            "defined in RFC 6376. Your mail server attaches a digital signature to every "
            "outgoing email using a private key. The corresponding public key is published "
            "in DNS. Receiving servers verify the signature — confirming both that the email "
            "came from your authorised server and that its content was not altered in transit."
        ),
        "why_it_matters": (
            "DKIM prevents email tampering and is required for DMARC to function effectively "
            "at p=reject. Without DKIM, forwarded emails often fail SPF (because the "
            "forwarding server's IP is not in your SPF record) and have no fallback "
            "authentication. A DKIM key below 1024 bits is considered cryptographically weak "
            "and can be factored — 2048-bit RSA keys are the current industry standard."
        ),
        "rfc": "RFC 6376",
        "standard": "IETF",
    },
    "MTA-STS": {
        "what_is_it": (
            "MTA-STS (Mail Transfer Agent Strict Transport Security) is defined in RFC 8461. "
            "It allows domains to declare that their mail servers support TLS and that sending "
            "MTAs should refuse to deliver mail if TLS cannot be established. This is done "
            "by publishing a policy file at a well-known HTTPS URL and a DNS TXT record "
            "pointing to it."
        ),
        "why_it_matters": (
            "Without MTA-STS, an attacker on the network path between two mail servers can "
            "perform a TLS downgrade attack — stripping encryption so email travels in "
            "plaintext. MTA-STS prevents this by making TLS enforcement mandatory. It is "
            "strongly recommended by NCSC and NIST as part of a layered email security "
            "posture. Paired with TLSRPT (RFC 8460) it also provides delivery failure reports."
        ),
        "rfc": "RFC 8461",
        "standard": "IETF / NCSC",
    },
    "STARTTLS": {
        "what_is_it": (
            "STARTTLS is an SMTP command that upgrades a plain-text email connection to an "
            "encrypted TLS connection. When a sending mail server connects to your MX server "
            "on port 25, it issues the STARTTLS command to negotiate encryption before "
            "transmitting the email content."
        ),
        "why_it_matters": (
            "Without STARTTLS, all inbound email to your mail server travels across the "
            "internet in plain text. Any network-level attacker or malicious ISP can read, "
            "copy, or modify email in transit. Most major providers have supported STARTTLS "
            "since 2014. Enabling it is one of the simplest and highest-impact security "
            "improvements for a mail server."
        ),
        "rfc": "RFC 3207",
        "standard": "IETF",
    },
    "BLACKLIST": {
        "what_is_it": (
            "Email blacklists (also called DNS-based Blackhole Lists or DNSBLs) are "
            "real-time databases that track IP addresses known to send spam, malware, or "
            "phishing emails. When a receiving mail server gets an incoming connection it "
            "queries these lists to decide whether to accept, reject, or tag the email. "
            "Major lists include Spamhaus ZEN, SpamCop, SORBS, and Barracuda Central."
        ),
        "why_it_matters": (
            "If your mail server's IP is listed on a blacklist, emails you send will be "
            "rejected or sent to spam by recipient mail servers. This directly breaks "
            "business email delivery. Listings typically result from a compromised account "
            "or server being used to send spam, or from a shared hosting IP with a bad "
            "reputation history."
        ),
        "rfc": "RFC 5782",
        "standard": "IETF",
    },
}


# ── Fix generators ─────────────────────────────────────────────────────────────

def _spf_fix(domain: str, issue: str) -> dict:
    ts = int(datetime.now(timezone.utc).timestamp())
    if "No SPF" in issue:
        return {
            "id": "spf_missing",
            "protocol": "SPF",
            "severity": CRITICAL,
            "title": "No SPF Record Found",
            "current_status": f"No SPF TXT record exists at {domain}. Any server on the internet can send email claiming to be from your domain.",
            **{k: PROTOCOL_LIBRARY["SPF"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                f"Log in to your DNS provider (e.g. Cloudflare, GoDaddy, Route53).",
                f"Navigate to the DNS records for {domain}.",
                "Add a new TXT record with the values below.",
                "If you use Google Workspace, use the 'google' example. For Microsoft 365 use 'microsoft'. For custom servers, replace the include: value with your provider's SPF hostname.",
                "Wait 30–60 minutes for DNS propagation, then re-scan to verify.",
            ],
            "dns_records": [
                {"type": "TXT", "name": "@", "ttl": "3600",
                 "value": f"v=spf1 -all",
                 "label": "Minimal safe SPF (no authorised senders — change before use)"},
                {"type": "TXT", "name": "@", "ttl": "3600",
                 "value": f"v=spf1 include:_spf.google.com -all",
                 "label": "Google Workspace / Gmail"},
                {"type": "TXT", "name": "@", "ttl": "3600",
                 "value": f"v=spf1 include:spf.protection.outlook.com -all",
                 "label": "Microsoft 365 / Exchange Online"},
                {"type": "TXT", "name": "@", "ttl": "3600",
                 "value": f"v=spf1 include:sendgrid.net -all",
                 "label": "SendGrid"},
            ],
            "estimated_effort": "15 minutes",
            "estimated_impact": "Eliminates domain spoofing via SPF; required for effective DMARC enforcement.",
        }
    elif "softfail" in issue or "~all" in issue:
        return {
            "id": "spf_softfail",
            "protocol": "SPF",
            "severity": HIGH,
            "title": "SPF Uses ~all (Softfail) — Not Fully Enforced",
            "current_status": f"Your SPF record uses ~all which marks unauthorised senders as suspicious but does not reject them. Spoofed emails may still be delivered.",
            **{k: PROTOCOL_LIBRARY["SPF"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                f"Find your existing SPF TXT record at {domain}.",
                "Change the trailing ~all to -all.",
                "Ensure all legitimate sending services are listed before making this change (missing a sender will cause delivery failures).",
                "Save the record and wait for DNS propagation.",
            ],
            "dns_records": [
                {"type": "TXT", "name": "@", "ttl": "3600",
                 "value": "v=spf1 <your-existing-includes> -all",
                 "label": "Change ~all to -all (keep your existing include: mechanisms)"},
            ],
            "estimated_effort": "5 minutes",
            "estimated_impact": "Upgrades from advisory-only to full rejection of unauthorised senders.",
        }
    elif "+all" in issue or "pass_all" in issue:
        return {
            "id": "spf_passall",
            "protocol": "SPF",
            "severity": CRITICAL,
            "title": "SPF Uses +all — Any Server Can Send As Your Domain",
            "current_status": "Your SPF record ends with +all which explicitly authorises every server in the world to send email as your domain. This is equivalent to having no SPF at all.",
            **{k: PROTOCOL_LIBRARY["SPF"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                f"Immediately update your SPF record at {domain}.",
                "List only your authorised sending services using include: or ip4: mechanisms.",
                "Replace +all with -all.",
            ],
            "dns_records": [
                {"type": "TXT", "name": "@", "ttl": "3600",
                 "value": "v=spf1 include:<your-provider> -all",
                 "label": "Replace +all with your providers and -all"},
            ],
            "estimated_effort": "15 minutes",
            "estimated_impact": "Critical — current configuration provides zero protection against spoofing.",
        }
    elif "lookup limit" in issue:
        return {
            "id": "spf_lookup_limit",
            "protocol": "SPF",
            "severity": MEDIUM,
            "title": "SPF Exceeds 10 DNS Lookup Limit",
            "current_status": "Your SPF record causes more than 10 DNS lookups during evaluation. This causes a PermError — receiving servers will treat SPF as failing entirely.",
            **{k: PROTOCOL_LIBRARY["SPF"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                "Audit your include: mechanisms and remove any that are unused.",
                "Replace multiple include: entries with direct ip4:/ip6: addresses where possible.",
                "Consider using an SPF flattening service to stay within 10 lookups.",
            ],
            "dns_records": [],
            "estimated_effort": "30–60 minutes",
            "estimated_impact": "Restores SPF validity. PermError causes SPF to fail which undermines DMARC.",
        }
    return None


def _dmarc_fix(domain: str, issue: str) -> dict:
    if "No DMARC" in issue:
        return {
            "id": "dmarc_missing",
            "protocol": "DMARC",
            "severity": CRITICAL,
            "title": "No DMARC Record Found",
            "current_status": f"No DMARC policy exists at _dmarc.{domain}. Receiving mail servers have no instruction on what to do with emails that fail SPF/DKIM checks.",
            **{k: PROTOCOL_LIBRARY["DMARC"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                f"Add a TXT record at _dmarc.{domain} (note the underscore prefix).",
                "Start with p=none to monitor without rejecting — collect reports for 2–4 weeks.",
                f"Set rua=mailto:dmarc-reports@{domain} to receive aggregate reports (or use a DMARC reporting service like Postmark, dmarcian, or Valimail).",
                "Once you have confirmed all legitimate senders pass SPF and DKIM, escalate to p=quarantine then p=reject.",
            ],
            "dns_records": [
                {"type": "TXT", "name": f"_dmarc", "ttl": "3600",
                 "value": f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; pct=100",
                 "label": "Step 1 — Monitor only (safe starting point, no emails rejected)"},
                {"type": "TXT", "name": f"_dmarc", "ttl": "3600",
                 "value": f"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}; pct=100",
                 "label": "Step 2 — Quarantine (send suspicious emails to spam)"},
                {"type": "TXT", "name": f"_dmarc", "ttl": "3600",
                 "value": f"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}; pct=100",
                 "label": "Step 3 — Reject (gold standard, required by PCI-DSS v4.0)"},
            ],
            "estimated_effort": "15 minutes (immediate) + 4 weeks to reach p=reject safely",
            "estimated_impact": "Eliminates domain spoofing. Required for PCI-DSS v4.0, NCSC Cyber Essentials, and CISA guidelines.",
        }
    elif "p=none" in issue or "monitoring only" in issue.lower():
        return {
            "id": "dmarc_none",
            "protocol": "DMARC",
            "severity": HIGH,
            "title": "DMARC Policy is p=none — Monitoring Only, Not Enforced",
            "current_status": f"DMARC exists at _dmarc.{domain} but is set to p=none. Spoofed emails are being reported but still delivered to recipients.",
            **{k: PROTOCOL_LIBRARY["DMARC"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                "Review your DMARC aggregate reports to confirm all legitimate mail sources are covered.",
                "Ensure SPF and DKIM are properly configured for all sending services.",
                "Escalate to p=quarantine, monitor for 2 weeks, then move to p=reject.",
            ],
            "dns_records": [
                {"type": "TXT", "name": "_dmarc", "ttl": "3600",
                 "value": f"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}; pct=100",
                 "label": "Upgrade to p=quarantine"},
                {"type": "TXT", "name": "_dmarc", "ttl": "3600",
                 "value": f"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}; pct=100",
                 "label": "Final target: p=reject"},
            ],
            "estimated_effort": "5 minutes + 2 weeks monitoring",
            "estimated_impact": "Active enforcement — spoofed emails are rejected rather than monitored.",
        }
    elif "no reporting" in issue.lower() or "rua" in issue.lower():
        return {
            "id": "dmarc_no_reporting",
            "protocol": "DMARC",
            "severity": LOW,
            "title": "DMARC Has No Aggregate Reporting (rua) Configured",
            "current_status": "DMARC is enforced but rua (reporting URI) is missing. You have no visibility into who is sending email using your domain.",
            **{k: PROTOCOL_LIBRARY["DMARC"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                "Add rua=mailto:dmarc-reports@your-domain to your DMARC record.",
                "Alternatively, use a DMARC reporting service (Postmark, dmarcian, Valimail, Google Postmaster).",
            ],
            "dns_records": [
                {"type": "TXT", "name": "_dmarc", "ttl": "3600",
                 "value": f"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}; pct=100",
                 "label": "Add rua reporting address"},
            ],
            "estimated_effort": "5 minutes",
            "estimated_impact": "Adds reporting visibility — you will receive daily aggregate reports.",
        }
    return None


def _dkim_fix(domain: str, issue: str) -> dict:
    if "No DKIM" in issue:
        return {
            "id": "dkim_missing",
            "protocol": "DKIM",
            "severity": HIGH,
            "title": "No DKIM Record Found",
            "current_status": f"No DKIM public key records were found after probing 36 common selectors on {domain}. Outbound emails cannot be cryptographically verified.",
            **{k: PROTOCOL_LIBRARY["DKIM"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                "Enable DKIM signing in your email service provider (instructions vary by provider — see examples below).",
                "Your provider will generate a public/private key pair and give you a DNS record to add.",
                "Add the TXT record at the selector shown (e.g. google._domainkey, selector1._domainkey).",
                "Verify DKIM is working by sending a test email and checking headers, or by re-scanning.",
            ],
            "dns_records": [
                {"type": "TXT", "name": f"google._domainkey.{domain}", "ttl": "3600",
                 "value": "v=DKIM1; k=rsa; p=<your-public-key-from-google-admin>",
                 "label": "Google Workspace — get key from Admin Console → Apps → Gmail → Authenticate email"},
                {"type": "TXT", "name": f"selector1._domainkey.{domain}", "ttl": "3600",
                 "value": "v=DKIM1; k=rsa; p=<your-public-key-from-m365>",
                 "label": "Microsoft 365 — get key from Exchange Admin → Mail flow → DKIM"},
                {"type": "TXT", "name": f"s1._domainkey.{domain}", "ttl": "3600",
                 "value": "v=DKIM1; k=rsa; p=<your-public-key-from-sendgrid>",
                 "label": "SendGrid — get key from Settings → Sender Authentication"},
            ],
            "estimated_effort": "15–30 minutes",
            "estimated_impact": "Enables cryptographic email authentication; required for DMARC p=reject to work reliably for forwarded mail.",
        }
    elif "weak" in issue.lower() or "1024" in issue or "512" in issue:
        return {
            "id": "dkim_weak_key",
            "protocol": "DKIM",
            "severity": MEDIUM,
            "title": "DKIM Key Strength Below Recommended 2048 Bits",
            "current_status": "A DKIM key smaller than 2048 bits is considered cryptographically weak. RSA keys below 1024 bits can be factored by modern hardware. 2048-bit is the current industry minimum.",
            **{k: PROTOCOL_LIBRARY["DKIM"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                "Generate a new 2048-bit RSA key pair via your mail provider or with: openssl genrsa -out dkim_private.pem 2048",
                "Publish the new public key under a new selector name (e.g. add '2024' prefix).",
                "Update your mail server to sign with the new private key.",
                "After confirming new key works, remove the old weak key from DNS.",
            ],
            "dns_records": [
                {"type": "TXT", "name": f"mail2024._domainkey.{domain}", "ttl": "3600",
                 "value": "v=DKIM1; k=rsa; p=<your-new-2048-bit-public-key>",
                 "label": "New 2048-bit DKIM key (use a new selector name)"},
            ],
            "estimated_effort": "30–60 minutes",
            "estimated_impact": "Eliminates cryptographic vulnerability; meets NIST SP 800-131A key strength requirements.",
        }
    return None


def _mta_sts_fix(domain: str, issue: str) -> dict:
    if "MTA-STS" in issue:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return {
            "id": "mta_sts_missing",
            "protocol": "MTA-STS",
            "severity": MEDIUM,
            "title": "No MTA-STS Policy Configured",
            "current_status": f"No MTA-STS DNS record or policy file found for {domain}. Sending mail servers can be tricked into delivering mail without TLS encryption (downgrade attack).",
            **{k: PROTOCOL_LIBRARY["MTA-STS"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                f"Step 1: Add a DNS TXT record at _mta-sts.{domain} with the value below.",
                f"Step 2: Set up a web server at mta-sts.{domain} (HTTPS required) to serve the policy file.",
                f"Step 3: Publish the policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt with the content below.",
                "Step 4: Optionally add TLSRPT reporting (RFC 8460) by adding a TXT record at _smtp._tls.<domain>.",
            ],
            "dns_records": [
                {"type": "TXT", "name": f"_mta-sts.{domain}", "ttl": "3600",
                 "value": f"v=STSv1; id={ts}",
                 "label": "Step 1 — DNS record (update id= each time policy changes)"},
                {"type": "TXT", "name": f"_smtp._tls.{domain}", "ttl": "3600",
                 "value": f"v=TLSRPTv1; rua=mailto:tls-reports@{domain}",
                 "label": "Optional — TLSRPT reporting (RFC 8460)"},
            ],
            "policy_file": {
                "url": f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                "content": f"version: STSv1\nmode: enforce\nmx: mail.{domain}\nmax_age: 604800",
                "note": "Replace mail.{domain} with your actual MX hostname(s). Use mode: testing first to avoid delivery disruptions.",
            },
            "estimated_effort": "1–2 hours (requires HTTPS web server setup)",
            "estimated_impact": "Prevents TLS downgrade attacks on inbound mail delivery.",
        }
    return None


def _starttls_fix(domain: str, issue: str) -> dict:
    if "STARTTLS" in issue:
        return {
            "id": "starttls_missing",
            "protocol": "STARTTLS",
            "severity": HIGH,
            "title": "MX Servers Do Not Support STARTTLS",
            "current_status": f"None of the MX servers for {domain} support STARTTLS. All inbound email arrives unencrypted, exposing its content to interception.",
            **{k: PROTOCOL_LIBRARY["STARTTLS"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                "Enable TLS in your mail server configuration. Instructions vary by mail server software:",
                "Postfix: Add 'smtpd_tls_cert_file', 'smtpd_tls_key_file', and 'smtpd_use_tls=yes' to main.cf",
                "Exim: Set 'tls_advertise_hosts = *' in exim.conf",
                "Microsoft Exchange: Enable Receive Connector TLS in the Exchange Admin Center",
                "Obtain an SSL/TLS certificate from a trusted CA (Let's Encrypt is free)",
                "Restart your mail service and re-scan to verify STARTTLS is active",
            ],
            "dns_records": [],
            "config_examples": {
                "postfix": (
                    "# Add to /etc/postfix/main.cf\n"
                    "smtpd_tls_cert_file = /etc/ssl/certs/mail.crt\n"
                    "smtpd_tls_key_file = /etc/ssl/private/mail.key\n"
                    "smtpd_use_tls = yes\n"
                    "smtpd_tls_security_level = may\n"
                    "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
                ),
                "exim": (
                    "# Add to /etc/exim4/exim4.conf.template\n"
                    "tls_advertise_hosts = *\n"
                    "tls_certificate = /etc/ssl/certs/mail.crt\n"
                    "tls_privatekey = /etc/ssl/private/mail.key"
                ),
            },
            "estimated_effort": "1–3 hours (requires server access and SSL certificate)",
            "estimated_impact": "Encrypts all inbound email in transit — eliminates passive interception risk.",
        }
    return None


def _blacklist_fix(domain: str, issue: str) -> dict:
    if "blacklisted" in issue.lower() or "blacklist" in issue.lower():
        ip = ""
        if "IP " in issue:
            parts = issue.split("IP ")
            if len(parts) > 1:
                ip = parts[1].split(" ")[0]
        return {
            "id": "blacklist_listed",
            "protocol": "BLACKLIST",
            "severity": CRITICAL,
            "title": f"Mail Server IP {ip} Is Listed on a Blacklist".strip(),
            "current_status": issue,
            **{k: PROTOCOL_LIBRARY["BLACKLIST"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                "Step 1: Identify and stop the source of spam — check for compromised email accounts, malware, or misconfigured mail relay.",
                "Step 2: Change any compromised passwords and patch vulnerabilities.",
                "Step 3: Submit delisting requests directly to each blacklist that has listed your IP.",
                "Step 4: After delisting, implement SPF, DMARC, and DKIM to prevent re-listing.",
                "Step 5: Consider a dedicated sending IP with a clean reputation if on shared hosting.",
            ],
            "dns_records": [],
            "delisting_urls": [
                {"name": "Spamhaus ZEN", "url": "https://www.spamhaus.org/lookup/"},
                {"name": "SpamCop", "url": "https://www.spamcop.net/bl.shtml"},
                {"name": "SORBS", "url": "http://www.sorbs.net/lookup.shtml"},
                {"name": "Barracuda Central", "url": "https://www.barracudacentral.org/rbl/removal-request"},
                {"name": "UCEPROTECT", "url": "https://www.uceprotect.net/en/rblcheck.php"},
            ],
            "estimated_effort": "24–72 hours (blacklist removal can take time)",
            "estimated_impact": "Restores email deliverability. Emails to major providers will stop being rejected.",
        }
    return None


def _deprecated_tls_fix(domain: str, issue: str) -> dict:
    if "deprecated" in issue.lower() or "TLS 1.0" in issue or "TLS 1.1" in issue:
        return {
            "id": "deprecated_tls",
            "protocol": "STARTTLS",
            "severity": MEDIUM,
            "title": "Mail Server Uses Deprecated TLS Version (TLS 1.0 or 1.1)",
            "current_status": "Your mail server supports TLS 1.0 or 1.1 which are deprecated and contain known vulnerabilities (POODLE, BEAST, SWEET32). PCI-DSS v4.0 requires disabling these.",
            **{k: PROTOCOL_LIBRARY["STARTTLS"][k] for k in ("what_is_it", "why_it_matters", "rfc", "standard")},
            "fix_steps": [
                "Disable TLS 1.0 and TLS 1.1 in your mail server configuration.",
                "Require TLS 1.2 as minimum (TLS 1.3 preferred).",
                "Test before rolling out to avoid breaking legacy clients.",
            ],
            "dns_records": [],
            "config_examples": {
                "postfix": "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1",
                "exim": "tls_require_ciphers = NORMAL:%VERS-TLS1.2",
            },
            "estimated_effort": "30 minutes",
            "estimated_impact": "Eliminates known TLS vulnerabilities; required for PCI-DSS v4.0 compliance.",
        }
    return None


# ── Issue → Fix Router ─────────────────────────────────────────────────────────

_FIX_HANDLERS = [
    ("SPF",      _spf_fix),
    ("DMARC",    _dmarc_fix),
    ("DKIM",     _dkim_fix),
    ("MTA-STS",  _mta_sts_fix),
    ("STARTTLS", _starttls_fix),
    ("blacklist", _blacklist_fix),
    ("blacklisted", _blacklist_fix),
    ("deprecated", _deprecated_tls_fix),
    ("TLS 1.0", _deprecated_tls_fix),
    ("TLS 1.1", _deprecated_tls_fix),
]

_SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}


def generate_education(scan_result: dict) -> dict:
    """
    Takes a scan result dict and returns a full educational remediation plan.
    """
    domain = scan_result.get("domain", "")
    issues = scan_result.get("issues", [])

    vulnerabilities = []
    seen_ids = set()

    for issue in issues:
        for keyword, handler in _FIX_HANDLERS:
            if keyword.lower() in issue.lower():
                try:
                    fix = handler(domain, issue)
                except Exception:
                    fix = None
                if fix and fix["id"] not in seen_ids:
                    seen_ids.add(fix["id"])
                    vulnerabilities.append(fix)
                break

    # Sort by severity
    vulnerabilities.sort(key=lambda v: _SEVERITY_ORDER.get(v["severity"], 99))

    critical_count = sum(1 for v in vulnerabilities if v["severity"] == CRITICAL)
    high_count = sum(1 for v in vulnerabilities if v["severity"] == HIGH)
    medium_count = sum(1 for v in vulnerabilities if v["severity"] == MEDIUM)

    spoofability = scan_result.get("spoofability", {})
    risk = spoofability.get("risk", "UNKNOWN")

    if critical_count > 0 or risk == "HIGH":
        overall_risk = "CRITICAL — Immediate action required"
        risk_detail = "This domain can be freely impersonated for phishing and business email compromise attacks."
    elif high_count > 0 or risk == "MEDIUM":
        overall_risk = "HIGH — Significant vulnerabilities present"
        risk_detail = "Partial protections exist but the domain remains spoofable under certain conditions."
    elif medium_count > 0:
        overall_risk = "MEDIUM — Security posture needs improvement"
        risk_detail = "Basic protections are in place but additional hardening is recommended."
    else:
        overall_risk = "LOW — Good security posture"
        risk_detail = "Email security controls are well configured. Continue monitoring."

    return {
        "domain": domain,
        "scan_grade": scan_result.get("grade", "F"),
        "scan_score": scan_result.get("score", 0),
        "overall_risk": overall_risk,
        "risk_detail": risk_detail,
        "vulnerability_count": len(vulnerabilities),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": sum(1 for v in vulnerabilities if v["severity"] == LOW),
        "spoofability_risk": risk,
        "can_be_spoofed": spoofability.get("can_spoof_from_header", False),
        "recommended_priority": [v["title"] for v in vulnerabilities if v["severity"] in (CRITICAL, HIGH)][:3],
        "vulnerabilities": vulnerabilities,
        "scan_result": scan_result,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": (
            "This report is generated automatically by MailGuard based on publicly available DNS "
            "and SMTP data. It is provided for informational and educational purposes only. "
            "MailGuard makes no warranty as to the completeness or accuracy of this report. "
            "Configuration changes should be tested in a staging environment before production "
            "deployment. MailGuard is not responsible for email delivery issues arising from "
            "DNS changes made based on this report."
        ),
    }
