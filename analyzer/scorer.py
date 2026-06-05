"""Main email security analyzer — orchestrates all 11 modules."""
import asyncio
import time
import httpx
from .spf import check_spf
from .dkim import check_dkim
from .dmarc import check_dmarc
from .mx_records import check_mx_records
from .bimi import check_bimi
from .mta_sts import check_mta_sts
from .blacklist import check_blacklist
from .dane_tlsa import check_dane
from .mail_tls import check_mail_tls
from .spoofability import assess_spoofability


def _grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


def _score_and_issues(spf, dkim, dmarc, mta_sts, mx, blacklist, mail_tls, spoof) -> tuple[int, list[str]]:
    score = 100
    issues = []

    # ── SPF ──────────────────────────────────────────────────────────────────
    if not spf["found"]:
        score -= 20
        issues.append("No SPF record — domain can be freely spoofed")
    elif spf["pass_all"]:
        score -= 25
        issues.append("SPF uses +all — any server can send as this domain")
    elif spf["neutral_all"]:
        score -= 10
        issues.append("SPF uses ?all (neutral) — provides no protection")
    elif spf["softfail_all"]:
        score -= 5
        issues.append("SPF uses ~all (softfail) — upgrade to -all for full enforcement")
    if spf["exceeds_lookup_limit"]:
        score -= 10
        issues.append(f"SPF exceeds 10 DNS lookup limit ({spf['dns_lookup_count']} lookups) — may cause PermError")
    if spf["syntax_error"]:
        score -= 5
        issues.append(f"SPF syntax error: {spf['syntax_error']}")

    # ── DMARC ─────────────────────────────────────────────────────────────────
    if not dmarc["found"]:
        score -= 25
        issues.append("No DMARC record — email authentication not enforced")
    else:
        if dmarc["policy"] == "none":
            score -= 15
            issues.append("DMARC policy is p=none — monitoring only, spoofed messages are delivered")
        elif dmarc["policy"] == "quarantine":
            score -= 5
            issues.append("DMARC policy is p=quarantine — upgrade to p=reject for full protection")
        pct = dmarc.get("pct") or 100
        if pct < 100:
            score -= 5
            issues.append(f"DMARC pct={pct} — policy only applies to {pct}% of messages")
        if not dmarc["has_reporting"]:
            score -= 3
            issues.append("DMARC has no rua reporting address — you won't receive DMARC feedback")

    # ── DKIM ──────────────────────────────────────────────────────────────────
    if not dkim["found"]:
        score -= 15
        issues.append(f"No DKIM record found after probing {dkim['selectors_probed']} selectors")
    elif dkim["has_weak_key"]:
        score -= 10
        issues.append(f"DKIM key is {dkim['weakest_key_bits']} bits — minimum is 1024 bits")
    elif dkim["has_short_key"]:
        score -= 3
        issues.append(f"DKIM key is {dkim['weakest_key_bits']} bits — upgrade to 2048 bits recommended")

    # ── MTA-STS ───────────────────────────────────────────────────────────────
    if not mta_sts["dns_record_found"] and not mta_sts["policy_fetched"]:
        score -= 5
        issues.append("No MTA-STS configured — outbound TLS not enforced for incoming mail")
    elif not mta_sts["policy_fetched"]:
        score -= 3
        issues.append(f"MTA-STS policy file unreachable: {mta_sts.get('fetch_error', 'unknown error')}")
    elif mta_sts["policy_mode"] == "testing":
        score -= 2
        issues.append("MTA-STS is in testing mode — not yet enforcing TLS")

    # ── MX / STARTTLS ─────────────────────────────────────────────────────────
    if not mx["found"]:
        score -= 15
        issues.append("No MX records found — domain cannot receive email")
    elif not mx["any_support_starttls"]:
        score -= 15
        issues.append("No MX servers support STARTTLS — all inbound mail is unencrypted")
    elif not mx["all_support_starttls"]:
        score -= 7
        issues.append(f"Only {mx['starttls_count']}/{mx['total_mx_count']} MX servers support STARTTLS")
    for srv in mx.get("records", []):
        if srv.get("banner_exposes_version"):
            score -= 2
            issues.append(f"MX server {srv['hostname']} banner exposes software version")
            break  # report once

    # ── Blacklist ─────────────────────────────────────────────────────────────
    if not blacklist["clean"]:
        deduction = min(blacklist["listed_count"] * 20, 40)
        score -= deduction
        listed_ips = {e["ip"] for e in blacklist["listings"] if e["listed"]}
        for ip in listed_ips:
            rbls = [e["rbl"] for e in blacklist["listings"] if e["ip"] == ip and e["listed"]]
            issues.append(f"Mail server IP {ip} is blacklisted on {', '.join(rbls)}")

    # ── Mail TLS ──────────────────────────────────────────────────────────────
    if mail_tls["any_deprecated_tls"]:
        score -= 5
        issues.append("Mail server uses deprecated TLS 1.0 or 1.1 for SMTP")
    if mail_tls["any_weak_cipher"]:
        score -= 5
        issues.append("Mail server negotiates a weak cipher on SMTP STARTTLS")

    # ── Spoofability bonus deduction ──────────────────────────────────────────
    if spoof["risk"] == "HIGH":
        score -= 10
    elif spoof["risk"] == "MEDIUM":
        score -= 5

    return max(0, score), issues


def _recommendations(issues: list[str]) -> list[str]:
    recs = []
    i = " ".join(issues).lower()
    if "no spf" in i:
        recs.append('Add an SPF record: v=spf1 include:_spf.yourmailprovider.com -all')
    elif "+all" in i or "softfail" in i or "neutral" in i:
        recs.append("Update SPF to use -all (hardfail) to reject unauthorized senders")
    if "lookup limit" in i:
        recs.append("Reduce SPF DNS lookups below 10 — flatten includes using tools like dmarcian or mxtoolbox")
    if "no dmarc" in i:
        recs.append('Add a DMARC record: _dmarc.yourdomain.com TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@yourdomain.com"')
    elif "p=none" in i:
        recs.append("Upgrade DMARC from p=none to p=quarantine, then p=reject once you verify legitimate senders pass")
    elif "p=quarantine" in i:
        recs.append("Upgrade DMARC from p=quarantine to p=reject for full enforcement")
    if "pct=" in i:
        recs.append("Set DMARC pct=100 to apply policy to all messages")
    if "no rua" in i or "rua reporting" in i:
        recs.append("Add rua=mailto:dmarc@yourdomain.com to DMARC to receive aggregate reports")
    if "no dkim" in i:
        recs.append("Configure DKIM signing on your mail server and publish a 2048-bit RSA public key in DNS")
    elif "weak" in i and "dkim" in i:
        recs.append("Rotate DKIM keys to at least 2048-bit RSA or use Ed25519")
    if "mta-sts" in i:
        recs.append('Enable MTA-STS: add _mta-sts TXT record and host policy file at https://mta-sts.yourdomain.com/.well-known/mta-sts.txt')
    if "starttls" in i:
        recs.append("Enable STARTTLS on all MX servers to encrypt inbound mail in transit")
    if "blacklist" in i or "blacklisted" in i:
        recs.append("Request delisting from spam blacklists at spamhaus.org/lookup, spamcop.net and check for compromised accounts sending spam")
    if "banner" in i:
        recs.append("Configure your SMTP server to hide software version from its banner greeting")
    if "deprecated tls" in i:
        recs.append("Disable TLS 1.0 and 1.1 on your mail server — require TLS 1.2 minimum")
    if "weak cipher" in i:
        recs.append("Update mail server TLS cipher configuration to disable RC4, 3DES and other weak ciphers")
    return list(dict.fromkeys(recs))  # deduplicate while preserving order


async def analyze_email(domain: str, http_client: httpx.AsyncClient, timeout: float = 20.0) -> dict:
    start = time.monotonic()
    loop = asyncio.get_running_loop()

    # Phase 1 — parallel DNS lookups (all blocking → executor)
    spf_f   = loop.run_in_executor(None, check_spf, domain, timeout)
    dkim_f  = loop.run_in_executor(None, check_dkim, domain, timeout)
    dmarc_f = loop.run_in_executor(None, check_dmarc, domain, timeout)
    mx_f    = loop.run_in_executor(None, check_mx_records, domain, timeout)
    bimi_f  = loop.run_in_executor(None, check_bimi, domain, timeout)

    spf, dkim, dmarc, mx, bimi = await asyncio.gather(spf_f, dkim_f, dmarc_f, mx_f, bimi_f)

    # Phase 2 — depends on mx being resolved; run remaining in parallel
    mta_sts_f  = check_mta_sts(domain, http_client, timeout)
    bl_f       = loop.run_in_executor(None, check_blacklist, mx, timeout)
    dane_f     = loop.run_in_executor(None, check_dane, mx, timeout)
    mail_tls_f = loop.run_in_executor(None, check_mail_tls, mx, timeout)

    mta_sts, blacklist, dane, mail_tls = await asyncio.gather(mta_sts_f, bl_f, dane_f, mail_tls_f)

    # Phase 3 — pure logic
    spoof = assess_spoofability(spf, dkim, dmarc)

    score, issues = _score_and_issues(spf, dkim, dmarc, mta_sts, mx, blacklist, mail_tls, spoof)
    recommendations = _recommendations(issues)
    duration_ms = int((time.monotonic() - start) * 1000)

    return {
        "domain": domain,
        "score": score,
        "grade": _grade(score),
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "mta_sts": mta_sts,
        "bimi": bimi,
        "mx": mx,
        "blacklist": blacklist,
        "dane": dane,
        "spoofability": spoof,
        "mail_tls": mail_tls,
        "issues": issues,
        "issue_count": len(issues),
        "recommendations": recommendations,
        "scan_duration_ms": duration_ms,
    }
