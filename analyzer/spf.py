"""SPF record analyzer."""
import re
import dns.resolver
import dns.exception
from config import settings

_DNS_CONSUMING = {"include", "a", "mx", "ptr", "exists", "redirect"}


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = settings.dns_timeout
    r.lifetime = settings.dns_timeout * 1.5
    return r


def check_spf(domain: str, timeout: float = None) -> dict:
    resolver = _make_resolver()
    result = dict(
        found=False, record=None, all_mechanism=None, dns_lookup_count=0,
        exceeds_lookup_limit=False, syntax_error=None, includes=[],
        mechanisms=[], pass_all=False, softfail_all=False,
        neutral_all=False, hardfail_all=False,
    )
    try:
        answers = resolver.resolve(domain, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return result

    spf_records = []
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace").strip()
        if txt.lower().startswith("v=spf1"):
            spf_records.append(txt)

    if not spf_records:
        return result

    if len(spf_records) > 1:
        result["found"] = True
        result["record"] = spf_records[0]
        result["syntax_error"] = f"Multiple SPF records found ({len(spf_records)}) — RFC 7208 requires exactly one"
        return result

    record = spf_records[0]
    result["found"] = True
    result["record"] = record

    parts = record.split()
    mechanisms = []
    lookup_count = 0
    includes = []

    for part in parts[1:]:  # skip "v=spf1"
        mechanisms.append(part)
        lower = part.lstrip("+-~?").lower()

        # Detect all mechanism
        if lower == "all":
            prefix = part[0] if part[0] in "+-~?" else "+"
            result["all_mechanism"] = prefix + "all"
            result["pass_all"] = prefix == "+"
            result["softfail_all"] = prefix == "~"
            result["neutral_all"] = prefix == "?"
            result["hardfail_all"] = prefix == "-"
            continue

        # Count DNS-consuming mechanisms
        mech_name = re.split(r"[:/=]", lower)[0]
        if mech_name in _DNS_CONSUMING:
            lookup_count += 1
            if mech_name == "include":
                inc_domain = part.split(":", 1)[1] if ":" in part else ""
                if inc_domain:
                    includes.append(inc_domain)
        elif lower.startswith("redirect="):
            lookup_count += 1

    result["mechanisms"] = mechanisms
    result["includes"] = includes
    result["dns_lookup_count"] = lookup_count
    result["exceeds_lookup_limit"] = lookup_count > 10
    return result
