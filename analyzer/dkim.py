"""DKIM selector prober."""
import base64
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import settings

DKIM_SELECTORS = [
    "default", "dkim", "mail", "email", "k1", "k2", "s1", "s2",
    "selector1", "selector2", "google", "mandrill", "mailchimp", "k3",
    "sendgrid", "s1024", "amazonses", "mailgun", "smtp", "protonmail",
    "protonmail2", "protonmail3", "zoho", "fm1", "fm2", "fm3",
    "20210112", "2048", "1024", "dkim1024", "dkim2048",
    "2022", "2023", "2024", "2025", "2026",
]


def _make_resolver():
    r = dns.resolver.Resolver()
    r.timeout = settings.dns_timeout
    r.lifetime = settings.dns_timeout * 1.5
    return r


def _get_key_bits(p_value: str, key_type: str) -> int | None:
    if not p_value:
        return None
    if key_type == "ed25519":
        return 256
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        der = base64.b64decode(p_value + "==")
        pub = load_der_public_key(der)
        return pub.key_size
    except Exception:
        return None


def _probe_selector(domain: str, selector: str) -> dict | None:
    resolver = _make_resolver()
    qname = f"{selector}._domainkey.{domain}"
    try:
        answers = resolver.resolve(qname, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None

    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace").strip()
        if "v=dkim1" not in txt.lower() and "p=" not in txt.lower():
            continue

        tags = {}
        for part in txt.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                tags[k.strip().lower()] = v.strip()

        p_val = tags.get("p", "")
        if p_val == "":  # revoked selector
            return None

        key_type = tags.get("k", "rsa").lower()
        key_bits = _get_key_bits(p_val, key_type)

        return {
            "selector": selector,
            "record": txt,
            "key_bits": key_bits,
            "key_type": key_type,
            "valid": True,
        }
    return None


def check_dkim(domain: str, timeout: float = None) -> dict:
    found_selectors = []

    with ThreadPoolExecutor(max_workers=16, thread_name_prefix="dkim") as ex:
        futures = {ex.submit(_probe_selector, domain, sel): sel for sel in DKIM_SELECTORS}
        for future in as_completed(futures):
            res = future.result()
            if res:
                found_selectors.append(res)

    bits_list = [s["key_bits"] for s in found_selectors if s["key_bits"]]
    return {
        "found": bool(found_selectors),
        "selectors_probed": len(DKIM_SELECTORS),
        "selectors_found": found_selectors,
        "strongest_key_bits": max(bits_list) if bits_list else None,
        "weakest_key_bits": min(bits_list) if bits_list else None,
        "has_weak_key": any(b < 1024 for b in bits_list),
        "has_short_key": any(1024 <= b < 2048 for b in bits_list),
    }
