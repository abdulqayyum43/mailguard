"""DMARC record analyzer."""
import dns.resolver
import dns.exception
from config import settings


def _make_resolver():
    r = dns.resolver.Resolver()
    r.timeout = settings.dns_timeout
    r.lifetime = settings.dns_timeout * 1.5
    return r


def check_dmarc(domain: str, timeout: float = None) -> dict:
    resolver = _make_resolver()
    result = dict(
        found=False, record=None, policy=None, subdomain_policy=None,
        pct=None, rua=[], ruf=[], adkim=None, aspf=None,
        has_reporting=False, enforced=False,
    )
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return result

    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace").strip()
        if not txt.lower().startswith("v=dmarc1"):
            continue
        result["found"] = True
        result["record"] = txt

        tags = {}
        for part in txt.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                tags[k.strip().lower()] = v.strip()

        result["policy"] = tags.get("p")
        result["subdomain_policy"] = tags.get("sp")
        result["adkim"] = tags.get("adkim", "r")
        result["aspf"] = tags.get("aspf", "r")

        pct_str = tags.get("pct")
        if pct_str is not None:
            try:
                result["pct"] = int(pct_str)
            except ValueError:
                result["pct"] = 100
        else:
            result["pct"] = 100

        rua_str = tags.get("rua", "")
        result["rua"] = [u.strip() for u in rua_str.split(",") if u.strip()]

        ruf_str = tags.get("ruf", "")
        result["ruf"] = [u.strip() for u in ruf_str.split(",") if u.strip()]

        result["has_reporting"] = bool(result["rua"])
        result["enforced"] = result["policy"] in ("quarantine", "reject")
        break

    return result
