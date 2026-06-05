"""BIMI record checker."""
import dns.resolver
import dns.exception
from config import settings


def _make_resolver():
    r = dns.resolver.Resolver()
    r.timeout = settings.dns_timeout
    r.lifetime = settings.dns_timeout * 1.5
    return r


def check_bimi(domain: str, timeout: float = None) -> dict:
    resolver = _make_resolver()
    result = dict(found=False, record=None, logo_url=None, vmc_url=None, vmc_present=False)
    try:
        answers = resolver.resolve(f"default._bimi.{domain}", "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace").strip()
            if "v=bimi1" not in txt.lower():
                continue
            result["found"] = True
            result["record"] = txt
            for part in txt.split(";"):
                part = part.strip()
                if part.lower().startswith("l="):
                    result["logo_url"] = part[2:].strip()
                elif part.lower().startswith("a="):
                    vmc = part[2:].strip()
                    result["vmc_url"] = vmc if vmc else None
                    result["vmc_present"] = bool(vmc)
            break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    return result
