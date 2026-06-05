"""DANE/TLSA record checker for MX servers."""
import dns.resolver
import dns.exception
from config import settings


def _make_resolver():
    r = dns.resolver.Resolver()
    r.timeout = settings.dns_timeout
    r.lifetime = settings.dns_timeout * 1.5
    return r


def check_dane(mx_result: dict, timeout: float = None) -> dict:
    resolver = _make_resolver()
    mx_results = []
    any_found = False

    for srv in mx_result.get("records", []):
        hostname = srv["hostname"]
        records = []
        found = False
        try:
            answers = resolver.resolve(f"_25._tcp.{hostname}", "TLSA")
            for rdata in answers:
                records.append(str(rdata))
            found = bool(records)
            if found:
                any_found = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass
        mx_results.append({
            "mx_hostname": hostname,
            "tlsa_found": found,
            "records": records,
            "record_count": len(records),
        })

    return {"any_tlsa_found": any_found, "mx_results": mx_results}
