"""MX IP blacklist checker against major RBLs."""
import ipaddress
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import settings

RBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
]


def _make_resolver():
    r = dns.resolver.Resolver()
    r.timeout = settings.dns_timeout
    r.lifetime = settings.dns_timeout * 1.5
    return r


def _reverse_ip(ip_str: str) -> str:
    addr = ipaddress.ip_address(ip_str)
    if isinstance(addr, ipaddress.IPv4Address):
        return ".".join(reversed(ip_str.split(".")))
    expanded = addr.exploded.replace(":", "")
    return ".".join(reversed(expanded))


def _check_one(ip: str, rbl: str) -> dict:
    resolver = _make_resolver()
    lookup = f"{_reverse_ip(ip)}.{rbl}"
    entry = {"ip": ip, "rbl": rbl, "listed": False, "reason": None}
    try:
        resolver.resolve(lookup, "A")
        entry["listed"] = True
        try:
            txts = resolver.resolve(lookup, "TXT")
            reasons = []
            for r in txts:
                reasons.append(b"".join(r.strings).decode("utf-8", errors="replace"))
            entry["reason"] = " | ".join(reasons)
        except Exception:
            entry["reason"] = "Listed"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except dns.exception.DNSException:
        pass
    return entry


def check_blacklist(mx_result: dict, timeout: float = None) -> dict:
    all_ips = []
    for srv in mx_result.get("records", []):
        all_ips.extend(srv.get("ip_addresses", []))
    # Only IPv4 for now (most RBLs don't support IPv6 well)
    ipv4s = [ip for ip in all_ips if ":" not in ip]
    unique_ips = list(dict.fromkeys(ipv4s))

    listings = []
    if unique_ips:
        pairs = [(ip, rbl) for ip in unique_ips for rbl in RBLS]
        with ThreadPoolExecutor(max_workers=20, thread_name_prefix="rbl") as ex:
            futures = [ex.submit(_check_one, ip, rbl) for ip, rbl in pairs]
            for f in as_completed(futures):
                listings.append(f.result())

    listed_ips = {e["ip"] for e in listings if e["listed"]}
    return {
        "ips_checked": unique_ips,
        "listings": listings,
        "listed_count": len(listed_ips),
        "clean": len(listed_ips) == 0,
    }
