"""MX record resolver + STARTTLS checker."""
import re
import smtplib
import socket
import ssl
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import settings

_VERSION_RE = re.compile(r"\d+\.\d+")


def _make_resolver():
    r = dns.resolver.Resolver()
    r.timeout = settings.dns_timeout
    r.lifetime = settings.dns_timeout * 1.5
    return r


def _resolve_ips(hostname: str) -> list[str]:
    resolver = _make_resolver()
    ips = []
    for rtype in ("A", "AAAA"):
        try:
            for rdata in resolver.resolve(hostname, rtype):
                ips.append(str(rdata))
        except Exception:
            pass
    return ips


def _check_smtp(hostname: str) -> dict:
    result = dict(
        hostname=hostname, priority=0, ip_addresses=[],
        banner=None, starttls_supported=False,
        tls_version=None, tls_cipher=None,
        banner_exposes_version=False, connect_error=None,
    )
    result["ip_addresses"] = _resolve_ips(hostname)
    to = settings.smtp_connect_timeout
    try:
        with smtplib.SMTP(hostname, 25, timeout=to) as smtp:
            welcome = smtp.getwelcome()
            if welcome:
                banner = welcome.decode("utf-8", errors="replace").strip()
                result["banner"] = banner
                result["banner_exposes_version"] = bool(_VERSION_RE.search(banner))
            smtp.ehlo()
            result["starttls_supported"] = smtp.has_extn("STARTTLS")
            if result["starttls_supported"]:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    smtp.starttls(context=ctx)
                    cipher = smtp.sock.cipher()
                    if cipher:
                        result["tls_cipher"] = cipher[0]
                        result["tls_version"] = cipher[1]
                except Exception:
                    pass
    except (ConnectionRefusedError, socket.timeout, socket.gaierror, OSError) as e:
        result["connect_error"] = str(e)
    except Exception as e:
        result["connect_error"] = str(e)
    return result


def check_mx_records(domain: str, timeout: float = None) -> dict:
    resolver = _make_resolver()
    result = dict(
        found=False, records=[],
        all_support_starttls=False, any_support_starttls=False,
        starttls_count=0, total_mx_count=0,
    )
    try:
        answers = resolver.resolve(domain, "MX")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return result

    mx_entries = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers])
    if not mx_entries:
        return result

    result["found"] = True
    result["total_mx_count"] = len(mx_entries)

    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="mx") as ex:
        futures = {ex.submit(_check_smtp, host): (prio, host) for prio, host in mx_entries}
        servers = []
        for future in as_completed(futures):
            prio, host = futures[future]
            srv = future.result()
            srv["priority"] = prio
            srv["hostname"] = host
            servers.append(srv)

    servers.sort(key=lambda s: s["priority"])
    result["records"] = servers

    starttls_count = sum(1 for s in servers if s["starttls_supported"])
    result["starttls_count"] = starttls_count
    result["any_support_starttls"] = starttls_count > 0
    result["all_support_starttls"] = starttls_count == len(servers) and len(servers) > 0
    return result
