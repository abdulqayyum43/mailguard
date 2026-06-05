"""MTA-STS DNS record and policy file checker."""
import httpx
import dns.resolver
import dns.exception
from config import settings


def _make_resolver():
    r = dns.resolver.Resolver()
    r.timeout = settings.dns_timeout
    r.lifetime = settings.dns_timeout * 1.5
    return r


async def check_mta_sts(domain: str, http_client: httpx.AsyncClient, timeout: float = None) -> dict:
    resolver = _make_resolver()
    result = dict(
        dns_record_found=False, dns_record=None,
        policy_fetched=False, policy_mode=None,
        policy_mx_hosts=[], policy_max_age=None,
        fetch_error=None, fully_configured=False,
    )

    # Check DNS TXT record
    try:
        answers = resolver.resolve(f"_mta-sts.{domain}", "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace").strip()
            if "v=stsv1" in txt.lower():
                result["dns_record_found"] = True
                result["dns_record"] = txt
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass

    # Fetch policy file
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        resp = await http_client.get(policy_url, timeout=10.0)
        if resp.status_code == 200:
            result["policy_fetched"] = True
            mx_hosts = []
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    k, _, v = line.partition(":")
                    k, v = k.strip().lower(), v.strip()
                    if k == "mode":
                        result["policy_mode"] = v
                    elif k == "mx":
                        mx_hosts.append(v)
                    elif k == "max_age":
                        try:
                            result["policy_max_age"] = int(v)
                        except ValueError:
                            pass
            result["policy_mx_hosts"] = mx_hosts
        else:
            result["fetch_error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        result["fetch_error"] = str(e)

    result["fully_configured"] = (
        result["dns_record_found"]
        and result["policy_fetched"]
        and result["policy_mode"] == "enforce"
    )
    return result
