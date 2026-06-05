"""Mail server TLS quality checker (checks negotiated TLS version + cipher)."""
import smtplib
import socket
import ssl
from config import settings

_WEAK_CIPHER_FRAGMENTS = {"RC4", "DES_CBC3", "NULL", "EXPORT", "ADH", "AECDH", "MD5", "IDEA"}
_DEPRECATED_TLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}


def _check_server_tls(hostname: str, port: int) -> dict:
    result = dict(
        mx_hostname=hostname, port=port,
        tls_version=None, cipher=None,
        tls_version_deprecated=False, cipher_weak=False,
        connect_error=None,
    )
    to = settings.smtp_connect_timeout
    try:
        with smtplib.SMTP(hostname, port, timeout=to) as smtp:
            smtp.ehlo()
            if not smtp.has_extn("STARTTLS"):
                result["connect_error"] = "STARTTLS not supported"
                return result
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            smtp.starttls(context=ctx)
            cipher_info = smtp.sock.cipher()
            if cipher_info:
                result["cipher"] = cipher_info[0]
                result["tls_version"] = cipher_info[1]
                result["tls_version_deprecated"] = cipher_info[1] in _DEPRECATED_TLS
                result["cipher_weak"] = any(f in cipher_info[0] for f in _WEAK_CIPHER_FRAGMENTS)
    except (ConnectionRefusedError, socket.timeout, socket.gaierror, OSError) as e:
        result["connect_error"] = str(e)
    except Exception as e:
        result["connect_error"] = str(e)
    return result


def check_mail_tls(mx_result: dict, timeout: float = None) -> dict:
    servers_checked = []
    for srv in mx_result.get("records", [])[:3]:  # check first 3 MX servers only
        hostname = srv["hostname"]
        for port in (25, 587):
            checked = _check_server_tls(hostname, port)
            servers_checked.append(checked)

    return {
        "servers_checked": servers_checked,
        "any_deprecated_tls": any(s["tls_version_deprecated"] for s in servers_checked),
        "any_weak_cipher": any(s["cipher_weak"] for s in servers_checked),
    }
