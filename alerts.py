"""
Alert delivery: Slack, PagerDuty, Email (SMTP), Webhook.
All methods swallow exceptions — alert failures must never crash the main scan.
"""
import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, UTC

import httpx

from config import settings


class AlertService:
    def __init__(self, http_client: httpx.AsyncClient):
        self.client = http_client

    async def send_all(self, domain, result: dict, alert_messages: list[str]) -> None:
        tasks = []
        if domain.slack_webhook:
            tasks.append(self._slack(domain, result, alert_messages))
        if domain.pagerduty_key:
            tasks.append(self._pagerduty(domain, result, alert_messages))
        if domain.webhook_url:
            tasks.append(self._webhook(domain, result, alert_messages))
        if domain.alert_email and settings.smtp_host:
            tasks.append(self._email(domain, result, alert_messages))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ── Slack ─────────────────────────────────────────────────────────────────

    async def _slack(self, domain, result: dict, messages: list[str]) -> None:
        grade = result.get("grade", "?")
        score = result.get("score", 0)
        color = "#ef4444" if grade in ("F", "D") else "#eab308" if grade == "C" else "#f97316"

        payload = {
            "attachments": [{
                "color": color,
                "title": f":lock: SSLGuard Alert — {domain.hostname}:{domain.port}",
                "fields": [
                    {"title": "Grade", "value": grade, "short": True},
                    {"title": "Score", "value": f"{score}/100", "short": True},
                    {"title": "Alerts", "value": "\n".join(f"• {m}" for m in messages), "short": False},
                    {"title": "Issues", "value": "\n".join(f"• {i}" for i in result.get("issues", [])[:5]) or "None", "short": False},
                ],
                "footer": "SSLGuard API",
                "ts": int(datetime.now(UTC).timestamp()),
            }]
        }
        try:
            await self.client.post(domain.slack_webhook, json=payload, timeout=5.0)
        except Exception:
            pass

    # ── PagerDuty ─────────────────────────────────────────────────────────────

    async def _pagerduty(self, domain, result: dict, messages: list[str]) -> None:
        grade = result.get("grade", "?")
        severity = "critical" if grade in ("F", "D") else "warning"
        payload = {
            "routing_key": domain.pagerduty_key,
            "event_action": "trigger",
            "dedup_key": f"sslguard-{domain.hostname}-{domain.port}",
            "payload": {
                "summary": f"SSLGuard: {domain.hostname} — {', '.join(messages)}",
                "severity": severity,
                "source": f"{domain.hostname}:{domain.port}",
                "custom_details": {
                    "grade": grade,
                    "score": result.get("score"),
                    "alerts": messages,
                    "issues": result.get("issues", [])[:5],
                    "recommendations": result.get("recommendations", [])[:3],
                },
            },
        }
        try:
            await self.client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=5.0,
            )
        except Exception:
            pass

    # ── Generic Webhook ───────────────────────────────────────────────────────

    async def _webhook(self, domain, result: dict, messages: list[str]) -> None:
        payload = {
            "event": "ssl_alert",
            "timestamp": datetime.now(UTC).isoformat(),
            "hostname": domain.hostname,
            "port": domain.port,
            "grade": result.get("grade"),
            "score": result.get("score"),
            "alerts": messages,
            "issues": result.get("issues", []),
            "recommendations": result.get("recommendations", []),
        }
        try:
            await self.client.post(domain.webhook_url, json=payload, timeout=5.0)
        except Exception:
            pass

    # ── Email ─────────────────────────────────────────────────────────────────

    async def _email(self, domain, result: dict, messages: list[str]) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._email_sync, domain, result, messages)

    def _email_sync(self, domain, result: dict, messages: list[str]) -> None:
        if not settings.smtp_host:
            return
        grade = result.get("grade", "?")
        score = result.get("score", 0)
        issues = result.get("issues", [])
        recs = result.get("recommendations", [])

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SSLGuard] Alert: {domain.hostname} — Grade {grade}"
        msg["From"] = settings.smtp_from
        msg["To"] = domain.alert_email

        text = (
            f"SSLGuard Alert\n"
            f"{'=' * 40}\n"
            f"Hostname : {domain.hostname}:{domain.port}\n"
            f"Grade    : {grade}\n"
            f"Score    : {score}/100\n\n"
            f"ALERTS:\n" + "\n".join(f"  - {m}" for m in messages) + "\n\n"
            f"ISSUES:\n" + ("\n".join(f"  - {i}" for i in issues) or "  None") + "\n\n"
            f"RECOMMENDATIONS:\n" + ("\n".join(f"  - {r}" for r in recs) or "  None") + "\n\n"
            f"Powered by SSLGuard API"
        )

        html = f"""
        <html><body style="font-family:sans-serif;color:#1e293b;background:#f8fafc;padding:24px">
        <h2 style="color:#ef4444">SSLGuard Alert</h2>
        <p><b>Hostname:</b> {domain.hostname}:{domain.port}</p>
        <p><b>Grade:</b> <span style="font-size:1.5em;font-weight:900">{grade}</span> &nbsp; <b>Score:</b> {score}/100</p>
        <h3>Alerts</h3><ul>{''.join(f'<li>{m}</li>' for m in messages)}</ul>
        <h3>Issues</h3><ul>{''.join(f'<li>{i}</li>' for i in issues) or '<li>None</li>'}</ul>
        <h3>Recommendations</h3><ul>{''.join(f'<li>{r}</li>' for r in recs) or '<li>None</li>'}</ul>
        <p style="color:#94a3b8;font-size:0.8em">Powered by SSLGuard API</p>
        </body></html>
        """

        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        try:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
                if settings.smtp_use_tls:
                    server.starttls()
                if settings.smtp_user:
                    server.login(settings.smtp_user, settings.smtp_password)
                server.sendmail(settings.smtp_from, domain.alert_email, msg.as_string())
        except Exception:
            pass
