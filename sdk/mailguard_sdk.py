"""MailGuard Python SDK — official client for the MailGuard Email Security API."""
from __future__ import annotations

import time
from typing import Optional
import httpx


class MailGuardError(Exception):
    """Raised when the API returns an error response."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class MailGuardClient:
    """
    Synchronous client for the MailGuard Email Security API.

    Usage::

        from mailguard_sdk import MailGuardClient

        client = MailGuardClient(api_key="mailg-pro-xxx", base_url="http://localhost:8003")

        result = client.analyze("google.com")
        print(result["grade"], result["score"])
    """

    def __init__(self, api_key: str, base_url: str = "http://localhost:8003", timeout: float = 60.0):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = httpx.Client(
            base_url=self.base_url,
            headers={"X-API-Key": api_key},
            timeout=timeout,
        )

    def _get(self, path: str, **params) -> dict:
        r = self._session.get(path, params={k: v for k, v in params.items() if v is not None})
        self._raise(r)
        return r.json()

    def _post(self, path: str, body: dict) -> dict:
        r = self._session.post(path, json=body)
        self._raise(r)
        return r.json()

    def _delete(self, path: str) -> dict:
        r = self._session.delete(path)
        self._raise(r)
        return r.json()

    @staticmethod
    def _raise(response: httpx.Response):
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise MailGuardError(response.status_code, detail)

    # ── Core Analysis ──────────────────────────────────────────────────────────

    def analyze(self, domain: str) -> dict:
        """Analyze a domain's email security posture.

        Returns the full scan result including SPF, DMARC, DKIM, MTA-STS,
        MX servers, blacklist status, spoofability score, and recommendations.
        """
        return self._post("/analyze", {"domain": domain})

    def bulk_analyze(self, domains: list[str]) -> list[dict]:
        """Analyze multiple domains sequentially and return a list of results."""
        results = []
        for domain in domains:
            try:
                results.append(self.analyze(domain))
            except MailGuardError as e:
                results.append({"domain": domain, "error": str(e)})
        return results

    # ── PDF Reports ────────────────────────────────────────────────────────────

    def get_pdf_report(self, domain: str) -> bytes:
        """Download the PDF security report for a domain as raw bytes."""
        r = self._session.get("/report", params={"domain": domain})
        self._raise(r)
        return r.content

    def save_pdf_report(self, domain: str, path: str) -> str:
        """Download and save the PDF security report to a file. Returns the file path."""
        pdf_bytes = self.get_pdf_report(domain)
        with open(path, "wb") as f:
            f.write(pdf_bytes)
        return path

    def get_compliance_report(self, domain: str, framework: str = "soc2") -> bytes:
        """Download a compliance PDF report.

        Args:
            domain: The domain to generate the report for.
            framework: One of ``pci-dss``, ``soc2``, or ``iso27001``.
        """
        r = self._session.get("/report/compliance", params={"domain": domain, "framework": framework})
        self._raise(r)
        return r.content

    def save_compliance_report(self, domain: str, framework: str, path: str) -> str:
        """Download and save a compliance PDF report. Returns the file path."""
        pdf_bytes = self.get_compliance_report(domain, framework)
        with open(path, "wb") as f:
            f.write(pdf_bytes)
        return path

    # ── Monitoring ─────────────────────────────────────────────────────────────

    def add_monitor(
        self,
        domain: str,
        check_interval_hours: int = 24,
        alert_email: Optional[str] = None,
        slack_webhook: Optional[str] = None,
        webhook_url: Optional[str] = None,
        alert_on_blacklist: bool = True,
        alert_on_spoofability_change: bool = True,
    ) -> dict:
        """Add a domain to continuous monitoring."""
        return self._post("/monitor", {
            "domain": domain,
            "check_interval_hours": check_interval_hours,
            "alert_email": alert_email,
            "slack_webhook": slack_webhook,
            "webhook_url": webhook_url,
            "alert_on_blacklist": alert_on_blacklist,
            "alert_on_spoofability_change": alert_on_spoofability_change,
        })

    def list_monitors(self) -> list[dict]:
        """List all monitored domains for this API key."""
        return self._get("/monitor").get("monitors", [])

    def force_monitor_check(self, domain: str) -> dict:
        """Trigger an immediate check for a monitored domain."""
        return self._post(f"/monitor/{domain}/check", {})

    def remove_monitor(self, domain: str) -> dict:
        """Remove a domain from monitoring."""
        return self._delete(f"/monitor/{domain}")

    # ── Scheduler ─────────────────────────────────────────────────────────────

    def add_schedule(
        self,
        domain: str,
        frequency: str = "daily",
        label: Optional[str] = None,
        notify_email: Optional[str] = None,
    ) -> dict:
        """Schedule a recurring automated scan.

        Args:
            domain: Domain to scan.
            frequency: ``hourly``, ``daily``, ``weekly``, or ``monthly``.
            label: Human-friendly label (defaults to domain).
            notify_email: Email to notify on completion.
        """
        return self._post("/schedule", {
            "domain": domain,
            "frequency": frequency,
            "label": label or domain,
            "notify_email": notify_email,
        })

    def list_schedules(self) -> list[dict]:
        """List all scheduled scans for this API key."""
        return self._get("/schedule").get("jobs", [])

    def remove_schedule(self, job_id: str) -> dict:
        """Delete a scheduled scan job."""
        return self._delete(f"/schedule/{job_id}")

    # ── Portfolio ──────────────────────────────────────────────────────────────

    def add_to_portfolio(self, domain: str, label: Optional[str] = None) -> dict:
        """Add a domain to your portfolio."""
        return self._post("/portfolio", {"domain": domain, "label": label or domain})

    def get_portfolio(self) -> dict:
        """Get portfolio summary with grade distribution and worst-performing domain."""
        return self._get("/portfolio")

    def refresh_portfolio(self) -> dict:
        """Re-scan all portfolio domains and update grades."""
        return self._post("/portfolio/refresh", {})

    def remove_from_portfolio(self, entry_id: str) -> dict:
        """Remove a domain from the portfolio by entry ID."""
        return self._delete(f"/portfolio/{entry_id}")

    # ── History ────────────────────────────────────────────────────────────────

    def get_history(self, domain: Optional[str] = None, limit: int = 50) -> list[dict]:
        """Retrieve scan history, optionally filtered by domain."""
        return self._get("/history", domain=domain, limit=limit).get("history", [])

    # ── Usage & Info ───────────────────────────────────────────────────────────

    def get_usage(self) -> dict:
        """Get API usage statistics for this key."""
        return self._get("/usage")

    def ping(self) -> bool:
        """Health check. Returns True if the API is reachable."""
        try:
            self._get("/health")
            return True
        except Exception:
            return False

    def close(self):
        """Close the underlying HTTP session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
