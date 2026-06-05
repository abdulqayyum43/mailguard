"""Continuous email security monitoring service."""
import asyncio
import uuid
from collections import defaultdict
from datetime import datetime, UTC, timedelta
from typing import Optional
from config import settings

_GRADE_ORDER = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}


class MonitoredDomain:
    def __init__(self, api_key, domain, check_interval_hours=24,
                 alert_on_grade_drop=True, alert_on_blacklist=True,
                 alert_on_spoofability_change=True,
                 slack_webhook=None, pagerduty_key=None,
                 alert_email=None, webhook_url=None):
        self.id = str(uuid.uuid4())[:8]
        self.api_key = api_key
        self.domain = domain
        self.check_interval_hours = check_interval_hours
        self.alert_on_grade_drop = alert_on_grade_drop
        self.alert_on_blacklist = alert_on_blacklist
        self.alert_on_spoofability_change = alert_on_spoofability_change
        self.slack_webhook = slack_webhook
        self.pagerduty_key = pagerduty_key
        self.alert_email = alert_email
        self.webhook_url = webhook_url
        self.created_at = datetime.now(UTC).isoformat()
        self.last_checked: Optional[datetime] = None
        self.last_grade: Optional[str] = None
        self.last_score: Optional[int] = None
        self.last_result: Optional[dict] = None
        self.last_blacklist_count: int = 0
        self.last_spoofability_risk: Optional[str] = None

    def is_due(self) -> bool:
        if not self.last_checked:
            return True
        return datetime.now(UTC) >= self.last_checked + timedelta(hours=self.check_interval_hours)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "domain": self.domain,
            "check_interval_hours": self.check_interval_hours,
            "alert_on_grade_drop": self.alert_on_grade_drop,
            "alert_on_blacklist": self.alert_on_blacklist,
            "alert_on_spoofability_change": self.alert_on_spoofability_change,
            "slack_webhook": bool(self.slack_webhook),
            "pagerduty_key": bool(self.pagerduty_key),
            "alert_email": self.alert_email,
            "webhook_url": bool(self.webhook_url),
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
            "last_grade": self.last_grade, "last_score": self.last_score,
            "last_spoofability_risk": self.last_spoofability_risk,
            "last_blacklist_count": self.last_blacklist_count,
            "created_at": self.created_at,
        }


class MonitoringService:
    def __init__(self):
        self._domains: dict[str, list[MonitoredDomain]] = defaultdict(list)

    def add(self, domain: MonitoredDomain) -> MonitoredDomain:
        # Deduplicate by domain per API key
        for existing in self._domains[domain.api_key]:
            if existing.domain == domain.domain:
                return existing
        self._domains[domain.api_key].append(domain)
        return domain

    def remove(self, api_key: str, monitor_id: str) -> bool:
        before = len(self._domains[api_key])
        self._domains[api_key] = [d for d in self._domains[api_key] if d.id != monitor_id]
        return len(self._domains[api_key]) < before

    def list_domains(self, api_key: str) -> list[dict]:
        return [d.to_dict() for d in self._domains[api_key]]

    def get_domain(self, api_key: str, monitor_id: str) -> Optional[MonitoredDomain]:
        for d in self._domains.get(api_key, []):
            if d.id == monitor_id:
                return d
        return None

    def admin_summary(self) -> dict:
        all_domains = [d.to_dict() for domains in self._domains.values() for d in domains]
        return {"total": len(all_domains), "domains": all_domains}

    async def run_loop(self, app) -> None:
        while True:
            try:
                await self._check_due(app)
            except Exception:
                pass
            await asyncio.sleep(settings.monitor_check_interval)

    async def _check_due(self, app) -> None:
        from analyzer.scorer import analyze_email
        from alerts import AlertService

        due = [d for domains in self._domains.values() for d in domains if d.is_due()]
        for domain in due:
            try:
                result = await analyze_email(domain.domain, app.state.http_client)
                now = datetime.now(UTC)
                alert_reasons = []

                if domain.alert_on_grade_drop and domain.last_grade:
                    if _GRADE_ORDER.get(result["grade"], 0) < _GRADE_ORDER.get(domain.last_grade, 0):
                        alert_reasons.append(f"Grade dropped from {domain.last_grade} to {result['grade']}")

                if domain.alert_on_blacklist:
                    new_bl = result["blacklist"]["listed_count"]
                    if new_bl > domain.last_blacklist_count:
                        alert_reasons.append(f"Mail server IP now blacklisted ({new_bl} listing(s))")

                if domain.alert_on_spoofability_change and domain.last_spoofability_risk:
                    risk_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
                    new_risk = result["spoofability"]["risk"]
                    if risk_order.get(new_risk, 0) > risk_order.get(domain.last_spoofability_risk, 0):
                        alert_reasons.append(f"Spoofability risk worsened to {new_risk}")

                domain.last_checked = now
                domain.last_grade = result["grade"]
                domain.last_score = result["score"]
                domain.last_result = result
                domain.last_blacklist_count = result["blacklist"]["listed_count"]
                domain.last_spoofability_risk = result["spoofability"]["risk"]

                if alert_reasons:
                    svc = AlertService(
                        slack_webhook=domain.slack_webhook,
                        pagerduty_key=domain.pagerduty_key,
                        alert_email=domain.alert_email,
                        webhook_url=domain.webhook_url,
                    )
                    await svc.send_all(
                        hostname=domain.domain, grade=result["grade"],
                        score=result["score"], issues=result["issues"],
                        http_client=app.state.http_client,
                    )
            except Exception:
                pass
