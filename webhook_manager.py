"""
Webhook delivery manager with retry logic and delivery logs.
Retries failed deliveries up to 3 times with exponential backoff.
Keeps a delivery log per API key.
"""
import asyncio
import uuid
from collections import defaultdict, deque
from datetime import datetime, UTC

import httpx


class DeliveryAttempt:
    def __init__(
        self,
        webhook_url: str,
        event: str,
        payload: dict,
        api_key: str,
    ):
        self.id = str(uuid.uuid4())[:8]
        self.webhook_url = webhook_url
        self.event = event
        self.payload = payload
        self.api_key = api_key
        self.created_at = datetime.now(UTC).isoformat()
        self.attempts: list[dict] = []
        self.delivered = False
        self.final_status: str = "pending"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event": self.event,
            "webhook_url": self.webhook_url[:60] + "..." if len(self.webhook_url) > 60 else self.webhook_url,
            "created_at": self.created_at,
            "delivered": self.delivered,
            "final_status": self.final_status,
            "attempt_count": len(self.attempts),
            "attempts": self.attempts,
        }


class WebhookManager:
    def __init__(self):
        # api_key -> deque of DeliveryAttempt
        self._logs: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def get_logs(self, api_key: str, limit: int = 50) -> list[dict]:
        records = list(self._logs.get(api_key, deque()))
        records.reverse()
        return [r.to_dict() for r in records[:limit]]

    def get_stats(self, api_key: str) -> dict:
        records = list(self._logs.get(api_key, deque()))
        if not records:
            return {"total": 0, "delivered": 0, "failed": 0, "pending": 0}
        return {
            "total": len(records),
            "delivered": sum(1 for r in records if r.delivered),
            "failed": sum(1 for r in records if r.final_status == "failed"),
            "pending": sum(1 for r in records if r.final_status == "pending"),
        }

    async def send(
        self,
        http_client: httpx.AsyncClient,
        api_key: str,
        webhook_url: str,
        event: str,
        payload: dict,
        max_retries: int = 3,
    ) -> bool:
        """
        Deliver webhook with up to max_retries attempts (exponential backoff).
        Returns True if delivered successfully.
        """
        attempt = DeliveryAttempt(
            webhook_url=webhook_url,
            event=event,
            payload={"event": event, "timestamp": datetime.now(UTC).isoformat(), "data": payload},
            api_key=api_key,
        )
        self._logs[api_key].append(attempt)

        for retry in range(max_retries):
            attempt_start = datetime.now(UTC)
            try:
                resp = await http_client.post(
                    webhook_url,
                    json=attempt.payload,
                    timeout=5.0,
                )
                status_code = resp.status_code
                success = resp.is_success

                attempt.attempts.append({
                    "attempt": retry + 1,
                    "at": attempt_start.isoformat(),
                    "status_code": status_code,
                    "success": success,
                })

                if success:
                    attempt.delivered = True
                    attempt.final_status = "delivered"
                    return True

            except Exception as exc:
                attempt.attempts.append({
                    "attempt": retry + 1,
                    "at": attempt_start.isoformat(),
                    "error": str(exc)[:200],
                    "success": False,
                })

            # Exponential backoff: 1s, 2s, 4s
            if retry < max_retries - 1:
                await asyncio.sleep(2 ** retry)

        attempt.final_status = "failed"
        return False
