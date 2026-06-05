"""Scheduled email security scan service."""
import asyncio
import uuid
from collections import defaultdict, deque
from datetime import datetime, UTC, timedelta
from typing import Optional
from config import settings

_FREQUENCIES = {"hourly": 1, "daily": 24, "weekly": 168}


class ScheduledJob:
    def __init__(self, api_key, domain, frequency="daily", label=None):
        self.id = str(uuid.uuid4())[:8]
        self.api_key = api_key
        self.domain = domain
        self.frequency = frequency
        self.label = label or domain
        self.interval_hours = _FREQUENCIES.get(frequency, 24)
        self.created_at = datetime.now(UTC).isoformat()
        self.last_run: Optional[datetime] = None
        self.next_run: datetime = datetime.now(UTC)
        self.run_count = 0
        self.last_grade: Optional[str] = None
        self.last_score: Optional[int] = None
        self.results: deque = deque(maxlen=20)

    def is_due(self) -> bool:
        return datetime.now(UTC) >= self.next_run

    def mark_ran(self, result: dict) -> None:
        self.last_run = datetime.now(UTC)
        self.next_run = self.last_run + timedelta(hours=self.interval_hours)
        self.run_count += 1
        self.last_grade = result.get("grade")
        self.last_score = result.get("score")
        self.results.append({
            "ran_at": self.last_run.isoformat(),
            "grade": result.get("grade"),
            "score": result.get("score"),
            "issue_count": result.get("issue_count", 0),
        })

    def to_dict(self) -> dict:
        return {
            "id": self.id, "domain": self.domain, "frequency": self.frequency,
            "label": self.label, "created_at": self.created_at,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat(),
            "run_count": self.run_count, "last_grade": self.last_grade,
            "last_score": self.last_score, "recent_results": list(self.results),
        }


class SchedulerService:
    def __init__(self):
        self._jobs: dict[str, list[ScheduledJob]] = defaultdict(list)

    def add(self, job: ScheduledJob) -> ScheduledJob:
        self._jobs[job.api_key].append(job)
        return job

    def remove(self, api_key: str, job_id: str) -> bool:
        before = len(self._jobs[api_key])
        self._jobs[api_key] = [j for j in self._jobs[api_key] if j.id != job_id]
        return len(self._jobs[api_key]) < before

    def list_jobs(self, api_key: str) -> list[dict]:
        return [j.to_dict() for j in self._jobs[api_key]]

    def get_job(self, api_key: str, job_id: str) -> Optional[ScheduledJob]:
        for j in self._jobs.get(api_key, []):
            if j.id == job_id:
                return j
        return None

    def all_due(self) -> list[ScheduledJob]:
        return [j for jobs in self._jobs.values() for j in jobs if j.is_due()]

    def all_jobs(self) -> list[dict]:
        return [j.to_dict() for jobs in self._jobs.values() for j in jobs]

    async def run_loop(self, app) -> None:
        while True:
            try:
                await self._run_due(app)
            except Exception:
                pass
            await asyncio.sleep(60)

    async def _run_due(self, app) -> None:
        from analyzer.scorer import analyze_email
        for job in self.all_due():
            try:
                result = await analyze_email(job.domain, app.state.http_client)
                job.mark_ran(result)
                app.state.history.record(
                    api_key=job.api_key, hostname=job.domain, port=0,
                    grade=result["grade"], score=result["score"],
                    issue_count=result["issue_count"], top_issues=result["issues"][:3],
                )
            except Exception:
                job.next_run = datetime.now(UTC) + timedelta(hours=job.interval_hours)
