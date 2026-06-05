from collections import defaultdict, deque
from datetime import datetime, UTC
import uuid


class ScanHistoryStore:
    def __init__(self, max_per_key: int = 100):
        self._max = max_per_key
        self._store: dict[str, deque] = defaultdict(lambda: deque(maxlen=self._max))

    def record(
        self,
        api_key: str,
        hostname: str,
        port: int,
        grade: str,
        score: int,
        issue_count: int,
        top_issues: list[str],
    ) -> dict:
        entry = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now(UTC).isoformat(),
            "hostname": hostname[:100],
            "port": port,
            "grade": grade,
            "score": score,
            "issue_count": issue_count,
            "top_issues": top_issues[:3],
        }
        self._store[api_key].append(entry)
        return entry

    def get_history(self, api_key: str, limit: int = 20) -> list[dict]:
        records = list(self._store.get(api_key, deque()))
        records.reverse()
        return records[:limit]

    def get_stats(self, api_key: str) -> dict:
        records = list(self._store.get(api_key, deque()))
        if not records:
            return {
                "total_scans": 0,
                "grade_distribution": {},
                "avg_score": None,
                "worst_scan": None,
            }

        grade_dist: dict[str, int] = defaultdict(int)
        scores: list[int] = []
        worst: dict | None = None

        for r in records:
            grade_dist[r["grade"]] += 1
            scores.append(r["score"])
            if worst is None or r["score"] < worst["score"]:
                worst = r

        return {
            "total_scans": len(records),
            "grade_distribution": dict(grade_dist),
            "avg_score": round(sum(scores) / len(scores), 1),
            "worst_scan": worst,
        }

    def clear(self, api_key: str) -> None:
        if api_key in self._store:
            self._store[api_key].clear()
