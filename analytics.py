from collections import defaultdict
from datetime import datetime, UTC


class UsageTracker:
    def __init__(self):
        # api_key -> list of scan records
        self._usage: dict[str, list[dict]] = defaultdict(list)

    def record(self, api_key: str, hostname: str, grade: str, score: int, issue_count: int) -> None:
        self._usage[api_key].append({
            "ts": datetime.now(UTC).isoformat(),
            "hostname": hostname[:100],
            "grade": grade,
            "score": score,
            "issue_count": issue_count,
        })

    def get_stats(self, api_key: str) -> dict:
        records = self._usage.get(api_key, [])
        if not records:
            return {
                "total_requests": 0,
                "avg_score": None,
                "grade_distribution": {},
                "last_used": None,
            }

        scores = [r["score"] for r in records]
        avg_score = round(sum(scores) / len(scores), 1)

        grade_dist: dict[str, int] = defaultdict(int)
        for r in records:
            grade_dist[r["grade"]] += 1

        return {
            "total_requests": len(records),
            "avg_score": avg_score,
            "grade_distribution": dict(grade_dist),
            "last_used": records[-1]["ts"],
        }

    def get_all_stats(self) -> dict:
        return {key: self.get_stats(key) for key in self._usage}
