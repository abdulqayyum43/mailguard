"""Multi-domain email security portfolio."""
import uuid
from collections import defaultdict
from typing import Optional

_GRADE_ORDER = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}


class PortfolioEntry:
    def __init__(self, api_key, domain, label=None):
        self.id = str(uuid.uuid4())[:8]
        self.api_key = api_key
        self.domain = domain
        self.label = label or domain
        self.last_grade: Optional[str] = None
        self.last_score: Optional[int] = None
        self.last_result: Optional[dict] = None

    def update(self, result: dict):
        self.last_grade = result.get("grade")
        self.last_score = result.get("score")
        self.last_result = result

    def to_dict(self) -> dict:
        return {
            "id": self.id, "domain": self.domain, "label": self.label,
            "last_grade": self.last_grade, "last_score": self.last_score,
        }


class PortfolioStore:
    def __init__(self):
        self._entries: dict[str, list[PortfolioEntry]] = defaultdict(list)

    def add(self, entry: PortfolioEntry) -> PortfolioEntry:
        for existing in self._entries[entry.api_key]:
            if existing.domain == entry.domain:
                return existing
        self._entries[entry.api_key].append(entry)
        return entry

    def get(self, api_key: str) -> list[PortfolioEntry]:
        return self._entries[api_key]

    def remove(self, api_key: str, entry_id: str) -> bool:
        before = len(self._entries[api_key])
        self._entries[api_key] = [e for e in self._entries[api_key] if e.id != entry_id]
        return len(self._entries[api_key]) < before

    def summary(self, api_key: str) -> dict:
        entries = self._entries[api_key]
        if not entries:
            return {"total": 0, "entries": [], "avg_score": None, "worst_domain": None, "grade_distribution": {}}
        graded = [e for e in entries if e.last_grade]
        scores = [e.last_score for e in graded if e.last_score is not None]
        dist: dict[str, int] = {}
        for e in graded:
            dist[e.last_grade] = dist.get(e.last_grade, 0) + 1
        sorted_entries = sorted(graded, key=lambda e: _GRADE_ORDER.get(e.last_grade, 0))
        worst = sorted_entries[0].domain if sorted_entries else None
        return {
            "total": len(entries),
            "avg_score": round(sum(scores) / len(scores)) if scores else None,
            "worst_domain": worst,
            "grade_distribution": dist,
            "entries": [e.to_dict() for e in sorted_entries] + [e.to_dict() for e in entries if not e.last_grade],
        }
