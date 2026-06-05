"""
Waitlist / lead capture store.
Persists entries to data/waitlist.json so they survive restarts.
"""

import json
import uuid
import os
from datetime import datetime, UTC
from dataclasses import dataclass, asdict
from threading import Lock


@dataclass
class WaitlistEntry:
    id: str
    email: str
    name: str
    plan: str          # free | pro | enterprise
    company: str
    created_at: str

    @classmethod
    def create(cls, email: str, name: str, plan: str = "pro", company: str = "") -> "WaitlistEntry":
        return cls(
            id=str(uuid.uuid4())[:8],
            email=email.lower().strip(),
            name=name.strip(),
            plan=plan,
            company=company.strip(),
            created_at=datetime.now(UTC).isoformat(),
        )

    def to_dict(self) -> dict:
        return asdict(self)


class WaitlistStore:
    def __init__(self, data_dir: str = "data"):
        self._path = os.path.join(data_dir, "waitlist.json")
        self._lock = Lock()
        os.makedirs(data_dir, exist_ok=True)
        self._entries: list[WaitlistEntry] = []
        self._load()

    def _load(self):
        if os.path.exists(self._path):
            try:
                with open(self._path) as f:
                    raw = json.load(f)
                self._entries = [WaitlistEntry(**e) for e in raw]
            except Exception:
                self._entries = []

    def _save(self):
        with open(self._path, "w") as f:
            json.dump([e.to_dict() for e in self._entries], f, indent=2)

    def add(self, email: str, name: str, plan: str = "pro", company: str = "") -> WaitlistEntry:
        with self._lock:
            # Deduplicate by email
            for e in self._entries:
                if e.email == email.lower().strip():
                    return e
            entry = WaitlistEntry.create(email=email, name=name, plan=plan, company=company)
            self._entries.append(entry)
            self._save()
            return entry

    def all(self) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in reversed(self._entries)]

    def count(self) -> int:
        return len(self._entries)

    def remove(self, entry_id: str) -> bool:
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if e.id != entry_id]
            if len(self._entries) < before:
                self._save()
                return True
            return False
