from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Dict, Any


@dataclass
class CSRFTokenRecord:
    random_token: str
    created_at: datetime
    session_id: Optional[str]
    used: bool = False


class InMemoryCSRFStorage:
    """Default in-memory CSRF token storage (single-process)."""

    def __init__(self) -> None:
        # Mirror legacy in-memory structure expected by some tests
        self._store: Dict[str, Dict[str, Any]] = {}

    def save(self, record: CSRFTokenRecord) -> None:
        self._store[record.random_token] = {
            "created_at": record.created_at,
            "session_id": record.session_id,
            "used": record.used,
        }

    def get(self, random_token: str) -> Optional[Dict[str, Any]]:
        return self._store.get(random_token)

    def mark_used(self, random_token: str) -> None:
        rec = self._store.get(random_token)
        if rec:
            rec["used"] = True

    def delete(self, random_token: str) -> None:
        self._store.pop(random_token, None)

    def cleanup_expired(self, older_than: datetime) -> int:
        to_delete = [k for k, v in self._store.items() if v["created_at"] < older_than]
        for k in to_delete:
            self._store.pop(k, None)
        return len(to_delete)


class DuckDBCSRFStorage:
    """DuckDB-backed CSRF token storage for multi-process environments."""

    def __init__(self, db_path: str = "app.db") -> None:
        import duckdb  # local import to avoid dependency if unused
        self._conn = duckdb.connect(db_path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS csrf_tokens (
                random_token VARCHAR PRIMARY KEY,
                created_at TIMESTAMP NOT NULL,
                session_id VARCHAR,
                used BOOLEAN DEFAULT FALSE
            )
            """
        )

    def save(self, record: CSRFTokenRecord) -> None:
        self._conn.execute(
            "INSERT INTO csrf_tokens (random_token, created_at, session_id, used) VALUES (?, ?, ?, ?)",
            [record.random_token, record.created_at, record.session_id, record.used],
        )

    def get(self, random_token: str) -> Optional[Dict[str, Any]]:
        res = self._conn.execute(
            "SELECT random_token, created_at, session_id, used FROM csrf_tokens WHERE random_token = ?",
            [random_token],
        ).fetchone()
        if not res:
            return None
        return {"created_at": res[1], "session_id": res[2], "used": res[3]}

    def mark_used(self, random_token: str) -> None:
        self._conn.execute(
            "UPDATE csrf_tokens SET used = TRUE WHERE random_token = ?",
            [random_token],
        )

    def delete(self, random_token: str) -> None:
        self._conn.execute("DELETE FROM csrf_tokens WHERE random_token = ?", [random_token])

    def cleanup_expired(self, older_than: datetime) -> int:
        res = self._conn.execute(
            "SELECT COUNT(*) FROM csrf_tokens WHERE created_at < ?",
            [older_than],
        ).fetchone()
        count = int(res[0]) if res else 0
        self._conn.execute("DELETE FROM csrf_tokens WHERE created_at < ?", [older_than])
        return count
