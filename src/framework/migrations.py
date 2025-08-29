"""
Lightweight migrations helpers for PY-Framework (DuckDB).

This module provides minimal primitives to record applied migrations.
For complex changes, prefer external tooling, but this acts as a safe default.
"""

from datetime import datetime
from typing import Any


def ensure_migrations_table(conn: Any) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id INTEGER PRIMARY KEY,
            name VARCHAR UNIQUE NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def record_migration(conn: Any, name: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (name) VALUES (?)",
        [name],
    )

