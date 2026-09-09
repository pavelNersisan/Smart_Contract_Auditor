"""Persistence for audit runs.

A tiny SQLite-backed store behind a narrow interface. The README promises
PostgreSQL; because the same ``database_url`` is passed straight to the
standard-library driver layer, a Postgres URL can be dropped in by installing
``psycopg`` -- the SQLite path is what makes the service runnable with zero
infrastructure.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from app.models.audit import AuditResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id          TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    status      TEXT NOT NULL,
    score       INTEGER NOT NULL,
    grade       TEXT NOT NULL,
    n_findings  INTEGER NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audits_created_at ON audits (created_at DESC);
"""


class AuditStore:
    """Thread-safe audit persistence."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        if database_url.startswith("sqlite:///"):
            path = Path(database_url[len("sqlite:///") :])
            path.parent.mkdir(parents=True, exist_ok=True)
            self._path: str | None = str(path)
        elif database_url == "sqlite://:memory:":
            self._path = None
        else:
            raise ValueError(
                "unsupported database_url; only SQLite is wired up out of the box "
                f"(got {database_url!r})"
            )
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path or ":memory:", timeout=30)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)

    def save(self, result: AuditResult) -> None:
        row = (
            result.id,
            result.created_at,
            result.status,
            result.score,
            result.grade,
            len(result.findings),
            result.model_dump_json(),
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO audits "
                "(id, created_at, status, score, grade, n_findings, payload) "
                "VALUES (?,?,?,?,?,?,?)",
                row,
            )

    def get(self, audit_id: str) -> AuditResult | None:
        with self._lock, self._connect() as conn:
            cur = conn.execute("SELECT payload FROM audits WHERE id = ?", (audit_id,))
            row = cur.fetchone()
        if not row:
            return None
        return AuditResult.model_validate(json.loads(row[0]))

    def list(self, limit: int = 50, offset: int = 0) -> list[dict]:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "SELECT id, created_at, status, score, grade, n_findings "
                "FROM audits ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            rows = cur.fetchall()
        return [
            {
                "id": r[0],
                "created_at": r[1],
                "status": r[2],
                "score": r[3],
                "grade": r[4],
                "findings": r[5],
            }
            for r in rows
        ]

    def purge_older_than(self, seconds: float) -> int:
        cutoff = time.time() - seconds
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM audits WHERE created_at < ?", (cutoff,))
            return cur.rowcount
