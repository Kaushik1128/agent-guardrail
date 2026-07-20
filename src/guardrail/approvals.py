"""The HITL approval queue.

This is deliberately the project's ONE mutable store. An approval is live state
- a question awaiting an answer - so it gets updated in place, unlike the audit
log, which records every transition immutably alongside it.

State machine (one-way, no take-backs):

    pending --> approved   (human said yes; the parked call proceeds)
            --> denied     (human said no; the parked call is refused)
            --> timeout    (nobody answered in time; refused, fail-closed)

`decide()` flips status only if it is still 'pending' (atomic compare-and-set in
SQL), so two reviewers racing each other - or a reviewer racing the timeout -
produce exactly one winner.

Two interchangeable backends, selected the same way as the audit log:
Postgres when DATABASE_URL is set, else SQLite.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardrail.db.connection import get_database_url

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    correlation_id  TEXT PRIMARY KEY,
    requested_at    TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    role            TEXT,
    tool_name       TEXT NOT NULL,
    arguments_json  TEXT,
    reason          TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    decided_at      TEXT,
    decided_by      TEXT,
    decision_note   TEXT
);
CREATE INDEX IF NOT EXISTS ix_approvals_status ON approvals (status, requested_at);
"""


def get_approval_store():
    """Return the configured approvals backend (mirrors get_audit_log())."""
    if get_database_url():
        return PostgresApprovalStore()
    from guardrail.config import get_db_path

    return SqliteApprovalStore(get_db_path())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqliteApprovalStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SQLITE_SCHEMA)
        self._conn.commit()

    def create(
        self,
        correlation_id: str,
        *,
        agent_id: str,
        role: str | None,
        tool_name: str,
        arguments: dict[str, Any] | None,
        reason: str,
    ) -> None:
        self._conn.execute(
            """INSERT INTO approvals
               (correlation_id, requested_at, agent_id, role, tool_name,
                arguments_json, reason)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (correlation_id, _now_iso(), agent_id, role, tool_name,
             json.dumps(arguments or {}, default=str), reason),
        )
        self._conn.commit()

    def status(self, correlation_id: str) -> str | None:
        cur = self._conn.execute(
            "SELECT status FROM approvals WHERE correlation_id = ?", (correlation_id,)
        )
        row = cur.fetchone()
        return row[0] if row else None

    def decide(
        self, correlation_id: str, *, approve: bool,
        decided_by: str, note: str = "",
    ) -> bool:
        """Atomically settle a pending approval. Returns False if it was
        already decided (or unknown) - first decision wins."""
        cur = self._conn.execute(
            """UPDATE approvals
               SET status = ?, decided_at = ?, decided_by = ?, decision_note = ?
               WHERE correlation_id = ? AND status = 'pending'""",
            ("approved" if approve else "denied", _now_iso(), decided_by, note,
             correlation_id),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def mark_timeout(self, correlation_id: str) -> bool:
        cur = self._conn.execute(
            """UPDATE approvals SET status = 'timeout', decided_at = ?
               WHERE correlation_id = ? AND status = 'pending'""",
            (_now_iso(), correlation_id),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def list(self, status: str | None = None, limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM approvals"
        params: tuple = ()
        if status:
            sql += " WHERE status = ?"
            params = (status,)
        sql += " ORDER BY requested_at DESC LIMIT ?"
        cur = self._conn.execute(sql, params + (limit,))
        cols = [c[0] for c in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:  # normalise to the same shape as the Postgres backend
            r["arguments"] = json.loads(r.pop("arguments_json") or "{}")
        return rows

    def close(self) -> None:
        self._conn.close()


class PostgresApprovalStore:
    def __init__(self) -> None:
        from guardrail.db.connection import connect

        self._connect = connect
        connect().close()  # fail fast if unreachable

    def create(self, correlation_id, *, agent_id, role, tool_name, arguments, reason):
        from psycopg.types.json import Json

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO approvals
                   (correlation_id, agent_id, role, tool_name, arguments, reason)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (correlation_id, agent_id, role, tool_name, Json(arguments or {}), reason),
            )
            conn.commit()

    def status(self, correlation_id) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM approvals WHERE correlation_id = %s",
                (correlation_id,),
            ).fetchone()
            return row[0] if row else None

    def decide(self, correlation_id, *, approve, decided_by, note="") -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                """UPDATE approvals
                   SET status = %s, decided_at = now(), decided_by = %s, decision_note = %s
                   WHERE correlation_id = %s AND status = 'pending'""",
                ("approved" if approve else "denied", decided_by, note, correlation_id),
            )
            conn.commit()
            return cur.rowcount == 1

    def mark_timeout(self, correlation_id) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                """UPDATE approvals SET status = 'timeout', decided_at = now()
                   WHERE correlation_id = %s AND status = 'pending'""",
                (correlation_id,),
            )
            conn.commit()
            return cur.rowcount == 1

    def list(self, status: str | None = None, limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM approvals"
        params: list = []
        if status:
            sql += " WHERE status = %s"
            params.append(status)
        sql += " ORDER BY requested_at DESC LIMIT %s"
        params.append(limit)
        with self._connect() as conn:
            cur = conn.execute(sql, params)
            cols = [d[0] for d in cur.description]
            return [
                {c: (str(v) if c == "correlation_id" else v)
                 for c, v in zip(cols, row)}
                for row in cur.fetchall()
            ]

    def close(self) -> None:
        pass
