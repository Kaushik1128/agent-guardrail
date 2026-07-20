"""Append-only audit log (SQLite, Phase 1).

Design notes worth carrying into Phase 2:

* Each tool call produces (at least) TWO rows sharing a ``correlation_id``:
  a ``request`` row written *before* the call is forwarded, and an ``outcome``
  row written *after*. Keeping request and outcome as separate append-only
  events - rather than one row we UPDATE - means the log reflects what actually
  happened in order, even if the process crashes mid-call. That request /
  decision / outcome separation is exactly what the Phase 2 Postgres schema
  formalises.

* "Append-only" here is a convention: this class only ever INSERTs. Real
  tamper-resistance (revoking UPDATE/DELETE, or hash-chaining rows) comes later;
  the point for now is that the *code* never mutates history.

SQLite is synchronous, which is fine: writes are local and sub-millisecond, and
serialising them actually gives us a clean, ordered log for free.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc          TEXT    NOT NULL,   -- ISO-8601 UTC timestamp
    correlation_id  TEXT    NOT NULL,   -- links the request row to its outcome row
    event           TEXT    NOT NULL,   -- 'request' | 'outcome'
    agent_id        TEXT,               -- who called (placeholder in Phase 1)
    tool_name       TEXT,
    arguments_json  TEXT,               -- request event: the call arguments
    decision        TEXT,               -- request event: 'allow' (policy arrives in Phase 2)
    outcome         TEXT,               -- outcome event: 'success' | 'error'
    result_json     TEXT,               -- outcome event: forwarded tool result
    error           TEXT                -- outcome event: error detail, if any
);

CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_log (correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts_utc);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    """Thin wrapper over a SQLite connection that only ever appends rows."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the MCP server may touch this from a worker
        # thread; we serialise writes ourselves and never share cursors.
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @staticmethod
    def new_correlation_id() -> str:
        return uuid.uuid4().hex

    def log_request(
        self,
        correlation_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
        *,
        agent_id: str | None = None,
        decision: str = "allow",
    ) -> None:
        """Record that a call was received and (in Phase 1) allowed."""
        self._conn.execute(
            """
            INSERT INTO audit_log
                (ts_utc, correlation_id, event, agent_id, tool_name, arguments_json, decision)
            VALUES (?, ?, 'request', ?, ?, ?, ?)
            """,
            (
                _now(),
                correlation_id,
                agent_id,
                tool_name,
                json.dumps(arguments or {}, default=str),
                decision,
            ),
        )
        self._conn.commit()

    def log_outcome(
        self,
        correlation_id: str,
        tool_name: str,
        outcome: str,
        *,
        result: Any = None,
        error: str | None = None,
    ) -> None:
        """Record what happened after the call was forwarded downstream."""
        self._conn.execute(
            """
            INSERT INTO audit_log
                (ts_utc, correlation_id, event, tool_name, outcome, result_json, error)
            VALUES (?, ?, 'outcome', ?, ?, ?, ?)
            """,
            (
                _now(),
                correlation_id,
                tool_name,
                outcome,
                json.dumps(result, default=str) if result is not None else None,
                error,
            ),
        )
        self._conn.commit()

    def all_rows(self) -> list[dict[str, Any]]:
        """Return the full log as dicts (used by tests and the demo)."""
        cur = self._conn.execute("SELECT * FROM audit_log ORDER BY id")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()
