"""SQLite audit backend (append-only by convention; the Postgres one enforces it).

Schema mirrors the Postgres event stream: one row per event, three events per
call (request -> decision -> outcome), sharing a correlation_id. Timestamps are
stored twice - ISO text for humans, epoch float for reliable window maths.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardrail.policy.models import PolicyDecision

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               TEXT    NOT NULL,   -- ISO-8601 UTC
    ts_epoch         REAL    NOT NULL,   -- seconds since epoch, for window queries
    correlation_id   TEXT    NOT NULL,
    event_type       TEXT    NOT NULL,   -- 'request' | 'decision' | 'outcome'
    agent_id         TEXT,
    role             TEXT,
    tool_name        TEXT,
    arguments_json   TEXT,               -- request
    decision         TEXT,               -- decision: 'allow' | 'deny'
    decision_rule    TEXT,               -- decision: which check fired
    decision_reason  TEXT,               -- decision: human-readable
    spend_amount     REAL,               -- decision: spend represented, if any
    outcome          TEXT,               -- outcome: 'success' | 'error'
    result_json      TEXT,               -- outcome
    error            TEXT                -- outcome
);
CREATE INDEX IF NOT EXISTS ix_sqlite_audit_corr  ON audit_events (correlation_id);
CREATE INDEX IF NOT EXISTS ix_sqlite_audit_agent ON audit_events (agent_id, ts_epoch);
"""


def _now() -> tuple[str, float]:
    dt = datetime.now(timezone.utc)
    return dt.isoformat(), dt.timestamp()


class SqliteAuditLog:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
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
        *,
        agent_id: str | None,
        role: str | None,
        tool_name: str,
        arguments: dict[str, Any] | None,
    ) -> None:
        ts, epoch = _now()
        self._conn.execute(
            """INSERT INTO audit_events
               (ts, ts_epoch, correlation_id, event_type, agent_id, role,
                tool_name, arguments_json)
               VALUES (?, ?, ?, 'request', ?, ?, ?, ?)""",
            (ts, epoch, correlation_id, agent_id, role, tool_name,
             json.dumps(arguments or {}, default=str)),
        )
        self._conn.commit()

    def log_decision(
        self,
        correlation_id: str,
        *,
        agent_id: str | None,
        role: str | None,
        tool_name: str,
        decision: PolicyDecision,
    ) -> None:
        ts, epoch = _now()
        self._conn.execute(
            """INSERT INTO audit_events
               (ts, ts_epoch, correlation_id, event_type, agent_id, role,
                tool_name, decision, decision_rule, decision_reason, spend_amount)
               VALUES (?, ?, ?, 'decision', ?, ?, ?, ?, ?, ?, ?)""",
            (ts, epoch, correlation_id, agent_id, role, tool_name,
             "allow" if decision.allowed else "deny",
             decision.rule.value, decision.reason, decision.spend_amount),
        )
        self._conn.commit()

    def log_outcome(
        self,
        correlation_id: str,
        *,
        tool_name: str,
        outcome: str,
        result: Any = None,
        error: str | None = None,
    ) -> None:
        ts, epoch = _now()
        self._conn.execute(
            """INSERT INTO audit_events
               (ts, ts_epoch, correlation_id, event_type, tool_name,
                outcome, result_json, error)
               VALUES (?, ?, ?, 'outcome', ?, ?, ?, ?)""",
            (ts, epoch, correlation_id, tool_name, outcome,
             json.dumps(result, default=str) if result is not None else None, error),
        )
        self._conn.commit()

    # --- policy state store -------------------------------------------------
    def count_requests(self, agent_id: str, within_seconds: int) -> int:
        cutoff = datetime.now(timezone.utc).timestamp() - within_seconds
        cur = self._conn.execute(
            """SELECT count(*) FROM audit_events
               WHERE event_type='request' AND agent_id=? AND ts_epoch >= ?""",
            (agent_id, cutoff),
        )
        return int(cur.fetchone()[0])

    def sum_allowed_spend(self, agent_id: str, tool: str, within_seconds: int) -> float:
        cutoff = datetime.now(timezone.utc).timestamp() - within_seconds
        cur = self._conn.execute(
            """SELECT coalesce(sum(spend_amount), 0) FROM audit_events
               WHERE event_type='decision' AND decision='allow'
                 AND agent_id=? AND tool_name=? AND spend_amount IS NOT NULL
                 AND ts_epoch >= ?""",
            (agent_id, tool, cutoff),
        )
        return float(cur.fetchone()[0])

    # --- helpers ------------------------------------------------------------
    def all_rows(self) -> list[dict[str, Any]]:
        cur = self._conn.execute("SELECT * FROM audit_events ORDER BY id")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()
