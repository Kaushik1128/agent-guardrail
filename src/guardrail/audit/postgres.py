"""Postgres audit backend - the real Phase 2 store.

Same interface as SqliteAuditLog, but writing to the append-only audit_events
table (see guardrail/db/schema.sql), where a trigger physically rejects any
UPDATE or DELETE. Window queries lean on Postgres's interval maths and the
(agent_id, ts) index.

Each write opens a short-lived connection. At this scale that's simpler than a
pool and keeps every write independently durable.
"""

from __future__ import annotations

import uuid
from typing import Any

from psycopg.types.json import Json

from guardrail.db.connection import connect
from guardrail.policy.models import PolicyDecision


class PostgresAuditLog:
    def __init__(self) -> None:
        # Fail fast if Postgres is unreachable, rather than at first write.
        connect().close()

    @staticmethod
    def new_correlation_id() -> str:
        return str(uuid.uuid4())

    def _insert(self, columns: dict[str, Any]) -> None:
        cols = ", ".join(columns)
        placeholders = ", ".join(["%s"] * len(columns))
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"INSERT INTO audit_events ({cols}) VALUES ({placeholders})",
                    list(columns.values()),
                )
            conn.commit()

    def log_request(
        self,
        correlation_id: str,
        *,
        agent_id: str | None,
        role: str | None,
        tool_name: str,
        arguments: dict[str, Any] | None,
    ) -> None:
        self._insert(
            {
                "correlation_id": correlation_id,
                "event_type": "request",
                "agent_id": agent_id,
                "role": role,
                "tool_name": tool_name,
                "arguments": Json(arguments or {}),
            }
        )

    def log_decision(
        self,
        correlation_id: str,
        *,
        agent_id: str | None,
        role: str | None,
        tool_name: str,
        decision: str,          # 'allow' | 'deny' | 'pending'
        rule: str,
        reason: str,
        spend_amount: float | None = None,
    ) -> None:
        self._insert(
            {
                "correlation_id": correlation_id,
                "event_type": "decision",
                "agent_id": agent_id,
                "role": role,
                "tool_name": tool_name,
                "decision": decision,
                "decision_rule": rule,
                "decision_reason": reason,
                "spend_amount": spend_amount,
            }
        )

    def log_policy_decision(
        self,
        correlation_id: str,
        *,
        agent_id: str | None,
        role: str | None,
        tool_name: str,
        decision: PolicyDecision,
    ) -> None:
        """Convenience: record a PolicyDecision from the engine."""
        self.log_decision(
            correlation_id,
            agent_id=agent_id,
            role=role,
            tool_name=tool_name,
            decision=(
                "pending" if decision.needs_approval
                else "allow" if decision.allowed else "deny"
            ),
            rule=decision.rule.value,
            reason=decision.reason,
            spend_amount=decision.spend_amount,
        )

    def log_outcome(
        self,
        correlation_id: str,
        *,
        tool_name: str,
        outcome: str,
        result: Any = None,
        error: str | None = None,
    ) -> None:
        self._insert(
            {
                "correlation_id": correlation_id,
                "event_type": "outcome",
                "tool_name": tool_name,
                "outcome": outcome,
                "result": Json(result) if result is not None else None,
                "error": error,
            }
        )

    # --- policy state store -------------------------------------------------
    def count_requests(self, agent_id: str, within_seconds: int) -> int:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT count(*) FROM audit_events
                       WHERE event_type='request' AND agent_id=%s
                         AND ts >= now() - make_interval(secs => %s)""",
                    (agent_id, within_seconds),
                )
                return int(cur.fetchone()[0])

    def sum_allowed_spend(self, agent_id: str, tool: str, within_seconds: int) -> float:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT coalesce(sum(spend_amount), 0) FROM audit_events
                       WHERE event_type='decision' AND decision='allow'
                         AND agent_id=%s AND tool_name=%s AND spend_amount IS NOT NULL
                         AND ts >= now() - make_interval(secs => %s)""",
                    (agent_id, tool, within_seconds),
                )
                return float(cur.fetchone()[0])

    def recent_calls(self, limit: int = 50) -> list[dict[str, Any]]:
        """One row per call from the v_tool_calls view, newest first."""
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM v_tool_calls ORDER BY last_event_at DESC LIMIT %s",
                    (limit,),
                )
                cols = [d[0] for d in cur.description]
                return [
                    {c: (str(v) if c == "correlation_id" else v)
                     for c, v in zip(cols, row)}
                    for row in cur.fetchall()
                ]

    # --- helpers ------------------------------------------------------------
    def all_rows(self) -> list[dict[str, Any]]:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM audit_events ORDER BY id")
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        # Nothing to hold open: each operation uses its own short-lived connection.
        pass
