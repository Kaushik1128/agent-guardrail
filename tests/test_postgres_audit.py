"""Postgres audit-backend integration tests.

Skipped automatically unless DATABASE_URL is set (i.e. `docker compose up -d db`
plus `python -m guardrail.db.migrate`). These verify the real append-only table,
the enforcing trigger, and the state-store queries.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("psycopg")

if not os.environ.get("DATABASE_URL"):
    pytest.skip("DATABASE_URL not set; skipping Postgres tests", allow_module_level=True)

import psycopg  # noqa: E402

from guardrail.audit.postgres import PostgresAuditLog  # noqa: E402
from guardrail.db.connection import connect  # noqa: E402
from guardrail.db.migrate import apply_schema  # noqa: E402
from guardrail.policy.models import DecisionRule, PolicyDecision  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _schema():
    apply_schema()


@pytest.fixture
def audit():
    # Isolate each test. TRUNCATE bypasses the row-level append-only trigger by
    # design; a hardened deployment would revoke TRUNCATE from the app role.
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE audit_events RESTART IDENTITY")
        conn.commit()
    return PostgresAuditLog()


def test_records_all_three_events_and_view(audit):
    cid = audit.new_correlation_id()
    audit.log_request(cid, agent_id="a1", role="support-agent",
                      tool_name="issue_refund", arguments={"amount": 30})
    audit.log_policy_decision(cid, agent_id="a1", role="support-agent", tool_name="issue_refund",
                              decision=PolicyDecision(True, DecisionRule.OK, "ok", spend_amount=30))
    audit.log_outcome(cid, tool_name="issue_refund", outcome="success", result="done")

    rows = audit.all_rows()
    assert {r["event_type"] for r in rows} == {"request", "decision", "outcome"}

    # The per-call view pivots the three events into one row.
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT decision, outcome, tool_name FROM v_tool_calls")
            decision, outcome, tool = cur.fetchone()
    assert (decision, outcome, tool) == ("allow", "success", "issue_refund")


def test_append_only_trigger_blocks_update_and_delete(audit):
    cid = audit.new_correlation_id()
    audit.log_request(cid, agent_id="a1", role="r", tool_name="t", arguments={})

    with connect() as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute("UPDATE audit_events SET tool_name='x'")
        conn.rollback()
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute("DELETE FROM audit_events")
        conn.rollback()


def test_state_queries(audit):
    for _ in range(3):
        audit.log_request(audit.new_correlation_id(), agent_id="a1", role="r",
                          tool_name="query_database", arguments={})
    assert audit.count_requests("a1", within_seconds=60) == 3
    assert audit.count_requests("other", within_seconds=60) == 0

    cid = audit.new_correlation_id()
    audit.log_policy_decision(cid, agent_id="a1", role="r", tool_name="issue_refund",
                              decision=PolicyDecision(True, DecisionRule.OK, "ok", spend_amount=40))
    assert audit.sum_allowed_spend("a1", "issue_refund", within_seconds=86400) == 40
