"""End-to-end gateway tests over the real MCP protocol path (SQLite backend).

Each test launches the real gateway over stdio (which spawns the real mock-tools
server), talks to it as a client, and inspects the SQLite audit log. The gateway
runs as the `support-agent` role. Nothing is mocked out.
"""

from __future__ import annotations

import os
import sys

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from guardrail.audit.sqlite import SqliteAuditLog


def _gateway_params(db_path: str, role: str = "support-agent") -> StdioServerParameters:
    env = dict(os.environ)
    env["GUARDRAIL_DB_PATH"] = db_path
    env["GUARDRAIL_AGENT_ROLE"] = role
    env["GUARDRAIL_AGENT_ID"] = "test-agent"
    env.pop("DATABASE_URL", None)  # force the SQLite backend for these tests
    return StdioServerParameters(
        command=sys.executable, args=["-m", "guardrail.gateway.server"], env=env
    )


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "audit.db")


async def _call(db_path, tool, args, role="support-agent"):
    async with stdio_client(_gateway_params(db_path, role)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(tool, args)


async def test_lists_downstream_tools(db_path):
    async with stdio_client(_gateway_params(db_path)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
    assert {"send_email", "query_database", "issue_refund"} <= tools


async def test_allowed_call_is_forwarded(db_path):
    result = await _call(db_path, "query_database", {"query": "SELECT 1"})
    assert "[MOCK] Executed query" in result.content[0].text
    assert not result.isError


async def test_denied_call_is_not_forwarded(db_path):
    # Mutating query violates the parameter constraint -> gateway denies it.
    result = await _call(db_path, "query_database", {"query": "DROP TABLE users"})
    text = result.content[0].text
    assert "[guardrail] DENIED" in text
    assert "params" in text
    # The mock tool must NOT have run.
    assert "[MOCK]" not in text


async def test_role_without_tool_is_denied(db_path):
    # readonly-agent cannot send email at all.
    result = await _call(
        db_path, "send_email",
        {"to": "ada@example.com", "subject": "s", "body": "b"},
        role="readonly-agent",
    )
    assert "[guardrail] DENIED (authz)" in result.content[0].text


async def test_audit_captures_request_decision_outcome(db_path):
    await _call(db_path, "query_database", {"query": "SELECT 1"})

    audit = SqliteAuditLog(db_path)
    rows = audit.all_rows()
    audit.close()

    by_type = {r["event_type"]: r for r in rows}
    assert set(by_type) == {"request", "decision", "outcome"}
    # All three events share one correlation id.
    assert len({r["correlation_id"] for r in rows}) == 1

    assert by_type["decision"]["decision"] == "allow"
    assert by_type["decision"]["decision_rule"] == "ok"
    assert by_type["outcome"]["outcome"] == "success"


async def test_denied_call_has_no_outcome_event(db_path):
    await _call(db_path, "query_database", {"query": "DELETE FROM t"})

    audit = SqliteAuditLog(db_path)
    types_logged = {r["event_type"] for r in audit.all_rows()}
    audit.close()

    # Denied calls are audited (request + decision) but never forwarded (no outcome).
    assert types_logged == {"request", "decision"}
