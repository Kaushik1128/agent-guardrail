"""Phase 1 end-to-end tests: prove the proxy plumbing and audit logging work.

Each test spins up the real gateway over stdio (which spawns the real mock-tools
server), talks to it as a client, and then inspects the SQLite audit log. Nothing
is mocked out - this exercises the actual protocol path.
"""

from __future__ import annotations

import os
import sys

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from guardrail.gateway.audit import AuditLog


def _gateway_params(db_path: str) -> StdioServerParameters:
    env = dict(os.environ)
    env["GUARDRAIL_DB_PATH"] = db_path  # point the gateway at the test's temp DB
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "guardrail.gateway.server"],
        env=env,
    )


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "audit.db")


async def test_gateway_lists_downstream_tools(db_path):
    async with stdio_client(_gateway_params(db_path)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}

    assert {"send_email", "query_database"} <= tools


async def test_call_is_forwarded_and_returns_result(db_path):
    async with stdio_client(_gateway_params(db_path)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "send_email",
                {"to": "x@example.com", "subject": "hi", "body": "body"},
            )

    text = result.content[0].text
    assert "[MOCK] Email queued to x@example.com" in text
    assert not result.isError


async def test_every_call_is_audited(db_path):
    async with stdio_client(_gateway_params(db_path)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("query_database", {"query": "SELECT 1"})

    audit = AuditLog(db_path)
    rows = audit.all_rows()
    audit.close()

    requests = [r for r in rows if r["event"] == "request"]
    outcomes = [r for r in rows if r["event"] == "outcome"]

    # Exactly one request and one outcome, sharing a correlation id.
    assert len(requests) == 1
    assert len(outcomes) == 1
    assert requests[0]["correlation_id"] == outcomes[0]["correlation_id"]

    assert requests[0]["tool_name"] == "query_database"
    assert requests[0]["decision"] == "allow"
    assert "SELECT 1" in requests[0]["arguments_json"]

    assert outcomes[0]["outcome"] == "success"
    assert "[MOCK] Executed query" in outcomes[0]["result_json"]
