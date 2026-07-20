"""Phase 3 tests: HTTP transport, authentication, and the HITL approval flow.

The e2e tests boot the real HTTP gateway (uvicorn, random port, SQLite backend)
inside the test process, then drive it exactly as production traffic would:
an MCP client with a Bearer key on /mcp, and an httpx admin client on /api.
"""

from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager

import httpx
import pytest
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from guardrail.config import DEFAULT_POLICY_PATH
from guardrail.policy import DecisionRule, PolicyEngine, load_policy
from guardrail.policy.state import InMemoryStateStore

SUPPORT_KEY = "test-key-support"
READONLY_KEY = "test-key-readonly"
ADMIN_KEY = "test-admin-key"


# ---------------------------------------------------------------------------
# Engine-level approval logic (pure, fast)
# ---------------------------------------------------------------------------

class TestApprovalPolicy:
    @pytest.fixture
    def engine(self):
        return PolicyEngine(load_policy(DEFAULT_POLICY_PATH))

    @pytest.fixture
    def state(self):
        s = InMemoryStateStore()
        s._clock = 1_000_000.0
        return s

    def _eval(self, engine, state, amount):
        return engine.evaluate(
            agent_id="a1", role_name="support-agent", tool_name="issue_refund",
            arguments={"customer": "c", "amount": amount, "reason": "r"}, state=state,
        )

    def test_small_refund_needs_no_approval(self, engine, state):
        d = self._eval(engine, state, 15)
        assert d.allowed and not d.needs_approval

    def test_large_refund_needs_approval(self, engine, state):
        d = self._eval(engine, state, 30)  # > 20 triggers approval, <= 50 passes params
        assert not d.allowed and d.needs_approval
        assert d.rule is DecisionRule.APPROVAL
        assert d.spend_amount == 30  # carried for spend-cap accounting

    def test_hard_violation_beats_approval(self, engine, state):
        # amount > 50 violates the params constraint -> denied outright, never queued.
        d = self._eval(engine, state, 60)
        assert not d.allowed and not d.needs_approval
        assert d.rule is DecisionRule.PARAMS


# ---------------------------------------------------------------------------
# End-to-end over real HTTP
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def gateway(tmp_path, monkeypatch):
    """A live HTTP gateway on a random port, backed by a temp SQLite db."""
    monkeypatch.setenv("GUARDRAIL_DB_PATH", str(tmp_path / "audit.db"))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv(
        "GUARDRAIL_AGENT_KEYS",
        f"{SUPPORT_KEY}:support-01:support-agent,{READONLY_KEY}:reader-01:readonly-agent",
    )
    monkeypatch.setenv("GUARDRAIL_ADMIN_KEY", ADMIN_KEY)
    monkeypatch.setenv("GUARDRAIL_APPROVAL_TIMEOUT", "8")
    monkeypatch.setenv("GUARDRAIL_APPROVAL_POLL_INTERVAL", "0.1")

    from guardrail.gateway.http_app import create_app

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    )
    task = asyncio.create_task(server.serve())

    base = f"http://127.0.0.1:{port}"
    async with httpx.AsyncClient() as probe:  # wait until it accepts requests
        for _ in range(100):
            try:
                if (await probe.get(f"{base}/healthz")).status_code == 200:
                    break
            except httpx.TransportError:
                await asyncio.sleep(0.05)
        else:
            pytest.fail("gateway did not start")

    yield base

    server.should_exit = True
    await task


@asynccontextmanager
async def _mcp(base: str, key: str):
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {key}"},
        timeout=30,  # must exceed the 8s approval timeout: the call stays open
        follow_redirects=True,
    ) as http_client:
        async with streamable_http_client(
            f"{base}/mcp/", http_client=http_client
        ) as streams:
            yield streams


def _admin(base: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=base, headers={"X-Admin-Key": ADMIN_KEY})


async def test_no_key_is_rejected(gateway):
    async with httpx.AsyncClient(follow_redirects=True) as client:
        r = await client.post(f"{gateway}/mcp/", json={})
        assert r.status_code == 401


async def test_admin_api_requires_key(gateway):
    async with httpx.AsyncClient() as client:
        assert (await client.get(f"{gateway}/api/approvals")).status_code == 401


async def test_authenticated_call_flows_end_to_end(gateway):
    async with _mcp(gateway, SUPPORT_KEY) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("query_database", {"query": "SELECT 1"})
    assert "[MOCK] Executed query" in result.content[0].text


async def test_role_comes_from_key_not_env(gateway):
    # The readonly key's role may not send email, whatever env vars say.
    async with _mcp(gateway, READONLY_KEY) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "send_email", {"to": "ada@example.com", "subject": "s", "body": "b"}
            )
    assert result.isError
    assert "DENIED (authz)" in result.content[0].text


async def test_approval_flow_approved(gateway):
    """A large refund parks in the queue; approving it releases the call."""
    async with _mcp(gateway, SUPPORT_KEY) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            call = asyncio.create_task(
                session.call_tool(
                    "issue_refund",
                    {"customer": "ada@example.com", "amount": 30, "reason": "late"},
                )
            )

            async with _admin(gateway) as admin:
                pending = []
                for _ in range(50):  # wait for the call to appear in the queue
                    r = await admin.get("/api/approvals", params={"status": "pending"})
                    pending = r.json()["approvals"]
                    if pending:
                        break
                    await asyncio.sleep(0.1)
                assert pending, "call never appeared in the approval queue"
                assert pending[0]["tool_name"] == "issue_refund"

                r = await admin.post(
                    f"/api/approvals/{pending[0]['correlation_id']}/decide",
                    json={"decision": "approve", "reviewer": "kaushik",
                          "note": "looks fine"},
                )
                assert r.status_code == 200

            result = await call

    assert not result.isError
    assert "[MOCK] Refund of 30.00" in result.content[0].text


async def test_approval_flow_denied(gateway):
    async with _mcp(gateway, SUPPORT_KEY) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            call = asyncio.create_task(
                session.call_tool(
                    "issue_refund",
                    {"customer": "ada@example.com", "amount": 45, "reason": "big"},
                )
            )

            async with _admin(gateway) as admin:
                pending = []
                for _ in range(50):
                    r = await admin.get("/api/approvals", params={"status": "pending"})
                    pending = r.json()["approvals"]
                    if pending:
                        break
                    await asyncio.sleep(0.1)
                assert pending
                await admin.post(
                    f"/api/approvals/{pending[0]['correlation_id']}/decide",
                    json={"decision": "deny", "reviewer": "kaushik", "note": "no"},
                )

            result = await call

    assert result.isError
    assert "DENIED (hitl)" in result.content[0].text

    # Double-deciding is refused: first decision wins.
    async with _admin(gateway) as admin:
        r = await admin.get("/api/approvals", params={"status": "denied"})
        cid = r.json()["approvals"][0]["correlation_id"]
        r = await admin.post(f"/api/approvals/{cid}/decide",
                             json={"decision": "approve"})
        assert r.status_code == 409


async def test_approval_timeout_fails_closed(gateway, monkeypatch):
    """Nobody answers -> the call is denied, and the queue records the timeout."""
    async with _mcp(gateway, SUPPORT_KEY) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(  # 8s approval timeout in fixture
                "issue_refund",
                {"customer": "ada@example.com", "amount": 25, "reason": "slow"},
            )

    assert result.isError
    assert "hitl_timeout" in result.content[0].text

    async with _admin(gateway) as admin:
        r = await admin.get("/api/approvals", params={"status": "timeout"})
        assert len(r.json()["approvals"]) == 1


async def test_audit_records_pending_then_final_verdict(gateway):
    """The audit trail for an approved call shows pending -> allow -> outcome."""
    async with _mcp(gateway, SUPPORT_KEY) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            call = asyncio.create_task(
                session.call_tool(
                    "issue_refund",
                    {"customer": "ada@example.com", "amount": 22, "reason": "r"},
                )
            )
            async with _admin(gateway) as admin:
                for _ in range(50):
                    r = await admin.get("/api/approvals", params={"status": "pending"})
                    if r.json()["approvals"]:
                        break
                    await asyncio.sleep(0.1)
                cid = r.json()["approvals"][0]["correlation_id"]
                await admin.post(f"/api/approvals/{cid}/decide",
                                 json={"decision": "approve"})
            await call

            async with _admin(gateway) as admin:
                calls = (await admin.get("/api/calls")).json()["calls"]

    ours = [c for c in calls if c["correlation_id"] == cid]
    assert ours and ours[0]["decision"] == "allow"      # final verdict wins
    assert ours[0]["decision_rule"] == "hitl"           # ...and it was a human's
    assert ours[0]["outcome"] == "success"
