"""HITL demo: watch a risky call park in the approval queue and get released.

Boots the HTTP gateway as a subprocess, then plays BOTH parts:
  * the agent (MCP client over streamable HTTP, authenticated with an API key)
  * the human reviewer (httpx against the admin API)

Sequence:
  1. small refund (amount 15)  -> allowed straight through
  2. large refund (amount 35)  -> parks as 'pending'; the "human" approves it
  3. large refund (amount 45)  -> parks as 'pending'; the "human" denies it

Run with:
    python scripts/run_hitl_demo.py
(Uses SQLite unless DATABASE_URL is set. No other services required.)
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

SUPPORT_KEY = "demo-key-support"
ADMIN_KEY = "demo-admin-key"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _reviewer(base: str, decision: str, note: str) -> None:
    """Poll for the pending approval, then decide it - the human's part."""
    async with httpx.AsyncClient(
        base_url=base, headers={"X-Admin-Key": ADMIN_KEY}
    ) as admin:
        for _ in range(100):
            r = await admin.get("/api/approvals", params={"status": "pending"})
            pending = r.json()["approvals"]
            if pending:
                item = pending[0]
                print(f"    [reviewer] sees pending: {item['tool_name']} "
                      f"{item['arguments']} ({item['reason']})")
                await asyncio.sleep(1.0)  # pretend to think about it
                await admin.post(
                    f"/api/approvals/{item['correlation_id']}/decide",
                    json={"decision": decision, "reviewer": "demo-human", "note": note},
                )
                print(f"    [reviewer] -> {decision.upper()} ({note})")
                return
            await asyncio.sleep(0.2)


async def main() -> None:
    port = _free_port()
    base = f"http://127.0.0.1:{port}"

    env = dict(os.environ)
    env.update({
        "GUARDRAIL_AGENT_KEYS": f"{SUPPORT_KEY}:demo-agent:support-agent",
        "GUARDRAIL_ADMIN_KEY": ADMIN_KEY,
        "GUARDRAIL_APPROVAL_TIMEOUT": "30",
        "GUARDRAIL_APPROVAL_POLL_INTERVAL": "0.2",
        "GUARDRAIL_HTTP_PORT": str(port),
    })
    print(f"Starting HTTP gateway on {base} ...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "guardrail.gateway.http_server"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        async with httpx.AsyncClient() as probe:
            for _ in range(100):
                try:
                    if (await probe.get(f"{base}/healthz")).status_code == 200:
                        break
                except httpx.TransportError:
                    await asyncio.sleep(0.1)
            else:
                raise RuntimeError("gateway did not start")
        print("Gateway up. Connecting as role=support-agent.\n")

        async with httpx.AsyncClient(
            headers={"Authorization": f"Bearer {SUPPORT_KEY}"},
            timeout=60, follow_redirects=True,
        ) as http_client:
            async with streamable_http_client(
                f"{base}/mcp/", http_client=http_client
            ) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()

                    print("1) issue_refund amount=15 (under approval threshold)")
                    r = await session.call_tool("issue_refund", {
                        "customer": "ada@example.com", "amount": 15, "reason": "late"})
                    print(f"    -> {r.content[0].text}\n")

                    print("2) issue_refund amount=35 (parks for approval...)")
                    reviewer = asyncio.create_task(_reviewer(base, "approve", "valid claim"))
                    r = await session.call_tool("issue_refund", {
                        "customer": "ada@example.com", "amount": 35, "reason": "damaged"})
                    await reviewer
                    print(f"    -> {r.content[0].text}\n")

                    print("3) issue_refund amount=45 (parks for approval...)")
                    reviewer = asyncio.create_task(_reviewer(base, "deny", "no evidence"))
                    r = await session.call_tool("issue_refund", {
                        "customer": "ada@example.com", "amount": 45, "reason": "vibes"})
                    await reviewer
                    print(f"    -> {r.content[0].text}\n")

        async with httpx.AsyncClient(
            base_url=base, headers={"X-Admin-Key": ADMIN_KEY}
        ) as admin:
            print("--- Recent calls (audit view) ---")
            for c in reversed((await admin.get("/api/calls")).json()["calls"]):
                print(f"  {c['tool_name']:<14} decision={c['decision']:<7} "
                      f"rule={c['decision_rule']:<12} outcome={c['outcome']}")
    finally:
        proc.terminate()


if __name__ == "__main__":
    asyncio.run(main())
