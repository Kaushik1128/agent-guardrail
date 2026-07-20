"""End-to-end demo: an MCP client driving the gateway.

This script plays the role the LangGraph agent will play in Phase 5. It:
  1. spawns the gateway (which in turn spawns the mock-tools server),
  2. lists the tools the gateway exposes,
  3. calls send_email and query_database through it,
  4. prints the results and then the resulting audit-log rows.

Run with:
    python scripts/run_agent_demo.py
"""

from __future__ import annotations

import asyncio
import os
import sys

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

# Make `guardrail` importable when run as a loose script (not just as a module).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from guardrail.config import get_db_path  # noqa: E402
from guardrail.gateway.audit import AuditLog  # noqa: E402


def gateway_params() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "guardrail.gateway.server"],
        env=dict(os.environ),
    )


async def main() -> None:
    print("Connecting to gateway (which will spawn the mock-tools server)...\n")
    async with stdio_client(gateway_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("Tools visible through the gateway:")
            for tool in tools.tools:
                print(f"  - {tool.name}: {tool.description}")
            print()

            print("Calling send_email...")
            r1 = await session.call_tool(
                "send_email",
                {"to": "ada@example.com", "subject": "Hello", "body": "Testing the gateway."},
            )
            print("  ->", r1.content[0].text, "\n")

            print("Calling query_database...")
            r2 = await session.call_tool(
                "query_database", {"query": "SELECT * FROM users LIMIT 2"}
            )
            print("  ->", r2.content[0].text, "\n")

    # Read back what the gateway logged.
    print("Audit log rows written:")
    audit = AuditLog(get_db_path())
    for row in audit.all_rows():
        detail = row["arguments_json"] if row["event"] == "request" else row["outcome"]
        print(f"  #{row['id']} [{row['event']:<7}] {row['tool_name']:<15} -> {detail}")
    audit.close()


if __name__ == "__main__":
    asyncio.run(main())
