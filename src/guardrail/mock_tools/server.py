"""Mock tools MCP server.

Exposes two fake tools over stdio using the high-level FastMCP API. FastMCP is
the ergonomic choice here because the tool set is *static* and known ahead of
time - each tool is just a decorated function, and FastMCP derives the JSON
Schema from the type hints automatically.

Run standalone (mostly for debugging) with:
    python -m guardrail.mock_tools.server
"""

from __future__ import annotations

import uuid

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mock-tools")


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Pretend to send an email. Returns a fake confirmation - nothing leaves the box."""
    message_id = uuid.uuid4().hex[:12]
    return (
        f"[MOCK] Email queued to {to} | subject={subject!r} "
        f"| {len(body)} chars | message_id={message_id}"
    )


@mcp.tool()
def query_database(query: str) -> str:
    """Pretend to run a read-only query. Returns canned rows - no real database."""
    # Deterministic canned response so tests and the demo are stable.
    return (
        f"[MOCK] Executed query: {query!r}\n"
        "rows=2\n"
        "  1 | Ada Lovelace   | ada@example.com\n"
        "  2 | Alan Turing    | alan@example.com"
    )


@mcp.tool()
def issue_refund(customer: str, amount: float, reason: str = "") -> str:
    """Pretend to issue a refund. Returns a fake confirmation - no money moves.

    Exists so the policy engine has something with a spend cap to guard.
    """
    txn_id = uuid.uuid4().hex[:12]
    return (
        f"[MOCK] Refund of {amount:.2f} issued to {customer} "
        f"| reason={reason!r} | txn_id={txn_id}"
    )


if __name__ == "__main__":
    # stdio transport: this process reads JSON-RPC on stdin, writes on stdout.
    mcp.run(transport="stdio")
