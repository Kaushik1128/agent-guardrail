"""The gateway MCP server (Phase 1: a transparent, logging proxy).

The gateway is simultaneously:

  * an MCP **server**, facing the agent (it answers tools/list and tools/call), and
  * an MCP **client**, facing the downstream mock-tools server (it forwards calls).

To the agent it is indistinguishable from the real tool server - same protocol,
same schemas. That transparency is the whole design: every call is funnelled
through one chokepoint (`_handle_call_tool`) where we can log it and, from
Phase 2 on, authorize / rate-limit / pause it for human approval.

We use the *low-level* `Server` API here (not FastMCP) because the gateway does
not know its tools ahead of time - it mirrors whatever the downstream server
exposes, discovered at runtime.

Run standalone with:
    python -m guardrail.gateway.server
(though you normally launch it via a client, e.g. scripts/run_agent_demo.py)
"""

from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from guardrail.config import get_db_path
from guardrail.gateway.audit import AuditLog

# Phase 1 has no real identity; every call is attributed to this placeholder.
# In Phase 2 the agent's identity/role arrives with the request instead.
DEFAULT_AGENT_ID = "demo-agent"


def build_downstream_params() -> StdioServerParameters:
    """How the gateway launches the downstream mock-tools server as a subprocess.

    We reuse the *current* interpreter (sys.executable) so the child runs inside
    the same virtualenv, and pass through os.environ so it inherits PYTHONPATH,
    the editable install, etc.
    """
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "guardrail.mock_tools.server"],
        env=dict(os.environ),
    )


@dataclass
class GatewayContext:
    """Shared state made available to every request handler via the lifespan."""

    downstream: ClientSession
    audit: AuditLog


def create_server() -> Server:
    """Build the gateway server with its handlers and downstream lifespan wired up."""

    @asynccontextmanager
    async def lifespan(_server: Server):
        """Open the downstream connection once, for the gateway's whole lifetime.

        The gateway *is a client* here: it spawns the mock-tools server, does the
        MCP handshake (`initialize`), and keeps the session open. Every proxied
        call rides this one session.
        """
        audit = AuditLog(get_db_path())
        async with stdio_client(build_downstream_params()) as (read, write):
            async with ClientSession(read, write) as downstream:
                await downstream.initialize()
                try:
                    yield GatewayContext(downstream=downstream, audit=audit)
                finally:
                    audit.close()

    server = Server("guardrail-gateway", lifespan=lifespan)

    @server.list_tools()
    async def _handle_list_tools() -> list[types.Tool]:
        """Mirror the downstream tool list verbatim.

        The agent asks us what tools exist; we ask downstream and pass the answer
        straight through. (A future phase could *filter* this list per role so an
        agent never even sees tools it may not call.)
        """
        ctx: GatewayContext = server.request_context.lifespan_context
        result = await ctx.downstream.list_tools()
        return result.tools

    @server.call_tool()
    async def _handle_call_tool(name: str, arguments: dict | None):
        """The single chokepoint: log -> forward -> log outcome -> return.

        This is where policy, rate limiting, and HITL approval will slot in
        during later phases. For now it is a transparent, fully-audited pass-through.

        Return contract (low-level SDK): returning a ``(content, structured)``
        tuple forwards *both* the text blocks and the structured payload. We must
        forward structured content because we also mirror the downstream tool's
        ``outputSchema`` in list_tools - and a tool that advertises an output
        schema is required to return structured content, or the call is rejected.
        """
        ctx: GatewayContext = server.request_context.lifespan_context
        correlation_id = ctx.audit.new_correlation_id()

        # 1. Record the request BEFORE doing anything with it.
        ctx.audit.log_request(
            correlation_id,
            tool_name=name,
            arguments=arguments,
            agent_id=DEFAULT_AGENT_ID,
            decision="allow",  # Phase 1: everything is allowed.
        )

        # 2. Forward to the real (mock) tool.
        try:
            result = await ctx.downstream.call_tool(name, arguments or {})
        except Exception as exc:  # transport/protocol failure talking downstream
            ctx.audit.log_outcome(
                correlation_id, name, outcome="error", error=repr(exc)
            )
            # Surface a clean error to the agent instead of leaking a stack trace.
            return [types.TextContent(type="text", text=f"[gateway] call failed: {exc}")]

        # 3. Record the outcome. `isError` is the tool telling us it failed
        #    logically (e.g. bad query) as opposed to a transport failure above.
        text_parts = [
            block.text for block in result.content
            if isinstance(block, types.TextContent)
        ]
        ctx.audit.log_outcome(
            correlation_id,
            name,
            outcome="error" if result.isError else "success",
            result="\n".join(text_parts) if text_parts else None,
            error="\n".join(text_parts) if result.isError else None,
        )

        # 4. Hand the downstream result back to the agent unchanged. Forward
        #    structured content alongside the text so schema validation passes.
        if result.structuredContent is not None:
            return list(result.content), result.structuredContent
        return list(result.content)

    return server


async def run() -> None:
    """Serve the gateway over stdio."""
    server = create_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    import anyio

    anyio.run(run)


if __name__ == "__main__":
    main()
