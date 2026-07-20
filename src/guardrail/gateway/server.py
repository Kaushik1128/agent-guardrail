"""The gateway over STDIO transport.

Thin wrapper around the shared pipeline in guardrail.gateway.core - policy,
audit, and HITL behaviour are identical to the HTTP transport. What differs:

  * identity is ASSERTED via env vars (GUARDRAIL_AGENT_ID / GUARDRAIL_AGENT_ROLE)
    by whoever launches the process - fine for local dev, not for production.
    The HTTP transport (guardrail.gateway.http_app) authenticates instead.
  * approvals still work (state lives in the shared database), but a human must
    answer via the HTTP API of a separately-running gateway, or directly in the
    database - so for HITL flows you normally want the HTTP transport.

Run standalone with:
    python -m guardrail.gateway.server
"""

from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from guardrail.approvals import get_approval_store
from guardrail.audit import get_audit_log
from guardrail.config import (
    get_agent_id,
    get_agent_role,
    get_approval_poll_interval,
    get_approval_timeout,
    get_policy_path,
)
from guardrail.gateway.core import AgentIdentity, GatewayDeps, handle_tool_call
from guardrail.policy import PolicyEngine, load_policy


def build_downstream_params() -> StdioServerParameters:
    """How the gateway launches the downstream mock-tools server as a subprocess."""
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "guardrail.mock_tools.server"],
        env=dict(os.environ),
    )


def create_server() -> Server:
    @asynccontextmanager
    async def lifespan(_server: Server):
        # Load policy once at startup; a malformed policy crashes here (loudly)
        # rather than silently failing open at request time.
        engine = PolicyEngine(load_policy(get_policy_path()))
        audit = get_audit_log()
        approvals = get_approval_store()

        async with stdio_client(build_downstream_params()) as (read, write):
            async with ClientSession(read, write) as downstream:
                await downstream.initialize()
                try:
                    yield GatewayDeps(
                        downstream=downstream,
                        audit=audit,
                        approvals=approvals,
                        engine=engine,
                        approval_timeout=get_approval_timeout(),
                        poll_interval=get_approval_poll_interval(),
                    )
                finally:
                    audit.close()
                    approvals.close()

    server = Server("guardrail-gateway", lifespan=lifespan)

    @server.list_tools()
    async def _handle_list_tools() -> list[types.Tool]:
        """Mirror the downstream tool list."""
        deps: GatewayDeps = server.request_context.lifespan_context
        result = await deps.downstream.list_tools()
        return result.tools

    @server.call_tool()
    async def _handle_call_tool(name: str, arguments: dict | None):
        deps: GatewayDeps = server.request_context.lifespan_context
        identity = AgentIdentity(agent_id=get_agent_id(), role=get_agent_role())
        return await handle_tool_call(deps, identity, name, arguments)

    return server


async def run() -> None:
    server = create_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    import anyio

    anyio.run(run)


if __name__ == "__main__":
    main()
