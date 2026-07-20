"""The gateway MCP server (Phase 2: policy-enforcing, Postgres-audited proxy).

Still a transparent MCP proxy - an MCP server to the agent, an MCP client to the
downstream tools - but now every call passes through the policy engine before it
is forwarded, and every request/decision/outcome is written to the append-only
audit log.

The single chokepoint `_handle_call_tool` does, in order:
    1. evaluate policy   (sees only PRIOR history, so the current call doesn't
       count against its own rate limit)
    2. log the request and the decision (denied calls are audited too)
    3. if denied  -> return the reason to the agent, forward nothing
    4. if allowed -> forward downstream, then log the outcome

Identity note: on stdio the agent's id/role are ASSERTED via env vars by whoever
launches the gateway - not authenticated. Real per-agent auth arrives with the
HTTP transport in Phase 3.

Run standalone with:
    python -m guardrail.gateway.server
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

from guardrail.audit import get_audit_log
from guardrail.config import get_agent_id, get_agent_role, get_policy_path
from guardrail.policy import PolicyEngine, load_policy


def build_downstream_params() -> StdioServerParameters:
    """How the gateway launches the downstream mock-tools server as a subprocess."""
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "guardrail.mock_tools.server"],
        env=dict(os.environ),
    )


@dataclass
class GatewayContext:
    """Shared state available to every request handler via the lifespan."""

    downstream: ClientSession
    audit: object          # SqliteAuditLog | PostgresAuditLog (duck-typed)
    engine: PolicyEngine
    agent_id: str
    role: str | None


def create_server() -> Server:
    @asynccontextmanager
    async def lifespan(_server: Server):
        # Load policy once at startup; a malformed policy crashes here (loudly)
        # rather than silently failing open at request time.
        engine = PolicyEngine(load_policy(get_policy_path()))
        audit = get_audit_log()
        agent_id = get_agent_id()
        role = get_agent_role()

        async with stdio_client(build_downstream_params()) as (read, write):
            async with ClientSession(read, write) as downstream:
                await downstream.initialize()
                try:
                    yield GatewayContext(
                        downstream=downstream,
                        audit=audit,
                        engine=engine,
                        agent_id=agent_id,
                        role=role,
                    )
                finally:
                    audit.close()

    server = Server("guardrail-gateway", lifespan=lifespan)

    @server.list_tools()
    async def _handle_list_tools() -> list[types.Tool]:
        """Mirror the downstream tool list.

        (A future refinement could filter this per role so an agent never even
        sees tools it may not call - for now we expose all and enforce at call time.)
        """
        ctx: GatewayContext = server.request_context.lifespan_context
        result = await ctx.downstream.list_tools()
        return result.tools

    @server.call_tool()
    async def _handle_call_tool(name: str, arguments: dict | None):
        ctx: GatewayContext = server.request_context.lifespan_context
        cid = ctx.audit.new_correlation_id()

        # 1. Evaluate BEFORE logging the request, so this call is not counted
        #    against its own rate limit (the state store sees prior events only).
        decision = ctx.engine.evaluate(
            agent_id=ctx.agent_id,
            role_name=ctx.role,
            tool_name=name,
            arguments=arguments,
            state=ctx.audit,
        )

        # 2. Audit the request and the decision (denials are recorded too).
        ctx.audit.log_request(
            cid, agent_id=ctx.agent_id, role=ctx.role,
            tool_name=name, arguments=arguments,
        )
        ctx.audit.log_decision(
            cid, agent_id=ctx.agent_id, role=ctx.role,
            tool_name=name, decision=decision,
        )

        # 3. Denied: return an error result explaining why. Forward nothing, and
        #    write no outcome event (the call never ran). Returning a
        #    CallToolResult with isError=True is the faithful MCP way to say
        #    "the call was refused" - and it bypasses output-schema validation,
        #    which a bare content list (having no structured payload) would fail.
        if not decision.allowed:
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=f"[guardrail] DENIED ({decision.rule.value}): {decision.reason}",
                    )
                ],
                isError=True,
            )

        # 4. Allowed: forward downstream and record the outcome.
        try:
            result = await ctx.downstream.call_tool(name, arguments or {})
        except Exception as exc:
            ctx.audit.log_outcome(cid, tool_name=name, outcome="error", error=repr(exc))
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"[gateway] call failed: {exc}")],
                isError=True,
            )

        text_parts = [
            b.text for b in result.content if isinstance(b, types.TextContent)
        ]
        ctx.audit.log_outcome(
            cid,
            tool_name=name,
            outcome="error" if result.isError else "success",
            result="\n".join(text_parts) if text_parts else None,
            error="\n".join(text_parts) if result.isError else None,
        )

        # Return the downstream result verbatim - fully transparent. Returning a
        # CallToolResult forwards content, structured output, and isError as-is,
        # with no re-validation at the gateway.
        return result

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
