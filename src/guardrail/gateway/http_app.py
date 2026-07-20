"""The gateway over Streamable HTTP: one service, two doors.

  * /mcp            - the MCP endpoint agents talk to (Streamable HTTP transport).
                      Requires an agent API key: Authorization: Bearer <key>.
  * /api/...        - the human/dashboard REST API: list pending approvals,
                      approve/deny, browse recent calls.
                      Requires the admin key: X-Admin-Key: <key>.
  * /healthz        - unauthenticated liveness probe.

Authentication model (this closes the Phase 2 "asserted identity" caveat):
agent API keys are mapped to (agent_id, role) via the GUARDRAIL_AGENT_KEYS env
var - the key proves WHO is calling, and policy.yaml decides what that role MAY
do. Keys live in the environment, never in git. Every /mcp message carries its
HTTP request into the tool handler (request_context.request), so identity is
authenticated per call, not per process.

The MCP transport runs STATELESS (each request self-contained): the gateway
keeps no per-session memory, which means it can restart or scale behind a load
balancer without breaking agents mid-conversation. All state that matters -
audit, rate windows, approvals - already lives in the database.
"""

from __future__ import annotations

import contextlib
import os
import sys

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount, Route


def JSONResponse(content, status_code: int = 200) -> Response:
    """JSON response with a tolerant encoder (datetimes/UUIDs from the DB
    stringify instead of raising, unlike starlette's strict JSONResponse)."""
    import json

    return Response(
        json.dumps(content, default=str),
        status_code=status_code,
        media_type="application/json",
    )

from guardrail.approvals import get_approval_store
from guardrail.audit import get_audit_log
from guardrail.config import (
    get_admin_key,
    get_agent_keys,
    get_approval_poll_interval,
    get_approval_timeout,
    get_policy_path,
)
from guardrail.gateway.core import AgentIdentity, GatewayDeps, handle_tool_call
from guardrail.policy import PolicyEngine, load_policy


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

def _agent_identity_from_headers(headers) -> AgentIdentity | None:
    """Resolve 'Authorization: Bearer <key>' to an identity, or None."""
    auth = headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    key = auth[7:].strip()
    entry = get_agent_keys().get(key)
    if entry is None:
        return None
    agent_id, role = entry
    return AgentIdentity(agent_id=agent_id, role=role)


def _is_admin(request: Request) -> bool:
    """Admin endpoints fail CLOSED: no admin key configured -> nobody gets in."""
    admin_key = get_admin_key()
    return admin_key is not None and request.headers.get("x-admin-key") == admin_key


# ---------------------------------------------------------------------------
# The MCP server behind /mcp
# ---------------------------------------------------------------------------

def _build_mcp_server(deps: GatewayDeps) -> Server:
    """Same handlers as the stdio gateway, but identity comes from the
    authenticated HTTP request that carried each message."""
    server = Server("guardrail-gateway")

    def _identity() -> AgentIdentity | None:
        request = server.request_context.request  # the Starlette Request
        if request is None:
            return None
        return _agent_identity_from_headers(request.headers)

    @server.list_tools()
    async def _handle_list_tools() -> list[types.Tool]:
        result = await deps.downstream.list_tools()
        return result.tools

    @server.call_tool()
    async def _handle_call_tool(name: str, arguments: dict | None):
        identity = _identity()
        if identity is None:
            # Defense in depth: the ASGI middleware already 401s unauthenticated
            # requests, but the chokepoint re-checks rather than trusting it.
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text", text="[guardrail] DENIED (auth): unknown API key."
                )],
                isError=True,
            )
        return await handle_tool_call(deps, identity, name, arguments)

    return server


# ---------------------------------------------------------------------------
# REST API for humans / the dashboard
# ---------------------------------------------------------------------------

async def _healthz(_request: Request) -> Response:
    return JSONResponse({"ok": True})


async def _list_approvals(request: Request) -> Response:
    if not _is_admin(request):
        return JSONResponse({"error": "admin key required"}, status_code=401)
    status = request.query_params.get("status")  # e.g. ?status=pending
    rows = request.app.state.approvals.list(status=status)
    return JSONResponse({"approvals": rows})


async def _decide_approval(request: Request) -> Response:
    if not _is_admin(request):
        return JSONResponse({"error": "admin key required"}, status_code=401)

    correlation_id = request.path_params["correlation_id"]
    body = await request.json()
    decision = body.get("decision")
    if decision not in ("approve", "deny"):
        return JSONResponse(
            {"error": "body must include decision: 'approve' or 'deny'"},
            status_code=400,
        )

    settled = request.app.state.approvals.decide(
        correlation_id,
        approve=(decision == "approve"),
        decided_by=body.get("reviewer", "admin"),
        note=body.get("note", ""),
    )
    if not settled:
        # Unknown id, or already decided / timed out: first decision wins.
        current = request.app.state.approvals.status(correlation_id)
        return JSONResponse(
            {"error": "not pending", "status": current}, status_code=409
        )
    return JSONResponse({"ok": True, "status": f"{decision}d"})


async def _recent_calls(request: Request) -> Response:
    if not _is_admin(request):
        return JSONResponse({"error": "admin key required"}, status_code=401)
    limit = min(int(request.query_params.get("limit", "50")), 500)
    return JSONResponse({"calls": request.app.state.audit.recent_calls(limit=limit)})


# ---------------------------------------------------------------------------
# App assembly
# ---------------------------------------------------------------------------

def _downstream_params() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "guardrail.mock_tools.server"],
        env=dict(os.environ),
    )


def create_app() -> Starlette:
    engine = PolicyEngine(load_policy(get_policy_path()))  # fail loud at build

    # The MCP server + session manager are created up front; the downstream
    # connection they use is filled in by the lifespan below.
    deps = GatewayDeps(
        downstream=None,  # set in lifespan
        audit=None,       # set in lifespan
        approvals=None,   # set in lifespan
        engine=engine,
        approval_timeout=get_approval_timeout(),
        poll_interval=get_approval_poll_interval(),
    )
    mcp_server = _build_mcp_server(deps)
    session_manager = StreamableHTTPSessionManager(
        app=mcp_server,
        stateless=True,       # no per-session memory: restart/scale freely
        json_response=True,   # plain JSON responses; no SSE stream to manage
    )

    async def mcp_asgi(scope, receive, send):
        # Cheap perimeter check: unauthenticated requests get a 401 before
        # touching the MCP machinery. The tool handler re-checks (defense in depth).
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        if _agent_identity_from_headers(headers) is None:
            response = JSONResponse({"error": "valid Bearer API key required"}, 401)
            await response(scope, receive, send)
            return
        await session_manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        audit = get_audit_log()
        approvals = get_approval_store()
        async with stdio_client(_downstream_params()) as (read, write):
            async with ClientSession(read, write) as downstream:
                await downstream.initialize()
                deps.downstream = downstream
                deps.audit = audit
                deps.approvals = approvals
                app.state.audit = audit
                app.state.approvals = approvals
                async with session_manager.run():
                    try:
                        yield
                    finally:
                        audit.close()
                        approvals.close()

    return Starlette(
        routes=[
            Route("/healthz", _healthz, methods=["GET"]),
            Route("/api/approvals", _list_approvals, methods=["GET"]),
            Route("/api/approvals/{correlation_id}/decide", _decide_approval,
                  methods=["POST"]),
            Route("/api/calls", _recent_calls, methods=["GET"]),
            Mount("/mcp", app=mcp_asgi),
        ],
        lifespan=lifespan,
    )
