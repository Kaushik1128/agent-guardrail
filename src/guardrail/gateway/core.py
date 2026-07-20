"""The transport-independent call pipeline.

Both transports (stdio and Streamable HTTP) funnel every tools/call through
`handle_tool_call`, so policy enforcement, auditing, and the HITL flow are
written once and cannot drift between transports.

Pipeline:

    evaluate policy
      -> DENY:            audit request+decision, return error result
      -> NEEDS APPROVAL:  audit 'pending', park in the approvals queue,
                          poll until a human decides or the timeout expires
                            approved -> audit 'allow' (rule=hitl), forward
                            denied   -> audit 'deny'  (rule=hitl), refuse
                            timeout  -> audit 'deny'  (rule=hitl_timeout), refuse
      -> ALLOW:           audit request+decision, forward, audit outcome

Why park-and-poll (vs. an in-process asyncio.Event): the approval arrives via a
DIFFERENT door - the REST API - possibly from a different process than the one
holding the parked call. Putting the pending state in the database means any
process can answer it, the queue survives a gateway restart, and the dashboard
reads it with a plain SELECT. The ~poll-interval of added latency is irrelevant
against a human's reaction time. The cost: the agent's HTTP client must keep the
tools/call request open for up to the approval timeout, so that timeout must be
shorter than the client's read timeout.
"""

from __future__ import annotations

from dataclasses import dataclass

import anyio
import mcp.types as types
from mcp.client.session import ClientSession

from guardrail.policy import PolicyEngine
from guardrail.policy.models import DecisionRule


@dataclass(frozen=True)
class AgentIdentity:
    """Who is calling. On HTTP this comes from an authenticated API key;
    on stdio it is asserted by the launching environment."""

    agent_id: str
    role: str | None


@dataclass
class GatewayDeps:
    """Everything the pipeline needs, wired once at startup."""

    downstream: ClientSession
    audit: object            # SqliteAuditLog | PostgresAuditLog
    approvals: object        # SqliteApprovalStore | PostgresApprovalStore
    engine: PolicyEngine
    approval_timeout: float
    poll_interval: float


def _error_result(text: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)], isError=True
    )


async def handle_tool_call(
    deps: GatewayDeps,
    identity: AgentIdentity,
    name: str,
    arguments: dict | None,
) -> types.CallToolResult:
    cid = deps.audit.new_correlation_id()

    # Evaluate BEFORE logging the request so this call is not counted against
    # its own rate limit (the state store sees prior events only).
    decision = deps.engine.evaluate(
        agent_id=identity.agent_id,
        role_name=identity.role,
        tool_name=name,
        arguments=arguments,
        state=deps.audit,
    )

    deps.audit.log_request(
        cid, agent_id=identity.agent_id, role=identity.role,
        tool_name=name, arguments=arguments,
    )
    deps.audit.log_policy_decision(
        cid, agent_id=identity.agent_id, role=identity.role,
        tool_name=name, decision=decision,
    )

    if decision.needs_approval:
        return await _await_approval(deps, identity, cid, name, arguments, decision)

    if not decision.allowed:
        return _error_result(
            f"[guardrail] DENIED ({decision.rule.value}): {decision.reason}"
        )

    return await _forward(deps, cid, name, arguments)


async def _await_approval(
    deps: GatewayDeps,
    identity: AgentIdentity,
    cid: str,
    name: str,
    arguments: dict | None,
    decision,
) -> types.CallToolResult:
    """Park the call in the approvals queue and poll until settled."""
    deps.approvals.create(
        cid,
        agent_id=identity.agent_id,
        role=identity.role,
        tool_name=name,
        arguments=arguments,
        reason=decision.reason,
    )

    async def _settle(status: str) -> types.CallToolResult | None:
        """Turn a settled approval status into the call's final result."""
        if status == "approved":
            # The human's verdict is itself an auditable decision. Carry the
            # spend amount on the ALLOW event so future spend-cap sums see it.
            deps.audit.log_decision(
                cid, agent_id=identity.agent_id, role=identity.role,
                tool_name=name, decision="allow", rule=DecisionRule.HITL.value,
                reason="Approved by human reviewer.",
                spend_amount=decision.spend_amount,
            )
            return await _forward(deps, cid, name, arguments)
        if status == "denied":
            deps.audit.log_decision(
                cid, agent_id=identity.agent_id, role=identity.role,
                tool_name=name, decision="deny", rule=DecisionRule.HITL.value,
                reason="Denied by human reviewer.",
            )
            return _error_result(
                "[guardrail] DENIED (hitl): a human reviewer denied this call."
            )
        return None  # still pending

    elapsed = 0.0
    while elapsed < deps.approval_timeout:
        await anyio.sleep(deps.poll_interval)
        elapsed += deps.poll_interval
        settled = await _settle(deps.approvals.status(cid))
        if settled is not None:
            return settled

    # Nobody decided in time: fail closed. mark_timeout is a compare-and-set
    # (only flips 'pending'), so if a reviewer decided in the instant after our
    # last poll, it returns False - honor their decision instead of timing out.
    if not deps.approvals.mark_timeout(cid):
        settled = await _settle(deps.approvals.status(cid))
        if settled is not None:
            return settled

    deps.audit.log_decision(
        cid, agent_id=identity.agent_id, role=identity.role,
        tool_name=name, decision="deny", rule=DecisionRule.HITL_TIMEOUT.value,
        reason=f"No human decision within {deps.approval_timeout:.0f}s.",
    )
    return _error_result(
        "[guardrail] DENIED (hitl_timeout): approval request timed out."
    )


async def _forward(
    deps: GatewayDeps, cid: str, name: str, arguments: dict | None
) -> types.CallToolResult:
    """Forward an allowed call downstream and audit the outcome."""
    try:
        result = await deps.downstream.call_tool(name, arguments or {})
    except Exception as exc:
        deps.audit.log_outcome(cid, tool_name=name, outcome="error", error=repr(exc))
        return _error_result(f"[gateway] call failed: {exc}")

    text_parts = [
        b.text for b in result.content if isinstance(b, types.TextContent)
    ]
    deps.audit.log_outcome(
        cid,
        tool_name=name,
        outcome="error" if result.isError else "success",
        result="\n".join(text_parts) if text_parts else None,
        error="\n".join(text_parts) if result.isError else None,
    )
    # Return the downstream CallToolResult verbatim - fully transparent, and it
    # bypasses output-schema re-validation at the gateway.
    return result
