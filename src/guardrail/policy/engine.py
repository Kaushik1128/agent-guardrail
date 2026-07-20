"""The policy engine: evaluate one tool call into an ALLOW / DENY decision.

Checks run cheapest-and-most-fundamental first, and the FIRST failure wins
(fail-closed): authorization, then parameter constraints, then rate limit, then
spend cap. Anything not explicitly allowed is denied - an unknown role or an
un-listed tool never falls through to "allow".
"""

from __future__ import annotations

import re

from guardrail.policy.models import (
    Constraint,
    DecisionRule,
    Policy,
    PolicyDecision,
    Role,
)
from guardrail.policy.state import PolicyStateStore


class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate(
        self,
        *,
        agent_id: str,
        role_name: str | None,
        tool_name: str,
        arguments: dict | None,
        state: PolicyStateStore,
    ) -> PolicyDecision:
        arguments = arguments or {}
        role = self.policy.role(role_name)

        # 1. Authorization: known role, and the tool is on its allowlist.
        if role is None:
            return PolicyDecision(
                False, DecisionRule.AUTHZ, f"Unknown role: {role_name!r}."
            )
        tool_rule = role.allowed_tools.get(tool_name)
        if tool_rule is None:
            return PolicyDecision(
                False,
                DecisionRule.AUTHZ,
                f"Role '{role.name}' is not permitted to call '{tool_name}'.",
            )

        # 2. Parameter constraints.
        for constraint in tool_rule.constraints:
            problem = _check_constraint(constraint, arguments)
            if problem:
                return PolicyDecision(False, DecisionRule.PARAMS, problem)

        # 3. Rate limit (needs history).
        if role.rate_limit:
            recent = state.count_requests(agent_id, role.rate_limit.per_seconds)
            # `recent` counts prior calls; deny once the window is already full.
            if recent >= role.rate_limit.max_calls:
                return PolicyDecision(
                    False,
                    DecisionRule.RATE_LIMIT,
                    f"Rate limit exceeded: {role.rate_limit.max_calls} calls "
                    f"per {role.rate_limit.per_seconds}s (already {recent}).",
                )

        # 4. Spend cap (needs history). Also computes this call's spend so an
        #    ALLOW decision can be logged with the amount for future sums.
        spend_amount = _spend_for_call(role, tool_name, arguments)
        if spend_amount is not None:
            cap = next(c for c in role.spend_caps if c.tool == tool_name)
            already = state.sum_allowed_spend(agent_id, tool_name, cap.per_seconds)
            if already + spend_amount > cap.max_total:
                return PolicyDecision(
                    False,
                    DecisionRule.SPEND_CAP,
                    f"Spend cap exceeded: {cap.max_total} per {cap.per_seconds}s "
                    f"(already {already}, this call {spend_amount}).",
                )

        return PolicyDecision(
            True, DecisionRule.OK, "Allowed by policy.", spend_amount=spend_amount
        )


def _spend_for_call(role: Role, tool_name: str, arguments: dict) -> float | None:
    """The spend this call represents, per the role's spend caps (or None)."""
    cap = next((c for c in role.spend_caps if c.tool == tool_name), None)
    if cap is None:
        return None
    try:
        return float(arguments.get(cap.field))
    except (TypeError, ValueError):
        # Missing/non-numeric spend field on a capped tool: treat as no spend.
        # The parameter constraints (min/max on the field) should already have
        # rejected a bad value before we get here.
        return None


def _check_constraint(c: Constraint, arguments: dict) -> str | None:
    """Return a human-readable problem string, or None if the constraint holds."""
    if c.field not in arguments:
        return f"Missing required argument '{c.field}'."
    value = arguments[c.field]

    if c.enum is not None and str(value) not in c.enum:
        return f"'{c.field}'={value!r} is not one of {list(c.enum)}."

    if c.max_length is not None and len(str(value)) > c.max_length:
        return f"'{c.field}' is too long (max {c.max_length} chars)."

    if c.must_match is not None and not re.search(c.must_match, str(value)):
        return f"'{c.field}'={value!r} must match /{c.must_match}/."

    if c.forbid_match is not None and re.search(c.forbid_match, str(value)):
        return f"'{c.field}'={value!r} matches forbidden pattern /{c.forbid_match}/."

    if c.max is not None or c.min is not None:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return f"'{c.field}'={value!r} must be numeric."
        if c.max is not None and numeric > c.max:
            return f"'{c.field}'={numeric} exceeds max {c.max}."
        if c.min is not None and numeric < c.min:
            return f"'{c.field}'={numeric} is below min {c.min}."

    return None
