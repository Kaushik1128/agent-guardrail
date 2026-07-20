"""Typed policy model.

These dataclasses are the in-memory shape of policy.yaml. Keeping them as
explicit types (rather than passing raw dicts around) means the engine reads
cleanly and a malformed config fails at load time with a clear error, not deep
inside a request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DecisionRule(str, Enum):
    """Which check produced a decision (also stored in the audit log)."""

    OK = "ok"                    # allowed - nothing objected
    AUTHZ = "authz"              # role not permitted to call this tool
    PARAMS = "params"            # an argument violated a constraint
    RATE_LIMIT = "rate_limit"    # too many calls in the window
    SPEND_CAP = "spend_cap"      # would exceed the spend cap
    APPROVAL = "approval"        # passed all checks but needs a human decision
    HITL = "hitl"                # a human decided (allow or deny)
    HITL_TIMEOUT = "hitl_timeout"  # no human decided in time -> denied


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule: DecisionRule
    reason: str
    # If this call represents spend (e.g. a refund amount), the engine records it
    # here so the audit log can sum it for future spend-cap checks.
    spend_amount: float | None = None
    # True when the call passed every hard check but policy requires a human to
    # sign off before it runs. `allowed` is False in that case - the call is not
    # allowed YET; the HITL flow may upgrade it after a human approves.
    needs_approval: bool = False


@dataclass(frozen=True)
class Constraint:
    """A single restriction on one argument of a tool call."""

    field: str
    max: float | None = None            # numeric ceiling (value <= max)
    min: float | None = None            # numeric floor   (value >= min)
    must_match: str | None = None       # regex the value MUST match (re.search)
    forbid_match: str | None = None     # regex the value must NOT match
    enum: tuple[str, ...] | None = None # value must be one of these
    max_length: int | None = None       # len(str(value)) <= max_length


@dataclass(frozen=True)
class Condition:
    """A trigger on one argument. Distinct from Constraint on purpose:
    a Constraint failing means DENY; a Condition matching means a consequence
    fires (here: human approval required). Mixing the two shapes invites
    inverted-logic bugs."""

    field: str
    gt: float | None = None
    gte: float | None = None
    lt: float | None = None
    lte: float | None = None
    equals: str | None = None       # compared as strings
    matches: str | None = None      # regex, re.search


@dataclass(frozen=True)
class ToolRule:
    """Permission to call one tool, plus any constraints on its arguments."""

    tool: str
    constraints: tuple[Constraint, ...] = ()
    # Human-in-the-loop: 'always' queues every call of this tool for approval;
    # conditions queue only the calls that match (e.g. amount > 20).
    approval_always: bool = False
    approval_if: tuple[Condition, ...] = ()


@dataclass(frozen=True)
class RateLimit:
    max_calls: int
    per_seconds: int


@dataclass(frozen=True)
class SpendCap:
    """Cap on the cumulative value of a numeric argument to a tool, over a window."""

    tool: str
    field: str          # which numeric argument represents spend (e.g. "amount")
    max_total: float
    per_seconds: int


@dataclass(frozen=True)
class Role:
    name: str
    description: str = ""
    allowed_tools: dict[str, ToolRule] = field(default_factory=dict)
    rate_limit: RateLimit | None = None
    spend_caps: tuple[SpendCap, ...] = ()


@dataclass(frozen=True)
class Policy:
    roles: dict[str, Role]
    default_role: str | None = None

    def role(self, name: str | None) -> Role | None:
        if name and name in self.roles:
            return self.roles[name]
        if self.default_role:
            return self.roles.get(self.default_role)
        return None
