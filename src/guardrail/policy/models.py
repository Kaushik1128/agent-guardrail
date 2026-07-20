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

    OK = "ok"                  # allowed - nothing objected
    AUTHZ = "authz"            # role not permitted to call this tool
    PARAMS = "params"          # an argument violated a constraint
    RATE_LIMIT = "rate_limit"  # too many calls in the window
    SPEND_CAP = "spend_cap"    # would exceed the spend cap


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule: DecisionRule
    reason: str
    # If this call represents spend (e.g. a refund amount), the engine records it
    # here so the audit log can sum it for future spend-cap checks.
    spend_amount: float | None = None


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
class ToolRule:
    """Permission to call one tool, plus any constraints on its arguments."""

    tool: str
    constraints: tuple[Constraint, ...] = ()


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
