"""Load and validate policy.yaml into the typed Policy model.

Validation is intentionally strict and fails loudly: a policy file with a typo
(a misspelled key, a missing field) should crash at startup with a clear message,
never silently disable a guardrail at request time. An open guardrail you didn't
notice is worse than no guardrail.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from guardrail.policy.models import (
    Constraint,
    Policy,
    RateLimit,
    Role,
    SpendCap,
    ToolRule,
)


class PolicyError(ValueError):
    """Raised when the policy file is malformed."""


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    if not path.exists():
        raise PolicyError(f"Policy file not found: {path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise PolicyError("Policy file must be a YAML mapping at the top level.")

    roles_raw = raw.get("roles")
    if not isinstance(roles_raw, dict) or not roles_raw:
        raise PolicyError("Policy must define at least one role under 'roles'.")

    roles: dict[str, Role] = {}
    for name, body in roles_raw.items():
        roles[name] = _parse_role(name, body or {})

    default_role = raw.get("default_role")
    if default_role is not None and default_role not in roles:
        raise PolicyError(f"default_role '{default_role}' is not a defined role.")

    return Policy(roles=roles, default_role=default_role)


def _parse_role(name: str, body: dict[str, Any]) -> Role:
    allowed: dict[str, ToolRule] = {}
    for entry in body.get("allow", []) or []:
        tool = entry.get("tool")
        if not tool:
            raise PolicyError(f"Role '{name}' has an allow entry with no 'tool'.")
        constraints = tuple(
            _parse_constraint(name, tool, c) for c in (entry.get("constraints") or [])
        )
        allowed[tool] = ToolRule(tool=tool, constraints=constraints)

    rate_limit = None
    if rl := body.get("rate_limit"):
        try:
            rate_limit = RateLimit(
                max_calls=int(rl["max_calls"]), per_seconds=int(rl["per_seconds"])
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError(f"Role '{name}' has an invalid rate_limit: {exc}") from exc

    spend_caps = []
    for sc in body.get("spend_caps", []) or []:
        try:
            spend_caps.append(
                SpendCap(
                    tool=sc["tool"],
                    field=sc["field"],
                    max_total=float(sc["max_total"]),
                    per_seconds=int(sc["per_seconds"]),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError(f"Role '{name}' has an invalid spend_cap: {exc}") from exc

    return Role(
        name=name,
        description=body.get("description", ""),
        allowed_tools=allowed,
        rate_limit=rate_limit,
        spend_caps=tuple(spend_caps),
    )


def _parse_constraint(role: str, tool: str, c: dict[str, Any]) -> Constraint:
    field = c.get("field")
    if not field:
        raise PolicyError(f"Role '{role}', tool '{tool}': constraint missing 'field'.")
    enum = c.get("enum")
    return Constraint(
        field=field,
        max=None if c.get("max") is None else float(c["max"]),
        min=None if c.get("min") is None else float(c["min"]),
        must_match=c.get("must_match"),
        forbid_match=c.get("forbid_match"),
        enum=tuple(str(v) for v in enum) if enum else None,
        max_length=None if c.get("max_length") is None else int(c["max_length"]),
    )
