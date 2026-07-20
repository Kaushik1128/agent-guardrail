"""The policy engine: decides ALLOW / DENY for each tool call.

Static rules live in a YAML file (policy-as-code, reviewable in git). The engine
is pure, deterministic logic; the only external thing it consults is a small
"state store" (how many calls recently, how much spent recently), which the audit
log satisfies - so the append-only log doubles as the policy state.
"""

from guardrail.policy.engine import PolicyEngine
from guardrail.policy.loader import load_policy
from guardrail.policy.models import DecisionRule, Policy, PolicyDecision

__all__ = ["PolicyEngine", "load_policy", "Policy", "PolicyDecision", "DecisionRule"]
