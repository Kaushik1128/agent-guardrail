"""The policy state store: the two questions the engine asks about history.

Rate limiting and spend caps are the only parts of policy that depend on what
happened *before* this call. We funnel that into a tiny interface so the engine
stays pure and testable:

  * count_requests  -> "how many calls has this agent made in the last N seconds?"
  * sum_allowed_spend -> "how much has this agent spent on this tool in the last N seconds?"

The append-only audit log answers both by querying itself, so in production the
audit log *is* the state store (see guardrail.audit). InMemoryStateStore here is
a dependency-free implementation used by the engine's unit tests.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@runtime_checkable
class PolicyStateStore(Protocol):
    def count_requests(self, agent_id: str, within_seconds: int) -> int: ...

    def sum_allowed_spend(
        self, agent_id: str, tool: str, within_seconds: int
    ) -> float: ...


@dataclass
class _Req:
    agent_id: str
    ts: float


@dataclass
class _Spend:
    agent_id: str
    tool: str
    amount: float
    ts: float


@dataclass
class InMemoryStateStore:
    """A fake state store for unit tests - records requests and allowed spend."""

    requests: list[_Req] = field(default_factory=list)
    spends: list[_Spend] = field(default_factory=list)
    _clock: float | None = None  # override "now" for deterministic tests

    def now(self) -> float:
        return self._clock if self._clock is not None else time.time()

    # --- recording helpers (tests call these to set up history) -------------
    def record_request(self, agent_id: str, at: float | None = None) -> None:
        self.requests.append(_Req(agent_id, at if at is not None else self.now()))

    def record_spend(
        self, agent_id: str, tool: str, amount: float, at: float | None = None
    ) -> None:
        self.spends.append(
            _Spend(agent_id, tool, amount, at if at is not None else self.now())
        )

    # --- PolicyStateStore interface -----------------------------------------
    def count_requests(self, agent_id: str, within_seconds: int) -> int:
        cutoff = self.now() - within_seconds
        return sum(1 for r in self.requests if r.agent_id == agent_id and r.ts >= cutoff)

    def sum_allowed_spend(self, agent_id: str, tool: str, within_seconds: int) -> float:
        cutoff = self.now() - within_seconds
        return sum(
            s.amount
            for s in self.spends
            if s.agent_id == agent_id and s.tool == tool and s.ts >= cutoff
        )
