"""Central configuration.

Kept deliberately tiny in Phase 1 - just enough to locate the audit database.
Anything environment-specific is read here so the rest of the code never touches
os.environ directly.
"""

from __future__ import annotations

import os
from pathlib import Path

# Repo root = two levels up from src/guardrail/config.py
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "audit.db"


DEFAULT_POLICY_PATH = PROJECT_ROOT / "policy.yaml"


def get_db_path() -> Path:
    """Location of the SQLite audit log (fallback when DATABASE_URL is unset).

    Overridable via GUARDRAIL_DB_PATH so tests can point at a temp file and the
    deployed service can point somewhere writable.
    """
    raw = os.environ.get("GUARDRAIL_DB_PATH")
    return Path(raw) if raw else DEFAULT_DB_PATH


def get_policy_path() -> Path:
    """Which policy.yaml the gateway loads."""
    raw = os.environ.get("GUARDRAIL_POLICY_PATH")
    return Path(raw) if raw else DEFAULT_POLICY_PATH


def get_agent_id() -> str:
    """The caller's identity on the STDIO transport only, where it is ASSERTED
    (set by whoever launches the gateway). The HTTP transport authenticates
    instead - see get_agent_keys()."""
    return os.environ.get("GUARDRAIL_AGENT_ID", "demo-agent")


def get_agent_role() -> str | None:
    """The caller's role on the stdio transport. Asserted, like the id."""
    return os.environ.get("GUARDRAIL_AGENT_ROLE")


# --- HTTP transport: authentication + HITL tuning ---------------------------

def get_agent_keys() -> dict[str, tuple[str, str]]:
    """API-key map for the HTTP transport: key -> (agent_id, role).

    Format: GUARDRAIL_AGENT_KEYS="key1:agent1:role1,key2:agent2:role2"
    Keys live in the environment (or a secret store in production) - never in
    git, and never in policy.yaml, which IS in git.
    """
    raw = os.environ.get("GUARDRAIL_AGENT_KEYS", "")
    keys: dict[str, tuple[str, str]] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) != 3:
            raise ValueError(
                f"GUARDRAIL_AGENT_KEYS entry must be key:agent_id:role, got {entry!r}"
            )
        key, agent_id, role = (p.strip() for p in parts)
        keys[key] = (agent_id, role)
    return keys


def get_admin_key() -> str | None:
    """Key required by the approve/deny endpoints. If unset, those endpoints
    reject everything - fail closed, never open."""
    return os.environ.get("GUARDRAIL_ADMIN_KEY") or None


def get_approval_timeout() -> float:
    """How long a call waits in the approval queue before being denied (seconds).

    Must be shorter than the agent's HTTP read timeout, since the tools/call
    request stays open while waiting.
    """
    return float(os.environ.get("GUARDRAIL_APPROVAL_TIMEOUT", "120"))


def get_approval_poll_interval() -> float:
    """How often the parked call re-checks the approvals table (seconds)."""
    return float(os.environ.get("GUARDRAIL_APPROVAL_POLL_INTERVAL", "0.5"))
