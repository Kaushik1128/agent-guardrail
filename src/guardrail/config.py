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
    """The caller's identity. ASSERTED on stdio (set by whoever launches the
    gateway), not authenticated - real auth arrives with the HTTP transport."""
    return os.environ.get("GUARDRAIL_AGENT_ID", "demo-agent")


def get_agent_role() -> str | None:
    """The caller's role, used to look up its policy. Asserted, like the id."""
    return os.environ.get("GUARDRAIL_AGENT_ROLE")
