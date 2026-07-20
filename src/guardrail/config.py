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


def get_db_path() -> Path:
    """Location of the SQLite audit log.

    Overridable via GUARDRAIL_DB_PATH so tests can point at a temp file and the
    deployed service can point somewhere writable.
    """
    raw = os.environ.get("GUARDRAIL_DB_PATH")
    return Path(raw) if raw else DEFAULT_DB_PATH
