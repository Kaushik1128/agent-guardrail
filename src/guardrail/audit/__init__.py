"""Audit log: the append-only record of every request, decision, and outcome.

Two interchangeable backends implement the same small interface:

  * SqliteAuditLog  - zero-setup, used when DATABASE_URL is unset (and by tests).
  * PostgresAuditLog - the real Phase 2 store (append-only enforced by a trigger).

Both also serve as the policy *state store*: they can answer "how many calls has
this agent made recently" and "how much has it spent recently" straight from the
log, which is why the engine needs no separate counter tables.

Use `get_audit_log()` to get whichever backend the environment is configured for.
"""

from __future__ import annotations

from guardrail.audit.sqlite import SqliteAuditLog
from guardrail.db.connection import get_database_url


def get_audit_log():
    """Return the configured audit backend: Postgres if DATABASE_URL is set, else SQLite."""
    if get_database_url():
        # Imported lazily so SQLite-only runs don't require psycopg at import time.
        from guardrail.audit.postgres import PostgresAuditLog

        return PostgresAuditLog()

    from guardrail.config import get_db_path

    return SqliteAuditLog(get_db_path())


__all__ = ["get_audit_log", "SqliteAuditLog"]
