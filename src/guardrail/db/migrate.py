"""Apply the database schema.

Deliberately minimal: the schema in schema.sql is written to be idempotent
(CREATE TABLE IF NOT EXISTS, CREATE OR REPLACE ...), so "migrating" is just
running it. A real project would graduate to Alembic or versioned migration
files once the schema starts changing in incompatible ways; this is the honest
minimum for now.

Run with:
    python -m guardrail.db.migrate
"""

from __future__ import annotations

from pathlib import Path

from guardrail.db.connection import connect

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def apply_schema() -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
    print(f"Applied schema from {SCHEMA_PATH.name}")


if __name__ == "__main__":
    apply_schema()
