"""Postgres connection helper.

Thin wrapper around psycopg so the rest of the code never reads DATABASE_URL
directly. We use short-lived connections rather than a pool: at this project's
scale (a handful of tool calls per second) the simplicity is worth more than the
few milliseconds a pool would save, and it keeps the failure modes obvious.
"""

from __future__ import annotations

import os

import psycopg


def get_database_url() -> str | None:
    """The Postgres DSN, or None if we should fall back to SQLite."""
    return os.environ.get("DATABASE_URL")


def connect() -> psycopg.Connection:
    """Open a new Postgres connection. Caller is responsible for closing it."""
    url = get_database_url()
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set - cannot connect to Postgres. "
            "Start it with `docker compose up -d db` and copy .env.example to .env."
        )
    return psycopg.connect(url)
