"""Run the HTTP gateway under uvicorn.

    python -m guardrail.gateway.http_server

Environment (see .env.example): GUARDRAIL_AGENT_KEYS and GUARDRAIL_ADMIN_KEY
must be set or every request will be rejected (fail closed, by design).
"""

from __future__ import annotations

import os

import uvicorn

from guardrail.gateway.http_app import create_app


def main() -> None:
    host = os.environ.get("GUARDRAIL_HTTP_HOST", "127.0.0.1")
    port = int(os.environ.get("GUARDRAIL_HTTP_PORT", "8000"))
    uvicorn.run(create_app(), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
