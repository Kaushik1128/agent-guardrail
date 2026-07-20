"""Agent Tool-Call Guardrail & Audit Layer.

A middleman that speaks MCP on both sides: it is an MCP *server* to the agent
and an MCP *client* to the real/mock tools. Every tool call passes through the
gateway, where it can be authorized, rate-limited, logged, and (later) routed to
a human for approval.
"""

__version__ = "0.1.0"
