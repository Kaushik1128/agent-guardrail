# Agent Tool-Call Guardrail & Audit Layer

A security layer that sits between an AI agent and its tools. Every tool call the
agent makes is intercepted, authorized against policy, rate-limited, logged to an
append-only audit trail, and - for risky actions - held for human approval before
it runs.

The agent never talks to its tools directly. It talks to a **gateway** that speaks
the [Model Context Protocol (MCP)](https://modelcontextprotocol.io) on both sides,
so from the agent's point of view the gateway *is* the toolbox. Security controls
live in deterministic code the agent's prompt cannot talk its way past - which is
the whole point, since anything that reads untrusted input (emails, web pages,
retrieved documents) can be steered by it.

> **Status:** built in phases. **Phase 1 (gateway MVP + audit log) is complete.**
> Policy engine, HITL approval, dashboard, sample agent, and adversarial tests follow.

## Architecture

```
Agent (LangGraph) --wants to call a tool--> Gateway (MCP proxy)
                                                  |
                                                  v
                                          Policy Engine ---> Audit Log (Postgres)
                                                  |
                                                  v
                                          HITL Queue (for risky actions)
                                                  |
                                                  v
                                          Real / Mock Tool
```

### How the gateway works

The gateway is simultaneously:

- an MCP **server**, facing the agent (it answers `tools/list` and `tools/call`), and
- an MCP **client**, facing the downstream tools (it forwards approved calls).

That "server on one side, client on the other" shape means the gateway is a
transparent proxy: same protocol, same tool schemas. Every call funnels through a
single chokepoint (`_handle_call_tool`) where authorization, rate limiting, and
human-in-the-loop approval slot in as the project grows.

### Security framing (OWASP MCP Top 10)

The design maps directly onto the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
(2025, beta):

| Risk | How this project addresses it |
|------|-------------------------------|
| **MCP07** – Insufficient Authentication & Authorization | Role-based policy engine (Phase 2) is the core |
| **MCP08** – Lack of Audit & Telemetry | Append-only audit log of every request, decision, and outcome |
| **MCP02** – Privilege Escalation via Scope Creep | Explicit per-role allowlists, parameter constraints, spend caps |
| **MCP06** – Intent Flow Subversion | Can't stop prompt injection, but caps its blast radius; risky calls stall in HITL |
| **MCP05** – Command Injection & Execution | Parameter validation at the gateway (e.g. read-only query constraints) |

## Project layout

```
src/guardrail/
  config.py              # env-driven configuration (DB location, ...)
  mock_tools/
    server.py            # downstream MCP server: fake send_email + query_database (FastMCP)
  gateway/
    server.py            # the proxy: MCP server to the agent + MCP client to the tools
    audit.py             # append-only SQLite audit log
scripts/
  run_agent_demo.py      # end-to-end demo client (stands in for the Phase 5 agent)
tests/
  test_gateway.py        # end-to-end tests over the real MCP protocol path
```

## Getting started

Requires Python 3.10+ (developed on 3.13).

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -e ".[dev]"
```

### Run the demo

```bash
python scripts/run_agent_demo.py
```

This spawns the gateway (which spawns the mock-tools server), lists the tools,
calls `send_email` and `query_database` through the gateway, and prints the audit
rows the gateway wrote to `data/audit.db`.

### Run the tests

```bash
pytest
```

The tests are true end-to-end checks: they launch the real gateway over stdio and
assert on protocol behaviour and the resulting audit log - nothing is mocked out.

## Design decisions (Phase 1)

- **Two separate MCP servers, not one.** The mock-tools server is a completely
  ordinary MCP server that knows nothing about the gateway. This keeps the proxy
  honest - calls really do cross a protocol boundary, exactly as they will with
  real tools.
- **Low-level `Server` for the gateway, `FastMCP` for the mock tools.** The mock
  tools are static and known ahead of time, so FastMCP's decorator style is
  ideal. The gateway must mirror *whatever* the downstream exposes, discovered at
  runtime, so it uses the low-level API instead.
- **stdio transport.** Simplest to debug (no networking); the gateway spawns the
  mock server as a subprocess. This switches to Streamable HTTP in a later phase,
  when the HITL approval queue requires the gateway to be a long-running service.
- **Request and outcome are separate audit rows.** Each call writes a `request`
  row before forwarding and an `outcome` row after, linked by a `correlation_id`.
  The log therefore reflects what actually happened, in order, even across a
  crash - foreshadowing the request/decision/outcome separation of the Phase 2
  Postgres schema.
