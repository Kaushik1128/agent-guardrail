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

> **Status:** built in phases.
> **Phase 1** (gateway MVP + audit log) and **Phase 2** (policy engine + Postgres)
> are complete. HITL approval, dashboard, sample agent, adversarial tests, and
> deployment follow.

## Architecture

```
Agent (LangGraph) --wants to call a tool--> Gateway (MCP proxy)
                                                  |
                                                  v
                                          Policy Engine ---> Audit Log (Postgres)
                                                  |
                                                  v
                                          HITL Queue (for risky actions)   <- Phase 3
                                                  |
                                                  v
                                          Real / Mock Tool
```

### How the gateway works

The gateway is simultaneously an MCP **server** (facing the agent) and an MCP
**client** (facing the downstream tools). That "server on one side, client on the
other" shape makes it a transparent proxy - same protocol, same tool schemas.
Every `tools/call` funnels through one chokepoint where policy is enforced and the
call is audited:

```
evaluate policy  ->  log request + decision  ->  DENY? return reason, stop
                                              ->  ALLOW? forward, log outcome
```

Policy is evaluated *before* the request is logged, so a call is never counted
against its own rate limit. Denied calls are still audited (request + decision),
they just never reach the tool.

### The audit log is also the policy state

The append-only log is the single source of truth, and it doubles as the policy
state store: a rate limit is "count this agent's recent `request` events", a spend
cap is "sum this agent's recent allowed `decision` amounts". No separate counter
tables to drift out of sync. (Trade-off: two simultaneous calls can race the check
- an accepted limitation at this scale, noted rather than hidden.)

### Security framing (OWASP MCP Top 10)

Maps onto the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (2025, beta):

| Risk | How this project addresses it | Status |
|------|-------------------------------|--------|
| **MCP07** – Insufficient Authn/Authz | Role-based policy engine: per-role tool allowlists | Phase 2 ✅ |
| **MCP08** – Lack of Audit & Telemetry | Append-only log of every request/decision/outcome, UPDATE/DELETE blocked by a DB trigger | Phase 2 ✅ |
| **MCP02** – Privilege Escalation / Scope Creep | Scope is *declared* (allowlists, param constraints, spend caps), never accumulated | Phase 2 ✅ |
| **MCP05** – Command Injection | Parameter validation, e.g. `query_database` must be a `SELECT` | Phase 2 ✅ |
| **MCP06** – Intent Flow Subversion | Can't stop prompt injection, but caps its blast radius; risky calls will stall in HITL | Phase 3 |

**Honest scope:** identity on the stdio transport is *asserted* by whoever
launches the gateway (env vars), not *authenticated*. Real per-agent auth
(API keys / OAuth) arrives with the HTTP transport in Phase 3. Saying otherwise
would be the wrong lesson - this is literally MCP07.

## Project layout

```
policy.yaml                    # the authorization surface (policy-as-code)
docker-compose.yml             # local Postgres
src/guardrail/
  config.py                    # env-driven config (DB, policy path, agent identity)
  mock_tools/server.py         # downstream MCP server: send_email, query_database, issue_refund
  gateway/server.py            # the proxy: MCP server to the agent + client to the tools
  policy/                      # the policy engine
    models.py                  #   typed policy (roles, constraints, limits, decisions)
    loader.py                  #   parse + validate policy.yaml (fails loud)
    engine.py                  #   evaluate() -> ALLOW / DENY, fail-closed
    state.py                   #   rate/spend state interface + in-memory impl for tests
  audit/                       # append-only audit log (two interchangeable backends)
    sqlite.py                  #   zero-setup fallback (and for tests)
    postgres.py                #   the real store
  db/
    schema.sql                 #   audit_events table + append-only trigger + v_tool_calls view
    migrate.py                 #   apply the schema
scripts/run_agent_demo.py      # end-to-end demo (allowed + denied calls)
tests/                         # policy unit tests + gateway e2e + Postgres integration
```

## Getting started

Requires Python 3.10+ (developed on 3.13). Postgres is optional for a first run.

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (source .venv/bin/activate on macOS/Linux)
pip install -e ".[dev]"
cp .env.example .env              # optional; edit if you want Postgres
```

### Run the demo (no Docker needed)

```bash
python scripts/run_agent_demo.py
```

Launches the gateway as the `support-agent` role and makes a mix of legitimate and
policy-violating calls, so you can watch some get allowed and others denied, then
prints the audit trail. Uses SQLite unless `DATABASE_URL` is set.

### Run with Postgres

```bash
docker compose up -d --wait db                 # start Postgres
export DATABASE_URL=postgresql://guardrail:guardrail@localhost:5432/guardrail
python -m guardrail.db.migrate                 # apply the schema
python scripts/run_agent_demo.py               # now logs to Postgres

# peek at the per-call view:
docker exec guardrail-db psql -U guardrail -d guardrail \
  -c "SELECT tool_name, decision, decision_rule, outcome FROM v_tool_calls;"
```

### Run the tests

```bash
pytest                                          # policy + gateway (SQLite)
DATABASE_URL=... pytest                          # also runs Postgres integration tests
```

Policy tests are pure and instant; gateway tests launch the real gateway over
stdio; Postgres tests verify the append-only trigger and the state queries against
a real database (skipped when `DATABASE_URL` is unset).

## Policy (policy-as-code)

Authorization lives in [`policy.yaml`](policy.yaml) - one reviewable file mapping
roles to the tools they may call, with argument constraints and limits. A call is
allowed only if the role lists the tool **and** every constraint passes **and**
limits aren't exceeded. Anything not listed is denied. Example:

```yaml
roles:
  support-agent:
    allow:
      - tool: query_database
        constraints:
          - field: query
            must_match: '^\s*SELECT\b'         # read-only
            forbid_match: '(?i)\b(insert|update|delete|drop)\b'
      - tool: issue_refund
        constraints:
          - field: amount
            min: 0
            max: 50                             # per-call cap
    rate_limit: { max_calls: 10, per_seconds: 60 }
    spend_caps:
      - { tool: issue_refund, field: amount, max_total: 200, per_seconds: 86400 }
```

## Design decisions

- **Static rules in git, dynamic state in the DB.** Policy is a version-controlled
  YAML file (reviewable diffs); the runtime state those rules need lives in the
  audit log. This is the split real authz systems (OPA, Cedar) make.
- **Append-only is enforced, not assumed.** A Postgres trigger raises on any
  `UPDATE`/`DELETE` of `audit_events`. History cannot be quietly rewritten.
- **Request / decision / outcome are separate events**, sharing a `correlation_id`,
  so the log records what actually happened in order - even across a crash.
- **Two audit backends behind one interface.** SQLite for zero-setup runs and
  tests, Postgres for real; selected by whether `DATABASE_URL` is set.
- **Low-level `Server` for the gateway, `FastMCP` for the mock tools.** The gateway
  mirrors whatever downstream exposes (discovered at runtime); the mock tools are
  static, so decorators fit.
- **stdio transport for now**, switching to Streamable HTTP in Phase 3 when the
  HITL approval queue requires a long-running service.
