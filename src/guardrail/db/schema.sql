-- Audit schema (Phase 2).
--
-- One append-only table is the single source of truth. Everything else (the
-- per-call view, the rate-limit and spend queries) is derived from it. This is
-- deliberately idempotent so the migration runner can apply it repeatedly.

-- ---------------------------------------------------------------------------
-- audit_events: the immutable event stream.
--
-- Each tool call emits three rows sharing a correlation_id, in this order:
--   1. 'request'  - the call arrived (agent, role, tool, arguments)
--   2. 'decision' - the policy verdict (allow/deny, which rule, why)
--   3. 'outcome'  - what happened when/if it was forwarded (success/error)
--
-- Keeping these as separate append-only events (rather than one row we UPDATE)
-- means the log records what actually happened, in order, and can never be
-- quietly rewritten. It also lets the log double as policy state: a rate limit
-- is "how many request events did this agent emit recently", a spend cap is
-- "sum of amounts in recent decision events".
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
    id               BIGSERIAL PRIMARY KEY,                 -- total, monotonic order
    ts               TIMESTAMPTZ NOT NULL DEFAULT now(),
    correlation_id   UUID        NOT NULL,                  -- links the 3 events of one call
    event_type       TEXT        NOT NULL
                     CHECK (event_type IN ('request', 'decision', 'outcome')),

    agent_id         TEXT,
    role             TEXT,
    tool_name        TEXT,

    -- request events
    arguments        JSONB,

    -- decision events
    decision         TEXT CHECK (decision IN ('allow', 'deny')),
    decision_rule    TEXT,        -- which check fired: authz | params | rate_limit | spend_cap | ok
    decision_reason  TEXT,        -- human-readable explanation
    spend_amount     NUMERIC,     -- the spend this call represents, if any (for spend caps)

    -- outcome events
    outcome          TEXT CHECK (outcome IN ('success', 'error')),
    result           JSONB,
    error            TEXT
);

CREATE INDEX IF NOT EXISTS ix_audit_correlation ON audit_events (correlation_id);
CREATE INDEX IF NOT EXISTS ix_audit_ts          ON audit_events (ts);
CREATE INDEX IF NOT EXISTS ix_audit_agent_ts    ON audit_events (agent_id, ts);
CREATE INDEX IF NOT EXISTS ix_audit_event_type  ON audit_events (event_type);

-- ---------------------------------------------------------------------------
-- Enforce append-only at the DATABASE level, not just by convention.
-- Any UPDATE or DELETE raises - history cannot be rewritten, even by a bug or a
-- compromised app credential. (A DBA/superuser could still drop the trigger;
-- true tamper-evidence would add row hash-chaining, noted as future work.)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_events_reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_events_append_only ON audit_events;
CREATE TRIGGER trg_audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutation();

-- ---------------------------------------------------------------------------
-- v_tool_calls: one row per call, pivoted from the event stream, for the
-- dashboard. A view (not a second table) keeps this always-consistent with the
-- log and rebuildable for free - there is no projection to maintain.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_tool_calls AS
SELECT
    correlation_id,
    min(ts)                                                    AS started_at,
    max(ts)                                                    AS last_event_at,
    max(agent_id)                                              AS agent_id,
    max(role)                                                  AS role,
    max(tool_name)                                             AS tool_name,
    (array_agg(arguments)       FILTER (WHERE event_type = 'request'))[1]  AS arguments,
    max(decision)               FILTER (WHERE event_type = 'decision')     AS decision,
    max(decision_rule)          FILTER (WHERE event_type = 'decision')     AS decision_rule,
    max(decision_reason)        FILTER (WHERE event_type = 'decision')     AS decision_reason,
    max(outcome)                FILTER (WHERE event_type = 'outcome')      AS outcome,
    (array_agg(error)           FILTER (WHERE event_type = 'outcome'))[1]  AS error
FROM audit_events
GROUP BY correlation_id;
