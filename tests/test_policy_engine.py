"""Unit tests for the policy engine - pure logic, no DB, no subprocesses.

These load the real policy.yaml and drive the engine against an in-memory state
store, so they run instantly and verify the actual shipped policy.
"""

from __future__ import annotations

import pytest

from guardrail.config import DEFAULT_POLICY_PATH
from guardrail.policy import DecisionRule, PolicyEngine, load_policy
from guardrail.policy.state import InMemoryStateStore


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(load_policy(DEFAULT_POLICY_PATH))


@pytest.fixture
def state() -> InMemoryStateStore:
    s = InMemoryStateStore()
    s._clock = 1_000_000.0  # frozen clock for deterministic windows
    return s


def _eval(engine, state, tool, args, role="support-agent", agent="a1"):
    return engine.evaluate(
        agent_id=agent, role_name=role, tool_name=tool, arguments=args, state=state
    )


# --- authorization ----------------------------------------------------------

def test_unknown_role_is_denied(engine, state):
    d = _eval(engine, state, "query_database", {"query": "SELECT 1"}, role="ghost")
    # Unknown role falls back to default_role (readonly-agent), which CAN query.
    assert d.allowed  # default role handles it
    # But a tool the default role lacks is denied:
    d2 = _eval(engine, state, "send_email",
               {"to": "x@example.com", "subject": "s", "body": "b"}, role="ghost")
    assert not d2.allowed and d2.rule is DecisionRule.AUTHZ


def test_tool_not_in_role_allowlist_is_denied(engine, state):
    d = _eval(engine, state, "send_email",
              {"to": "x@example.com", "subject": "s", "body": "b"},
              role="readonly-agent")
    assert not d.allowed and d.rule is DecisionRule.AUTHZ


# --- parameter constraints --------------------------------------------------

def test_select_query_allowed(engine, state):
    assert _eval(engine, state, "query_database", {"query": "SELECT * FROM t"}).allowed


def test_mutating_query_denied(engine, state):
    d = _eval(engine, state, "query_database", {"query": "DELETE FROM users"})
    assert not d.allowed and d.rule is DecisionRule.PARAMS


def test_external_email_denied(engine, state):
    d = _eval(engine, state, "send_email",
              {"to": "attacker@evil.com", "subject": "s", "body": "b"})
    assert not d.allowed and d.rule is DecisionRule.PARAMS


def test_internal_email_allowed(engine, state):
    assert _eval(engine, state, "send_email",
                 {"to": "ada@example.com", "subject": "s", "body": "b"}).allowed


def test_refund_over_cap_denied(engine, state):
    d = _eval(engine, state, "issue_refund",
              {"customer": "c", "amount": 51, "reason": "r"})
    assert not d.allowed and d.rule is DecisionRule.PARAMS


def test_negative_refund_denied(engine, state):
    d = _eval(engine, state, "issue_refund",
              {"customer": "c", "amount": -5, "reason": "r"})
    assert not d.allowed and d.rule is DecisionRule.PARAMS


def test_missing_required_argument_denied(engine, state):
    d = _eval(engine, state, "query_database", {})
    assert not d.allowed and d.rule is DecisionRule.PARAMS


# --- rate limiting ----------------------------------------------------------

def test_rate_limit_allows_up_to_max(engine, state):
    for _ in range(10):  # support-agent: 10 per 60s
        state.record_request("a1", at=state.now())
    # 10 prior calls already made -> the next is denied.
    d = _eval(engine, state, "query_database", {"query": "SELECT 1"})
    assert not d.allowed and d.rule is DecisionRule.RATE_LIMIT


def test_rate_limit_ignores_old_calls(engine, state):
    for _ in range(10):
        state.record_request("a1", at=state.now() - 120)  # 2 min ago, outside 60s
    d = _eval(engine, state, "query_database", {"query": "SELECT 1"})
    assert d.allowed


# --- spend caps -------------------------------------------------------------

def test_spend_under_cap_allowed_and_records_amount(engine, state):
    state.record_spend("a1", "issue_refund", 150, at=state.now())  # cap is 200/day
    # amount <= 20 so the HITL approval condition (amount > 20) does not fire.
    d = _eval(engine, state, "issue_refund",
              {"customer": "c", "amount": 20, "reason": "r"})
    assert d.allowed
    assert d.spend_amount == 20  # recorded so the audit log can sum it later


def test_spend_over_cap_denied(engine, state):
    state.record_spend("a1", "issue_refund", 180, at=state.now())
    d = _eval(engine, state, "issue_refund",
              {"customer": "c", "amount": 40, "reason": "r"})  # 180+40 > 200
    assert not d.allowed and d.rule is DecisionRule.SPEND_CAP


# --- ordering / fail-closed -------------------------------------------------

def test_authz_checked_before_params(engine, state):
    # readonly-agent can't send_email at all; even a valid-looking call is AUTHZ-denied.
    d = _eval(engine, state, "send_email",
              {"to": "ada@example.com", "subject": "s", "body": "b"},
              role="readonly-agent")
    assert d.rule is DecisionRule.AUTHZ
