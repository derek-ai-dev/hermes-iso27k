import os
import tempfile

from plugin.policy import PolicyEngine


def test_default_rules_loaded():
    engine = PolicyEngine(mode="permissive")
    assert len(engine.rules) >= 3


def test_match_deny_rule():
    engine = PolicyEngine(mode="enforce")
    decision = engine.evaluate(
        tool="terminal",
        args="echo > ~/.ssh/authorized_keys",
        path="",
    )
    assert decision is not None
    assert decision["action"] == "deny"
    assert decision["rule_id"] == "deny-write-ssh-auth"


def test_no_match():
    engine = PolicyEngine(mode="enforce")
    assert engine.evaluate(tool="terminal", args="ls", path="") is None


def test_permissive_downgrades_deny_to_flag():
    engine = PolicyEngine(mode="permissive")
    decision = engine.evaluate(
        tool="terminal",
        args="echo > ~/.ssh/authorized_keys",
        path="",
    )
    assert decision is not None
    assert decision["action"] == "flag"


def test_policy_file_loaded(monkeypatch, tmp_path):
    policy = tmp_path / "rules.yaml"
    policy.write_text(
        """
- id: custom-deny
  match:
    tool: web_request
    args_contains: example
  action: deny
  reason: custom
"""
    )
    engine = PolicyEngine(mode="enforce", policy_file=str(policy))
    decision = engine.evaluate(tool="web_request", args="curl example.com", path="")
    assert decision is not None
    assert decision["rule_id"] == "custom-deny"
    assert decision["action"] == "deny"
