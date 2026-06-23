#!/usr/bin/env python3
"""Tests for vault redaction and hook events."""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HERMES_HOME"] = str(Path(__file__).resolve().parent.parent.parent.parent / ".hermes" / "profiles" / "iso27k-test")


def test_vault_redact_aws_key():
    from plugin.audit_store import _vault_redact
    text = "use AKIAIOSFODNN7EXAMPLE to access s3"
    assert "AKIA" not in _vault_redact(text)
    assert "REDACTED" in _vault_redact(text)


def test_vault_redact_api_key():
    from plugin.audit_store import _vault_redact
    text = "api_key = abcdef1234567890abcdef"
    out = _vault_redact(text)
    assert "abcdef1234567890abcdef" not in out


def test_vault_redact_token():
    from plugin.audit_store import _vault_redact
    text = "token = abcdef1234567890abcdef1234567890"
    out = _vault_redact(text)
    assert "abcdef1234567890abcdef1234567890" not in out


def test_vault_redact_no_false_positive():
    from plugin.audit_store import _vault_redact
    text = "hello world"
    assert _vault_redact(text) == text


def test_session_start_and_end_logged(tmp_path, monkeypatch):
    from plugin.hooks import on_session_start, on_session_end
    from plugin.audit_store import AuditStore
    log = tmp_path / "audit.jsonl"
    store = AuditStore(path=str(log))
    on_session_start("sid-1", store=store)
    on_session_end("sid-1", store=store)
    lines = log.read_text().splitlines()
    assert len(lines) == 2
    events = [json.loads(l)["event_type"] for l in lines]
    assert "session_start" in events
    assert "session_end" in events


def test_config_change_logged(tmp_path):
    from plugin.hooks import on_config_change
    from plugin.audit_store import AuditStore
    log = tmp_path / "audit.jsonl"
    store = AuditStore(path=str(log))
    on_config_change("foo", "old", "new", store=store)
    lines = log.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["event_type"] == "config_change"
    assert "old -> new" in entry["args_summary"]
