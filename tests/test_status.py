"""Tests for plugin status and path resolution."""
import os
import json
from pathlib import Path

import pytest


def test_status_without_env(tmp_path, monkeypatch):
    monkeypatch.delenv("HERMES_27K_LOG", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from plugin import status
    s = status()
    assert s["plugin"] == "hermes-iso27k"
    assert s["status"] in ("ok", "error")
    if s["status"] == "ok":
        assert "audit_log" in s
        assert "rules_loaded" in s


def test_status_with_explicit_log(tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("HERMES_27K_LOG", str(log))
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    # reset module-level store so it picks up new env
    import plugin.hooks as hooks
    hooks._store = None
    from plugin import status
    s = status()
    assert s.get("audit_log") == str(log)
