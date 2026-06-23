import json
import os
import tempfile
from pathlib import Path

from plugin.audit_store import AuditStore


def test_genesis_chain_empty():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "audit.jsonl"
        store = AuditStore(path=str(path))
        assert store.verify() == {"ok": True, "entries": 0}


def test_append_and_verify():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "audit.jsonl"
        store = AuditStore(path=str(path))
        store.append("tool_call", tool="terminal", args_summary="ls", result_summary="out")
        result = store.verify()
        assert result["ok"] is True
        assert result["entries"] == 1


def test_tamper_detection():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "audit.jsonl"
        store = AuditStore(path=str(path))
        store.append("tool_call", tool="terminal", args_summary="ls", result_summary="out")
        original = path.read_text().rstrip("\n")
        tamper = json.dumps(
            {
                "sequence": 1,
                "timestamp": "2099-01-01T00:00:00+00:00",
                "event_type": "tool_call",
                "tool": "terminal",
                "args_summary": "hacked",
                "result_summary": "bad",
                "control_hints": [],
                "prev_hash": "0" * 64,
                "hash": "abcd",
            }
        )
        path.write_text(original + "\n" + tamper + "\n")
        result = store.verify()
        assert result["ok"] is False


def test_chain_break_detected():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "audit.jsonl"
        store = AuditStore(path=str(path))
        store.append("tool_call", tool="read_file", args_summary="/etc/passwd", result_summary="...")
        store.append("tool_call", tool="write_file", args_summary="x", result_summary="y")
        lines = path.read_text().splitlines()
        entry = json.loads(lines[1])
        entry["prev_hash"] = "bad"
        lines[1] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n")
        result = store.verify()
        assert result["ok"] is False
        assert result.get("error") == "hash break at line 2"
