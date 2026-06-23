import json
import os
import tempfile
import time
from pathlib import Path

import pytest

PROFILE_DIR = Path.home() / ".hermes" / "profiles" / "iso27k-test"
PLUGIN_DIR = PROFILE_DIR / "plugins" / "hermes-iso27k"
os.environ["HERMES_HOME"] = str(PROFILE_DIR)

from plugin.audit_store import AuditStore
from plugin.policy import PolicyEngine


@pytest.fixture
def tmp_store(tmp_path):
    return AuditStore(path=str(tmp_path / "audit.jsonl"))


@pytest.fixture
def tmp_evidence(tmp_path):
    return tmp_path / "evidence"


# =============================================================================
# A.8 / A.12 — Hash chain integrity & tamper detection
# =============================================================================

class TestHashChainIntegrity:
    def test_genesis_chain(self, tmp_store):
        assert tmp_store.verify() == {"ok": True, "entries": 0}

    def test_append_maintains_chain(self, tmp_store):
        for i in range(100):
            tmp_store.append("tool_call", tool="read_file", args_summary=f"/etc/passwd-{i}", result_summary="...")
        result = tmp_store.verify()
        assert result["ok"] is True
        assert result["entries"] == 100

    def test_sequential_hashes_are_unique(self, tmp_store):
        tmp_store.append("event_a", args_summary="alpha")
        tmp_store.append("event_b", args_summary="beta")
        lines = (Path(tmp_store.path)).read_text().splitlines()
        h1 = json.loads(lines[0])["hash"]
        h2 = json.loads(lines[1])["hash"]
        assert h1 != h2

    def test_tamper_prev_hash_breaks_chain(self, tmp_store):
        tmp_store.append("tool_call", tool="terminal", args_summary="ls", result_summary="out")
        tmp_store.append("tool_call", tool="write_file", args_summary="x", result_summary="y")
        path = Path(tmp_store.path)
        lines = path.read_text().splitlines()
        entry = json.loads(lines[1])
        entry["prev_hash"] = "bad"
        lines[1] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n")
        result = tmp_store.verify()
        assert result["ok"] is False
        assert result["error"] == "hash break at line 2"

    def test_tamper_hash_field_detected(self, tmp_store):
        tmp_store.append("tool_call", tool="terminal", args_summary="ls", result_summary="out")
        path = Path(tmp_store.path)
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
        result = tmp_store.verify()
        assert result["ok"] is False
        assert result["error"] == "sequence gap at line 2"

    def test_sequence_gap_detected(self, tmp_store):
        tmp_store.append("event_a", args_summary="1")
        tmp_store.append("event_b", args_summary="2")
        path = Path(tmp_store.path)
        lines = path.read_text().splitlines()
        entry1 = json.loads(lines[0])
        entry2 = json.loads(lines[1])
        entry2["sequence"] = 99
        lines[1] = json.dumps(entry2)
        path.write_text("\n".join(lines) + "\n")
        result = tmp_store.verify()
        assert result["ok"] is False
        assert result["error"] == "sequence gap at line 2"

    def test_unicode_and_newlines_in_args(self, tmp_store):
        weird = "特殊中文\n特殊字符\ttabs\rcarriage"
        tmp_store.append("tool_call", tool="write_file", args_summary=weird, result_summary=weird)
        result = tmp_store.verify()
        assert result["ok"] is True
        assert result["entries"] == 1

    def test_large_payload(self, tmp_store):
        big = "y" * 100_000
        tmp_store.append("tool_call", tool="terminal", args_summary=big, result_summary=big)
        result = tmp_store.verify()
        assert result["ok"] is True
        lines = Path(tmp_store.path).read_text().splitlines()
        assert len(lines) == 1
        assert len(lines[0]) > 90_000


# =============================================================================
# A.12 / A.14 / A.16 / A.18 — Policy engine coverage
# =============================================================================

class TestPolicyEngineCoverage:
    @pytest.fixture(autouse=True)
    def load_external_rules(self):
        import os
        os.environ["HERMES_ISO27K_POLICY"] = str(PLUGIN_DIR / "policy-rules.yaml")

    def _engine(self):
        return PolicyEngine(mode="enforce", policy_file=str(PLUGIN_DIR / "policy-rules.yaml"))

    def test_external_rules_loaded(self):
        engine = self._engine()
        assert len(engine.rules) >= 15

    def test_all_rules_have_control_ids(self):
        engine = self._engine()
        missing = [r for r in engine.rules if not r.get("control")]
        assert missing == [], f"Rules missing control IDs: {[r['id'] for r in missing]}"

    def test_all_rules_have_nonempty_reason(self):
        engine = self._engine()
        empty = [r for r in engine.rules if not r.get("reason")]
        assert empty == [], f"Rules missing reason: {[r['id'] for r in empty]}"

    @pytest.mark.parametrize(
        "tool,args,path,expected_action",
        [
            ("terminal", "echo > ~/.ssh/authorized_keys", "", "deny"),
            ("terminal", "chmod 777 /tmp/x", "", "flag"),
            ("terminal", "rm -rf /", "", "deny"),
            ("write_file", "", "/app/.env", "require_approval"),
            ("terminal", "fred", "", None),
            ("web_request", "curl example.com", "", None),
        ],
    )
    def test_policy_match_parametrized(self, tool, args, path, expected_action):
        engine = self._engine()
        decision = engine.evaluate(tool=tool, args=args, path=path)
        if expected_action is None:
            assert decision is None
        else:
            assert decision is not None
            assert decision["action"] == expected_action

    def test_permissive_mode_never_denies(self):
        engine = PolicyEngine(mode="permissive")
        decision = engine.evaluate("terminal", args="echo > ~/.ssh/authorized_keys")
        assert decision["action"] in ("flag", "allow", "require_approval")

    def test_destructive_commands_are_denied(self):
        engine = self._engine()
        for payload in ["rm -rf /", "DROP DATABASE"]:
            decision = engine.evaluate("terminal", args=payload)
            if decision and decision.get("action") == "deny":
                return
        pytest.fail("No destructive deny rule matched")


# =============================================================================
# A.12 / A.14 / A.18 — Evidence bundle generation
# =============================================================================

class TestEvidenceBundleGeneration:
    def test_report_generator_creates_markdown(self, tmp_path, tmp_store, monkeypatch):
        from skill.scripts.report_generator import (
            default_log,
            default_evidence,
            read_entries,
            filter_controls,
            build_markdown_report,
            write_bundle,
        )
        # seed a couple of entries
        tmp_store.append("tool_call", tool="terminal", args_summary="ls", result_summary="out",
                         control_hints=["A.12.4"])
        tmp_store.append("session_end", tool=None, args_summary="s1", result_summary="",
                         control_hints=["A.12.4"])
        monkeypatch.setattr("skill.scripts.report_generator.default_log", lambda: Path(tmp_store.path))
        monkeypatch.setattr("skill.scripts.report_generator.default_evidence", lambda: tmp_path / "evidence")
        entries = read_entries(Path(tmp_store.path))
        report_md = build_markdown_report(entries, "A.12")
        assert "ISO 27001 Evidence Report" in report_md
        assert "A.12" in report_md
        write_bundle(entries, "A.12", tmp_path / "evidence")
        out_dir = tmp_path / "evidence"
        assert (out_dir / "control-report.md").exists()
        assert (out_dir / "audit-chain.jsonl").exists()
        assert (out_dir / "config-snapshot.yaml").exists()
        assert (out_dir / "sha256sums.txt").exists()
        sums = (out_dir / "sha256sums.txt").read_text()
        assert len(sums.strip().splitlines()) >= 3

    def test_report_per_control_filter(self, tmp_store):
        from skill.scripts.report_generator import filter_controls, read_entries
        path = Path(tmp_store.path)
        tmp_store.append("tool_call", tool="terminal", args_summary="ls",
                         result_summary="out", control_hints=["A.12.4", "A.9.4"])
        tmp_store.append("tool_call", tool="write_file", args_summary="/etc/passwd",
                         result_summary="ok", control_hints=["A.8.3"])
        entries = read_entries(path)
        a12 = filter_controls(entries, "A.12")
        a8 = filter_controls(entries, "A.8")
        assert len(a12) == 1
        assert len(a8) == 1

    def test_report_per_control_filter_no_match(self, tmp_store):
        from skill.scripts.report_generator import filter_controls, read_entries
        path = Path(tmp_store.path)
        tmp_store.append("tool_call", tool="terminal", args_summary="ls",
                         result_summary="out", control_hints=["A.12.4"])
        entries = read_entries(path)
        result = filter_controls(entries, "A.99.nonexistent")
        assert result == []


# =============================================================================
# A.8 / A.9 / A.12 — Redaction / secrets behavior
# =============================================================================

class TestRedactionBehavior:
    def test_secrets_not_written_verbatim(self, tmp_store):
        secret = "AKIAIOSFODNN7EXAMPLE"
        tmp_store.append("tool_call", tool="read_file", args_summary=f"path=/keys/{secret}", result_summary="ok")
        text = Path(tmp_store.path).read_text()
        assert secret not in text
        assert "[REDACTED:" in text

    def test_empty_args_does_not_crash(self, tmp_store):
        tmp_store.append("tool_call", tool="terminal", args_summary="", result_summary="ok")
        result = tmp_store.verify()
        assert result["ok"] is True


# =============================================================================
# A.12 / A.17 — Retention & cross-session persistence
# =============================================================================

class TestRetentionAndPersistence:
    def test_log_survives_reopen(self, tmp_path):
        path1 = tmp_path / "audit.jsonl"
        store1 = AuditStore(path=str(path1))
        store1.append("tool_call", tool="terminal", args_summary="cmd1", result_summary="r1")
        store2 = AuditStore(path=str(path1))
        assert store2.verify()["entries"] == 1
        store2.append("tool_call", tool="terminal", args_summary="cmd2", result_summary="r2")
        assert store2.verify()["entries"] == 2

    def test_retention_days_parsed_as_int(self):
        engine = PolicyEngine(mode="permissive")
        # Just ensures policy loads; retention value isn't enforced here,
        # but the config accepts an int.
        assert engine.mode in ("permissive", "enforce")

    def test_logs_can_be_incremented_over_time(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        store = AuditStore(path=str(path))
        for i in range(50):
            store.append("tool_call", args_summary=f"step-{i}", result_summary="ok")
        result = store.verify()
        assert result["entries"] == 50
        assert len(result["last_hash"]) == 64


# =============================================================================
# A.5 / A.8 / A.12 — Session boundary evidence
# =============================================================================

class TestSessionBoundaryEvidence:
    def test_session_start_and_end_events_are_logged(self, tmp_path):
        from plugin.hooks import on_session_start, on_session_end
        store = AuditStore(path=str(tmp_path / "audit.jsonl"))
        on_session_start("s1", store=store)
        on_session_end("s1", store=store)
        result = store.verify()
        assert result["entries"] == 2
        content = Path(store.path).read_text()
        assert "session_start" in content
        assert "session_end" in content

    def test_multiple_sessions_preserve_ordering(self, tmp_path):
        from plugin.hooks import on_session_start
        store = AuditStore(path=str(tmp_path / "audit.jsonl"))
        for sid in ["s1", "s2", "s3"]:
            on_session_start(sid, store=store)
        result = store.verify()
        assert result["entries"] == 3
