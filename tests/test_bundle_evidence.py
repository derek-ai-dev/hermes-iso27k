"""Tests for evidence bundling script."""
import hashlib
import json
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def test_bundle_evidence_creates_files(tmp_path):
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("bundle_evidence", REPO / "scripts" / "bundle_evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    entry = json.dumps({"sequence": 1, "timestamp": "2024-01-01T00:00:00+00:00", "event_type": "test", "tool": "x", "args_summary": "", "result_summary": "", "control_hints": [], "prev_hash": "0" * 64, "hash": "abc"}) + "\n"
    fake_log = tmp_path / "audit.jsonl"
    fake_log.write_text(entry)

    out = tmp_path / "bundles"
    bundle = mod.build_bundle(fake_log, out, retention_days=30)
    assert bundle.exists()
    assert (bundle / "audit-chain.jsonl").exists()
    assert (bundle / "bundle-manifest.json").exists()
    manifest = json.loads((bundle / "bundle-manifest.json").read_text())
    assert "audit-chain.jsonl" in manifest["files"]
    assert "bundle-manifest.json" in manifest["files"]
    expected = hashlib.sha256(entry.encode()).hexdigest()
    assert manifest["files"]["audit-chain.jsonl"]["sha256"] == expected


def test_prune_old_removes_expired(tmp_path):
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("bundle_evidence", REPO / "scripts" / "bundle_evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    old = tmp_path / "bundle-old"
    old.mkdir()
    (old / "f").write_text("x")
    # backdate mtime
    import time
    past = time.time() - (31 * 86400)
    os.utime(old, (past, past))

    new = tmp_path / "bundle-new"
    new.mkdir()
    (new / "f").write_text("x")

    mod.prune_old(tmp_path, retention_days=30)
    assert not old.exists()
    assert new.exists()
