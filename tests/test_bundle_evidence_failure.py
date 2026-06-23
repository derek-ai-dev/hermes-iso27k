#!/usr/bin/env python3
"""Tests for bundle_evidence failure paths."""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_bundle_evidence_missing_log(tmp_path):
    from scripts.bundle_evidence import build_bundle
    missing = tmp_path / "missing.jsonl"
    with pytest.raises(FileNotFoundError):
        build_bundle(missing, tmp_path / "out", retention_days=30)


def test_bundle_evidence_creates_manifest_and_hashes(tmp_path):
    from scripts.bundle_evidence import build_bundle
    log = tmp_path / "audit.jsonl"
    log.write_text(json.dumps({"sequence": 1, "timestamp": "2026-01-01T00:00:00+00:00", "event_type": "x", "tool": "t", "args_summary": "", "result_summary": "", "control_hints": [], "prev_hash": "0" * 64, "hash": "a" * 64}) + "\n")
    out = tmp_path / "evidence"
    bundle = build_bundle(log, out, retention_days=7)
    assert bundle.is_dir()
    assert (bundle / "audit-chain.jsonl").exists()
    assert (bundle / "bundle-manifest.json").exists()
    manifest = json.loads((bundle / "bundle-manifest.json").read_text())
    assert "files" in manifest
    assert "audit-chain.jsonl" in manifest["files"]
    assert manifest["files"]["audit-chain.jsonl"]["sha256"]


def test_bundle_evidence_prunes_old(tmp_path):
    from scripts.bundle_evidence import build_bundle, prune_old
    import time
    out = tmp_path / "evidence"
    old = out / "evidence-2000-01-01.bundle"
    old.mkdir(parents=True)
    (old / "old.txt").write_text("old")
    old_mtime = time.time() - (10 * 86400)
    os.utime(old, (old_mtime, old_mtime))
    log = tmp_path / "audit.jsonl"
    log.write_text(json.dumps({"sequence": 1, "timestamp": "2026-01-01T00:00:00+00:00", "event_type": "x", "tool": "t", "args_summary": "", "result_summary": "", "control_hints": [], "prev_hash": "0" * 64, "hash": "a" * 64}) + "\n")
    build_bundle(log, out, retention_days=7)
    prune_old(out, retention_days=7)
    assert not old.exists()
