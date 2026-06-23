#!/usr/bin/env python3
"""Tests for report_generator failure paths."""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_report_generator_missing_log(tmp_path, monkeypatch):
    from skill.scripts.report_generator import read_entries, build_markdown_report
    missing = tmp_path / "does-not-exist.jsonl"
    entries = read_entries(missing)
    assert entries == []
    md = build_markdown_report(entries, "")
    assert "# ISO 27001 Evidence Report" in md
    assert "Entries: 0" in md


def test_report_generator_empty_log(tmp_path, monkeypatch):
    from skill.scripts import report_generator
    from skill.scripts.report_generator import read_entries, build_markdown_report, write_bundle
    log = tmp_path / "empty.jsonl"
    log.write_text("")
    entries = read_entries(log)
    assert entries == []
    out = tmp_path / "bundle"
    monkeypatch.setattr(report_generator, "default_log", lambda: log)
    write_bundle(entries, "", out)
    assert (out / "control-report.md").exists()
    text = (out / "control-report.md").read_text()
    assert "Entries: 0" in text


def test_report_generator_control_filter(tmp_path, monkeypatch):
    from skill.scripts.report_generator import read_entries, filter_controls
    entries = [
        {"control_hints": ["A.12.1", "A.9.4"], "tool": "t"},
        {"control_hints": ["A.8.15"], "tool": "t"},
    ]
    filtered = filter_controls(entries, "A.12")
    assert len(filtered) == 1
    assert filtered[0]["control_hints"] == ["A.12.1", "A.9.4"]
    filtered_all = filter_controls(entries, "")
    assert len(filtered_all) == 2
