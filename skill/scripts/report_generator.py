#!/usr/bin/env python3
"""
Generate ISO 27001 evidence bundles from the hermes-iso27k audit log.
"""
import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path


def default_log() -> Path:
    hermes_home = os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))
    return Path(hermes_home) / "iso27k" / "audit.jsonl"


def default_evidence() -> Path:
    return default_log().parent / "evidence"


def read_entries(path: Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def filter_controls(entries, control_prefix: str):
    prefix = control_prefix.strip()
    if not prefix:
        return entries
    return [e for e in entries if any(prefix in c for c in e.get("control_hints", []))]


def build_markdown_report(entries, control_prefix: str) -> str:
    lines = [
        f"# ISO 27001 Evidence Report",
        f"",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Entries: {len(entries)}",
        f"Control target: {control_prefix or 'all'}",
        f"",
        f"## Summary",
        f"",
    ]
    tool_counts = {}
    control_counts = {}
    for e in entries:
        t = e.get("tool") or "system"
        tool_counts[t] = tool_counts.get(t, 0) + 1
        for c in e.get("control_hints", []):
            control_counts[c] = control_counts.get(c, 0) + 1
    lines.append("### Tools")
    for t, c in sorted(tool_counts.items()):
        lines.append(f"- {t}: {c}")
    lines.append("")
    lines.append("### Controls")
    for c, n in sorted(control_counts.items()):
        lines.append(f"- {c}: {n}")
    lines += ["", "## Raw Entries", ""]
    for e in entries:
        lines.append(f"- {e.get('timestamp')} `{e.get('event_type')}` tool={e.get('tool')} controls={e.get('control_hints')}")
        if e.get("metadata", {}).get("decision"):
            lines.append(f"  - decision={e['metadata']['decision']}")
    return "\n".join(lines)


def write_bundle(entries, control_prefix: str, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "control-report.md").write_text(build_markdown_report(entries, control_prefix))
    # Symlink or copy current log
    shutil.copy2(default_log(), out_dir / "audit-chain.jsonl")
    # Config snapshot
    config_path = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))) / "config.yaml"
    if config_path.exists():
        shutil.copy2(config_path, out_dir / "config-snapshot.yaml")
    # Checksums
    sums = []
    for name in ["control-report.md", "audit-chain.jsonl", "config-snapshot.yaml"]:
        p = out_dir / name
        if p.exists():
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            sums.append(f"{h}  {name}")
    (out_dir / "sha256sums.txt").write_text("\n".join(sums) + "\n")


def main():
    parser = argparse.ArgumentParser(description="ISO 27001 evidence bundle generator")
    parser.add_argument("--control", default="", help="Control prefix (e.g. A.12)")
    parser.add_argument("--log", default=str(default_log()), help="Audit log path")
    parser.add_argument("--out", default=str(default_evidence()), help="Evidence output dir")
    args = parser.parse_args()
    entries = read_entries(Path(args.log))
    if args.control:
        entries = filter_controls(entries, args.control)
    write_bundle(entries, args.control, Path(args.out))
    print(f"Wrote evidence bundle to {args.out}")


if __name__ == "__main__":
    main()
