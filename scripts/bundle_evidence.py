#!/usr/bin/env python3
"""
ISO 27001 evidence bundler for cron.

Creates dated, tamper-evident evidence packages containing:
  - audit-chain.jsonl (current audit log)
  - config-snapshot.yaml (Hermes config)
  - bundle-manifest.json (hashes + metadata)

Usage:
  python scripts/bundle_evidence.py [--retention-days 365]
"""
import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_LOG = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))) / "iso27k" / "audit.jsonl"
DEFAULT_EVIDENCE = DEFAULT_LOG.parent / "evidence"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_bundle(log: Path, out_dir: Path, retention_days: int = 365) -> Path:
    if not log.exists():
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("")

    out_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    bundle = out_dir / f"evidence-{today}.bundle"
    bundle.mkdir(parents=True, exist_ok=True)

    # 1. Copy audit chain
    shutil.copy2(log, bundle / "audit-chain.jsonl")

    # 2. Copy config snapshot
    config_path = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))) / "config.yaml"
    if config_path.exists():
        shutil.copy2(config_path, bundle / "config-snapshot.yaml")

    # 3. Build manifest with hashes
    manifest = {
        "bundle_id": bundle.name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_log": str(log),
        "retention_days": retention_days,
        "files": {},
        "note": "Hash-chained evidence bundle for ISO 27001 audit.",
    }
    for child in sorted(bundle.iterdir()):
        if child.is_file() and child.name != "bundle-manifest.json":
            manifest["files"][child.name] = {
                "sha256": sha256(child),
                "bytes": child.stat().st_size,
                "mtime": datetime.fromtimestamp(child.stat().st_mtime, tz=timezone.utc).isoformat(),
            }

    # 4. Write manifest, then add its own hash
    manifest_path = bundle / "bundle-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    manifest["files"]["bundle-manifest.json"] = {
        "sha256": sha256(manifest_path),
        "bytes": manifest_path.stat().st_size,
        "mtime": datetime.fromtimestamp(manifest_path.stat().st_mtime, tz=timezone.utc).isoformat(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    return bundle


def prune_old(out_dir: Path, retention_days: int):
    cutoff = datetime.now(timezone.utc).timestamp() - (retention_days * 86400)
    for child in out_dir.iterdir():
        if child.is_dir() and child.stat().st_mtime < cutoff:
            shutil.rmtree(child)


def main():
    parser = argparse.ArgumentParser(description="ISO 27001 evidence bundler")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--out", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--retention-days", type=int, default=365)
    args = parser.parse_args()

    bundle = build_bundle(args.log, args.out, args.retention_days)
    prune_old(args.out, args.retention_days)
    print(json.dumps({"bundle": str(bundle), "files": sorted(p.name for p in bundle.iterdir())}, indent=2))


if __name__ == "__main__":
    main()
