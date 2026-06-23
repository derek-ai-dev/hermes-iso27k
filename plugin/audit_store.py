"""
Hash-chained audit log store.

Writes append-only JSONL with SHA-256 chain linkage.
"""
import json
import hashlib
import os
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any


@dataclass
class AuditEntry:
    sequence: int
    timestamp: str
    event_type: str
    tool: Optional[str]
    args_summary: str
    result_summary: str
    control_hints: list = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""


class AuditStore:
    def __init__(self, path: str = None):
        self.path = Path(path or os.environ.get("HERMES_ISO27K_LOG", "")).expanduser()
        if not self.path:
            hermes_home = os.environ.get("HERMES_HOME", Path.home() / ".hermes")
            self.path = Path(hermes_home) / "iso27k" / "audit.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._sequence = 0
        self._last_hash = self._genesis_hash()
        self._bootstrap()

    def _genesis_hash(self) -> str:
        return "0" * 64

    def _compute_hash(self, entry: AuditEntry) -> str:
        payload = json.dumps(
            {
                "sequence": entry.sequence,
                "timestamp": entry.timestamp,
                "event_type": entry.event_type,
                "tool": entry.tool,
                "args_summary": entry.args_summary,
                "result_summary": entry.result_summary,
                "control_hints": entry.control_hints,
                "prev_hash": entry.prev_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def _bootstrap(self):
        if not self.path.exists():
            return
        lines = self.path.read_text().splitlines()
        if not lines:
            return
        last = json.loads(lines[-1])
        self._sequence = last.get("sequence", 0)
        self._last_hash = last.get("hash", self._genesis_hash())

    def append(self, event_type: str, tool: str = None, args_summary: str = "", result_summary: str = "", control_hints: list = None, metadata: dict = None) -> AuditEntry:
        self._sequence += 1
        entry = AuditEntry(
            sequence=self._sequence,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            tool=tool,
            args_summary=args_summary,
            result_summary=result_summary,
            control_hints=control_hints or [],
            metadata=metadata or {},
            prev_hash=self._last_hash,
        )
        entry.hash = self._compute_hash(entry)
        with open(self.path, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")
        self._last_hash = entry.hash
        return entry

    def verify(self) -> dict:
        if not self.path.exists():
            return {"ok": True, "entries": 0}
        lines = self.path.read_text().splitlines()
        prev_hash = self._genesis_hash()
        expected_seq = 1
        for i, line in enumerate(lines, 1):
            entry = json.loads(line)
            if entry.get("sequence") != expected_seq:
                return {"ok": False, "error": f"sequence gap at line {i}", "line": i}
            if entry.get("prev_hash") != prev_hash:
                return {"ok": False, "error": f"hash break at line {i}", "line": i}
            # recompute hash
            payload = json.dumps(
                {
                    "sequence": entry["sequence"],
                    "timestamp": entry["timestamp"],
                    "event_type": entry["event_type"],
                    "tool": entry.get("tool"),
                    "args_summary": entry.get("args_summary", ""),
                    "result_summary": entry.get("result_summary", ""),
                    "control_hints": entry.get("control_hints", []),
                    "prev_hash": entry["prev_hash"],
                },
                sort_keys=True,
            )
            computed = hashlib.sha256(payload.encode()).hexdigest()
            if computed != entry.get("hash"):
                return {"ok": False, "error": f"tampered hash at line {i}", "line": i}
            prev_hash = entry["hash"]
            expected_seq += 1
        return {"ok": True, "entries": len(lines), "last_hash": prev_hash}
