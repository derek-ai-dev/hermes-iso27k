"""Hash-chained audit log store.

Writes append-only JSONL with SHA-256 chain linkage and optional PII/secret redaction.
"""
import fcntl
import json
import hashlib
import os
import re
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

_VAULT_PATTERNS = {
    "AWS key id": r"AKIA[0-9A-Z]{16}",
    "API key": r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{16,}",
    "token": r"(?i)token\s*[:=]\s*[A-Za-z0-9_\-\.]{16,}",
    "secret": r"(?i)secret\s*[:=]\s*[A-Za-z0-9_\-\.]{16,}",
}


def _vault_redact(text: str) -> str:
    out = text or ""
    for label, pat in _VAULT_PATTERNS.items():
        try:
            out = re.sub(pat, f"[REDACTED:{label}]", out)
        except re.error as exc:
            logger.error("redaction pattern failed for %s: %s", label, exc)
    return out


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
        raw = path or os.environ.get("HERMES_27K_LOG")
        self.path = Path(raw).expanduser() if raw else None
        if not self.path:
            hermes_home = os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))
            self.path = Path(hermes_home) / "iso27k" / "audit.jsonl"
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error("cannot create audit log directory %s: %s", self.path.parent, exc)
            raise
        self._lock = threading.Lock()
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
                "metadata": entry.metadata,
                "prev_hash": entry.prev_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def _bootstrap(self):
        if not self.path.exists():
            return
        try:
            with self.path.open("r") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                lines = f.read().splitlines()
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            logger.error("cannot read audit log %s: %s", self.path, exc)
            return
        if not lines:
            return
        for line in lines:
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                logger.error("corrupt audit log line skipped: %s", exc)
                return
        last = json.loads(lines[-1])
        self._sequence = last.get("sequence", 0)
        self._last_hash = last.get("hash", self._genesis_hash())

    def append(self, event_type: str, tool: Optional[str] = None, args_summary: str = "", result_summary: str = "", control_hints: Optional[list] = None, metadata: Optional[dict] = None) -> Optional[AuditEntry]:
        if not self.path:
            logger.error("audit append failed: no log path configured")
            return None
        try:
            with self._lock:
                self._sequence += 1
                entry = AuditEntry(
                    sequence=self._sequence,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    event_type=event_type,
                    tool=tool,
                    args_summary=_vault_redact(args_summary),
                    result_summary=_vault_redact(result_summary),
                    control_hints=control_hints or [],
                    metadata=metadata or {},
                    prev_hash=self._last_hash,
                )
                entry.hash = self._compute_hash(entry)
                with self.path.open("a") as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    f.write(json.dumps(asdict(entry)) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                self._last_hash = entry.hash
                return entry
        except OSError as exc:
            logger.error("audit append failed for %s: %s", self.path, exc)
            return None

    def verify(self) -> dict:
        if not self.path.exists():
            return {"ok": True, "entries": 0}
        try:
            lines = self.path.read_text().splitlines()
        except OSError as exc:
            logger.error("cannot read audit log %s: %s", self.path, exc)
            return {"ok": False, "error": str(exc)}
        if not lines:
            return {"ok": True, "entries": 0}
        prev_hash = self._genesis_hash()
        expected_seq = 1
        for i, line in enumerate(lines, 1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return {"ok": False, "error": f"invalid json at line {i}", "line": i}
            if entry.get("sequence") != expected_seq:
                return {"ok": False, "error": f"sequence gap at line {i}", "line": i}
            if entry.get("prev_hash") != prev_hash:
                return {"ok": False, "error": f"hash break at line {i}", "line": i}
            recomputed = self._compute_hash(AuditEntry(
                sequence=entry["sequence"],
                timestamp=entry["timestamp"],
                event_type=entry["event_type"],
                tool=entry.get("tool"),
                args_summary=entry.get("args_summary", ""),
                result_summary=entry.get("result_summary", ""),
                control_hints=entry.get("control_hints", []),
                metadata=entry.get("metadata", {}),
                prev_hash=entry["prev_hash"],
            ))
            if recomputed != entry.get("hash"):
                return {"ok": False, "error": f"tampered hash at line {i}", "line": i}
            prev_hash = entry["hash"]
            expected_seq += 1
        return {"ok": True, "entries": len(lines), "last_hash": prev_hash}
