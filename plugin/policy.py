"""Policy engine for ISO 27001 enforcement rules.

Rules are loaded from YAML. In permissive mode the engine only logs.
In enforce mode it returns decisions for block/flag/allow actions.
"""
import os
import re
from pathlib import Path
from typing import Optional


class PolicyEngine:
    def __init__(self, mode: str = "permissive", policy_file: str = None):
        self.mode = mode or "permissive"
        self.policy_file = Path(policy_file).expanduser() if policy_file else None
        self.rules = self._load_rules()

    def _load_rules(self) -> list:
        # Default built-in rules when no external file exists
        defaults = [
            {
                "id": "deny-write-ssh-auth",
                "match": {"tool": "terminal", "args_contains": "~/.ssh/authorized_keys"},
                "action": "deny",
                "control": "A.9.4",
                "reason": "Writing to authorized_keys is a sensitive access-control change",
            },
            {
                "id": "flag-chmod-777",
                "match": {"tool": "terminal", "args_contains": "chmod 777"},
                "action": "flag",
                "control": "A.12.3",
                "reason": "Overly permissive file permissions",
            },
            {
                "id": "require-approval-config-edit",
                "match": {"tool": "write_file", "path_contains": ".env"},
                "action": "require_approval",
                "control": "A.12.1",
                "reason": "Secrets file modification requires human approval",
            },
        ]
        if self.policy_file and self.policy_file.exists():
            import yaml
            data = yaml.safe_load(self.policy_file.read_text())
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and isinstance(data.get("rules"), list):
                return data["rules"]
        return defaults

    def evaluate(self, tool: str, args: str = "", path: str = "") -> Optional[dict]:
        matched = None
        for rule in self.rules:
            m = rule.get("match", {})
            if m.get("tool") and m["tool"] != tool:
                continue
            if m.get("args_contains") and m["args_contains"] not in args:
                continue
            if m.get("args_regex") and not re.search(m["args_regex"], args):
                continue
            if m.get("path_contains") and m["path_contains"] not in path:
                continue
            matched = rule
            break
        if not matched:
            return None
        action = matched.get("action", "allow")
        if self.mode == "permissive" and action == "deny":
            action = "flag"
        return {
            "rule_id": matched["id"],
            "action": action,
            "control": matched.get("control"),
            "reason": matched.get("reason"),
        }
