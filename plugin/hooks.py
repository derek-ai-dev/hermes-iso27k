"""
Hermes plugin hooks for hermes-iso27k.

Requires: plugin.yaml, audit_store, policy, slash commands.
"""
import os
import yaml
from pathlib import Path
from typing import Optional
from .audit_store import AuditStore
from .policy import PolicyEngine


_store: AuditStore = None
_policy: PolicyEngine = None


def _get_store() -> AuditStore:
    global _store
    if _store is None:
        _store = AuditStore()
    return _store


def _get_policy() -> PolicyEngine:
    global _policy
    if _policy is None:
        config_path = os.environ.get("HERMES_ISO27K_POLICY", "")
        mode = os.environ.get("HERMES_ISO27K_MODE", "permissive")
        _policy = PolicyEngine(mode=mode, policy_file=config_path or None)
    return _policy


def _summarize_args(args: dict) -> str:
    try:
        return str(args)[:500]
    except Exception:
        return ""


def post_tool_call(tool_name: str, args: dict, result, **kwargs):
    store = _get_store()
    policy = _get_policy()
    args_text = _summarize_args(args or {})
    result_text = str(result)[:500] if result is not None else ""
    path = ""
    if isinstance(args, dict):
        path = str(args.get("path") or args.get("path") or "")
    decision = policy.evaluate(tool=tool_name, args=args_text, path=path)
    control_hints = []
    if decision:
        control_hints.append(decision.get("control", ""))
    store.append(
        event_type="tool_call",
        tool=tool_name,
        args_summary=args_text,
        result_summary=result_text,
        control_hints=control_hints,
        metadata={"decision": decision},
    )
    return None


def on_session_start(session_id: str, store: Optional[AuditStore] = None, **kwargs):
    s = store or _get_store()
    s.append(
        event_type="session_start",
        tool=None,
        args_summary=session_id or "",
        result_summary="",
        control_hints=["A.12.4"],
    )


def on_session_end(session_id: str, store: Optional[AuditStore] = None, **kwargs):
    s = store or _get_store()
    s.append(
        event_type="session_end",
        tool=None,
        args_summary=session_id or "",
        result_summary="",
        control_hints=["A.12.4"],
    )


def on_config_change(key: str, old_value, new_value, store: Optional[AuditStore] = None, **kwargs):
    s = store or _get_store()
    s.append(
        event_type="config_change",
        tool="config",
        args_summary=f"{key}: {old_value} -> {new_value}",
        result_summary="",
        control_hints=["A.12.1"],
    )


def register(plugin_manager):
    plugin_manager.register_hook("post_tool_call", post_tool_call)
    plugin_manager.register_hook("on_session_end", on_session_end)
    plugin_manager.register_hook("on_config_change", on_config_change)
