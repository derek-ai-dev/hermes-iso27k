#!/usr/bin/env python3
"""Smoke tests for hermes-iso27k plugin against the iso27k-test profile."""
import os
import sys
import json
import tempfile
from pathlib import Path

PROFILE_DIR = Path.home() / ".hermes" / "profiles" / "iso27k-test"
PLUGIN_DIR = PROFILE_DIR / "plugins" / "hermes-iso27k"
SKILL_DIR = PROFILE_DIR / "skills" / "iso27k"
os.environ["HERMES_HOME"] = str(PROFILE_DIR)

results = []

def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    results.append((name, status, detail))
    return condition

# 1. Profile directory exists
check("profile_dir_exists", PROFILE_DIR.is_dir(), str(PROFILE_DIR))

# 2. Plugin symlink/file exists
check("plugin_dir_exists", PLUGIN_DIR.is_dir() or PLUGIN_DIR.is_symlink(), str(PLUGIN_DIR))

# 3. Plugin yaml exists
plugin_yaml = PLUGIN_DIR / "plugin.yaml"
check("plugin_yaml_exists", plugin_yaml.is_file(), str(plugin_yaml))

# 4. Hooks module exists
hooks_py = PLUGIN_DIR / "hooks.py"
check("hooks_py_exists", hooks_py.is_file(), str(hooks_py))

# 5. Audit store module exists
audit_py = PLUGIN_DIR / "audit_store.py"
check("audit_store_py_exists", audit_py.is_file(), str(audit_py))

# 6. Policy module exists
policy_py = PLUGIN_DIR / "policy.py"
check("policy_py_exists", policy_py.is_file(), str(policy_py))

# 7. Skill SKILL.md exists
skill_md = SKILL_DIR / "SKILL.md"
check("skill_md_exists", skill_md.is_file(), str(skill_md))

# 8. Config has plugin enabled
config_path = PROFILE_DIR / "config.yaml"
config_text = config_path.read_text() if config_path.is_file() else ""
check("plugin_enabled_in_config", "hermes-iso27k" in config_text, "plugins.enabled contains hermes-iso27k")

# 9. Policy rules file exists
policy_rules = PLUGIN_DIR / "policy-rules.yaml"
check("policy_rules_yaml_exists", policy_rules.is_file(), str(policy_rules))

# 10. Import and instantiate AuditStore with profile path
sys.path.insert(0, str(PLUGIN_DIR.parent))
try:
    from plugin.audit_store import AuditStore
    audit_path = PROFILE_DIR / "iso27k" / "smoke-audit.jsonl"
    store = AuditStore(path=str(audit_path))
    check("audit_store_import_instantiate", True)
except Exception as e:
    check("audit_store_import_instantiate", False, str(e))
    store = None

# 11. Append an audit entry
if store is not None:
    try:
        store.append(
            event_type="smoke_test",
            tool="smoke_tester",
            args_summary="smoke-test",
            result_summary="ok",
            control_hints=["A.12.4"],
        )
        check("audit_store_append", audit_path.is_file() and audit_path.stat().st_size > 0)
    except Exception as e:
        check("audit_store_append", False, str(e))

# 12. Verify hash chain
if store is not None:
    try:
        result = store.verify()
        check("audit_store_verify", result.get("ok") is True, json.dumps(result))
    except Exception as e:
        check("audit_store_verify", False, str(e))

# 13. Policy engine loads defaults
try:
    from plugin.policy import PolicyEngine
    engine = PolicyEngine(mode="permissive")
    check("policy_engine_defaults", len(engine.rules) > 0, f"{len(engine.rules)} rules")
except Exception as e:
    check("policy_engine_defaults", False, str(e))

# 14. Policy engine evaluates deny rule
try:
    engine = PolicyEngine(mode="enforce")
    decision = engine.evaluate(tool="terminal", args="echo > ~/.ssh/authorized_keys", path="")
    check("policy_engine_evaluate", decision is not None and decision.get("action") == "deny", str(decision))
except Exception as e:
    check("policy_engine_evaluate", False, str(e))

# 15. Policy engine loads external rules file
try:
    engine = PolicyEngine(mode="enforce", policy_file=str(policy_rules))
    check("policy_engine_external_rules", len(engine.rules) >= 15, f"{len(engine.rules)} rules")
except Exception as e:
    check("policy_engine_external_rules", False, str(e))

# 16. Run iso27k-test chat help to confirm binary works
import subprocess
try:
    proc = subprocess.run(
        ["/home/kaliuser/.local/bin/iso27k-test", "plugins", "list"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    out = proc.stdout + proc.stderr
    check("profile_plugins_list", "hermes-iso27k" in out, out[:200])
except Exception as e:
    check("profile_plugins_list", False, str(e))

# Report
print("\n=== Smoke Test Results ===")
for name, status, detail in results:
    print(f"[{status}] {name}")
    if detail and status == "FAIL":
        print(f"       -> {detail[:300]}")

failed = [r for r in results if r[1] == "FAIL"]
print(f"\nTotal: {len(results)} | Passed: {len(results)-len(failed)} | Failed: {len(failed)}")
sys.exit(1 if failed else 0)
