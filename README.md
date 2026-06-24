# hermes-iso27k

ISO 27001:2022 Annex A evidence collection and policy enforcement plugin for Hermes Agent.

Provides tamper-evident audit logging, rule-based policy enforcement, and evidence bundling for compliance review.

## What it does

- **Audit log** — append-only JSONL with SHA-256 hash chaining; detects tampering (sequence gaps, broken links, corrupted hashes)
- **Policy engine** — YAML-driven allow / flag / require_approval / deny rules with permissive and enforce modes
- **Redaction** — AWS key IDs, API keys, tokens, and secrets are redacted before writing to logs
- **Evidence bundling** — dated, hashed packages (audit chain + config snapshot + manifest) for long-term retention

## Install

```bash
# 1. Clone or link the plugin
ln -s /path/to/hermes-iso27k/plugin ~/.hermes/plugins/hermes-iso27k

# 2. Install the skill
cp -r /path/to/hermes-iso27k/skill ~/.hermes/skills/iso27k

# 3. Enable the plugin
hermes plugins enable hermes-iso27k
```

## Configuration

Set via environment variables:

| Option | Env var | Default | Description |
|---|---|---|---|
| `enforcement` | `HERMES_ISO27K_MODE` | `permissive` | `permissive` = log only; `enforce` = apply rules |
| `audit_log` | `HERMES_27K_LOG` | `~/.hermes/iso27k/audit.jsonl` | Audit log path |
| `policy_file` | `HERMES_ISO27K_POLICY` | — | YAML policy rules file |

### Policy file reference

Create a YAML file matching the structure in `plugin/policy-rules.yaml`. Each rule needs:

```yaml
- id: unique-rule-id
  match:
    tool: terminal            # optional
    args_contains: "pattern"  # optional
    args_regex: "regex"       # optional
    path_contains: "path"     # optional
  action: deny                # deny | flag | require_approval | allow
  control: A.12.1             # ISO 27001 control reference
  reason: Human readable explanation
```

## Usage

```bash
# Check plugin status
python -c "from hermes_iso27k import status; print(status())"

# Verify audit log integrity
python scripts/bundle_evidence.py --verify

# Generate an evidence bundle
python scripts/bundle_evidence.py

# Generate a control-specific report
python skill/scripts/report_generator.py --control A.12
```

## Evidence bundling cron

```bash
0 2 * * * HERMES_HOME=/home/kaliuser/.hermes/profiles/iso27k-test python /home/kaliuser/hermes-iso27k/scripts/bundle_evidence.py --log /home/kaliuser/.hermes/profiles/iso27k-test/iso27k/audit.jsonl --out /home/kaliuser/.hermes/profiles/iso27k-test/evidence --retention-days 365
```

## Security notes

- Audit logs contain no secrets; redaction runs before writes
- Hash chain is append-only; any post-write edit breaks verification
- Default mode is permissive; switch to `enforce` only after tuning rules

## Uninstall

```bash
hermes plugins disable hermes-iso27k
rm ~/.hermes/plugins/hermes-iso27k
rm -rf ~/.hermes/skills/iso27k
```

## License

MIT
