---
name: iso27k
description: "ISO 27001 Annex A evidence collection and compliance reporting for Hermes Agent."
version: 0.1.0
tags: [compliance, iso27001, audit, evidence, governance]
---

# ISO 27001 Compliance Skill

Generates auditor-ready evidence from the `hermes-iso27k` plugin audit log.

## Prerequisites

- `hermes-iso27k` plugin enabled
- Audit log at `${HERMES_HOME}/iso27k/audit.jsonl`

## Workflow

1. Check plugin health: `python -c "from hermes_iso27k import status; print(status())"`
2. Verify audit log integrity: `python -c "from plugin.audit_store import AuditStore; print(AuditStore().verify())"`
3. Use `skill/scripts/report_generator.py` to build an evidence bundle for specific controls.
4. Store produced reports under `${HERMES_HOME}/iso27k/evidence/`.

## Evidence Bundle Layout

```
evidence/
  YYYY-MM-DD/
    audit-chain.jsonl
    config-snapshot.yaml
    control-report.md
    sha256sums.txt
```

## Control Mapping

See `references/iso27001-controls.md`.

## Commands

| Command | Action |
|---|---|
| `python -c "from hermes_iso27k import status; ..."` | Plugin status + audit summary |
| `python -c "from plugin.audit_store import AuditStore; print(AuditStore().verify())"` | Recompute full hash chain |
| `python skill/scripts/report_generator.py --control A.12` | Generate control-specific evidence |
| `python skill/scripts/report_generator.py --all` | Generate full evidence bundle |
| `python scripts/bundle_evidence.py` | Create dated evidence package |

## Pitfalls

- Do not print secrets from the audit log. Redact before sharing.
- The audit log is append-only. Never modify or delete historical entries.
