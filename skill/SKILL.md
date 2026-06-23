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

1. Run `/iso27k status` to confirm the plugin is active and the chain is healthy.
2. Run `/iso27k verify` to check hash-chain integrity.
3. Use `scripts/report_generator.py` to build an evidence bundle for specific controls.
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
|---------|--------|
| `/iso27k status` | Plugin status + tail of audit log |
| `/iso27k verify` | Recompute full hash chain |
| `/iso27k report --control A.12` | Generate control-specific evidence |
| `/iso27k report --all` | Generate full evidence bundle |

## Pitfalls

- Do not print secrets from the audit log. Redact before sharing.
- The audit log is append-only. Never modify or delete historical entries.
