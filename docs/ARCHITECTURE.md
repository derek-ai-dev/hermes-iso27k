# Architecture

## Plugin layer (`plugin/`)
- Hooks: `post_tool_call`, `on_session_end`, `on_config_change`
- `AuditStore`: append-only JSONL with SHA-256 chain + `verify()`
- `PolicyEngine`: YAML/rules-based allow/flag/deny
- Slash commands: `/iso27k status`, `/iso27k verify`, `/iso27k report`

## Skill layer (`skill/`)
- `SKILL.md`: Hermes skill definition
- `scripts/report_generator.py`: builds Markdown evidence bundles
- `references/iso27001-controls.md`: control-to-event mapping

## Data flow
1. Tool call happens in Hermes
2. Plugin hook logs event to `audit.jsonl`
3. Policy engine evaluates and tags control hints
4. Cron/skill reads log and produces immutable evidence bundle

## Verification
- `verify()` walks the chain recomputing hashes on read
- No secret material is logged (use existing Hermes redaction)
