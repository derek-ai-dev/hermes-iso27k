# Changelog

All notable changes to `hermes-iso27k` are documented here.

## [0.1.0] - 2026-06-24

### Added
- Hash-chained append-only audit log (`AuditStore`) with SHA-256 linkage and `verify()` tamper detection
- Vault redaction for AWS key IDs, API keys, tokens, and secrets before log writes
- Policy engine (`PolicyEngine`) with YAML-driven rules and `permissive` / `enforce` modes
- 15 production-grade policy rules covering SSH auth, destructive commands, PII, secrets, cron, plugin installs, and web exfiltration
- Plugin hooks: `post_tool_call`, `on_session_start`, `on_session_end`, `on_config_change`
- Evidence bundler (`scripts/bundle_evidence.py`) producing dated packages with manifest hashes and retention pruning
- Pytest suite covering audit store, policy engine, ISO 27001 alignment, and evidence bundling
- CI workflow running pytest on Python 3.11 for push and PR to `main`
- Daily cron template for evidence bundle generation

### Fixed
- Narrowed `deny-web-exfil-noncorp` regex to prevent false positives
- Tightened `flag-external-data-transfer` substring match
- Added missing `on_session_start` hook registration
- Fixed policy engine type hint for `mode=None` safety
- Fixed redundant `path` lookup in hooks

### Changed
- Default policy mode set to `permissive` (log-only) for safe initial deployment
- Test profile isolation via `HERMES_ISO27K_POLICY` environment variable
