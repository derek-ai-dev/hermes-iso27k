# hermes-iso27k

ISO 27001 Annex A evidence collection and enforcement plugin for Hermes Agent.

## Components

- `plugin/` — Bundled Hermes plugin (tracks tool calls, enforces policies, writes hash-chained audit log)
- `skill/` — Hermes skill + cron jobs (maps events to ISO 27001 controls, generates evidence bundles)
- `docs/` — Mapping tables, architecture, deployment notes
- `tests/` — Unit tests for the plugin logic

## Install (development)

```bash
# Symlink into Hermes plugins dir
ln -s /home/kaliuser/hermes-iso27k/plugin ~/.hermes/plugins/hermes-iso27k

# Install skill
cp -r /home/kaliuser/hermes-iso27k/skill ~/.hermes/skills/iso27k

# Enable plugin
hermes plugins enable hermes-iso27k
```

## Usage

```bash
hermes chat -q "/iso27k status"
hermes chat -q "/iso27k verify"
hermes chat -q "/iso27k report --control A.12.4"
```

## License

MIT
