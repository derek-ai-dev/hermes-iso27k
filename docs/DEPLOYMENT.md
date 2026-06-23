# Deployment

## Option A: local development install
```bash
# 1. Link plugin
ln -s /home/kaliuser/hermes-iso27k/plugin ~/.hermes/plugins/hermes-iso27k

# 2. Install skill
cp -r /home/kaliuser/hermes-iso27k/skill ~/.hermes/skills/iso27k

# 3. Enable
hermes plugins enable hermes-iso27k
hermes skills install /home/kaliuser/hermes-iso27k/skill/SKILL.md --name iso27k
```

## Option B: pip installable package (future)
```bash
pip install hermes-iso27k
hermes plugins enable hermes-iso27k
```

## Option C: symlink into hermes-agent source tree
```bash
ln -s /home/kaliuser/hermes-iso27k/plugin /home/kaliuser/.hermes/hermes-agent/plugins/hermes-iso27k
```

## Evidence retention
Set `retention_days` in `plugin.yaml` or env to match your organization's journaling policy.
