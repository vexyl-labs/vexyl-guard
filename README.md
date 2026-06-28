# Vexyl Guard

Vexyl Guard is a lightweight Linux server security agent for authorized operators of exposed VPS, web, and application hosts.

The public project focuses on the local host agent, install packaging, safe fixture tests, and operator-facing documentation. Hosted Vexyl infrastructure, billing, console, deployment configuration, website source, active intelligence data, and internal research notes are maintained outside this public repository.

This project is intentionally defensive. It does not scan third-party systems, exploit targets, hide itself, or create irreversible persistence.

## What Is Included

- `agent/vexyl-guard.sh`: Bash host agent for Linux servers.
- `intel/`: public runtime interfaces and redaction helpers for local defensive scoring. Active schemas and seed data are private.
- `vexyl`: Python CLI entry point for local Vexyl commands.
- `config/vexyl-guard.conf.example`: agent configuration template.
- `packaging/`: local install helper and optional systemd unit.
- `tests/`: safe local fixtures for agent parsing, classification, and scoring.
- `docs/security/`: public security notes.

## Install Preview

The live preview installer is served from Vexyl.dev:

```bash
curl -fsSL https://vexyl.dev/install.sh | sudo sh
sudo systemctl start vexyl-guard
sudo vexyl-guard status
```

Start in monitor mode. Move to enforcement only after reviewing local output and confirming the host policy is appropriate.

## Local Source Install

```bash
sudo install -m 0755 agent/vexyl-guard.sh /usr/local/sbin/vexyl-guard
sudo install -d -m 0750 /etc/vexyl /var/lib/vexyl
sudo install -m 0640 config/vexyl-guard.conf.example /etc/vexyl/guard.conf
sudo vexyl-guard once
sudo vexyl-guard daemon
```

To allow automatic local firewall blocks, edit `/etc/vexyl/guard.conf`:

```bash
VEXYL_MODE=enforce
```

The agent prefers `nftables`, falls back to `iptables`/`ip6tables`, and stays in monitor behavior when no supported firewall command is available.

## Defensive Defaults

- Monitor mode is the default.
- Logs and local decisions redact secrets and avoid storing raw sensitive prompts.
- Local allowlists are checked before scoring or blocking.
- Firewall changes are plain local `nftables`/`iptables` rules, not hidden persistence.

## Tests

```bash
tests/run-agent-fixtures.sh
```

The GitHub Actions workflow runs the same safe fixture checks.

## Security

Do not open public issues that include active secrets, private logs, runnable exploit code, malware code, or step-by-step offensive instructions.

Private vulnerability reports: `security@vexyl.dev`

## License

Vexyl Guard is licensed under the Apache License 2.0. See `LICENSE`.

## Support

Vexyl Guard is free to install. Monthly support plans help fund signed releases, packaging, hosted services, and continued defensive research:

```text
https://vexyl.dev/#plans
```
