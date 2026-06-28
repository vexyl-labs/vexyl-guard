# Contributing

Vexyl Guard welcomes defensive contributions that help authorized operators run safer Linux servers.

## Ground Rules

- Keep contributions defensive.
- Do not submit malware, exploit chains, credential material, or full jailbreak payloads.
- Redact secrets, customer data, private hostnames, and live IP evidence.
- Prefer small, reviewable changes with tests or fixture coverage.
- Preserve monitor-first behavior and operator-controlled action paths.

## Useful Checks

Run these before opening a pull request:

```bash
tests/run-agent-fixtures.sh
```

## Project Areas

- `agent/`: Linux host agent.
- `intel/`: public runtime interfaces and redaction helpers.
- `config/`: local configuration examples and public verification keys.
- `packaging/`: local install helper and systemd unit.
- `tests/`: safe local fixtures and regression checks.
- `docs/`: public security notes.
