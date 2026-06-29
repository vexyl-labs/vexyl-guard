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

## Packages

Use the signed package repository when you want the agent tracked by the host package manager.

Debian / Ubuntu:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://vexyl.dev/repo/vexyl-packages.asc \
  | sudo tee /etc/apt/keyrings/vexyl-packages.asc >/dev/null
curl -fsSL https://vexyl.dev/repo/vexyl.sources \
  | sudo tee /etc/apt/sources.list.d/vexyl.sources >/dev/null
sudo apt update
sudo apt install vexyl-guard
sudo systemctl start vexyl-guard
```

Fedora / RHEL:

```bash
sudo curl -fsSL https://vexyl.dev/repo/vexyl.repo \
  -o /etc/yum.repos.d/vexyl.repo
sudo dnf install vexyl-guard
sudo systemctl start vexyl-guard
```

Manual package downloads are still available from the GitHub release page. Verify release downloads with `SHA256SUMS`, `SHA256SUMS.sig`, and `release-signing-public.pem`.

Maintainers can configure `VEXYL_PLATFORM_PROMOTION_TOKEN` so the release workflow dispatches the private platform promotion after signed assets are published.

## Release Readiness

Maintainers can cut a release from GitHub Actions with the `Prepare Release` workflow. It bumps `agent/vexyl-guard.sh` and `pyproject.toml`, runs the package and repository checks, commits the version bump, creates the `vX.Y.Z` tag, pushes it, and dispatches the signed release workflow.

Local equivalent:

```bash
scripts/prepare-release.sh --version 0.2.9 --commit --tag --push
```

The signed release workflow publishes GitHub assets. The private platform repository then promotes the latest signed package repository to `vexyl.dev`.

Build preview Linux packages from the public source tree:

```bash
packaging/build-packages.sh --format deb
packaging/build-packages.sh --format rpm
packaging/sign-rpm-packages.sh --signing-key repo-private.asc dist/packages/*.rpm
packaging/build-repositories.sh --packages-dir dist/packages
```

Packages install the agent service, CLI, default monitor-mode configuration, and public trust material. Debian packages are built with `dpkg-deb`; RPM packages require `rpmbuild`.

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

GitHub Sponsors is also enabled for the Vexyl Labs profile.
