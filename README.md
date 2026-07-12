# Vexyl Guard

Vexyl Guard is a lightweight Linux server security agent for authorized operators of exposed VPS, web, and application hosts.

The public project focuses on the local host agent, install packaging, safe fixture tests, and operator-facing documentation. Hosted Vexyl infrastructure, billing, console, deployment configuration, website source, active intelligence data, and internal research notes are maintained outside this public repository.

This project is intentionally defensive. It does not scan third-party systems, exploit targets, hide itself, or create irreversible persistence.

## Quick Links

- Install: `https://vexyl.dev/#install`
- Resources: `https://vexyl.dev/resources/`
- Verify before installing: `https://vexyl.dev/resources/verify-before-you-install/`
- Public preview feedback: `https://github.com/vexyl-labs/vexyl-guard/issues/1`
- Structured install report: `https://github.com/vexyl-labs/vexyl-guard/issues/new?template=install_feedback.yml`
- Operator Notes: `https://vexyl.dev/updates/`
- Sponsor Vexyl Labs: `https://github.com/sponsors/vexyl-labs`

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

To share public preview feedback without exposing host-specific details, generate a redacted support report:

```bash
sudo vexyl-guard support-report
```

## Preview Feedback

Public preview feedback is welcome here:

```text
https://github.com/vexyl-labs/vexyl-guard/issues/1
```

Structured install reports can also be opened here:

```text
https://github.com/vexyl-labs/vexyl-guard/issues/new?template=install_feedback.yml
```

Useful reports include distro/version, install method, service startup result, monitor-mode clarity, noisy signals, false positives, missing docs, and the redacted output from `sudo vexyl-guard support-report`.

Do not post secrets, private logs, customer data, hostnames, public IP addresses, usernames, tokens, runnable exploit code, malware code, or offensive instructions. Send sensitive reports to `security@vexyl.dev`.

## Operator Resources

These guides are useful even before installing Vexyl Guard:

```text
https://vexyl.dev/resources/linux-server-exposure-checklist/
https://vexyl.dev/resources/verify-before-you-install/
https://vexyl.dev/resources/redacted-support-reports/
```

Use them to review exposed Linux hosts, inspect release artifacts, and avoid leaking sensitive details when asking for help.

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

Package installs send a minimal install-status event so Vexyl Labs can spot broken package paths. No host logs, prompts, secrets, or local config values are sent. To disable this during install:

```bash
sudo env VEXYL_INSTALL_REPORT=off apt install vexyl-guard
sudo env VEXYL_INSTALL_REPORT=off dnf install vexyl-guard
```

Maintainers can configure `VEXYL_PLATFORM_PROMOTION_TOKEN` so the release workflow dispatches the private platform promotion after signed assets are published.

## Release Readiness

Maintainers must run the `Release Preflight` workflow before cutting a release. It accepts the proposed version and release notes, runs the same version bump, package, repository, and note validation checks, then stops before creating a commit, tag, push, or release dispatch.

After preflight passes on the same commit, cut the release from GitHub Actions with the `Prepare Release` workflow. It refuses to run without a successful matching preflight, accepts the same release notes, bumps `agent/vexyl-guard.sh` and `pyproject.toml`, runs the package and repository checks again, commits the version bump, creates an annotated `vX.Y.Z` tag, pushes it, and dispatches the signed `Release` workflow with those notes.

Local equivalent:

```bash
scripts/prepare-release.sh --version 0.2.9 --notes-file RELEASE_NOTES.md --dry-run
scripts/prepare-release.sh --version 0.2.9 --notes-file RELEASE_NOTES.md --commit --tag --push
```

For local releases, the annotated tag carries the release notes and the tag push starts the signed `Release` workflow. The private platform repository then promotes the latest signed package repository to `vexyl.dev`.

Build preview Linux packages from the public source tree:

```bash
packaging/build-packages.sh --format deb
packaging/build-packages.sh --format rpm
packaging/sign-rpm-packages.sh --signing-key repo-private.asc dist/packages/*.rpm
packaging/build-repositories.sh --packages-dir dist/packages
```

Packages install the agent service, CLI, default monitor-mode configuration, and public trust material. Debian packages are built with `dpkg-deb`; RPM packages require `rpmbuild`.
CI and release readiness also run containerized APT and DNF install smoke tests from the generated repositories. These require Docker and verify package-manager installs before a release is cut.
The scheduled `Live Install Canary` workflow runs the same kind of install check against the production `https://vexyl.dev/repo` repositories every six hours to catch publishing or CDN drift after promotion.

Workflow failure emails are sent through Resend when these GitHub Actions secrets are configured:

```bash
RESEND_API_KEY
VEXYL_ALERT_FROM
VEXYL_ALERT_RECIPIENTS
```

`VEXYL_ALERT_RECIPIENTS` accepts comma-separated operator email addresses. `VEXYL_ALERT_REPLY_TO` can also be set as an optional reply-to address.

## Defensive Defaults

- Monitor mode is the default.
- Logs and local decisions redact secrets and avoid storing raw sensitive prompts.
- Local IPv4/IPv6 address and CIDR allowlists are checked before scoring or blocking.
- Firewall changes are plain local `nftables`/`iptables` rules, not hidden persistence.

## Tests

```bash
tests/run-agent-fixtures.sh
python3 -m unittest tests/test_public_intel.py -v
```

The GitHub Actions workflow runs the same safe fixture and public AI threat-intelligence contract checks.

## Security

Do not open public issues that include active secrets, private logs, runnable exploit code, malware code, or step-by-step offensive instructions.

Private vulnerability reports: `security@vexyl.dev`

## License

Vexyl Guard is licensed under the Apache License 2.0. See `LICENSE`.

## Support

Vexyl Guard is free to install. Monthly support plans help fund signed releases, packaging, hosted services, and continued defensive research:

```text
https://vexyl.dev/#support
https://github.com/sponsors/vexyl-labs
```

GitHub Sponsors is also enabled for the Vexyl Labs profile.
