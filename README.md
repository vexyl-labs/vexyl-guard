# Vexyl Guard

[![CI](https://github.com/vexyl-labs/vexyl-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/vexyl-labs/vexyl-guard/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/vexyl-labs/vexyl-guard?display_name=tag)](https://github.com/vexyl-labs/vexyl-guard/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-245BB3)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-Vexyl%20Labs-121D2F)](https://github.com/sponsors/vexyl-labs)

Vexyl Guard is a free, open-source Linux server security agent for exposed VPS, web, and application hosts. It watches supported local logs for login attacks, exploit probes, hostile automation, suspicious service activity, and selected threats aimed at AI-connected applications.

It starts in monitor mode. Operators review local findings, validate configuration, and decide whether to enable local `nftables` or `iptables` enforcement.

```bash
curl -fsSL https://vexyl.dev/install.sh | sudo sh
sudo systemctl start vexyl-guard
sudo vexyl-guard status
```

> Vexyl Guard is in public preview. Start with one non-critical host and keep provider-console access available while evaluating any root-level security agent.

## OpenAI Build Week 2026

Vexyl Guard fits the **Developer Tools** track as a pre-existing project that was meaningfully extended during the July 13-21 submission period. Judges should evaluate the Build Week work, not the earlier Linux host-agent baseline.

The eligible extension adds four connected capabilities:

- Stateful correlation across external content, memory writes, model use, agent plans, and tool calls.
- An authenticated, local Unix-socket decision gateway with redacted request contracts.
- Python and dependency-free Node.js integration helpers, plus runnable FastAPI and Express reference apps.
- Signed defensive intelligence updates with expiry, revocation, anti-rollback, atomic activation, and last-known-good recovery.

### Judge Quick Start

The judge demo runs from a clone with Python 3.10 or newer. It uses a temporary SQLite database and bundled public defensive records. It does not need root access, a build step, network access, an account, a token, a running daemon, or private intelligence data.

```bash
git clone https://github.com/vexyl-labs/vexyl-guard.git
cd vexyl-guard
./scripts/build-week-demo.sh
```

The demo searches the public prompt-injection baseline, allows an explicitly scoped read-only tool action, records a redacted high-risk external-content event, and then blocks the same otherwise-authorized tool action when it follows that event in the same session. It finishes by returning history counts without raw prompts or tool arguments.

Supported production platforms are Linux hosts using Debian/Ubuntu or Fedora/RHEL-compatible packages. The source demo and tests require Python 3.10 or newer on Linux. Node.js 20 or newer is required for the Node integration tests and Express reference app.

Full submission scope, architecture, evidence, form copy, and video plan: [`docs/build-week-submission.md`](docs/build-week-submission.md)

### Built With Codex And GPT-5.6

The public project existed before Build Week. Commit [`9dc5d17`](https://github.com/vexyl-labs/vexyl-guard/commit/9dc5d170b2365280b3ff763a0f26b2dae883ceed), dated July 12, is the documented pre-challenge baseline. From that baseline through v0.2.15, the public history records 46 changed files, 7,972 additions, and 176 deletions during the submission period.

Codex with GPT-5.6 accelerated repository analysis, multi-file implementation, adversarial test design, Python/Node contract conformance, package integration, release automation, and documentation. It was used to carry one security invariant through each layer: external or model-controlled content remains data and cannot grant itself tool authority.

The operator retained the consequential product and security decisions:

- Extend the existing agent instead of rewriting its monitor-first host behavior.
- Keep decisions local over an authenticated Unix socket rather than opening a network listener.
- Accept normalized, redacted event metadata rather than collecting raw prompts, logs, or tool arguments.
- Require independent task, user-scope, and tool-policy authorization; fail closed at sensitive boundaries.
- Keep active intelligence private while publishing interfaces, safe fallback records, tests, and signed update verification.
- Require authenticated, anti-rollback intelligence delivery with atomic activation and recovery.

The principal eligible implementation commits are:

- [`2f203dd`](https://github.com/vexyl-labs/vexyl-guard/commit/2f203dde438b40d85803fbcf7158edd127956b35): stateful AI runtime defense.
- [`17bab48`](https://github.com/vexyl-labs/vexyl-guard/commit/17bab48bcfa167229e8b9c5401f60e89a8018ca7): authenticated local AI decision gateway.
- [`4f501f4`](https://github.com/vexyl-labs/vexyl-guard/commit/4f501f4a5841a10138f09e5311eda54e5980c030): framework policy guards and cross-language conformance.
- [`b4b03f0`](https://github.com/vexyl-labs/vexyl-guard/commit/b4b03f035be07fd0a45d720dc223a519ec69b06b): signed intelligence updates and recovery.

## Why Vexyl Guard

Internet-facing Linux servers rarely receive only one kind of hostile traffic. Authentication attempts, path guessing, scanner requests, exploit probes, and application-specific attacks can arrive from the same source or change rapidly across categories.

Vexyl Guard provides one small, local scoring path for that activity:

- **Monitor first:** installation does not immediately turn every finding into a firewall rule.
- **Multiple log surfaces:** supported authentication, web, mail, firewall, VPN, database, object-storage, and edge/CDN logs.
- **AI threat context:** prompt-probe classification, rapid mutation signal, and local defensive scoring contracts for prompts, external content, agent plans, and tool calls.
- **Signed intelligence updates:** authenticated, signature-verified defensive records with monotonic versions, atomic activation, and last-known-good recovery.
- **Operator-controlled response:** optional local blocking after policy review and configuration validation.
- **Verifiable delivery:** public source, signed checksums, signed APT metadata, signed RPM packages, and recurring install canaries.
- **Safer feedback:** redacted support reports omit raw logs and host-specific secrets.

Vexyl Guard complements patching, access control, backups, firewall policy, and application security. It does not claim to stop every attack or prove whether every hostile request was generated by AI.

## Quick Links

- Install: `https://vexyl.dev/install/`
- Linux server security: `https://vexyl.dev/linux-server-security/`
- AI threat security: `https://vexyl.dev/ai-threat-security/`
- Resources: `https://vexyl.dev/resources/`
- Verify before installing: `https://vexyl.dev/resources/verify-before-you-install/`
- Public preview feedback: `https://github.com/vexyl-labs/vexyl-guard/issues/1`
- Questions and discussion: `https://github.com/vexyl-labs/vexyl-guard/discussions`
- Structured install report: `https://github.com/vexyl-labs/vexyl-guard/issues/new?template=install_feedback.yml`
- Operator Notes: `https://vexyl.dev/updates/`
- Sponsor Vexyl Labs: `https://github.com/sponsors/vexyl-labs`

## What Is Included

- [`agent/vexyl-guard.sh`](agent/vexyl-guard.sh): Bash host agent for Linux servers.
- [`intel/`](intel): public runtime interfaces and redaction helpers for local defensive scoring. Active intelligence records remain private.
- [`integrations/`](integrations): Python and Node.js boundaries, framework guards, and runnable FastAPI/Express reference apps for the authenticated local AI decision gateway.
- [`vexyl`](vexyl): Python CLI entry point for local threat-intelligence commands.
- [`config/vexyl-guard.conf.example`](config/vexyl-guard.conf.example): monitor-first agent configuration.
- [`packaging/`](packaging): Debian/RPM builds, signed repository tooling, and systemd service.
- [`tests/`](tests): safe fixtures for parsing, classification, scoring, redaction, and policy contracts.

Hosted account, billing, console, deployment, website, active intelligence data, and internal research material are maintained separately from the public agent repository.

## Install in Monitor Mode

The live preview installer is served from Vexyl.dev:

```bash
curl -fsSL https://vexyl.dev/install.sh | sudo sh
sudo systemctl start vexyl-guard
sudo vexyl-guard status
sudo vexyl-guard validate-config
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

Maintainers must configure `VEXYL_PLATFORM_PROMOTION_TOKEN` in the public repository so the release workflow can dispatch and verify the private platform promotion after signed assets are published. Use a fine-grained token scoped only to the `vexyl-platform` repository and its Actions workflows. A missing token fails the release instead of silently leaving `vexyl.dev/repo` behind GitHub.

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

Validate the effective host configuration before starting the service or changing to enforcement mode:

```bash
sudo vexyl-guard validate-config
```

Warnings describe optional or degraded capabilities. Configuration errors return a nonzero exit status and should be resolved before enforcement.

## Runtime AI Defense

AI applications, model gateways, RAG pipelines, and agent runtimes can submit a redacted `vexyl.ai_event.v1` envelope before a memory write, plan approval, tool call, external write, or model invocation. A stable session hash enables sequence detection; a stable user hash enables aggregate volume and budget controls.

```bash
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite \
  score-event --record --policy-exit-code /run/vexyl/event.json
```

Generate a bounded operator explanation from either that event file or a saved
v1 decision:

```bash
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite \
  explain /run/vexyl/event.json

sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite \
  explain --json /run/vexyl/decision.json
```

Explanations use stable rule and context factor codes. They omit excerpts, raw
content, tool arguments, destinations, and raw or non-opaque source identifiers. The
strict `vexyl.risk_decision.v1` gateway schema remains unchanged.

The runtime layer correlates high-risk external content with later memory or tool actions, sensitive-data access with egress, repeated tool loops, aggregate token/cost use, high-diversity model probing, and model identity drift. It also enforces trusted metadata boundaries for delegated identity, inter-agent messages, orchestration fanout, human approval, and runtime oversight. Raw prompts, tool arguments, destinations, and arbitrary event context are not stored. Derived runtime history defaults to 24-hour retention.

Integration contract and privacy boundary: [`docs/security/runtime-ai-defense.md`](docs/security/runtime-ai-defense.md)

Packages also include an opt-in authenticated Unix-socket gateway for synchronous application checks. It is installed disabled and never opens a TCP port:

```bash
sudo systemctl enable --now vexyl-ai-gateway
sudo vexyl gateway health
```

The gateway rejects raw prompt, message, tool-argument, output, and arbitrary context fields. Python adapters and dependency-free Node.js clients cover RAG, memory, agents, MCP tools, model gateways, and AI supply-chain boundaries. ASGI/FastAPI and Express guards expose a request-scoped decision boundary without reading application request bodies. Sensitive actions fail closed when the gateway is unavailable.

Gateway setup and examples: [`docs/security/ai-gateway-integration.md`](docs/security/ai-gateway-integration.md)

Framework and middleware examples: [`docs/security/framework-integrations.md`](docs/security/framework-integrations.md)

Runnable reference apps and safe fixtures: [`integrations/examples/README.md`](integrations/examples/README.md)

### Signed Intelligence Updates

Packages include an opt-in updater for Vexyl's defensive AI threat records. It accepts only authenticated HTTPS responses that also pass local RSA signature, revocation, expiry, sequence, record-hash, and defensive-shape checks. Updates replace intelligence tables atomically and preserve redacted runtime history.

The updater is installed disabled and does not create a credential. After enrolling a host, provision `/etc/vexyl/intel-update.token` with mode `0600`, then enable the randomized six-hour timer:

```bash
sudo systemctl enable --now vexyl-intel-update.timer
sudo systemctl start vexyl-intel-update.service
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite intel-status
```

Trust model, token handling, manual verification, rollback, and recovery: [`docs/security/signed-intelligence-updates.md`](docs/security/signed-intelligence-updates.md)

## Tests

```bash
tests/run-agent-fixtures.sh
python3 -m unittest tests/test_public_intel.py -v
node tests/test_node_gateway_client.mjs
python3 -m unittest tests/test_framework_integrations.py -v
python3 -m unittest tests/test_intel_updates.py -v
node tests/test_node_framework_integrations.mjs
python3 -m tests.run_gateway_conformance
python3 -m tests.run_example_compatibility
# After installing the optional example dependencies:
python3 -m unittest tests/test_example_apps.py -v
node tests/test_express_example.mjs
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
