# OpenAI Build Week 2026 Submission

This document contains the judge path, eligible implementation scope, Devpost copy, and video plan for Vexyl Guard. It describes only public interfaces and safe defensive examples. Active intelligence records, private research, credentials, and host data are not part of the public repository.

## Submission Summary

**Project name:** Vexyl Guard

**Category:** Developer Tools

**Tagline:** Local, redacted policy checks for AI-connected workloads, backed by a monitor-first Linux security agent.

**Built with:** Codex, GPT-5.6, Python 3, Bash, SQLite, Node.js, systemd, and GitHub Actions

**Challenge:** `https://openai.devpost.com/`

**Repository:** `https://github.com/vexyl-labs/vexyl-guard`

**Product:** `https://vexyl.dev`

**Release:** `https://github.com/vexyl-labs/vexyl-guard/releases/tag/v0.2.15`

## Short Description

Vexyl Guard is an open-source Linux security agent with a local policy gateway for AI-connected applications. The Build Week extension correlates redacted runtime events across retrieved content, memory, agent plans, model use, and tool calls; requires explicit tool authorization; and distributes defensive intelligence through signed, anti-rollback updates.

## Project Description

AI-connected applications can cross several trust boundaries in seconds. An external document enters a RAG context, a model proposes a plan, memory persists it, and a tool acts on it. Looking at each event in isolation misses the sequence, while collecting every raw prompt and tool argument creates a second security problem.

During Build Week, Vexyl Guard was extended with a local decision layer for those boundaries. Applications submit a small `vexyl.ai_event.v1` envelope containing normalized, redacted security metadata. Vexyl Guard scores the event from 0 to 100, correlates it with short-lived derived history, and returns matched defensive rules plus an action such as allow, warn, require approval, quarantine, or block.

External content never receives system or developer trust. Tool calls must be allowed independently by the task, user scope, and tool policy. High-impact actions require approval. Raw prompts, arbitrary context, raw tool arguments, secrets, and host logs are rejected or omitted from the gateway contract.

The runtime is exposed through an authenticated Unix socket rather than a TCP listener. Python helpers and dependency-free Node.js clients cover RAG, memory, agent, MCP-tool, model-gateway, ASGI/FastAPI, and Express boundaries. Signed intelligence updates add local signature verification, expiry and revocation checks, monotonic sequence enforcement, atomic activation, and last-known-good recovery.

This complements the existing monitor-first Linux host agent. It does not claim to identify whether every request was AI-generated, and it does not silently execute enforcement actions on behalf of an application.

## Devpost Story

### Inspiration

Server security and AI application security are often treated as separate products even when they protect the same workload. A Linux host can be patched and monitored while its AI application still accepts untrusted retrieved instructions, over-broad tool calls, or model supply-chain drift. We wanted one local, operator-controlled boundary that could evaluate both conventional host activity and security-relevant AI runtime behavior without collecting a warehouse of sensitive prompts.

### What It Does

Vexyl Guard provides a monitor-first Linux agent and a local AI decision gateway. The Build Week work adds:

- Stateful detection of external-content-to-memory and external-content-to-tool sequences.
- Sensitive-read-to-egress, repeated-tool, token/cost, model-probing, identity, orchestration, approval, and oversight checks.
- Explicit task, user-scope, and tool-policy authorization for agent actions.
- Redacted event models that reject raw prompts, messages, tool arguments, outputs, and unknown context fields.
- An authenticated Unix-socket gateway with Python and Node.js clients.
- ASGI/FastAPI and Express guards with shared cross-language conformance fixtures.
- Signature-verified intelligence updates with anti-rollback and recovery.

### How We Built It

The eligible extension is primarily Python 3 standard-library code, dependency-free Node.js modules, Bash packaging, SQLite state, systemd units, and GitHub Actions. A versioned event contract feeds a common scoring layer. The gateway validates and authenticates requests before scoring and records only bounded derived facts needed for short-window correlation.

The same conformance fixtures run against Python and Node integrations so an allow or deny result cannot drift by language. Package smoke tests exercise clean Debian and RPM-family installs. Release workflows publish signed checksums and packages, then verify the promoted production repository.

### How Codex And GPT-5.6 Were Used

Codex with GPT-5.6 was the implementation partner for the Build Week extension. It inspected the pre-existing repository, traced the existing monitor-first and packaging boundaries, implemented coordinated changes across Python, Node.js, Bash, systemd, tests, and documentation, and repeatedly ran the real test and release paths.

GPT-5.6 was particularly useful for maintaining invariants across layers: schema and model fields, redaction rules, score behavior, gateway validation, client behavior, middleware policy, package contents, and documentation all had to agree. Codex also generated adversarial-but-non-offensive test cases, found contract drift, tightened failure behavior, and verified clean package installation and signed release promotion.

Human decisions remained explicit. We chose a local Unix socket over a network API, redacted metadata over raw prompt collection, independent authorization over model-declared permission, fail-closed behavior for sensitive integrations, private active intelligence with public safe fallbacks, and signed monotonic updates with recovery.

### Challenges

The hardest problem was state without surveillance. Sequence detection needs enough history to connect external content to a later memory or tool action, but the database must not become a prompt archive. The implementation stores short, redacted summaries and derived flags, locally hashes identifiers again, enforces private file permissions, limits retention, and exposes count-only status output.

A second challenge was making enforcement consistent across languages and frameworks. Shared fixtures and cross-language conformance tests keep Python and Node policy behavior aligned.

### Accomplishments

- Added a complete local runtime decision path without changing the host agent's monitor-first default.
- Added stateful security checks while keeping raw prompts and tool arguments out of runtime history.
- Shipped authenticated gateway and framework integrations without opening a TCP port.
- Added signature, revocation, expiry, sequence, atomicity, and recovery checks for intelligence updates.
- Released the work as v0.2.15 with public source, signed artifacts, APT/DNF packages, CI, and live install canaries.

### What We Learned

AI runtime defense is strongest at explicit application boundaries, not through hidden interception. The application already knows when it is about to retrieve content, persist memory, call a tool, or change a model. A small redacted contract at those boundaries is easier to audit, test, and operate than broad traffic capture.

We also learned that authorization context must come from trusted application policy. Retrieved content and model output cannot be allowed to populate their own scope, approval, or mitigation fields.

### What's Next

Next work will expand public integration examples, operator-facing decision explanations, compatibility testing, and privacy-preserving evaluation fixtures. Enforcement remains opt-in and operator-controlled. Any future action workflow will keep explicit approval, auditability, least privilege, and redaction as hard requirements.

## Build Week Eligibility And Evidence

Vexyl Guard existed before the event. The last public commit before the July 13 submission period is:

```text
9dc5d170b2365280b3ff763a0f26b2dae883ceed
2026-07-12T19:39:31-05:00
Link public discussions
```

The Build Week functionality was added after that baseline. Through v0.2.15, the public diff contains 46 changed files, 7,972 additions, and 176 deletions. Principal implementation commits are:

```text
2f203dde438b40d85803fbcf7158edd127956b35  Add stateful AI runtime defense
17bab48bcfa167229e8b9c5401f60e89a8018ca7  Add authenticated AI decision gateway
4f501f4a5841a10138f09e5311eda54e5980c030  Add framework AI policy guards
b4b03f035be07fd0a45d720dc223a519ec69b06b  Add signed AI intelligence updates
35a0db902d7a0ef1c47572bd819807d45aaefb04  Release Vexyl Guard v0.2.15
```

Judges should evaluate that extension. Earlier host-agent, website, account, and package-platform work is context, not claimed Build Week implementation.

## Architecture

```text
AI application / RAG pipeline / agent runtime
  -> redacted vexyl.ai_event.v1 metadata
  -> authenticated local Unix socket
  -> contract validation and policy scoring
  -> short-lived derived SQLite correlation history
  -> allow / warn / approval / quarantine / block decision

Signed Vexyl intelligence endpoint
  -> authenticated HTTPS download
  -> local signature, expiry, revocation, sequence, and shape checks
  -> atomic activation with last-known-good recovery
```

The Linux host agent remains monitor-first. The AI application owns its final action boundary and should fail closed when a sensitive decision cannot be obtained.

## Judge Test Path

### Requirements

- Linux
- Bash
- Python 3.10 or newer
- No root access
- No network access after cloning
- No account or credential
- No build step

### Run

```bash
git clone https://github.com/vexyl-labs/vexyl-guard.git
cd vexyl-guard
./scripts/build-week-demo.sh
```

The script creates a private temporary SQLite database, loads public defensive fallback records, and demonstrates:

1. Direct and indirect prompt-injection records are searchable.
2. A scoped read-only action is allowed.
3. Retrieved external content is forced to untrusted-data status.
4. A later tool call in the same session is denied even when that tool is otherwise scoped and allowlisted.
5. Runtime status returns counts rather than raw prompt or tool data.
6. All temporary files are deleted when the demo exits.

### Full Tests

```bash
tests/run-agent-fixtures.sh
python3 -m unittest tests/test_public_intel.py -v
python3 -m unittest tests/test_framework_integrations.py -v
python3 -m unittest tests/test_intel_updates.py -v
node tests/test_node_gateway_client.mjs
node tests/test_node_framework_integrations.mjs
python3 -m tests.run_gateway_conformance
```

## Supported Platforms

- Production agent and packages: Debian/Ubuntu and Fedora/RHEL-compatible Linux hosts.
- Source demo and Python tests: Linux with Python 3.10 or newer.
- Node integration tests: Linux with Node.js 20 or newer.
- Service integration: systemd and a Unix-domain socket.

Vexyl Guard is not an Android antivirus, VPN, SSH client, third-party scanner, or exploit tool.

## Safety And Privacy

- Public fallback records contain defensive summaries, indicators, mitigations, and framework mappings only.
- Runnable exploit code, malware code, full jailbreak payloads, and offensive instructions are excluded.
- The gateway rejects raw prompts, messages, tool arguments, outputs, and arbitrary unknown context.
- Runtime history is local, private, redacted, bounded, and short-lived.
- External content can never grant itself system/developer trust or tool authority.
- Active intelligence and internal research are not included in the public repository.

## Demo Video Plan

Target length: **2 minutes 40 seconds**. Keep the final upload below three minutes. Record a clean terminal and the Vexyl Guard product page. Use a clear human or generated voiceover and no music. Do not show tokens, private logs, hostnames, IP addresses, customer data, browser bookmarks, notifications, or unrelated tabs.

### Generated Voiceover Workflow

Generate the six narration blocks below as separate audio clips instead of one long file. This keeps each clip aligned with its shot and lets one section be corrected without regenerating the entire voiceover.

- Use a neutral stock voice. Do not clone or imitate a real person.
- Keep the speaking rate near normal, with roughly 0.25 seconds of silence at each clip boundary.
- If needed, enter `Vex-ill` for pronunciation, but keep the visible product name and captions as `Vexyl`.
- Enter `G P T five point six`, `Node dot J S`, and `system D` if the voice engine mispronounces the technical names. Correct the final captions to `GPT-5.6`, `Node.js`, and `systemd`.
- Export the finished video as a 1080p H.264 MP4. Confirm the duration is below three minutes before uploading.
- Enable captions on YouTube and manually correct `Vexyl Guard`, `Codex`, `GPT-5.6`, `Unix socket`, `Node.js`, and `systemd`.

### Shot List And Narration

**0:00-0:20 - Product and problem**

Show `https://vexyl.dev`, then the terminal.

> Vexyl Guard is an open-source, monitor-first Linux security agent. For Build Week, I extended it with a local policy gateway for AI-connected workloads, where one retrieved document can influence memory, an agent plan, and a later tool call.

**0:20-0:43 - Eligible Build Week scope**

Show the Build Week section of `README.md`, including the four eligible commits.

> The project existed before the event, so this submission is specifically the work added after July thirteenth: stateful AI runtime correlation, an authenticated Unix-socket gateway, Python and Node framework guards, and signed intelligence updates.

**0:43-1:48 - Working demo**

Run:

```bash
./scripts/build-week-demo.sh
```

Pause briefly on the search, allow, external-content, correlated deny, and privacy-status outputs.

> This no-root demo uses public defensive records and a temporary local database. First, Vexyl finds direct and indirect prompt-injection patterns. A read-only tool action is allowed because the tool, user scope, and policy all agree. Next, retrieved content attempts to redirect the task. Vexyl marks it untrusted and records only derived, redacted facts. The same otherwise-authorized tool action now follows that event in the same session, so Vexyl blocks it at the correlation boundary. Status returns a count, not raw prompts or tool arguments, and the temporary data is removed.

**1:48-2:15 - Architecture and delivery**

Show the architecture block in this document, then the v0.2.15 release page without exposing unrelated browser UI.

> Applications send normalized metadata over an authenticated local Unix socket; Vexyl never opens a TCP listener for this path. Defensive intelligence updates must pass signature, expiry, revocation, monotonic sequence, and shape checks before atomic activation, with last-known-good recovery if needed.

**2:15-2:43 - Codex and GPT-5.6**

Show the README's Codex section and a terminal view of the dated commit history.

> I used Codex with GPT-5.6 to inspect the existing architecture and implement coordinated Python, Node, Bash, systemd, test, packaging, and documentation changes. It accelerated adversarial test design and cross-language conformance. I kept the key decisions human-owned: local over networked, redacted over raw collection, explicit authorization over model-declared permission, and fail closed for sensitive actions.

**2:43-2:52 - Close**

Return to the Vexyl Guard page.

> Vexyl Guard brings host visibility and AI runtime policy into one operator-controlled, open-source Linux project. The repository and judge demo are linked below.

## YouTube Upload Copy

**Title:** Vexyl Guard: Local AI Runtime Defense | OpenAI Build Week 2026

**Description:**

```text
Vexyl Guard is an open-source, monitor-first Linux security agent with a local policy gateway for AI-connected applications.

This OpenAI Build Week demo shows the work added with Codex and GPT-5.6: stateful runtime correlation, an authenticated Unix-socket gateway, Python and Node.js framework guards, and signed defensive intelligence updates.

Repository and judge demo:
https://github.com/vexyl-labs/vexyl-guard

Product:
https://vexyl.dev

Release:
https://github.com/vexyl-labs/vexyl-guard/releases/tag/v0.2.15

#OpenAIBuildWeek #Codex #Cybersecurity
```

Set visibility to **Public** and verify playback in a signed-out browser window. Do not add copyrighted music. Keep automatic captions enabled, then correct product names and technical terms before submitting the URL.

## Final Submission Checklist

### Requirement Coverage

| Build Week requirement | Vexyl Guard submission artifact |
| --- | --- |
| Working project | `./scripts/build-week-demo.sh` runs locally without root, network access, credentials, or a build step. |
| Category | Developer Tools. |
| Project description | Use the Short Description and Devpost Story above. |
| Public demo video under three minutes | Shot list, narration, and YouTube copy are ready above; recording and upload remain manual. |
| Public repository and license | `https://github.com/vexyl-labs/vexyl-guard`, Apache-2.0. |
| Setup, sample data, and judge test path | The README Judge Quick Start uses bundled safe fallback records and a temporary database. |
| Codex and GPT-5.6 contribution | The README and Devpost Story identify the accelerated work and the human-owned decisions. |
| Developer-tool installation and platforms | The README documents package installation, source testing, supported Linux platforms, and the no-build judge demo. |
| Codex session ID | Run `/feedback` in the main project thread and paste the returned ID into Devpost; this cannot be prefilled in the repository. |

- Select **Developer Tools**.
- Paste the tagline, short description, and Devpost story from this document.
- Use `https://github.com/vexyl-labs/vexyl-guard` as the public Apache-2.0 repository.
- Link the public YouTube video and verify it plays while signed out.
- Keep the video below three minutes and include audible coverage of both Codex and GPT-5.6.
- In this Codex project thread, run `/feedback`, choose to share the existing session, submit the feedback dialog, and paste the returned session ID into Devpost.
- Do not substitute a local transcript filename or internal session identifier for the ID returned by `/feedback`.
- Submit before July 21, 2026 at 5:00 PM Pacific / 7:00 PM Central.
- Re-open the submitted Devpost page and verify every link before the deadline.
