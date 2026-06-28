# Security Policy

Vexyl Guard is a defensive project for authorized server operators. Please do not open public issues that include active secrets, private logs, runnable exploit code, malware code, or step-by-step offensive instructions.

## Reporting Vulnerabilities

Report suspected vulnerabilities privately by emailing:

```text
security@vexyl.dev
```

Include:

- A clear summary of the issue.
- The affected component and version or commit.
- Safe reproduction notes without live secrets or offensive payloads.
- Expected impact and any suggested mitigation.

We will prioritize reports that affect agent integrity, update verification, policy delivery, authentication, billing/account access, and sensitive event handling.

## Public Issue Boundary

Public GitHub issues are appropriate for bugs, documentation gaps, install problems, feature requests, and defensive detection improvements. Redact hostnames, IP addresses, tokens, customer data, and log lines that identify a real system unless you are certain they are safe to publish.

## Supported Versions

The public preview follows the signed release metadata served from:

```text
https://vexyl.dev/downloads/RELEASE.json
```

Use the latest preview unless a maintainer asks you to test a specific build.
