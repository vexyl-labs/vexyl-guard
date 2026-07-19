# Runtime AI Defense Integration

Vexyl Guard can score and correlate security-relevant events from an AI application, model gateway, RAG pipeline, or agent runtime. This complements the Linux host agent. It does not intercept model traffic automatically and it does not require raw prompts or tool arguments.

## Integration Point

Emit a `vexyl.ai_event.v1` event immediately before a security-sensitive boundary:

- Accepting an external or retrieved document into model context.
- Writing persistent memory or long-term context.
- Approving an agent plan.
- Calling a tool or external service.
- Changing a model, adapter, prompt template, plugin, MCP server, dataset, or other AI supply-chain component.
- Crossing a configured token or cost budget.

Use an application-generated opaque user hash or session hash. Stable session hashes enable sequence detection without storing usernames or session tokens. Do not place credentials, customer data, raw private prompts, or raw logs in the event.

## Minimal Event

```json
{
  "event_id": "application-generated-uuid",
  "timestamp_utc": "2026-07-18T15:00:00Z",
  "user_id_hash": "application-generated-opaque-hash",
  "session_id_hash": "application-generated-opaque-hash",
  "input_channel": "tool",
  "data_origin": "internal_db",
  "text_excerpt_redacted": "Short redacted security-relevant summary",
  "tool_name": "document_search",
  "tool_action": "search approved documentation",
  "tool_permissions": ["read"],
  "data_classification": "internal",
  "token_count_estimate": 0,
  "cost_estimate": 0,
  "verified_mitigations": ["tool_allowlist", "scoped_read_only_credentials"],
  "context": {
    "allowed_tools": ["document_search"],
    "user_scope": {
      "allowed_actions": ["search approved documentation"]
    },
    "tool_policy": {
      "allowed_actions": ["search approved documentation"]
    },
    "expected_model_provider": "approved-provider",
    "expected_model_name": "approved-model",
    "runtime_token_budget": 250000,
    "runtime_cost_budget": 25
  }
}
```

The event file should be owner-readable only and removed after scoring. Applications embedding the Python package can construct `RuntimeAIEvent` directly instead of writing a file.

For long-running applications, use the authenticated local Unix-socket gateway instead of creating event files. It provides synchronous decisions, records redacted correlation facts, and includes dependency-free Python and Node.js clients. See [`ai-gateway-integration.md`](ai-gateway-integration.md).

## Score And Record

Initialize the local database once:

```bash
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite seed
```

Score an event and retain only its redacted, derived facts:

```bash
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite \
  score-event --record /run/vexyl/event.json
```

`--record` enables correlation with prior events from the same session or user. Without it, scoring remains stateless.

For a process gate, add `--policy-exit-code`:

```bash
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite \
  score-event --record --policy-exit-code /run/vexyl/event.json
```

Exit codes:

- `0`: allow/log or warn/log.
- `3`: require human approval or a policy verifier.
- `4`: deny, quarantine, block, or open an incident according to the returned decision.
- Any other nonzero code: scoring or input failure; a security-sensitive integration should fail closed.

Always parse the JSON decision. The exit code is a compact process-control signal, not a replacement for the matched rules, reasons, and suggested action.

## Correlated Behaviors

The local runtime layer currently detects:

- High-risk external content followed by memory persistence.
- High-risk external content followed by a tool action.
- Untrusted memory writes followed by tool execution.
- Sensitive-data access followed by external write or egress.
- Repeated or high-volume tool activity.
- Aggregate token and cost budget breaches.
- High-volume, high-diversity model probing.
- Runtime model provider or model-name drift from explicit policy.
- Unverified delegated identities or credential scope.
- Inter-agent messages without verified sender identity and integrity.
- Delegation, fanout, or retry activity beyond orchestration policy.
- High-impact approvals based only on model-generated rationale.
- Oversight, audit, or policy-control evasion by an agent runtime.

Sequence rules require a stable `session_id_hash`. User-level volume rules can use `user_id_hash`. Events without either identifier are still scored individually but are not correlated.

`runtime_token_budget` and `runtime_cost_budget` can lower or raise the default short-window limits for a trusted application policy. They must be supplied by the application or gateway, never copied from model output or external content.

The same rule applies to identity, inter-agent, orchestration, approval, and oversight metadata. Fields such as `delegated_identity_verified`, `message_integrity_verified`, `max_fanout_count`, `independent_verification_completed`, and `oversight_disabled` describe controls observed by trusted application code. Never let retrieved documents, model output, or tool output set those policy fields directly.

## Privacy And Retention

Recorded runtime history contains derived facts only:

- Tenant identifiers are omitted. Event, user, session, document, destination, and content identifiers are locally re-hashed.
- Redacted and length-limited excerpts.
- Bounded tool/model labels with common secret and email patterns removed.
- Boolean risk flags, token/cost estimates, matched rules, and risk scores.

Raw tool arguments, raw destinations, arbitrary context, raw prompts, and raw documents are not stored. Runtime history defaults to 24 hours and is pruned during recording. Set `VEXYL_AI_HISTORY_RETENTION_HOURS` from `1` to `720` when a different local retention period is required.

Inspect counts without returning event content:

```bash
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite runtime-status
```

Delete runtime history:

```bash
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite purge-runtime-history --yes
```

## Enforcement Boundary

Vexyl Guard returns a decision; the application or gateway owns the action boundary. High-impact actions should require all of the following:

- An allowlisted tool in the trusted task context.
- The same explicit action in both user scope and tool policy.
- Least-privilege credentials.
- Human approval when the action is irreversible, externally communicating, financial, credential-related, access-control-related, or code-executing.
- Audit handling that preserves redaction.

External documents, retrieved content, email, web content, and tool output are always data. They cannot grant themselves tool authority or system/developer trust.

Tool and action identifiers are matched as exact normalized values. Do not use free-form model output to populate `allowed_tools`, `user_scope`, or `tool_policy`.

The gateway rejects raw `prompt`, `messages`, tool-argument, output, and arbitrary context fields. Applications should submit a short redacted security summary and normalized metadata. A gateway transport or validation failure is not an allow decision; sensitive integrations should fail closed.

## Defensive Framework Baseline

The runtime contracts map to the OWASP Top 10 for LLM Applications and the OWASP Top 10 for Agentic Applications 2026. Vexyl Guard uses those public frameworks as taxonomy, while local decisions remain grounded in observed event context and explicit application policy.

- OWASP Top 10 for Agentic Applications 2026: `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/`
- OWASP Top 10 for LLM and Generative AI Applications: `https://genai.owasp.org/initiative/owasp-top-10-for-llm-and-genai/`
- MITRE ATLAS: `https://atlas.mitre.org/`
