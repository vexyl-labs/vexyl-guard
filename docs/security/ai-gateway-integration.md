# Local AI Decision Gateway

The Vexyl Guard AI decision gateway gives an AI application a synchronous policy check before it crosses a security-sensitive boundary. It complements the Linux host agent and does not modify or proxy model traffic.

The gateway is local-only:

- It listens on an authenticated Unix socket, not a TCP port.
- It accepts only the bounded `vexyl.ai_event.v1` JSON contract.
- It rejects raw prompt, message, tool-argument, output, and arbitrary context fields.
- It records only the derived, redacted facts used for short-window correlation.
- It returns a decision to the calling application; it never executes a tool or changes application state.

## Enable The Service

The Debian and RPM packages install the gateway, generate `/etc/vexyl/ai-gateway.token`, and leave the service disabled. Enable it only on a host running an AI application that will use the decision boundary:

```bash
sudo systemctl enable --now vexyl-ai-gateway
sudo vexyl gateway health
```

The default socket is `/run/vexyl/ai-gateway.sock`. Both the socket and token are available only to `root` and the local `vexyl` group.

Grant an application service account access, then restart that application so it receives the new group membership:

```bash
sudo usermod -aG vexyl my-ai-service
sudo systemctl restart my-ai-service
```

Membership in `vexyl` authorizes a local process to request decisions. Grant it only to trusted application service accounts. Do not grant it to model sandboxes, tool subprocesses, or untrusted user workloads.

Configuration is in `/etc/vexyl/ai-gateway.conf`. The default service accepts at most 65,536 bytes per request and is restricted to `AF_UNIX` by systemd.

## Decision Contract

Submit an envelope to `POST /v1/decisions`:

```json
{
  "schema": "vexyl.ai_event.v1",
  "event": {
    "tenant_id_hash": "89b92958d05fc449d911d1d517ff3ae6839a73348aac6fec44981be08554e95a",
    "session_id_hash": "application-generated-opaque-hash",
    "input_channel": "tool",
    "data_origin": "internal_db",
    "text_excerpt_redacted": "Read the approved service status",
    "tool_name": "document_search",
    "tool_action": "search approved documentation",
    "tool_permissions": ["read"],
    "context": {
      "allowed_tools": ["document_search"],
      "user_scope": {
        "allowed_actions": ["search approved documentation"]
      },
      "tool_policy": {
        "allowed_actions": ["search approved documentation"]
      }
    }
  }
}
```

The gateway always records the redacted decision facts so sequence detection remains active. A successful HTTP response uses `vexyl.risk_decision.v1` and includes:

- `policy_exit_code: 0` for allow/log or warn/log.
- `policy_exit_code: 3` when an independent verifier or human approval is required.
- `policy_exit_code: 4` for deny, quarantine, or block decisions.
- `decision` with score, matched rules, reasons, action, and correlation details.

Policy decisions use HTTP 200. Authentication, schema, size, and local scoring failures use non-200 responses. A security-sensitive integration must fail closed when the gateway is unavailable or returns an invalid response.

The packaged Python and Node.js clients validate both sides of this contract. Requests reject unknown nested context, raw prompt/tool fields, invalid enums, and out-of-range values before transmission. Responses must use the complete v1 decision shape, confirm that correlation state was recorded, match the submitted event ID, and keep score, suggested action, tool denial, and policy exit code consistent. Unknown response fields and contradictory or downgraded decisions raise a client error instead of becoming an allow result.

### Tenant Isolation

Multi-tenant applications should derive `tenant_id_hash` with `hash_identifier(internal_tenant_reference, application_hashing_key)` and include the same value at every Vexyl boundary for that tenant. The field accepts only a lowercase 64-character HMAC-SHA256 value. Do not send a tenant name, customer ID, domain, or billing identifier.

Vexyl Guard hashes the supplied value again before local storage. Correlation first matches tenant scope and only then evaluates session or user history. Events from different tenant hashes never share correlation state, even when their session or user hashes are identical. Events without tenant scope remain supported and are isolated from scoped history.

## Python Integration

Install the source package in the application virtual environment:

```bash
python3 -m pip install /path/to/vexyl-guard-source
```

The Linux package also places the modules in `/opt/vexyl`; package-managed applications can add that directory to `PYTHONPATH` instead of copying files.

Call the gateway before the tool executes:

```python
from intel.client import GatewayClientError, VexylGatewayClient
from intel.integration import hash_identifier, tool_call_event

client = VexylGatewayClient()
tenant_hash = hash_identifier(local_tenant_id, application_hashing_key)
session_hash = hash_identifier(local_session_id, application_hashing_key)

event = tool_call_event(
    "Search the approved internal documentation corpus.",
    tool_name="document_search",
    tool_action="search approved documentation",
    permissions=["read"],
    allowed_tools=["document_search"],
    user_allowed_actions=["search approved documentation"],
    policy_allowed_actions=["search approved documentation"],
    verified_mitigations=["tool_allowlist", "scoped_read_only_credentials"],
    tenant_id_hash=tenant_hash,
    session_id_hash=session_hash,
)

try:
    response = client.score(event)
except GatewayClientError:
    deny_tool_call("Vexyl Guard decision service unavailable")
else:
    if response["policy_exit_code"] != 0:
        deny_tool_call(response["decision"]["suggested_action"])
    execute_allowlisted_tool()
```

The Python adapters cover prompts, RAG content, memory writes, agent plans, generic tools, MCP tools, model API use, and AI supply-chain changes. Adapter inputs are concise security summaries and normalized policy labels, not raw prompts or tool arguments.

## Node.js Integration

The package installs a dependency-free ES module at:

```text
/usr/share/vexyl/integrations/node/vexyl-guard-client.mjs
```

Use it before a retrieved document is added to model context:

```javascript
import {
  VexylGatewayClient,
  hashIdentifier,
  ragContentEvent,
} from "/usr/share/vexyl/integrations/node/vexyl-guard-client.mjs";

const client = new VexylGatewayClient();
const tenantIdHash = hashIdentifier(localTenantId, applicationHashingKey);
const sessionIdHash = hashIdentifier(localSessionId, applicationHashingKey);
const event = ragContentEvent("External document contains instruction-like content.", {
  documentIds: [opaqueDocumentHash],
  tenantIdHash,
  sessionIdHash,
});

const response = await client.score(event);
if (response.policy_exit_code !== 0) {
  quarantineRetrievedContent(response.decision.suggested_action);
}
```

Unhandled client errors should stop a sensitive action. Do not silently bypass the gateway when a model, RAG, memory, tool, or supply-chain boundary depends on its decision.

## Integration Points

Use the gateway at these application-owned boundaries:

| Boundary | Submit before | Adapter |
| --- | --- | --- |
| User prompt | Model context assembly | `prompt_event` |
| RAG or external document | Content enters trusted model context | `rag_content_event` |
| Persistent memory | Memory write commits | `memory_write_event` |
| Agent plan | Plan is approved or delegated | `agent_plan_event` |
| Tool or MCP call | Arguments reach the tool executor | `tool_call_event` or `mcp_tool_call_event` |
| Model API | Provider/model invocation and budget spend | `model_api_event` |
| Supply chain | Model, adapter, prompt template, plugin, or dataset change | `supply_chain_event` |

The trusted application must populate allowlists, user scope, tool policy, model identity expectations, budgets, and approval state. Never copy those control fields from retrieved content, model output, tool output, or an inter-agent message.

## Operations

Inspect privacy-safe history counts:

```bash
sudo vexyl gateway health
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite runtime-status
```

Submit a local redacted test event through the running service:

```bash
sudo vexyl gateway score-event --policy-exit-code event.json
```

Rotate the local bearer token:

```bash
sudo systemctl stop vexyl-ai-gateway
sudo vexyl gateway init-token --force --group vexyl
sudo systemctl start vexyl-ai-gateway
```

Restart every authorized application after rotation. Never print the token, place it in source control, pass it as a command-line argument, or send it to a hosted service.
