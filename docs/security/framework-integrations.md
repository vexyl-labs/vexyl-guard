# Framework Integrations

Vexyl Guard framework integrations place the local AI decision gateway at application-owned boundaries. They do not intercept requests, read framework request bodies, proxy model traffic, or execute tools.

The application remains responsible for creating a short redacted security summary and supplying trusted policy metadata. Retrieved content, model output, tool output, and inter-agent messages must never populate allowlists, user scope, tool policy, approval state, model identity expectations, or budgets.

## FastAPI And ASGI

`VexylASGIMiddleware` is dependency-free ASGI middleware. It adds a `VexylRequestGuard` to request state and converts uncaught Vexyl policy exceptions into bounded JSON responses:

- HTTP `409` for policy code `3`, which requires approval or independent verification.
- HTTP `403` for policy code `4`, which denies or quarantines an action.
- HTTP `503` when the local gateway is unavailable or returns an invalid response.

The middleware does not call `receive()` and does not inspect request headers or bodies.

```python
from fastapi import FastAPI, Request

from intel.integration import rag_content_event
from intel.middleware import VexylASGIMiddleware

app = FastAPI()
app.add_middleware(VexylASGIMiddleware)


@app.post("/retrieve")
async def retrieve(request: Request):
    event = rag_content_event(
        "External document contains instruction-like text.",
        document_ids=[opaque_document_hash],
        session_id_hash=opaque_session_hash,
    )
    await request.state.vexyl_guard.require_allowed(event)
    return add_redacted_document_to_context()
```

Use `score(event)` when the application needs to display or route a decision itself. Use `require_allowed(event)` immediately before a sensitive boundary; it fails closed for policy codes `3` and `4` and for gateway failures.

## Express

The dependency-free Node.js middleware adds a non-writable `req.vexylGuard` property and never reads `req.body`:

```javascript
import express from "express";
import { ragContentEvent } from "/usr/share/vexyl/integrations/node/vexyl-guard-client.mjs";
import {
  createVexylGuardMiddleware,
  vexylGuardErrorHandler,
} from "/usr/share/vexyl/integrations/node/vexyl-guard-middleware.mjs";

const app = express();
app.use(createVexylGuardMiddleware());

app.post("/retrieve", async (req, res, next) => {
  try {
    const event = ragContentEvent(
      "External document contains instruction-like text.",
      {
        documentIds: [opaqueDocumentHash],
        sessionIdHash: opaqueSessionHash,
      },
    );
    await req.vexylGuard.requireAllowed(event);
    res.json(addRedactedDocumentToContext());
  } catch (error) {
    next(error);
  }
});

app.use(vexylGuardErrorHandler);
```

Install the Vexyl error handler after application routes. Applications using their own error handler can catch `VexylPolicyDenied` and `VexylPolicyUnavailable` directly.

## MCP Tools

Configure MCP tool identity and authorization from static application policy. The model can request a tool, but it cannot add itself to the allowlist or widen the action label.

```python
from intel.middleware import MCPToolGuard

mcp_guard = MCPToolGuard(
    request.state.vexyl_guard,
    server_name="docs",
    tool_name="search",
    tool_action="search approved documentation",
    permissions=["read"],
    user_allowed_actions=["search approved documentation"],
    policy_allowed_actions=["search approved documentation"],
    verified_mitigations=[
        "tool_allowlist",
        "scoped_read_only_credentials",
    ],
)

await mcp_guard.authorize(
    "Search the approved internal documentation corpus.",
    session_id_hash=opaque_session_hash,
)
result = await execute_mcp_tool_with_validated_arguments()
```

The normalized tool identity becomes `mcp:docs:search`. The same exact value must be authorized by the trusted tool policy. Raw MCP arguments are not included in the event.

## Model Gateways

`ModelGatewayGuard` checks the selected provider and model against application-owned expectations and submits token and cost estimates to the stateful budget controls:

```python
from intel.middleware import ModelGatewayGuard

model_guard = ModelGatewayGuard(
    request.state.vexyl_guard,
    expected_model_provider="approved-provider",
    expected_model_name="approved-model",
    runtime_token_budget=250_000,
    runtime_cost_budget=25.0,
)

await model_guard.authorize(
    "Invoke the approved summarization model.",
    model_provider=selected_provider,
    model_name=selected_model,
    session_id_hash=opaque_session_hash,
    token_count_estimate=estimated_tokens,
    cost_estimate=estimated_cost,
)
response = await invoke_model_provider()
```

Provider selection, model selection, budgets, and cost estimates must come from trusted gateway code. Do not accept those control values from the model request body without independent validation.

Equivalent `MCPToolGuard` and `ModelGatewayGuard` classes are exported by `vexyl-guard-middleware.mjs` for Express and other Node.js applications.

## Runnable Reference Apps

[`integrations/examples`](../../integrations/examples) contains small FastAPI and Express applications plus reusable Python and Node.js RAG and MCP boundaries. The examples use fixed synthetic metadata and never parse or forward HTTP request bodies. Local document and session references are converted to keyed hashes before an event reaches the gateway.

The examples bind to loopback, keep authorization policy in application-owned constants, reject malformed MCP queries, and install bounded policy-error handling. They are intended to be copied and adapted at an existing application boundary, not deployed as public gateway proxies.

Setup commands, package-installed paths, and safe production adaptation notes are in the [example README](../../integrations/examples/README.md).

## Conformance

The shared conformance fixtures are evaluated through the real Python gateway by both clients:

```bash
python3 -m tests.run_gateway_conformance
python3 -m tests.run_example_compatibility
```

The harnesses verify matching policy outcomes for authorized read-only tools, unauthorized actions, retrieved instruction takeover, model identity drift, disabled runtime oversight, and the packaged RAG/MCP boundaries. Client tests also verify that malformed, unrecorded, mismatched, or downgraded decision responses fail closed and that nested request context cannot carry undeclared raw data. Fixtures contain defensive summaries only, not full jailbreak payloads, exploit instructions, or malware code.

Run all framework contracts:

```bash
python3 -m unittest tests/test_framework_integrations.py -v
node tests/test_node_framework_integrations.mjs
# After installing integrations/examples dependencies:
python3 -m unittest tests/test_example_apps.py -v
node tests/test_express_example.mjs
```
