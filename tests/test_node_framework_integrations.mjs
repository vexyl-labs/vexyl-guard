import assert from "node:assert/strict";

import {
  DECISION_SCHEMA,
  VexylGatewayError,
} from "../integrations/node/vexyl-guard-client.mjs";
import {
  MCPToolGuard,
  ModelGatewayGuard,
  VexylPolicyDenied,
  VexylPolicyUnavailable,
  VexylRequestGuard,
  createVexylGuardMiddleware,
  vexylGuardErrorHandler,
} from "../integrations/node/vexyl-guard-middleware.mjs";

class FakeGatewayClient {
  constructor({ response = allowedResponse(), error } = {}) {
    this.response = response;
    this.error = error;
    this.events = [];
  }

  async score(event) {
    this.events.push(event);
    if (this.error) throw this.error;
    return this.response;
  }
}

function allowedResponse() {
  return {
    ok: true,
    schema: DECISION_SCHEMA,
    request_id: "safe-request-id",
    recorded: true,
    policy_exit_code: 0,
    decision: decisionPayload(0, "allow/log", false),
  };
}

function deniedResponse(policyExitCode = 4) {
  return {
    ok: true,
    schema: DECISION_SCHEMA,
    request_id: "safe-request-id",
    recorded: true,
    policy_exit_code: policyExitCode,
    decision: decisionPayload(
      policyExitCode === 4 ? 78 : 58,
      policyExitCode === 4
        ? "quarantine/block tool action"
        : "require human approval or policy verifier",
      policyExitCode === 4,
    ),
  };
}

function decisionPayload(score, suggestedAction, denyToolCall) {
  return {
    event_id: "safe-event-id",
    score,
    suggested_action: suggestedAction,
    matched_attack_ids: [],
    matched_rules: [],
    reasons: [],
    mitigations_applied: [],
    trust_level: "internal_data",
    redacted_excerpt: "Bounded defensive summary.",
    deny_tool_call: denyToolCall,
    correlation_scope: null,
    correlation_window_seconds: 0,
    correlated_event_count: 0,
  };
}

const request = {};
Object.defineProperty(request, "body", {
  get() {
    throw new Error("middleware must not inspect request.body");
  },
});
const middlewareClient = new FakeGatewayClient();
const middleware = createVexylGuardMiddleware({ client: middlewareClient });
let middlewareError;
middleware(request, {}, (error) => {
  middlewareError = error;
});
assert.equal(middlewareError, undefined);
assert.ok(request.vexylGuard instanceof VexylRequestGuard);
assert.throws(() => {
  request.vexylGuard = "replacement";
});

const allowed = await request.vexylGuard.requireAllowed({
  input_channel: "chat",
  data_origin: "user",
});
assert.equal(allowed.policy_exit_code, 0);

const deniedGuard = new VexylRequestGuard(
  new FakeGatewayClient({ response: deniedResponse(4) }),
);
await assert.rejects(
  deniedGuard.requireAllowed({ input_channel: "tool", data_origin: "internal_db" }),
  VexylPolicyDenied,
);

const unavailableGuard = new VexylRequestGuard(
  new FakeGatewayClient({ error: new VexylGatewayError("local test failure") }),
);
await assert.rejects(
  unavailableGuard.requireAllowed({ input_channel: "chat", data_origin: "user" }),
  VexylPolicyUnavailable,
);

const error = new VexylPolicyDenied(deniedResponse(3));
const response = {
  headersSent: false,
  statusCode: 0,
  headers: {},
  payload: undefined,
  status(code) {
    this.statusCode = code;
    return this;
  },
  set(name, value) {
    this.headers[name] = value;
    return this;
  },
  json(payload) {
    this.payload = payload;
    return this;
  },
};
vexylGuardErrorHandler(error, request, response, (nextError) => {
  throw nextError;
});
assert.equal(response.statusCode, 409);
assert.equal(response.payload.policy_exit_code, 3);
assert.equal(response.payload.matched_rules, undefined);

const mcpClient = new FakeGatewayClient();
const tenantIdHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const mcpGuard = new MCPToolGuard(new VexylRequestGuard(mcpClient), {
  serverName: "docs",
  toolName: "search",
  toolAction: "search approved documentation",
  permissions: ["read"],
  userAllowedActions: ["search approved documentation"],
  policyAllowedActions: ["search approved documentation"],
  verifiedMitigations: ["tool_allowlist", "scoped_read_only_credentials"],
});
await mcpGuard.authorize("Search approved internal documentation.", { tenantIdHash });
assert.equal(mcpClient.events[0].tool_name, "mcp:docs:search");
assert.equal(mcpClient.events[0].tenant_id_hash, tenantIdHash);
assert.deepEqual(mcpClient.events[0].context.allowed_tools, ["mcp:docs:search"]);

const modelClient = new FakeGatewayClient();
const modelGuard = new ModelGatewayGuard(new VexylRequestGuard(modelClient), {
  expectedModelProvider: "approved-provider",
  expectedModelName: "approved-model",
});
await modelGuard.authorize("Invoke the approved summarization model.", {
  modelProvider: "approved-provider",
  modelName: "approved-model",
  tokenCountEstimate: 1200,
});
assert.equal(modelClient.events[0].context.expected_model_name, "approved-model");

console.log("Node.js framework integration contracts verified");
